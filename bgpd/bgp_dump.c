/* BGP-4, BGP-4+, BGP-5 dump routine
   Copyright (C) 1996, 97 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "version.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "prefix.h"
#include "linklist.h"

#include "bgpd.h"
#include "bgp_aspath.h"
#include "bgp_route.h"
#include "bgp_attr.h"
#include "bgp_dump.h"
#include "bgp_peer.h"
#include "bgp_community.h"

extern FILE *logfp;

int dump_open;
int dump_update;
int dump_keepalive;
int dump_notify;

/* messages for BGP-4 status */
message bgp_status_msg[] = 
{
  { 0, "null" },
  { Idle, "Idle" },
  { Connect, "Connect" },
  { Active, "Active" },
  { OpenSent, "OpenSent" },
  { OpenConfirm, "OpenConfirm" },
  { Established, "Established" },
};
int bgp_status_msg_max = BGP_STATUS_MAX;

/* message for BGP-4 packet sort */
message bgp_packet_msg[] = 
{
  { 0, "null" },
  { BGP_MSG_OPEN, "OPEN" },
  { BGP_MSG_UPDATE, "UPDATE" },
  { BGP_MSG_NOTIFY, "NOTIFY" },
  { BGP_MSG_KEEPALIVE, "KEEPALIVE"},
};
int bgp_packet_msg_max = BGP_MSG_MAX;

/* message for BGP-4 Notify */
message bgp_notify_msg[] = 
{
  { 0, "null" },
  { BGP_NOTIFY_HEADER_ERR, "Message Header Error"},
  { BGP_NOTIFY_OPEN_ERR, "OPEN Message Error"},
  { BGP_NOTIFY_UPDATE, "UPDATE Message Error"},
  { BGP_NOTIFY_HOLD_ERR, "Hold Timer Expired"},
  { BGP_NOTIFY_FSM_ERR, "Finite State Machine Error"},
  { BGP_NOTIFY_CEASE, "Cease"},
};
int bgp_notify_msg_max = BGP_NOTIFY_MAX;

message bgp_notify_head_msg[] = 
{
  { 0, "null"},
  { BGP_NOTIFY_HEADER_NOT_SYNC, ""},
  { BGP_NOTIFY_HEADER_BAD_MESLEN, ""},
  { BGP_NOTIFY_HEADER_BAD_MESTYPE, ""}
};
int bgp_notify_head_msg_max = BGP_NOTIFY_HEADER_MAX;

message bgp_notify_open_msg[] = 
{
  { 0, "null" },
  { BGP_NOTIFY_OPEN_UNSUP_VERSION, "Unsupported Version Number." },
  { BGP_NOTIFY_OPEN_BAD_PEER_AS, "Bad Peer AS."},
  { BGP_NOTIFY_OPEN_BAD_BGP_IDENT, "Bad BGP Identifier."},
  { BGP_NOTIFY_OPEN_UNSUP_PARAM, "Unsupported Optional Parameter."},
  { BGP_NOTIFY_OPEN_AUTH_FAILURE, "Authentication Failure."},
  { BGP_NOTIFY_OPEN_UNACEP_HOLDTIME, "Unacceptable Hold Time."}, 
  { BGP_NOTIFY_OPEN_UNSUP_CAPBL, "Unsupported Capability."},
};
int bgp_notify_open_msg_max = BGP_NOTIFY_OPEN_MAX;

message bgp_notify_update_msg[] = 
{
  { 0, "null"}, 
  { BGP_NOTIFY_UPDATE_MAL_ATTR, "Malformed Attribute List."},
  { BGP_NOTIFY_UPDATE_UNREC_ATTR, "Unrecognized Well-known Attribute."},
  { BGP_NOTIFY_UPDATE_MISS_ATTR, "Missing Well-known Attribute."},
  { BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR, "Attribute Flags Error."},
  { BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, "Attribute Length Error."},
  { BGP_NOTIFY_UPDATE_INVAL_ORIGIN, "Invalid ORIGIN Attribute."},
  { BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP, "AS Routing Loop."},
  { BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP, "Invalid NEXT_HOP Attribute."},
  { BGP_NOTIFY_UPDATE_OPT_ATTR_ERR, "Optional Attribute Error."},
  { BGP_NOTIFY_UPDATE_INVAL_NETWORK, "Invalid Network Field."},
  { BGP_NOTIFY_UPDATE_MAL_AS_PATH, "Malformed AS_PATH."},
};
int bgp_notify_update_msg_max = BGP_NOTIFY_UPDATE_MAX;

char *
lookupmes (message *array, int key)
{
  message *pnt;

  for (pnt = array; pnt->key != 0; pnt++) {
    if (pnt->key == key) {
      return pnt->str;
    }
  }  
  return NULL;
}

/* message lookup function */
char *
mes_lookup (message *meslist, int max, int index)
{
  if (index < 0 || index >= max) {
    log ("message index out of bound: %d\n", max);
    return NULL;
  }
  return meslist[index].str;
}

/* Dump bgp header information. */
void
bgp_dump_header (struct bgp_header *bgp_header)
{
  int flag = 0;

  switch (bgp_header->type) {
  case BGP_MSG_OPEN:
    if (IS_SET(dump_open, DUMP_DETAIL))
      flag = 1;
    break;
  case BGP_MSG_UPDATE:
    if (IS_SET(dump_open, DUMP_DETAIL))
      flag = 1;
    break;
  case BGP_MSG_KEEPALIVE:
    if (IS_SET(dump_keepalive, DUMP_DETAIL))
      flag = 1;
    break;
  default:
  }
  if (flag) {
    log ( "Head: %s(%d) length(%d)\n",
	     LOOKUP (bgp_packet_msg, bgp_header->type), bgp_header->type, 
	     bgp_header->length);
    log_flush ();
  }
}

/* Dump attribute. */
void
bgp_dump_attr (struct peer *peer, struct attr *attr)
{
  char *bgp_update_str[] = {"i","e","?"};

  if (attr == NULL)
    return;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    log2 (" lpref: %ld", attr->local_pref);

  log2 (" nexthop: %s", inet_ntoa (attr->next_hop));

  /* MED */
  if (attr->med)
    log2 (" med: %ld", attr->med);

  if (attr->community) 
    {
      log2 (" comm:");
      community_print (logfp, attr->community);
    }

  if (attr->aspath) 
    {
      log2 (" aspath:");
      aspath_log (attr->aspath);
    }

  log2 (" %s", bgp_update_str[attr->origin]);
}

void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  char buf[BUFSIZ];

  len = vty_out (vty, "%s/%d", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen);
  len = 20 - len;
  if (len < 0)
    len = 0;
  vty_out (vty, "%*s", len, " ");
}

/* dump notify packet */
void
bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify)
{
  char *subcode_str;

  subcode_str = "";

  switch (bgp_notify->err_code) {
  case BGP_NOTIFY_HEADER_ERR:
    subcode_str = LOOKUP (bgp_notify_head_msg, bgp_notify->err_subcode);
    break;
  case BGP_NOTIFY_OPEN_ERR:
    subcode_str = LOOKUP (bgp_notify_open_msg, bgp_notify->err_subcode);
    break;
  case BGP_NOTIFY_UPDATE:
    subcode_str = LOOKUP (bgp_notify_update_msg, bgp_notify->err_subcode);
    break;
  case BGP_NOTIFY_HOLD_ERR:
    subcode_str = "";
    break;
  case BGP_NOTIFY_FSM_ERR:
    subcode_str = "";
    break;
  case BGP_NOTIFY_CEASE:
    subcode_str = "";
    break;
  }
  log ( "Notify:[%s] %s (%s)\n",
       peer->host,
       LOOKUP (bgp_notify_msg, bgp_notify->err_code),
       subcode_str);
}


/* For debug statement. */
unsigned long bgp_debug_option = 0;

void
debug_on (unsigned int option)
{
  bgp_debug_option |= option;
}

void
debug_off (unsigned int option)
{
  bgp_debug_option &= ~option;
}

int
debug (unsigned int option)
{
  return bgp_debug_option & option;
}

/**/
#include "command.h"

DEFUN (debug_bgp, debug_bgp_cmd,
       "debug bgp DEBUG_OPT",
       DEBUG_STR
       BGP_STR
       "Debug option set for bgpd\n")
{
  if (strcmp (argv[0], "fsm") == 0)
    debug_on (DEBUG_BGP_FSM);
  else
    {
      vty_out (vty, "debug option %s doesn't supported\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp, no_debug_bgp_cmd,
       "no debug bgp DEBUG_OPT",
       NO_STR
       DEBUG_STR
       BGP_STR
       "Debug option unset for bgpd\n")
{
  if (strcmp (argv[0], "fsm") == 0)
    debug_off (DEBUG_BGP_FSM);
  else
    {
      vty_out (vty, "debug option %s doesn't supported\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (show_debug_bgp, show_debug_bgp_cmd,
       "show debug bgp",
       SHOW_STR
       DEBUG_STR
       BGP_STR)
{
  vty_out (vty, "Debug option\r\n");
  vty_out (vty, "============\r\n");

  vty_out (vty, "debug bgp fsm : ");
  if (debug (DEBUG_BGP_FSM))
    vty_out (vty, "on\r\n");
  else
    vty_out (vty, "off\r\n");

  return CMD_SUCCESS;
}

void
bgp_dump_init ()
{
  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &debug_bgp_cmd);
  install_element (CONFIG_NODE, &debug_bgp_cmd);
  install_element (ENABLE_NODE, &no_debug_bgp_cmd);
}
