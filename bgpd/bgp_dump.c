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
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <arpa/inet.h>
#include <time.h>
#include <config.h>

#include "bgpd.h"
#include "bgp_aspath.h"
#include "bgp_route.h"
#include "bgp_attr.h"
#include "bgp_dump.h"
#include "bgp_peer.h"

#include "version.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "route.h"

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

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

/* message of route origin */
char *bgp_update_origin[] = 
{
  "i",
  "e",
  "?",
};

/* for update */
message bgp_update_origin_long[] = 
{
  { BGP_ORIGIN_IGP, "IGP" },
  { BGP_ORIGIN_EGP, "EGP" },
  { BGP_ORIGIN_INCOMPLETE, "Incomplete" }
};
int bgp_update_origin_long_max = BGP_ORIGIN_INCOMPLETE + 1;

char *
lookupmes (message *array, int key)
{
  message *pnt;

  for (pnt = array; pnt->key != 0; pnt++) {
    if (pnt->key == key) {
      return pnt->str;
    }
  }  
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

/* message check routine */
mes_check (meslist, max)
     message *meslist;
     int max;
{
  int i;

  for (i = 0; i < max; i++) {
    if (meslist[i].key != i) {
      fprintf (stderr, "messages list error!\n");
      exit (1);
    }
  }
}

bgp_dump_header (bgp_header)
     struct bgp_header *bgp_header;
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
    fflush (logfp);
  }
}

#define PACKET_SEND 1
#define PACKET_RECV 2

/*
 * open packet dump
 */
bgp_open_dump (bgp_open, peer, direct)
     struct bgp_open *bgp_open;
     struct peer * peer;
     int direct;
{
  /* decide whether dump or not */
  if (direct == PACKET_RECV &&
      IS_SET(dump_open, DUMP_SEND)) {

    if (IS_SET(dump_open, DUMP_DETAIL)) {
      /* detail */
      log ( "Open: peer(%s) version(%d) AS(%d) holdtime(%d)\n"
	       "      ident(%lu) optlen(%d)\n",
	       peer->host,
	       bgp_open->version, bgp_open->asno, bgp_open->holdtime,
	       bgp_open->ident, bgp_open->optlen);
    } else {
      /* normal */
      log ( "Open: peer(%s)\n",
	       peer->host);
    }
    fflush (logfp);
  }
}

nprint (fd, str)
     int fd;
     char *str;
{
  writen (fd, str, strlen(str));
}

/* called from BGP Update packet */
bgp_log_route(struct peer *peer, struct bgp_route *br, int dup)
{
  struct in_addr hop;
  struct attr *attr;

  attr = br->attr;

  if (dup)
    log ( "Update[r]:");
  else
    log ( "Update:");

  log2 ("[%s] ", peer->host);
  fprintf (logfp, "%s/%d", inet_ntoa(br->prefix), br->mask);

  if (attr)
    dump_attr (peer, attr);

  log2 ("\r\n");
  log_flash ();
}

/*
 * called from show ip bgp x.x.x.x
 * need detailed information
 */
bgp_print_route (struct vty *vty, struct prefix_in *r)
{
  struct bgp_route *br;
  struct attr *attr;

  br = (struct bgp_route *) r;
  if (br == NULL)
    return;
    
  attr = br->attr;
  if (attr == NULL)
    return;

  if (attr->aspath) 
    {
      aspath_print_vty (vty, attr->aspath);
      vty_out (vty, "\r\n");
    }

  /* show route. */
  vty_out (vty, "   ");
  route_vty_out_route (r, vty);

  /* show nex hop */
  if (attr) {
    vty_out (vty, "Nexthop %s\r\n      Origin %s, Metric %lu, Localpref %lu",
	     inet_ntoa(attr->next_hop),
	     LOOKUP (bgp_update_origin_long, attr->origin),
	     attr->med, attr->local_pref);
    if (attr->community) {
      vty_out (vty, ", Commuity");
      community_print_vty (vty, attr->community);
    }
    vty_out (vty, "\r\n");
  }
}

/**/
dump_attr (struct peer *peer, struct attr *attr)
{
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
      aspath_log (logfp, attr->aspath);
    }

  log2 (" %s", bgp_update_origin[attr->origin]);
}

route_vty_out_route (struct prefix_in *pin, struct vty *vty)
{
  int len;

  len = vty_out (vty, "%s/%d", inet_ntoa (pin->prefix), pin->mask);

  len = 25 - len;
  if (len > 0)
    vty_out (vty, "%*s", len, " ");
}


#ifdef HAVE_IPV6
route_vty_out_route_in6 (struct prefix_in6 *pin6, struct vty *vty)
{
  int len;
  char buf[INET6_ADDRSTRLEN];

  len = vty_out (vty, "%s/%d", 
		 inet_ntop(AF_INET6, &pin6->prefix, buf, INET6_ADDRSTRLEN),
		 pin6->mask);

  len = 25 - len;
  if (len > 0)
    vty_out (vty, "%*s", len, " ");
}
#endif /* HAVE_IPV6 */

/* dump notify packet */
bgp_notify_print(peer, bgp_notify)
     struct peer * peer;
     struct bgp_notify *bgp_notify;
{
  char *subcode_str;

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

char *logfile_name;

dump_update_size (length, size)
{
  if (IS_SET (dump_update, DUMP_DETAIL))
    printf ("Update headerlength(%d) reachstart(%d)\n", length, size);
}


/* Print BGPd start messages. */
bgp_start_msg ()
{
  log ("BGPd (%s) starts\n", ZEBRA_VERSION);
}

int Debug_Event = 1;
int Debug_Keepalive = 0;
int Debug_Update = 0;
int Debug_Radix = 0;

#if 0
/* debug on */
debug_on (flag)
     int *flag;
{
  *flag = 1;
}

/* debug off */
debug_off (flag)
     int *flag;
{
  *flag = 0;
}

/* show debug */
debug_show (fp)
     FILE *fp;
{
  fprintf (fp, "Debug flag value list\r\n");
  fprintf (fp, "  event     : %s\r\n", Debug_Event ? "on" : "off");
  fprintf (fp, "  update    : %s\r\n", Debug_Update ? "on" : "off");
  fprintf (fp, "  keepalive : %s\r\n", Debug_Keepalive ? "on" : "off");
  fflush (fp);
}
#endif

/* Reopen log file by HUP signal. */
void
rotate_log ()
{
  if (logfp == stdout)
    return;

  fflush (logfp);
  fclose (logfp);
  
  logfp = fopen (logfile_name, "a");

  if (logfp == NULL)
    fprintf (stderr, "%s: can't open logfile %s\n", progname, logfile_name);
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
       "Debug option set for bgpd.")
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
       "Debug option unset for bgpd.")
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
       "Show debug information of bgpd.")
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

bgp_dump_init ()
{
  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &debug_bgp_cmd);
  install_element (CONFIG_NODE, &debug_bgp_cmd);
  install_element (ENABLE_NODE, &no_debug_bgp_cmd);
}
