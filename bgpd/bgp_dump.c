/*
 * BGP-4, BGP-4+, BGP-5 dump routine
 * Copyright (C) 1996, 97, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "version.h"
#include "prefix.h"
#include "linklist.h"
#include "stream.h"
#include "command.h"
#include "str.h"
#include "log.h"
#include "sockunion.h"

#include "zebra/zebra.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_community.h"

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

/* BGP message type string. */
char *bgp_type_str[] =
{
  NULL,
  "OPEN",
  "UPDATE",
  "NOTIFY",
  "KEEPALIVE"
};

/* message for BGP-4 Notify */
message bgp_notify_msg[] = 
{
  { 0, "null" },
  { BGP_NOTIFY_HEADER_ERR, "Message Header Error"},
  { BGP_NOTIFY_OPEN_ERR, "OPEN Message Error"},
  { BGP_NOTIFY_UPDATE_ERR, "UPDATE Message Error"},
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

/* Origin strings. */
char *bgp_origin_str[] = {"i","e","?"};

char *
lookupmes (message *array, int key)
{
  message *pnt;

  for (pnt = array; pnt->key != 0; pnt++) 
    if (pnt->key == key) 
      return pnt->str;

  return NULL;
}

/* message lookup function */
char *
mes_lookup (message *meslist, int max, int index)
{
  if (index < 0 || index >= max) 
    {
      zlog (NULL, LOG_INFO, "message index out of bound: %d", max);
      return NULL;
    }
  return meslist[index].str;
}

#if 0
/* Dump bgp header information. */
void
bgp_dump_header (struct bgp_header *bgp_header)
{
  int flag = 0;

  switch (bgp_header->type) 
    {
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
      break;
    }

  if (flag) 
    zlog (NULL, LOG_INFO, "Head: %s(%d) length(%d)",
	    bgp_type_str[bgp_header->type], 
	    bgp_header->type, bgp_header->length);
}
#endif

/* Dump attribute. */
void
bgp_dump_attr (struct peer *peer, struct attr *attr, char *buf, size_t size)
{
  if (attr == NULL)
    return;

  snprintf (buf, size, "nexthop: %s", inet_ntoa (attr->nexthop));

#ifdef HAVE_IPV6
  {
    char addrbuf[BUFSIZ];

    /* Add MP case. */
    if (attr->mp_nexthop_len == 16 || attr->mp_nexthop_len == 32)
      snprintf (buf + strlen (buf), size - strlen (buf), " mp_nexthop: %s",
		inet_ntop (AF_INET6, &attr->mp_nexthop_global, 
			   addrbuf, BUFSIZ));

    if (attr->mp_nexthop_len == 32)
      snprintf (buf + strlen (buf), size - strlen (buf), "(%s)",
		inet_ntop (AF_INET6, &attr->mp_nexthop_local, 
			   addrbuf, BUFSIZ));
  }
#endif /* HAVE_IPV6 */

  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " lpref: %d",
		attr->local_pref);
    }

  if (attr->med)
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " metric: %d",
		attr->med);
    }

  if (attr->community) 
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " comm:%s",
		community_print (attr->community));
    }

  if (attr->aggregator_as)
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " aggregator: %s[%d]",
		inet_ntoa (attr->aggregator_addr), attr->aggregator_as);
    }

  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " originator-id: %s ",
		inet_ntoa (attr->originator_id));
    }

  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_CLUSTER_LIST))
    {
      int i;

      snprintf (buf + strlen (buf), size - strlen (buf), "cluster-list: ");
      for (i = 0; i < attr->cluster->length / 4; i++)
	snprintf (buf + strlen (buf), size - strlen (buf), "%s ",
		  inet_ntoa (attr->cluster->list[i]));
    }

  if (attr->aspath) 
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " aspath: %s %s",
		aspath_print (attr->aspath), bgp_origin_str[attr->origin]);
    }
  else
    {
      snprintf (buf + strlen (buf), size - strlen (buf), " origin %s",
		bgp_origin_str[attr->origin]);
    }
}

/* dump notify packet */
void
bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify)
{
  char *subcode_str;

  subcode_str = "";

  switch (bgp_notify->err_code) 
    {
    case BGP_NOTIFY_HEADER_ERR:
      subcode_str = LOOKUP (bgp_notify_head_msg, bgp_notify->err_subcode);
      break;
    case BGP_NOTIFY_OPEN_ERR:
      subcode_str = LOOKUP (bgp_notify_open_msg, bgp_notify->err_subcode);
      break;
    case BGP_NOTIFY_UPDATE_ERR:
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
  zlog (peer->log, LOG_INFO, "Notify:[%s] %s (%s)",
	peer ? peer->host : "",
	LOOKUP (bgp_notify_msg, bgp_notify->err_code),
	subcode_str);
}

#if 0
/* Open packet dump */
void
bgp_open_dump (struct bgp_open *bgp_open, struct peer *peer, int direct)
{
  /* decide whether dump or not */
  if (direct == PACKET_RECV &&
      IS_SET(dump_open, DUMP_SEND)) {

    if (IS_SET(dump_open, DUMP_DETAIL)) {
      /* detail */
      zlog (peer->log, LOG_INFO, "Open: peer(%s) version(%d) AS(%d) holdtime(%d)"
	      "      ident(%lu) optlen(%d)",
	      peer->host,
	      bgp_open->version, bgp_open->asno, bgp_open->holdtime,
	      bgp_open->ident, bgp_open->optlen);
    } else {
      /* normal */
      zlog (peer->log, LOG_INFO, "Open: peer(%s)", peer->host);
    }
  }
}
#endif

/* Dump BGP open packet. */
void
bgp_packet_open_dump (struct stream *s)
{
  printf ("BGP open ");
  printf ("version: %d ", stream_getc (s));
  printf ("as: %d ", stream_getw (s));
  printf ("holdtime: %d ", stream_getw (s));
  printf ("ident: %d\n", stream_getl (s));

  /* Open message option. */
  printf ("opt parm len: %d\n", stream_getc (s));
}

void
bgp_packet_notify_dump (struct stream *s)
{
  struct bgp_notify bgp_notify;

  bgp_notify.err_code = stream_getc (s);
  bgp_notify.err_subcode = stream_getc (s);
  bgp_notify_print(NULL, &bgp_notify);
}

/* Dump bgp update packet. */
void
bgp_update_dump (struct stream *s)
{
  u_char *endp;
  bgp_size_t unfeasible_len;
  bgp_size_t attr_total_len;

  unfeasible_len = stream_getw (s);
  printf ("Unfeasible length: %d\n", unfeasible_len);

  stream_forward (s, unfeasible_len);

  attr_total_len = stream_getw (s);
  printf ("Attribute length: %d\n", attr_total_len);

  endp = STREAM_PNT (s) + attr_total_len;

  while (STREAM_PNT (s) < endp)
    {
      u_char flag;
      u_char type;
      bgp_size_t length;

      flag = stream_getc (s);
      type = stream_getc (s);

      printf ("flag: %d\n", flag);
      printf ("type: %d\n", type);
  
      if (flag & ATTR_FLAG_EXTLEN)
	length = stream_getw (s);
      else
	length = stream_getc (s);

      printf ("length %d\n", length);

      stream_forward (s, length);
    }
}

/* Debug dump of bgp packet. */
void
bgp_packet_dump (struct stream *s)
{
  int i;
  u_char type;
  u_int16_t size;
  unsigned long sp;

  /* Preserve pointer. */
  sp = stream_get_getp (s);
  stream_set_getp (s, 0);

  /* Marker dump. */
  printf ("BGP packet marker : ");
  for (i = 0; i < BGP_MARKER_SIZE; i++)
    printf ("%x ", stream_getc (s));
  printf ("\n");

  /* BGP packet size. */
  size = stream_getw (s);
  printf ("BGP packet size : %d\n", size);

  /* BGP packet type. */
  type = stream_getc (s);
  printf ("BGP packet type : %s (%d)\n", bgp_type_str[type], type);

  switch (type)
    {
    case BGP_MSG_OPEN:
      bgp_packet_open_dump (s);
      break;
    case BGP_MSG_KEEPALIVE:
      assert (size == BGP_HEADER_SIZE);
      return;
      break;
    case BGP_MSG_UPDATE:
      bgp_update_dump (s);
      break;
    case BGP_MSG_NOTIFY:
      bgp_packet_notify_dump (s);
      break;
    }
  stream_set_getp (s, sp);
}

/* Debug option setting interface. */
unsigned long bgp_debug_option = 0;

void debug_on  (unsigned int option) { bgp_debug_option |= option; }
void debug_off (unsigned int option) { bgp_debug_option &= ~option; }
int  debug     (unsigned int option) { return bgp_debug_option & option; }

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

/* debgp ip bgp [events|keepalives|updates] [recv|send] [detail] */
DEFUN (debug_ip_bgp, debug_ip_bgp_cmd,
       "debug ip bgp [DEBUG_OPTION]",
       "Debug option\n"
       "IP debug\n"
       "BGP debug\n"
       "BGP debug option\n"
       "BGP debug option\n")
{
  /* All BGP option are set to normal level. */
  if (argc == 0)
    {
      ;
    }
  if (argc == 1)
    vty_out (vty, "option1 %s\r\n", argv[0]);
  else if (argc == 2)
    vty_out (vty, "option2 %s\r\n", argv[1]);
  else
    vty_out (vty, "no option\r\n");

  return CMD_SUCCESS;
}

/* Some define for BGP packet dump. */

/* Type value */
#define MSG_PROTOCOL_BGP4MP 16

/* Subtype value */
#define BGP4MP_STATE_CHANGE 0
#define BGP4MP_MESSAGE 1
#define BGP4MP_ENTRY 2
#define BGP4MP_SNAPSHOT 3

/* BGP packet dump file name. */
char *bgp_dump_file;
FILE *bgp_dump_fp;

FILE *
bgp_open_dump_file (char *filename)
{
  if (bgp_dump_fp)
    fclose (bgp_dump_fp);

  bgp_dump_fp = fopen (filename, "w");
  if (bgp_dump_fp == NULL)
    return NULL;

  bgp_dump_file = strdup (filename);

  return bgp_dump_fp;
}

/* Set packet dump header. */
void
bgp_dump_set_header (struct stream *s)
{
  time_t clock;

  time (&clock);

  stream_putl (s, clock);	/* Time */
  stream_putw (s, MSG_PROTOCOL_BGP4MP);	/* Type */
  stream_putw (s, BGP4MP_MESSAGE);	/* Subtype */
  stream_putl (s, 0);		/* Length */
}

void
bgp_dump_set_size (struct stream *s)
{
  /* If size is specifed use it. */
  stream_putl_at (s, 8, stream_get_endp (s));

  return;
}

/* Dump incoming BGP packet into the file.  */
void
bgp_dump_incoming (struct peer *peer, struct stream *packet)
{
  struct stream *s;

  /* If dump file pointer is disabled return immediately. */
  if (bgp_dump_fp == NULL)
    return;

  /* Make dump stream. */
  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Set header. */
  bgp_dump_set_header (s);

  /* Source AS number and Destination AS number. */
  stream_putw (s, peer->as);
  stream_putw (s, peer->bgp->as);

#ifdef HAVE_IPV6
  /* Interface Index and Address family. */
  stream_putw (s, 0);
  stream_putw (s, AF_INET6);

  /* Source IP Address and Destination IP Address. */
  stream_put (s, &peer->su->sin6.sin6_addr, 16);
  stream_put (s, &peer->su->sin6.sin6_addr, 16);
#endif /* HAVE_IPV6 */

  /* Packet contents. */
  stream_put (s, STREAM_DATA (packet), stream_get_endp (packet));
  
  /* Set length. */
  bgp_dump_set_size (s);

  /* Write to the stream. */
  fwrite (STREAM_DATA (s), stream_get_putp (s), 1, bgp_dump_fp);
  fflush (bgp_dump_fp);

  /* Free dump stream. */
  stream_free (s);
}

/* BGP packet dump file name setup. */
DEFUN (config_dumpfile,
       config_dumpfile_cmd,
       "dumpfile PATH",
       "BGP Packet dumpfile specify command\n"
       "Path name of dumpfile\n")
{
  FILE *fp;

  fp = bgp_open_dump_file (argv[0]);
  if (fp == NULL)
    {
      vty_out (vty, "Can't open dumpfile %s\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

void
bgp_dump_init ()
{
  bgp_dump_fp = NULL;

  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &show_debug_bgp_cmd);
  install_element (ENABLE_NODE, &debug_bgp_cmd);
  install_element (CONFIG_NODE, &debug_bgp_cmd);
  install_element (ENABLE_NODE, &no_debug_bgp_cmd);
  install_element (CONFIG_NODE, &config_dumpfile_cmd);

  install_element (ENABLE_NODE, &debug_ip_bgp_cmd);
}
