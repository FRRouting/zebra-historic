/* BGP message definition header.
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

/* BGP message header. */
#define BGP_MARKER_SIZE		16
#define BGP_HEADER_SIZE		19
#define BGP_MAX_PACKET_SIZE   4096

#ifdef SUNOS_5
#ifndef _BGPD_SUNOS_H
#define _BGPD_SUNOS_H
typedef unsigned int u_int32_t; 
typedef unsigned short u_int16_t; 
#endif /* _BGPD_SUNOS_H */
#endif /* SUNOS_5 */

/* BGP message header structure. */
struct bgp_header 
{
  u_char marker[BGP_MARKER_SIZE];
  u_int16_t length;
  u_char type;
};

/* BGP Open message format. */
struct bgp_open 
{
  u_char version;
  u_int16_t asno;
  u_int16_t holdtime;
  u_int32_t ident;
  u_char optlen;
  u_char *optparam;
};  

/* BGP Notify message format. */
struct bgp_notify 
{
  u_char err_code;
  u_char err_subcode;
  char *data;
};

/* BGP instance structure.  `BGPd' can handle multiple BGP
   instance. */
struct bgp 
{
  /* BGP instance's AS. */
  u_int16_t as;

  /* BGP identifier. */
  u_int32_t ident;
  
  /* Default value setting flag */
#define VAL_LOCAL_PREF 0x01
#define VAL_MED        0x02
#define VAL_NEXT_HOP   0x04
  unsigned int def;

  /* Default localpreference value. */
  long localpref;
  
  /* BGP neighbor list */
  struct _list *peer;
};

/* BGP Versions. */
#define BGP_VERSION_2		  2    /* Obsoletes. */
#define BGP_VERSION_3		  3    /* Obsoletes. */
#define BGP_VERSION_4		  4    /* bgpd supports this version. */
#define BGP_VERSION_MP_4_DRAFT_00 40   /* bgpd supports this version. */
#define BGP_VERSION_MP_4	  41   /* bgpd supports this version. */
#define BGP_VERSION_5		  5    /* same as above ;-) */

/* BGP messages. */
#define	BGP_MSG_OPEN		1
#define	BGP_MSG_UPDATE		2
#define	BGP_MSG_NOTIFY		3
#define	BGP_MSG_KEEPALIVE	4
#define BGP_MSG_MAX		5

/* BGP open option message. */
#define BGP_OPEN_OPT_AUTH       1
#define BGP_OPEN_OPT_CAP        2

/* BGP4 Attribute Type Codes. */
#define BGP_ATTR_ORIGIN             1
#define BGP_ATTR_AS_PATH            2
#define BGP_ATTR_NEXT_HOP           3
#define BGP_ATTR_MULTI_EXIT_DISC    4
#define BGP_ATTR_LOCAL_PREF         5
#define BGP_ATTR_ATOMIC_AGGREGATE   6
#define BGP_ATTR_AGGREGATOR         7
#define BGP_ATTR_COMMUNITIES        8
#define BGP_ATTR_ORIGINATOR         9
#define BGP_ATTR_CLUSTERLIST       10
#define BGP_ATTR_DPA               11
#define BGP_ATTR_ADVERTISER        12
#define BGP_ATTR_RCID_PATH         13
#define BGP_ATTR_MP_REACH_NLRI     14
#define BGP_ATTR_MP_UNREACH_NLRI   15

/* BGP Update ORIGIN */
#define BGP_ORIGIN_IGP              0
#define BGP_ORIGIN_EGP              1
#define BGP_ORIGIN_INCOMPLETE       2

/* BGP Notify message format */
#define BGP_NOTIFY_HEADER_ERR 1
#define BGP_NOTIFY_OPEN_ERR   2
#define BGP_NOTIFY_UPDATE     3
#define BGP_NOTIFY_HOLD_ERR   4
#define BGP_NOTIFY_FSM_ERR    5
#define BGP_NOTIFY_CEASE      6
#define BGP_NOTIFY_MAX	      7

/* BGP_NOTIFY_HEADER_ERR sub code */
#define BGP_NOTIFY_HEADER_NOT_SYNC    1
#define BGP_NOTIFY_HEADER_BAD_MESLEN  2
#define BGP_NOTIFY_HEADER_BAD_MESTYPE 3
#define BGP_NOTIFY_HEADER_MAX         4

/* BGP_NOTIFY_OPEN_ERR sub code */
#define BGP_NOTIFY_OPEN_UNSUP_VERSION   1
#define BGP_NOTIFY_OPEN_BAD_PEER_AS     2
#define BGP_NOTIFY_OPEN_BAD_BGP_IDENT   3
#define BGP_NOTIFY_OPEN_UNSUP_PARAM     4
#define BGP_NOTIFY_OPEN_AUTH_FAILURE    5
#define BGP_NOTIFY_OPEN_UNACEP_HOLDTIME 6
#define BGP_NOTIFY_OPEN_UNSUP_CAPBL     7
#define BGP_NOTIFY_OPEN_MAX             8

/* BGP_NOTIFY_UPDATE_ERR sub code */
#define BGP_NOTIFY_UPDATE_MAL_ATTR       1
#define BGP_NOTIFY_UPDATE_UNREC_ATTR     2
#define BGP_NOTIFY_UPDATE_MISS_ATTR      3
#define BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR  4
#define BGP_NOTIFY_UPDATE_ATTR_LENG_ERR  5
#define BGP_NOTIFY_UPDATE_INVAL_ORIGIN   6
#define BGP_NOTIFY_UPDATE_AS_ROUTE_LOOP  7
#define BGP_NOTIFY_UPDATE_INVAL_NEXT_HOP 8
#define BGP_NOTIFY_UPDATE_OPT_ATTR_ERR   9
#define BGP_NOTIFY_UPDATE_INVAL_NETWORK 10
#define BGP_NOTIFY_UPDATE_MAL_AS_PATH   11
#define BGP_NOTIFY_UPDATE_MAX           12

/* Finite State Machine Status */
#define Idle                          1
#define Connect                       2
#define Active                        3
#define OpenSent                      4
#define OpenConfirm                   5
#define Established                   6
#define BGP_STATUS_MAX                7

/* Finite State Machine Event */
#define BGP_Start                     1
#define BGP_Stop                      2
#define TCP_connection_open           3
#define TCP_connection_closed         4
#define TCP_connection_open_failed    5
#define TCP_fatal_error               6
#define ConnectRetry_timer_expired    7
#define Hold_Timer_expired            8
#define KeepAlive_timer_expired       9
#define Receive_OPEN_message         10
#define Receive_KEEPALIVE_message    11
#define Receive_UPDATE_message       12
#define Receive_NOTIFICATION_message 13
#define BGP_EVENTS_MAX               14

/* Default port values. */
#define BGP_PORT_DEFAULT   179
#define BGP_VTY_PORT      2605

/* Default configuration file name for bgpd. */
#define BGP_DEFAULT_CONFIG "bgpd.conf"

/* Time in second to start bgp connection. */
#define BGP_INIT_START_TIMER        5
#define BGP_ERROR_START_TIMER      30
#define BGP_DEFAULT_HOLDTIME_BIG  240
#define BGP_DEFAULT_HOLDTIME      180
#define BGP_DEFAULT_KEEPALIVE      30
#define BGP_CLEAR_CONNECT_RETRY    20
#if 0
#define BGP_DEFAULT_CONNECT_RETRY 120
#endif 
#define BGP_DEFAULT_CONNECT_RETRY  10

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* For massage lookup and check */
#define LOOKUP(x, y) mes_lookup(x, x ## _max, y)
#define CHECKMES(x) mes_check(x, x ## _max)

/* To convert index into message structure. */
typedef struct message
{
  int key;
  char *str;
} message;

/* Debug option : should be bgp_dump.h. */
extern int dump_open;
extern int dump_update;
extern int dump_keepalive;
extern int dump_notify;

/* Messages */
extern message bgp_status_msg[];
extern int bgp_status_msg_max;

extern char *progname;

/**/
#define st_1byte(val, pnt) \
{ \
    (*(u_char *)(pnt)++) = (u_char)(val); \
}

#define st_2byte(val, pnt) \
{\
   u_int16_t t = htons((u_int16_t)(val)); \
   bcopy (&t, (pnt), 2); \
   (pnt) += 2;\
}

#define st_4byte(val, pnt) \
{\
   u_int32_t t = htonl((u_int32_t)(val)); \
   bcopy (&t, (pnt), 4); \
   (pnt) += 4;\
}

#define ld_1byte(val, pnt) \
{ \
  (val) = (u_char)(*(pnt)++); \
}

#define ld_2byte(val, pnt) \
do { \
  (val) = (u_int16_t)(*(pnt)++) << 8; \
  (val) |= (u_int16_t)(*(pnt)++); \
} while (0)

#define ld_4byte(val, pnt) \
{ \
  (val) = (u_int32_t)(*(pnt)++) << 24; \
  (val) |= (u_int32_t)(*(pnt)++) << 16; \
  (val) |= (u_int32_t)(*(pnt)++) << 8; \
  (val) |= (u_int32_t)(*(pnt)++); \
}

#define st_4octet(val, pnt) \
{\
   bcopy (&val, (pnt), 4); \
   (pnt) += 4;\
}

#define ld_4octet(val, pnt) \
{ \
  (val) = (*(pnt)++) << 24; \
  (val) |= (*(pnt)++) << 16; \
  (val) |= (*(pnt)++) << 8; \
  (val) |= (*(pnt)++); \
  (val) = ntohl (val); \
}

enum
{
  /* Debug option. */
  DEBUG_BGP_FSM = 0x01,
};

