/*
 * BGP message definition header.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGPD_H
#define _ZEBRA_BGPD_H

/* BGP message header and packet size. */
#define BGP_MARKER_SIZE		16
#define BGP_HEADER_SIZE		19
#define BGP_MAX_PACKET_SIZE   4096

/* Declare Some BGP specific types. */
typedef u_int16_t as_t;
typedef u_int32_t ident_t;
typedef u_int16_t bgp_size_t;

/* BGP instance structure. bgpd can handle multiple BGP instance. */
struct bgp 
{
  as_t as;			/* BGP instance's AS. */
  ident_t ident;		/* BGP identifier. */
  ident_t cluster;		/* BGP route reflector cluster ID */
  int reflector_cnt;		/* BGP route reflector neighbor count. */

#define BGP_CONFIG_ROUTER_ID  1
#define BGP_CONFIG_CLUSTER_ID 2
  unsigned int config;		/* BGP configuration. */

  u_char redist_static;		/* Redistribute static route. */
  u_char redist_connect;	/* Redistribute connected route. */
  u_char redist_rip;		/* Redistribute rip route. */
  u_char redist_ripng;		/* Redistribute ripng route. */
  u_char redist_ospf;		/* Redistribute ospf route. */
  u_char redist_ospf6;		/* Redistribute ospf6 route. */

  struct _list *peer;		/* BGP neighbor list */
};

/* BGP neighbor structure. */
struct peer
{
  /* This peer's parent bgp. */
  struct bgp *bgp;		

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream_fifo *obuf;

  /* Peer information */
  char *host;			/* Printable address of the peer. */
  union sockunion *su;		/* Sockunion address of the peer. */
  union sockunion *su_local;	/* Sockunion of local address.  */
  int fd;			/* File descriptor */
  int ttl;			/* TTL of TCP connection to the peer. */
  char *desc;			/* Description of the peer. */
  int shutdown;			/* Shutdown flag. */
  int passive;			/* Passive flag. */
  char *ifname;			/* bind interface name. */
  ZLOG *log;			/* ZLOG stream to use for this peer -
				   NULL means use main log */

  u_char version;		/* Peer BGP version. */
  as_t as;			/* Peer AS number. */
  ident_t ident;		/* Peer BGP identifier. */
  ident_t myident;		/* My BGP identifier. */

  /* Status of the peer. */
  int status;			/* peer finite state machine status */
  int ostatus;			/* Old peer status. */

  /* Default attribute value for this peer. */
  unsigned int def;		/* Option set flag. */
  long localpref;		/* default local preference. */
  int reflector_client;		/* Route reflector client. */
  time_t uptime;		/* Last Up/Down time */

  /* Timer values. */
  u_int32_t v_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_asorig;
  u_int32_t v_routeadv;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_asorig;
  struct thread *t_routeadv;

  /* Statistics field */
  u_int32_t open_in;		/* Open message input count */
  u_int32_t open_out;		/* Open message output count */
  u_int32_t update_in;		/* Update with nlri message input count */
  u_int32_t update_out;		/* Update with nlri message ouput count */
  u_int32_t withdrow_in;	/* Update with withdrow message input count */
  u_int32_t withdrow_out;	/* Update with withdrow message output count */
  u_int32_t keepalive_in;	/* Keepalive input count */
  u_int32_t keepalive_out;	/* Keepalive output count */
  u_int32_t notify_in;		/* Notify input count */
  u_int32_t notify_out;		/* Notify output count */

  /* For filter type slot. */
#define BGP_FILTER_IN  0
#define BGP_FILTER_OUT 1
#define BGP_FILTER_MAX 2

  /* Access list based filter. */
  struct 
  {
    char *name;
    struct access_list *list;
  } distribute[BGP_FILTER_MAX];

  /* Prefix list based filter. */
  struct
  {
    char *name;
    struct prefix_list *plist;
  } plist[BGP_FILTER_MAX];

  /* AS list based filter. */
  struct
  {
    char *name;
    struct as_list *filter;
  } filter[BGP_FILTER_MAX];

  /* Route map based filer. */
  struct
  {
    char *name;
    struct route_map *map;
  } route_map[BGP_FILTER_MAX];

  /* prefix_in/out will be need. */
  unsigned int prefix_count;	/* Prefix count of this peer. */
};

/* BGP Notify message format. */
struct bgp_notify 
{
  u_char err_code;
  u_char err_subcode;
  char *data;
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
#define BGP_ATTR_ORIGINATOR_ID      9
#define BGP_ATTR_CLUSTER_LIST      10
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
#define BGP_NOTIFY_UPDATE_ERR 3
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
#define BGP_DEFAULT_HOLDTIME      180
#define BGP_DEFAULT_KEEPALIVE      30
#define BGP_CLEAR_CONNECT_RETRY    20
#define BGP_DEFAULT_CONNECT_RETRY 120

/* Macros. */
#define BGP_INPUT(P)         ((P)->ibuf)
#define BGP_INPUT_PNT(P)     (STREAM_PNT(BGP_INPUT(P)))

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

enum
{
  /* Debug option. */
  DEBUG_BGP_FSM = 0x01,
};

/* IBGP/EBGP identifier */
enum
{
  BGP_PEER_IBGP,
  BGP_PEER_EBGP,
  BGP_PEER_INTERNAL
};

#define PACKET_SEND 1
#define PACKET_RECV 2

/* Default max TTL. */
#define TTL_MAX 255

/* Prototypes. */
void bgp_init ();
void zebra_init ();
void bgp_terminate ();
void bgp_route_map_init ();
int bgp_peer_sort (struct peer *peer);
void bgp_filter_init ();
void zebra_start ();

struct bgp *bgp_new (as_t);
struct bgp *bgp_lookup_by_as (as_t);

struct peer *peer_lookup_by_su (union sockunion *);
struct peer *peer_lookup_from_bgp (struct bgp *bgp, char *addr);
struct peer *peer_lookup_by_host (char *host);
struct peer *peer_new (void);
void event_add (struct peer *peer, int event);
void bgp_clear(struct peer *peer, int error);
void peer_delete_all ();
void peer_delete (struct peer *peer);
void bgp_open_recv (struct peer *peer, u_int16_t size);
void bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify);

void bgp_zebra_redistribute (int);
void bgp_zebra_no_redistribute (int);

extern struct thread_master *master;

#endif /* _ZEBRA_BGPD_H */
