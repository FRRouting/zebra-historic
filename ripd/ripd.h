/* RIP related values and structures.
 * Copyright (C) 1997, 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIP_H
#define _ZEBRA_RIP_H

#include "if.h"

/* RIP version number. */
#define RIPv1                1
#define RIPv2                2

/* RIP command list. */
#define RIP_REQUEST          1
#define RIP_RESPONSE         2
#define RIP_TRACEON          3	/* obsolete? */
#define RIP_TRACEOFF         4	/* obsolete? */
#define RIP_POLL             5
#define RIP_POLL_ENTRY       6
#define RIP_COMMAND_MAX      7

/* RIP metric infinity value.*/
#define RIP_METRIC_INFINITY 16

/* Normal RIP packet max size. */
#define RIP_PACKET_MAXSIZ        512

/* Max count of routing table entry in one rip packet. */
#define RIP_MAX_RTE 25

/* RIP version 2 multicast address. */
#ifndef INADDR_RIP_GROUP
#define INADDR_RIP_GROUP        0xe0000009    /* 224.0.0.9 */
#endif

/* RIP timers */
#define RIP_UPDATE_TIMER_DEFAULT       30
#define RIP_TIMEOUT_TIMER_DEFAULT     180
#define RIP_GARBAGE_TIMER_DEFAULT     120

#if 0
#define RIP_INVALID_TIMER_DEFAULT     180
#define RIP_HOLDDOWN_TIMER_DEFAULT    180
#define RIP_FLUSH_TIMER_DEFALUT       240
#endif /*0 */

/* RIP port number. */
#define RIP_PORT_DEFAULT            520
#define RIP_VTY_PORT               2602

/* Default configuration file name. */
#define RIPD_DEFAULT_CONFIG "ripd.conf"

/* RIPng route types. */
#define RIP_ROUTE_RTE              0
#define RIP_ROUTE_STATIC           1

/* RIP structure. */
struct rip 
{
  /* RIP socket. */
  int sock;

  /* Default version of rip instance. */
  u_char version;

  /* Output buffer of RIP. */
  struct stream *obuf;

  /* RIP routing information base. */
  struct route_table *table;

  /* RIP only static routing information. */
  struct route_table *route;
  
  /* RIP neighbor. */
  struct route_table *neighbor;
  
  /* RIP threads. */
  struct thread *t_read;

  /* Update and garbage timer. */
  struct thread *t_update;
  struct thread *t_garbage;

  /* Triggered update hack. */
  int trigger;
  struct thread *t_triggered_update;
  struct thread *t_triggered_interval;

  /* RIP timer values. */
  unsigned long update_time;
  unsigned long timeout_time;
  unsigned long garbage_time;

  /* For redistribute route map. */
  struct
  {
    char *name;
    struct route_map *map;
  } route_map[ZEBRA_ROUTE_MAX];
};

/* RIP routing table entry which belong to rip_packet. */
struct rte
{
  u_int16_t family;		/* Address family of this route. */
  u_int16_t tag;		/* Route Tag which included in RIP2 packet. */
  struct in_addr prefix;	/* Prefix of rip route. */
  struct in_addr mask;		/* Netmask of rip route. */
  struct in_addr nexthop;	/* Next hop of rip route. */
  u_int32_t metric;		/* Metric value of rip route. */
};

/* RIP packet structure. */
struct rip_packet
{
  unsigned char command;	/* Command type of RIP packet. */
  unsigned char version;	/* RIP version which coming from peer. */
  unsigned char pad1;		/* Padding of RIP packet header. */
  unsigned char pad2;		/* Same as above. */
  struct rte rte[1];		/* Address structure. */
};

/* Buffer to read RIP packet. */
union rip_buf
{
  struct rip_packet rip_packet;
  char buf[RIP_PACKET_MAXSIZ];
};

/* RIP route information. */
struct rip_info
{
  /* This route's type. */
  int type;

  /* Sub type. */
  int sub_type;

  /* RIP nexthop. */
  struct in_addr nexthop;
  struct in_addr from;

  /* Which interface does this route come from. */
  unsigned int ifindex;

  /* Metric of this route. */
  u_int32_t metric;

  /* Tag information of this route. */
  u_int16_t tag;

  /* Flags of RIP route. */
#define RIP_RTF_FIB      1
#define RIP_RTF_CHANGED  2
  u_char flags;

  /* Garbage collect timer. */
  struct thread *t_timeout;
  struct thread *t_garbage_collect;

  /* Route-map futures - this variables can be changed. */
  struct in_addr nexthop_out;
  u_int32_t      metric_out;
  unsigned int   ifindex_out;

  struct route_node *rp;
};

/* RIP specific interface configuration. */
struct rip_interface
{
  /* RIP is enabled on this interface. */
  int enable_network;
  int enable_interface;

  /* RIP is running on this interface. */
  int running;

  /* RIP version control. */
  int ri_send;
  int ri_receive;

  /* RIPv2 authentication string. */
  char *auth_str;

  /* Wake up thread. */
  struct thread *t_wakeup;
};

/* RIP accepet/announce methods. */
#define RI_RIP_UNSPEC          0
#define RI_RIP_VERSION_1       1
#define RI_RIP_VERSION_2       2
#define RI_RIP_VERSION_1_AND_2 3
#define RI_RIP_NONE            4 /* This means this interface doesn't
                                    send/recieve RIP packet.  */

/* Split horizon definitions. */
#define RI_RIP_SPLIT_HORIZON_UNSPEC   0
#define RI_RIP_SPLIT_HORIZON_NONE     1
#define RI_RIP_SPLIT_HORIZON          2
#define RI_RIP_SPLIT_HORIZON_POISONED 3

/* RIP default route's accept/announce methods. */
#define RIP_DEFAULT_ADVERTISE_UNSPEC 0
#define RIP_DEFAULT_ADVERTISE_NONE   1
#define RIP_DEFAULT_ADVERTISE        2
#define RIP_DEFAULT_ACCEPT_UNSPEC    0
#define RIP_DEFAULT_ACCEPT_NONE      1
#define RIP_DEFAULT_ACCEPT           2

/* RIP multicast configuration. */
#define RIP_MULTICAST 0
#define RIP_BROADCAST 1

/* For easy string print out. */
struct message
{
  int key;
  char *str;
};

/* RIP event. */
enum rip_event 
{
  RIP_READ,
  RIPNG_REQUEST_EVENT,
  RIP_UPDATE_EVENT,
  RIP_TRIGGERED_UPDATE,
};

#define LOOKUP(X, Y)  (X)[(Y)].str

/* There is only one rip strucutre. */
extern struct rip *rip;

/* Prototypes. */
void rip_init ();

void rip_terminate ();

void zebra_start ();

void rip_if_init ();

void rip_route_map_init ();

int 
if_check_address (struct in_addr addr);

int 
if_valid_neighbor (struct in_addr addr);

int 
rip_request_send (struct sockaddr_in *, struct interface *, u_char);

int
rip_neighbor_lookup (struct sockaddr_in *);

void
rip_redistribute_add (int, int, struct prefix_ipv4 *, unsigned int, 
		      struct in_addr *);

void
rip_redistribute_delete (int, int, struct prefix_ipv4 *, unsigned int);

void
rip_redistribute_withdraw (int);

void
rip_zebra_ipv4_add (struct prefix_ipv4 *, struct in_addr *, unsigned int);

void
rip_zebra_ipv4_delete (struct prefix_ipv4 *, struct in_addr *, unsigned int);

void
rip_interface_multicast_set (int, struct interface *);

int
config_write_rip_network (struct vty *, int);

int
config_write_rip_redistribute (struct vty *, int);

extern struct thread_master *master;

#endif /* _ZEBRA_RIP_H */
