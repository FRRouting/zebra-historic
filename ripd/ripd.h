/*
 * RIP related values and structures.
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

/* RIP metric infinity value.*/
#define RIP_METRIC_INFINITY 16

/* Normal RIP packet max size. */
#define RIP_PACKET_MAXSIZ  512

/* Max count of routing table entry in one rip packet. */
#define RIP_MAX_RTE 25

/* RIP version 2 multicast address. */
#ifndef INADDR_RIP_GROUP
#define INADDR_RIP_GROUP        0xe0000009    /* 224.0.0.9 */
#endif

/* RIP timers */
#define RIP_TEST

#ifdef RIP_TEST
#define RIP_FLASH_TIMER     10
#define RIP_DELETE          30
#define RIP_TIMEOUT         60
#else
#define RIP_FLASH_TIMER     30
#define RIP_DELETE          60
#define RIP_TIMEOUT        180
#endif /* RIP_TEST */

/* RIP port number. */
#define RIP_PORT_DEFAULT   520
#define RIP_VTY_PORT      2602

/* Default configuration file name. */
#define RIPD_DEFAULT_CONFIG "ripd.conf"

/* RIP structure. */
struct rip 
{
  int sock;			/* RIP socket. */
  u_char version;		/* Default version of rip instance. */
  u_char multicast;		/* Do multicast treatment. */
  struct thread *read;		/* Update timer. */
  struct thread *timer;		/* Update timer. */
};

/* RIP routing table entry which belong to rip_packet. */
struct rte
{
  u_int16_t family;		/* Address family of this route. */
  u_int16_t tag;		/* Route Tag which included in RIP2 packet. */
  u_int32_t prefix;		/* Prefix of rip route. */
  u_int32_t netmask;		/* Netmask of rip route. */
  u_int32_t nexthop;		/* Next hop of rip route. */
  u_int32_t metric;		/* Metric value of rip route. */
};

/* RIP packet structure. */
struct rip_packet
{
  unsigned char command;	/* Command type of RIP packet. */
  unsigned char version;	/* RIP version which coming from peer. */
  unsigned char pad1;		/* Padding of RIP packet header. */
  unsigned char pad2;		/* Same as above. */
  struct rte route[1];		/* Address structure. */
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
  /* For doubly linked list. */
  struct rip_info *next;
  struct rip_info *prev;

  int fib;			/* Forwarding information base. */
  int type;			/* RIP|Static|Connected route type. */
  int pref;			/* Preference of this route. */
  u_int32_t tag;		/* Tag information of this route. */
  u_int32_t metric;		/* Metric of this route. */
  struct in_addr nexthop;	/* Nexthop of this route. */
  struct in_addr from;		/* From which gateway this route is listen. */
  struct interface *ifp;
  time_t timer;			/* Update timer of this route. */
};

/* RIP specific interface configuration. */
struct rip_interface
{
  int ri_send;
  int ri_receive;
  int ri_split_horizon;
  int ri_default_send;
  int ri_default_receive;
  int ri_multicast;
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

#define LOOKUP(X, Y)  (X)[(Y)].str

/* There is only one rip strucutre. */
extern struct rip *rip;

/* Prototypes. */
void rip_start ();
void rip_init ();
void rip_rib_close ();
void rip_if_init ();
void rip_delete_rinfo (struct rip_info **rp, struct rip_info *rinfo);
int rip_make_request (u_char *pnt, int version);
int rip_udp_send (int sock, u_char *pnt, int size, struct sockaddr_in *dest);
struct rip_info *rip_info_new ();

/* rip_interface.c */
int if_check_address (struct in_addr addr);
struct interface *if_lookup_address (struct in_addr addr);
void rip_multicast_enable (int sock);
void rip_request_all ();
int zebra_get_interface (int sock, u_int16_t length);

int
rip_add_route (struct prefix_ipv4 *p, struct rip_info *rinfo, 
	       struct sockaddr_in *from, struct interface *ifp);

#endif /* _ZEBRA_RIP_H */
