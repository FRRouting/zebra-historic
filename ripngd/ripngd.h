/*
 * RIPng related value and structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIPNG_RIPNGD_H
#define _ZEBRA_RIPNG_RIPNGD_H

/* RIPng version and port number. */
#define RIPNG_V1                         1
#define RIPNG_PORT_DEFAULT             521
#define RIPNG_VTY_PORT                2603
#define RIPNG_PRIORITY_DEFAULT           0

/* RIPng commands. */
#define RIPNG_REQUEST                    1
#define RIPNG_RESPONSE                   2

/* RIPng metric and multicast group address. */
#define RIPNG_METRIC_INFINITY           16
#define RIPNG_METRIC_NEXTHOP          0xff
#define RIPNG_GROUP              "ff02::9"

/* RIPng timers. */
#define RIPNG_FLUSH_TIMER               30
#define RIPNG_TIMEOUT_TIMER            180
#define RIPNG_GARBAGE_TIMER            120

/* Default config file name. */
#define RIPNG_DEFAULT_CONFIG "ripngd.conf"

/* RIPng route types. */
#define RIPNG_ROUTE_RTE              0
#define RIPNG_ROUTE_STATIC           1
#define RIPNG_ROUTE_AGGREGATE        2

/* Interface send/receive configuration. */
#define RIPNG_SEND_UNSPEC            0
#define RIPNG_SEND_OFF               1
#define RIPNG_RECEIVE_UNSPEC         0
#define RIPNG_RECEIVE_OFF            1

/* Split horizon definitions. */
#define RIPNG_SPLIT_HORIZON_UNSPEC     0
#define RIPNG_SPLIT_HORIZON_NONE       1
#define RIPNG_SPLIT_HORIZON            2
#define RIPNG_SPLIT_HORIZON_POISONED   3

/* RIP default route's accept/announce methods. */
#define RIPNG_DEFAULT_ADVERTISE_UNSPEC 0
#define RIPNG_DEFAULT_ADVERTISE_NONE   1
#define RIPNG_DEFAULT_ADVERTISE        2

#define RIPNG_DEFAULT_ACCEPT_UNSPEC    0
#define RIPNG_DEFAULT_ACCEPT_NONE      1
#define RIPNG_DEFAULT_ACCEPT           2

/* RIPng structure. */
struct ripng 
{
  /* RIPng socket. */
  int sock;

  /* RIPng Parameters.*/
  unsigned char command;
  unsigned char version;
  unsigned int update_time;
  unsigned int timeout_time;
  unsigned int garbage_time;
  int max_mtu;
  int default_information;

  /* Input/output buffer of RIPng. */
  struct stream *ibuf;
  struct stream *obuf;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_update;
  struct thread *t_garbage;
  struct thread *t_zebra;

  /* Triggered update trick. */
  int trigger;
  struct thread *t_triggered_update;
  struct thread *t_triggered_interval;
};

/* Routing table entry. */
struct rte
{
  struct in6_addr addr;
  u_short tag;
  u_char prefixlen;
  u_char metric;
};

/* RIPNG send packet. */
struct ripng_packet
{
  u_char command;
  u_char version;
  u_int16_t zero; 
  struct rte rte[1];
};

/* Each route's information. */
struct ripng_info
{
  /* This route's type.  Static, ripng or aggregate. */
  u_char type;

  /* Sub type for static route. */
  u_char sub_type;

  /* RIPng specific information */
  struct in6_addr nexthop;	
  struct in6_addr from;

  /* Which interface this route comes from. */
  unsigned int ifindex;		

  /* Metric of this route.  */
  u_char metric;		

  /* Tag field of RIPng packet.*/
  u_short tag;		

  /* For aggregation. */
  unsigned int suppress;

  /* Flags of RIPng route. */
#define RIPNG_RTF_FIB      1
#define RIPNG_RTF_CHANGED  2
  u_char flags;

  /* Garbage collect timer. */
  struct thread *t_timeout;
  struct thread *t_garbage_collect;

  struct route_node *rp;
};

/* RIPng specific interface configuration. */
struct ripng_interface
{
  /* RIPng is enabled on this interface. */
  int enable;

  /* Default route configuration. */
  int ri_send;
  int ri_receive;
  int ri_default_send;
  int ri_default_receive;

  /* Split horizon configuration. */
  int ri_split_horizon;
};

enum event
{
  RIPNG_READ,
  RIPNG_ZEBRA,
  RIPNG_REQUEST_EVENT,
  RIPNG_UPDATE_EVENT,
  RIPNG_TRIGGERED_UPDATE,
};

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Macro to set link local index to the IPv6 address.  For KAME IPv6
   stack. */
#ifdef KAME
#define	IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr8[2] << 8 | (a).s6_addr8[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i) \
  do { \
    (a).s6_addr8[2] = ((i) >> 8) & 0xff; \
    (a).s6_addr8[3] = (i) & 0xff; \
  } while (0)
#else
#define	IN6_LINKLOCAL_IFINDEX(a)
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)
#endif /* KAME */

/* Extern variables. */
extern struct ripng *ripng;

/* Prototypes. */
void ripng_init ();
void ripng_if_init ();
void ripng_terminate ();
void zebra_start ();

struct ripng_info *ripng_info_new ();
void ripng_info_free (struct ripng_info *rinfo);

/* Function prototype for RIPngd event routine. */
void ripng_event (enum event, int);

void ripng_zebra_ipv6_add (struct prefix_ipv6 *p, struct in6_addr *nexthop,
			   unsigned int ifindex);
void ripng_zebra_ipv6_delete (struct prefix_ipv6 *p, struct in6_addr *nexthop,
			      unsigned int ifindex);

void ripng_redistribute_add (int, int, struct prefix_ipv6 *, unsigned int);
void ripng_redistribute_delete (int, int, struct prefix_ipv6 *, unsigned int);

#endif /* _ZEBRA_RIPNG_RIPNGD_H */
