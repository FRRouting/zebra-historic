/* RIPng related value and structure.
   Copyright (C) 1998 Kunihiro Ishiguro

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

#define RIPNG_V1                         1
#define RIPNG_PORT_DEFAULT             521
#define RIPNG_VTY_PORT                2603
#define RIPNG_PRIORITY_DEFAULT           0

#define RIPNG_REQUEST                    1
#define RIPNG_RESPONSE                   2

#define RIPNG_METRIC_INFINITY           16
#define RIPNG_METRIC_NEXTHOP          0xff
#define RIPNG_GROUP              "ff02::9"

#define RIPNG_FLUSH_TIMER               30
#define RIPNG_TIMEOUT_TIMER            180
#define RIPNG_GARBAGE_TIMER            120

#define RIPNG_DEFAULT_CONFIG "ripngd.conf"

/* RIPng structure. */
struct ripng 
{
  /* RIPng socket. */
  int sock;

  /* RIPng Parameters.*/
  unsigned char command;
  unsigned char version;
  unsigned int flush_time;
  unsigned int timeout_time;
  unsigned int garbage_time;
  int max_mtu;

  /* Input/output buffer of RIPng. */
  struct stream *ibuf;
  struct stream *obuf;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_flush;
  struct thread *t_garbage;
  struct thread *t_zebra;
};

/* Routing table entry. */
struct rte
{
  struct in6_addr addr;
  u_short tag;
  u_char masklen;
  u_char metric;
};

/* RIPNG send packet. */
struct ripng_packet
{
  u_char command;
  u_char version;
  u_char padding[2]; 
  struct rte rte[1];
};

/* Each route's information. */
struct ripng_info
{
  /* This route's type.  Static, ripng or aggregate. */
  u_char type;

  /* RIPng specific information */
  struct in6_addr nexthop;	
  struct in6_addr gateway;

  /* Which interface this route comes from. */
  unsigned int ifindex;		

  /* Metric of this route.  */
  u_char metric;		

  /* Tag field of RIPng packet.*/
  u_short rip_tag;		

  /* Update timer of this route. */
  time_t timer;			

  /* Whether send to zebra or not. */
  int fib;			
};

struct ripng_slot
{
  struct ripng_info *rinfo[3];
};

#define RIPNG_SLOT_RTE(R)           ((R)->rinfo[0])
#define RIPNG_SLOT_STATIC(R)        ((R)->rinfo[1])
#define RIPNG_SLOT_AGGREGATE(R)     ((R)->rinfo[2])

/* RIPng specific interface configuration. */
struct ripng_interface
{
  int ri_send;
  int ri_receive;
  int ri_split_horizon;
  int ri_default_send;
  int ri_default_receive;
};

enum event
{
  RIPNG_REQUEST_EVENT,
  RIPNG_FLUSH_EVENT,
  RIPNG_ZEBRA,
  RIPNG_READ,
};

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
#define RIPNG_SPLIT_HORIZON_UNSPEC   0
#define RIPNG_SPLIT_HORIZON_NONE     1
#define RIPNG_SPLIT_HORIZON          2
#define RIPNG_SPLIT_HORIZON_POISONED 3

/* RIP default route's accept/announce methods. */
#define RIPNG_DEFAULT_ADVERTISE_UNSPEC 0
#define RIPNG_DEFAULT_ADVERTISE_NONE   1
#define RIPNG_DEFAULT_ADVERTISE        2

#define RIPNG_DEFAULT_ACCEPT_UNSPEC    0
#define RIPNG_DEFAULT_ACCEPT_NONE      1
#define RIPNG_DEFAULT_ACCEPT           2

/* Global variables. */
extern struct ripng *ripng;

/* For messages. */
struct message
{
  int key;
  char *str;
};

/* If linux hasn't define this. */
#ifndef uint32_t
#define uint32_t unsigned int
#endif /* uint32_t */

#define IN6_COPY_ADDR(X,Y)  memcpy(X, Y, sizeof (struct in6_addr))

/* Macro to set link local index to the IPv6 address.  For
   Hydrangea. */
#define	IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr8[2] << 8 | (a).s6_addr8[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i) \
  (a).s6_addr8[2] = ((i) >> 8) & 0xff; \
  (a).s6_addr8[3] = (i) & 0xff; \

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif /* INET6_ADDRSTRLEN */

/* Prototypes */

#define ld_1byte(val, pnt) \
{ \
  (val) = (u_char)(*(pnt)++); \
}

#define ld_4byte(val, pnt) \
{ \
  (val) = (u_int32_t)(*(pnt)++) << 24; \
  (val) |= (u_int32_t)(*(pnt)++) << 16; \
  (val) |= (u_int32_t)(*(pnt)++) << 8; \
  (val) |= (u_int32_t)(*(pnt)++); \
}
