/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#define RIB_FIB       0x01
#define RIB_LINK      0x02
#define RIB_INTERNAL  0x04

#define RIB_FIB_SET(RIB) (((RIB)->status) |= RIB_FIB)
#define RIB_FIB_UNSET(RIB) (((RIB)->status) &= ~RIB_FIB)
#define IS_RIB_FIB(RIB)  (((RIB)->status) & RIB_FIB)

#define RIB_LINK_SET(RIB) (((RIB)->status) |= RIB_LINK)
#define RIB_LINK_UNSET(RIB) (((RIB)->status) &= ~RIB_LINK)
#define IS_RIB_LINK(RIB) (((RIB)->status) & RIB_LINK)

#define RIB_INTERNAL_SET(RIB) (((RIB)->status) |= RIB_INTERNAL)
#define RIB_INTERNAL_UNSET(RIB) (((RIB)->status) &= ~RIB_INTERNAL)
#define IS_RIB_INTERNAL(RIB) (((RIB)->status) & RIB_INTERNAL)

/* Structure for routing information base. */
struct rib
{
  int type;			/* Type of this route */
  u_char flags;			/*  */
  unsigned int status;		/* Have this route goes to fib. */
  u_char distance;		/* Distance of this route. */
  int table;			/* Which routing table */
  u_int32_t metric;		/* Metric of this route. */
  struct
  {
    struct in_addr gate4;
#ifdef HAVE_IPV6
    struct in6_addr gate6;
#endif
    unsigned int ifindex;
#ifdef HAVE_IF_PSEUDO
    char ifname[INTERFACE_NAMSIZ];
#endif /* HAVE_IF_PSEUDO */
  } u;
  struct
  {
    struct in_addr gate4;
#ifdef HAVE_IPV6
    struct in6_addr gate6;
#endif
    unsigned int ifindex;
#ifdef HAVE_IF_PSEUDO    
    char ifname[INTERFACE_NAMSIZ];
#endif /* HAVE_IF_PSEUDO */
  } i;

  struct rib *next;
  struct rib *prev;
};

#ifndef OLD_RIB

#define DISTANCE_INFINITY  255

/* Routing information base. */
struct new_rib
{
  /* Link list. */
  struct new_rib *next;
  struct new_rib *prev;

  /* Type fo this route. */
  int type;

  /* Which routing table */
  int table;			

  /* Distance. */
  u_char distance;

  /* Flags of this route. */
  u_char flags;
#define RIB_FLAG_SELECTED   0x10
#define RIB_FLAG_CHANGED    0x20
#define RIB_FLAG_INTERNAL   0x40

  /* Metric */
  u_int32_t metric;

  /* Uptime. */
  time_t uptime;

  /* Nexthop information. */
  u_char nexthop_num;

  u_char nexthop_active_num;
  u_char nexthop_fib_num;
  struct nexthop *nexthop;
};

/* Static route information. */
struct static_ipv4
{
  /* For linked list. */
  struct static_ipv4 *prev;
  struct static_ipv4 *next;

  /* Administrative distance. */
  u_char distance;

  /* Flag for this static route's type. */
  u_char flags;
#define STATIC_IPV4_GATEWAY  (1 << 0)
#define STATIC_IPV4_IFNAME   (1 << 1)

  /* Nexthop value. */
  union 
  {
    struct in_addr ipv4;
    char *ifname;
  } gate;
};

/* Nexthop structure. */
struct nexthop
{
  struct nexthop *next;
  struct nexthop *prev;

  u_char type;
#define NEXTHOP_TYPE_IFINDEX        1 /* Directly connected. */
#define NEXTHOP_TYPE_IFNAME         2 /* Interface route. */
#define NEXTHOP_TYPE_IPV4           3 /* IPv4 nexthop. */
#define NEXTHOP_TYPE_IPV4_IFINDEX   4 /* IPv4 nexthop with ifindex. */
#define NEXTHOP_TYPE_IPV6           5 /* IPv6 nexthop. */
#define NEXTHOP_TYPE_IPV6_IFINDEX   6 /* IPv6 nexthop with ifindex. */

  u_char flags;
#define NEXTHOP_FLAG_ACTIVE     (1 << 0) /* This nexthop is alive. */
#define NEXTHOP_FLAG_FIB        (1 << 1) /* FIB nexthop. */
#define NEXTHOP_FLAG_RECURSIVE  (1 << 2) /* Recursive nexthop. */

  /* Interface index. */
  unsigned int ifindex;
  unsigned int rifindex;
  unsigned int krnl_ifindex; /* For kernel routes so we can ditch 
				them on if_down */

  /* Nexthop address or interface name. */
  union
  {
    struct in_addr ipv4;
#ifdef HAVE_IPV6
    struct in6_addr ipv6;
#endif /* HAVE_IPV6*/
    char *ifname;
  } gate;

  /* Recursive lookup nexthop. */
  u_char rtype;
  union
  {
    struct in_addr ipv4;
#ifdef HAVE_IPV6
    struct in6_addr ipv6;
#endif /* HAVE_IPV6 */
  } rgate;

  struct nexthop *indirect;
};

int kernel_add_ipv4_multipath (struct prefix *, struct new_rib *);
int kernel_delete_ipv4_multipath (struct prefix *, struct new_rib *);

struct nexthop *nexthop_ifindex_add (struct new_rib *, unsigned int);
struct nexthop *nexthop_ifname_add (struct new_rib *, char *);
struct nexthop *nexthop_ipv4_add (struct new_rib *, struct in_addr *, 
				  unsigned int);
#ifdef HAVE_IPV6
struct nexthop *nexthop_ipv6_add (struct new_rib *, struct in6_addr *,
				  unsigned int);
#endif /* HAVE_IPV6 */

int rib_add_ipv4_multipath (struct prefix_ipv4 *, struct new_rib *);

void rib_update ( unsigned int ifindex, struct prefix *p);
int rib_check_for_connected_ipv4(struct prefix_ipv4 *p, unsigned int ifindex);

#endif /* ! OLD_RIB */

/* RIB table. */
extern struct route_table *ipv4_rib_table;
#ifdef HAVE_IPV6
extern struct route_table *ipv6_rib_table;
#endif /* HAVE_IPV6 */

/* Prototypes. */
void zebra_sweep_route ();
void rib_close ();
void rib_init ();
struct rt *rib_search_rt (int, struct rt *);

int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table,
	      u_int32_t, u_char);
int
rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table);

#ifdef HAVE_IF_PSEUDO
int
rib_add_ipv4_pseudo (int type, int flags, struct prefix_ipv4 *p, 
		     struct in_addr *gate, char *ifname , int table);

int
rib_delete_ipv4_pseudo (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, char *ifname, int table);
#endif /* HAVE_IF_PSEUDO */
#ifdef HAVE_IPV6
int
rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table);

int
rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, int table);
#endif /* HAVE_IPV6 */

void rib_if_up (struct interface *);
void rib_if_down (struct interface *);
void rib_if_delete (struct interface *);
#ifdef HAVE_IF_PSEUDO
void rib_ifindex_update_name(char *name,int ifindex_new);
#endif /* HAVE_IF_PSEUDO */

#ifdef OLD_RIB
u_int32_t rib_lookup_ipv4_nexthop (struct in_addr);
#else
struct new_rib *rib_lookup_ipv4_nexthop (struct in_addr);
#endif /* OLD_RIB */

#endif /*_ZEBRA_RIB_H */
