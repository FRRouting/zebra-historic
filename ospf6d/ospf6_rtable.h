/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#ifndef OSPF6_RTABLE_H
#define OSPF6_RTABLE_H

/* Destination Types (from InternetDraft 3.3) */
#define DTYPE_PREFIX         1   /* IPv6 prefix */
#define DTYPE_ASBR           2   /* AS boundary router */
#define DTYPE_INTRA_ROUTER   3   /* each router in the area */
#define DTYPE_INTRA_LINK     4   /* each transit link in the area */

/* Path-types (from RFC2328 11), decreasing order of preference */
#define PTYPE_INTRA          1   /* intra-area */
#define PTYPE_INTER          2   /* inter-area */
#define PTYPE_TYPE1_EXTERNAL 3   /* type 1 external */
#define PTYPE_TYPE2_EXTERNAL 4   /* type 2 external */

/* Next Hop */
struct ospf6_nexthop
{
  unsigned long   ifindex;
  struct in6_addr ipaddr;    /* if any */
  unsigned long   advrtr;    /* for inter-area and AS external nexthop */
                             /* 0 for intra-area routes */
  unsigned int    lock;      /* reference count of this nexthop(nexthop) */
};

union dest_id
{
  rtr_id_t        router_id;
  unsigned long   network_id[2];
  struct in6_addr prefix;
};

struct ospf6_rtentry
{
  /* for doubly linked list */
  struct ospf6_rtentry *prev;
  struct ospf6_rtentry *next;

  unsigned char dest_type;           /* Destination Type */
  union dest_id dest_id;             /* Destination ID */
  unsigned char opt_cap[3];          /* Optional Capability */
  unsigned char path_type;           /* Path-type */
  cost_t        cost;
  cost_t        cost_type2;
  struct lsa_internal *ls_origin;    /* Link State Origin, for MOSPF */
  list          nexthops;               /* list of struct ospf6_nexthop */
};

struct ospf6_rtable
{
  struct ospf6_rtentry *current_top;
  struct ospf6_rtentry *previous_top;
};

void nexthop_init ();
void nexthop_add_from_vertex (struct vertex *, struct vertex *, list);

void rtable_init (struct ospf6_rtable *);

struct ospf6_rtentry *rtable_lookup (unsigned char, union dest_id *,
                                     struct ospf6_rtentry *);
void rtable_install (unsigned char, union dest_id *, cost_t,
                     unsigned char, list,
                     struct ospf6_rtable *);
void rtable_uninstall (unsigned char, union dest_id *,
                       struct ospf6_rtable *);

void rtable_update_zebra (struct ospf6_rtable *);
void rtable_vty_entry (struct vty *, struct ospf6_rtentry *);

#endif /* OSPF6_RTABLE_H */

