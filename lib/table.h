/* Routing Table
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

/* Prefix structure. */
struct newprefix
{
  /* Address family of this prefix. */
  /* sa_family_t family; */
  u_char family;

  /* Prefix length. */
  u_char prefixlen;

  /* We handle IPv4 and IPv6 address. */
  union 
  {
    u_char prefix;
    struct in_addr prefix4;
#ifdef HAVE_IPV6
    struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
  } u;
};

/* Routing table top structure. */
struct route_table
{
  struct route_node *top;
};

/* Each routing entry. */
struct route_node
{
  /* Actual prefix of this radix. */
  struct newprefix p;

  /* Tree link. */
  struct route_table *table;
  struct route_node *parent;
  struct route_node *link[2];

#define l_left   link[0]
#define l_right  link[1]

  /* Lock of this radix */
  unsigned int lock;

  /* Each node of route. */
  void *route;
};

struct route_table *route_table_init (void);
struct route_node *route_top (struct route_table *);
struct route_node *route_next (struct route_node *);
struct route_node *route_node_get (struct route_table *, struct newprefix *);
#ifdef HAVE_IPV6
struct route_node *route_node_lookup (struct route_table *, 
				      struct in6_addr *,
				      int);
#endif /* HAVE_IPV6 */
