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

/* Structure for routing information base. */
struct rib
{
  int type;			/* Type of this route */
  int fib;			/* Have this route goes to fib. */
  int pref;			/* Preference of this route. */
  int ifindex;			/* Interface index. */
  int table;			/* Which routing table */
  union
  {
    struct in_addr gate4;
#ifdef HAVE_IPV6
    struct in6_addr gate6;
#endif
  } u;

  struct rib *next;
  struct rib *prev;
};

/* RIB table. */
extern struct route_table *ipv4_rib_table;
#ifdef HAVE_IPV6
extern struct route_table *ipv6_rib_table;
#endif /* HAVE_IPV6 */

/* Prototypes. */
void rib_close ();
void rib_init ();
struct rt *rib_search_rt (int, struct rt *);

int
rib_add_ipv4 (int type, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table);
int
rib_delete_ipv4 (int type, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table);

#ifdef HAVE_IPV6
int
rib_add_ipv6 (int type, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table);

int
rib_delete_ipv6 (int type, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, int table);
#endif /* HAVE_IPV6 */

#endif /*_ZEBRA_RIB_H */
