/*
 * OSPF LSDB support.
 * Copyright (C) 1999 Alex Zinin
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
 * 02111-1307, USA.  */

#ifndef _ZEBRA_OSPF_LSDB_H
#define _ZEBRA_OSPF_LSDB_H

#define OSPF_LSDB_HASH 0x1
#define OSPF_LSDB_LIST 0x2
#define OSPF_LSDB_RT   0x4

#define OSPF_LSDB_DEF  OSPF_LSDB_HASH

struct ospf_lsdb
{
  u_char       flags;

  struct Hash *hash;		/* Hash table for LSAs. */
  list	       list;		/* List version. */
  struct route_table *rt;	/* RT version. */
  u_int	       count;
  u_int	       count_self;
  struct ospf_area * area;	/* Associated area */
};

struct ospf_lsdb* ospf_lsdb_new (u_char);
void ospf_lsdb_free ();
struct ospf_lsa *ospf_lsdb_add (struct ospf_lsdb *, struct ospf_lsa *);
void ospf_lsdb_delete (struct ospf_lsdb *, struct ospf_lsa *);
struct ospf_lsa *ospf_lsdb_lookup (struct ospf_lsdb *, struct in_addr,
				   struct in_addr);
struct ospf_lsa *ospf_lsdb_lookup_by_id (struct ospf_lsdb *, struct in_addr);
struct ospf_lsa *ospf_lsdb_lookup_by_header (struct ospf_lsdb *,
					     struct ospf_lsa *);
struct ospf_lsa *ospf_lsdb_iterator (struct ospf_lsdb *, void *, int,
				     int (*callback) (struct ospf_lsa *, void *, int));
void id_to_prefix (struct in_addr, struct prefix *);
void get_lsa_prefix (struct ospf_lsa *, struct prefix *);

#endif /* _ZEBRA_OSPF_LSDB_H */
