/*
 * Route object related header for route server.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGP_ROUTE_H
#define _ZEBRA_BGP_ROUTE_H

#define BGP_ROUTE_NORMAL    0
#define BGP_ROUTE_STATIC    1
#define BGP_ROUTE_AGGREGATE 2

/* I want to change structure name from bgp_route to bgp_info. */
struct bgp_info
{
  /* For linked list. */
  struct bgp_info *next;
  struct bgp_info *prev;

  /* Type of this prefix */
  u_char type;

  /* Type of bgp prefix. */
  u_char sub_type;

  /* Selected route flag. */
  u_char selected;

  /* Pointer to peer structure. */
  struct peer *peer;

  /* Pointer to attributes structure. */
  struct attr *attr;

  /* Aggregate related information. */
  int aggregate_count;
  int suppress_count;
};

/* Prototypes. */
struct bgp_info *bgp_info_new ();

void bgp_route_init ();
void bgp_peer_delete (struct peer *peer);
void bgp_announce_table (struct peer *peer);
void route_parse (u_char *pnt, int rsize, struct attr *attr, struct peer *peer);
void withdraw_route(unsigned char *pnt, int unfeasible_len, struct peer *peer);
void nlri_process (struct prefix *p, struct bgp_info *br);
void nlri_parse (struct peer *peer, struct attr *attr, u_char *pnt, int len, int family);
void nlri_unfeasible (struct peer *peer, bgp_size_t unfeasible_len);
int nlri_delete (struct peer *peer, struct prefix *p);
void bgp_dump_attr (struct peer *peer, struct attr *attr, char *attrstr, size_t size);
void bgp_peer_delete (struct peer *peer);

#endif /* _ZEBRA_BGP_ROUTE_H */
