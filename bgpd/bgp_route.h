/* Route object related header for route server.
 * Copyright (C) 1996, 97, 98, 2000 Kunihiro Ishiguro
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

/* I want to change structure name from bgp_route to bgp_info. */
struct bgp_info
{
  /* For linked list. */
  struct bgp_info *next;
  struct bgp_info *prev;

  /* Type of this prefix */
  u_char type;

  /* Type of bgp prefix. */
#define BGP_ROUTE_NORMAL    0
#define BGP_ROUTE_STATIC    1
#define BGP_ROUTE_AGGREGATE 2
  u_char sub_type;

  /* Selected route flag. */
  u_char selected;

  /* Pointer to peer structure. */
  struct peer *peer;

  /* Pointer to attributes structure. */
  struct attr *attr;

  /* Aggregate related information. */
  int suppress;
  
  /* Time */
  time_t uptime;
};

/* Prototypes. */
void bgp_route_init ();
void bgp_announce_table (struct peer *);
void bgp_route_clear (struct peer *);

int nlri_sanity_check (struct peer *, int, u_char *, bgp_size_t);
int nlri_parse (struct peer *, struct attr *, struct bgp_nlri *);

void bgp_redistribute_add (struct prefix *, u_char);
void bgp_redistribute_delete (struct prefix *, u_char);
void bgp_redistribute_withdraw (struct bgp *, afi_t, int);

int bgp_config_write_network (struct vty *, struct bgp *, afi_t);

#endif /* _ZEBRA_BGP_ROUTE_H */
