/* Route object related header for route server.
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

struct bgp_route
{
  /* For linked list. */
  struct bgp_route *next;
  struct bgp_route *prev;

  /* Type of this prefix */
  u_char type;

  /* Tags of this route. */
  u_char tag;

  /* Network mask length of this prefix */
  u_char mask;

  /* Prefix of this route. */
  struct in_addr prefix;

  /* Pointer to peer structure. */
  struct peer *peer;

  /* Pointer to attributes structure. */
  struct attr *attr;
};

/* Prototypes. */
struct bgp_route *bgp_route_new ();
void bgp_route_init ();
void bgp_peer_delete (struct peer *peer);
void route_parse (u_char *pnt, int rsize, struct attr *attr, struct peer *peer);
void withdraw_route(unsigned char *pnt, int unfeasible_len, struct peer *peer);
void route_vty_out_route (struct prefix *p, struct vty *vty);
