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
  u_char as_selected;

  /* BGP info status. */
  u_char flags;
#define BGP_INFO_IGP_CHANGED    (1 << 0)
#define BGP_INFO_DAMPED         (1 << 1)
#define BGP_INFO_HISTORY        (1 << 2)
#define BGP_INFO_SELECTED       (1 << 3)
#define BGP_INFO_VALID          (1 << 4)
#define BGP_INFO_ATTR_CHANGED   (1 << 5)

  /* Pointer to peer structure. */
  struct peer *peer;

  /* Pointer to attributes structure. */
  struct attr *attr;

  /* Aggregate related information. */
  int suppress;
  
  /* Nexthop reachability check. */
  u_int32_t igpmetric;

  /* Time */
  time_t uptime;

  /* Pointer to dampening structure */
  struct bgp_damp_info *bgp_damp_info;

  /* Tag */
  u_char tag[3];
};

/* BGP static route configuration. */
struct bgp_static
{
  safi_t safi;
  int backdoor;
  u_char valid;
  u_int32_t igpmetric;
};

/* Prototypes. */
void bgp_route_init ();
void bgp_announce_table (struct peer *);
void bgp_refresh_table (struct peer *, afi_t, safi_t);
void bgp_route_clear (struct peer *);
void bgp_soft_reconfig_in (struct peer *, afi_t, safi_t);

int nlri_sanity_check (struct peer *, int, u_char *, bgp_size_t);
int nlri_parse (struct peer *, struct attr *, struct bgp_nlri *);

void bgp_redistribute_add (struct prefix *, struct in_addr *, u_char);
void bgp_redistribute_delete (struct prefix *, u_char);
void bgp_redistribute_withdraw (struct bgp *, afi_t, int);

void bgp_static_delete (struct bgp *);
int bgp_static_set_vpnv4 (struct vty *vty, char *, char *, char *);

int bgp_static_unset_vpnv4 (struct vty *, char *, char *, char *);

int bgp_config_write_network (struct vty *, struct bgp *, afi_t);
int bgp_config_write_distance (struct vty *, struct bgp *);

void route_vty_out_detail (struct vty *, struct prefix *, struct bgp_info *);

void bgp_aggregate_increment (struct bgp *, struct prefix *, struct bgp_info *,
			      afi_t, safi_t);
void bgp_aggregate_decrement (struct bgp *, struct prefix *, struct bgp_info *,
			      afi_t, safi_t);

u_char bgp_distance_apply (struct prefix *, struct bgp_info *, struct bgp *);

#endif /* _ZEBRA_BGP_ROUTE_H */
