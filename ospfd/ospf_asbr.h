/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_ASBR_H
#define _ZEBRA_OSPF_ASBR_H

#define OSPF_ASBR_CHECK_DELAY 30

void ospf_external_route_remove (struct prefix_ipv4 *p);

void ospf_asbr_status_update (u_char);
#if 0
struct ospf_external_route *ospf_external_route_new ();
struct ospf_external_route *ospf_external_route_lookup (struct prefix_ipv4 *);
void ospf_asbr_route_add (u_char, struct prefix_ipv4 *,
			  unsigned int, struct in_addr);
void ospf_asbr_route_delete (u_char, struct prefix_ipv4 *,
			     unsigned int, struct in_addr);
#endif
void ospf_redistribute_withdraw (u_char);
void ospf_asbr_check();
void ospf_schedule_asbr_check ();
void ospf_asbr_route_install_lsa (struct ospf_lsa *lsa);

#endif /* _ZEBRA_OSPF_ASBR_H */
