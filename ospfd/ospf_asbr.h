/*
 * OSPF ASBR functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_OSPF_ASBR_H
#define _ZEBRA_OSPF_ASBR_H

#define OSPF_ASBR_CHECK_DELAY 5

void ospf_asbr_status_update (u_char);
void ospf_asbr_route_add (u_char, struct prefix_ipv4 *,
			  unsigned int, struct in_addr);
void ospf_asbr_route_delete (u_char, struct prefix_ipv4 *, unsigned int);
void ospf_redistribute_withdraw (u_char);
void ospf_asbr_check();
void ospf_schedule_asbr_check ();

#endif /* _ZEBRA_OSPF_ASBR_H */
