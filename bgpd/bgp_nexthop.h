/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#ifndef _ZEBRA_BGP_NEXTHOP_H
#define _ZEBRA_BGP_NEXTHOP_H

#define BGP_SCAN_INTERVAL_DEFAULT 60

void bgp_scan_init ();
u_int32_t bgp_nexthop_lookup (struct peer *peer, struct in_addr, int *);
void bgp_connected_add (struct connected *c);
void bgp_connected_delete (struct connected *c);
u_int32_t bgp_multiaccess_check_v4 (struct in_addr, char *);
int bgp_config_write_scan_time (struct vty *);

#endif /* _ZEBRA_BGP_NEXTHOP_H */
