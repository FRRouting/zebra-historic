/*
 * zebra's client header.
 * Copyright (C) 1997, 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */


#ifndef _ZEBRA_CLIENT_H
#define _ZEBRA_CLIENT_H

/* Prototypes of zebra client service functions. */
int zebra_connect ();
void zebra_get_hostinfo (int sock);
void zebra_get_all_interface (int sock);

/* Redistribute message. */
int zebra_redistribute_send (int command, int sock, int type);

/* IPv4 prefix add and delete function prototype. */
int
zebra_ipv4_add (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex);
int
zebra_ipv4_delete (int sock, int type, int flags, struct prefix_ipv4 *p,
		   struct in_addr *nexthop, unsigned int ifindex);

#ifdef HAVE_IPV6
/* IPv6 prefix add and delete function prototype. */
int
zebra_ipv6_add (int sock, int type, int flags, struct prefix_ipv6 *p,
		struct in6_addr *nexthop, unsigned int ifindex);
int
zebra_ipv6_delete (int sock, int type, int flags, struct prefix_ipv6 *p,
		   struct in6_addr *nexthop, unsigned int ifindex);
#endif /* HAVE_IPV6 */

#endif /* _ZEBRA_CLIENT_H */
