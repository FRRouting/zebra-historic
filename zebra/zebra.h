/* zebra daemon header.
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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

/* Zebra request command definition. */
#define ZEBRA_IPV4_ROUTE_ADD    1
#define ZEBRA_IPV4_ROUTE_DELETE 2
#define ZEBRA_IPV6_ROUTE_ADD    3
#define ZEBRA_IPV6_ROUTE_DELETE 4
#define ZEBRA_GET_ALL_INTERFACE 5
#define ZEBRA_GET_ONE_INTERFACE 6
#define ZEBRA_GET_HOSTINFO      7

/* Error code of zebra. */
#define ZEBRA_ERR_RTEXIST       1
#define ZEBRA_ERR_RTUNREACH     2
#define ZEBRA_ERR_EPERM         3
#define ZEBRA_ERR_RTNOEXIST     4

/* Zebra route's type. */
#define ZEBRA_ROUTE_SYSTEM      0
#define ZEBRA_ROUTE_KERNEL      1
#define ZEBRA_ROUTE_CONNECT     2
#define ZEBRA_ROUTE_STATIC      3
#define ZEBRA_ROUTE_RIP         4
#define ZEBRA_ROUTE_RIPNG       5
#define ZEBRA_ROUTE_BGP         6

/* Default port information. */
#define ZEBRA_PORT           2600
#define ZEBRA_VTY_PORT       2601

/* Default configuration filename. */
#define DEFAULT_CONFIG_FILE "zebra.conf"

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ 4096

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

/* Prototypes. */
void zebra_init ();
void zebra_if_init ();
void hostinfo_get ();
void rib_init ();
void interface_list ();
void kernel_init ();
void route_read ();
