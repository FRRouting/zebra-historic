/* OSPF routing table.
   Copyright (C) 1999 Toshiaki Takada

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

#define OSPF_DESTINATION_ROUTER		1
#define OSPF_DESTINATION_NETWORK	2

#define OSPF_PATH_INTRA_AREA		1
#define OSPF_PATH_INTER_AREA		2
#define OSPF_PATH_TYPE1_EXTERNAL	3
#define OSPF_PATH_TYPE2_EXTERNAL	4

struct ospf_path
{
  struct in_addr nexthop;
  struct in_addr adv_router;
};

struct ospf_route
{
  u_char type;
  struct in_addr id;
  struct in_addr mask;
  u_char options;
  struct ospf_area *area;
  u_char path_type;
  u_int16_t cost;
  u_int16_t type2_cost;
  struct in_addr origin;
  list path;
};

void ospf_install_route (struct route_table *);
void ospf_route_table_dump (struct route_table *);
void ospf_intra_route_add (struct route_table *, struct vertex *, 
			   struct ospf_area *);
