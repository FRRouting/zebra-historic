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
#define OSPF_DESTINATION_DISCARD	3

#define OSPF_PATH_INTRA_AREA		1
#define OSPF_PATH_INTER_AREA		2
#define OSPF_PATH_TYPE1_EXTERNAL	3
#define OSPF_PATH_TYPE2_EXTERNAL	4

struct ospf_path
{
  struct in_addr nexthop;
  struct in_addr adv_router;
  struct interface *ifp;
};


struct ospf_router_route
{
  list routes;			/* list of (struct ospf_route *) */
  struct ospf_route * best;	/* the best route */
};

/* Below is the structure linked to every
   route node. Note that for Network routing
   entries a single ospf_route is kept, while
   for ABRs and ASBRs (Router routing entries),
   we link an instance of ospf_router_route
   where a list of paths is maintained, so

   nr->info is a (struct ospf_route *) for OSPF_DESTINATION_NETWORK
   but
   nr->info is a (struct ospf_router_route *) for OSPF_DESTINATION_ROUTER
*/


struct ospf_route
{
  u_char type;
  struct in_addr id;
  struct in_addr mask;
  u_char options;
  struct ospf_area *area;
  u_char path_type;
  u_int32_t cost;
  u_int32_t type2_cost;
  struct lsa_header * origin;
  list path;
  u_char flags; 		/* From router-LSA */
  struct ospf_route *asbr; 	/* only for external routes*/
  u_int32_t tag;
};

struct ospf_path *ospf_path_new ();
void ospf_path_free (struct ospf_path *op);
struct ospf_route *ospf_route_new ();
void ospf_route_free (struct ospf_route *or);
void ospf_route_delete (struct route_table *rt);
void ospf_route_table_free (struct route_table *rt);

void ospf_route_install (struct route_table *);
void ospf_route_table_dump (struct route_table *);
void ospf_intra_route_add (struct route_table *, struct vertex *, 
			   struct ospf_area *);

void ospf_intra_add_router (struct route_table *, struct vertex *,
			    struct ospf_area *);

void ospf_intra_add_transit (struct route_table *, struct vertex *,
			     struct ospf_area *);

void ospf_intra_add_stub (struct route_table *, struct router_lsa_link *,
 		          struct vertex *, struct ospf_area *);

int ospf_route_cmp (struct ospf_route *, struct ospf_route *);
void ospf_route_copy_nexthops (struct ospf_route *, list);
void ospf_route_copy_nexthops_from_vertex (struct ospf_route *,
					   struct vertex * );

void ospf_route_subst (struct route_node *, struct ospf_route *,
		       struct ospf_route *);
void ospf_route_add (struct route_table *, struct prefix_ipv4 *,
		     struct ospf_route *, struct ospf_route *);

void ospf_route_subst_nexthops (struct ospf_route *, list);
void ospf_prune_unreachable_networks (struct route_table *);
void ospf_prune_unreachable_routers (struct route_table *);
int ospf_add_discard_route (struct route_table *, struct ospf_area *, 
			    struct prefix_ipv4 *);
void ospf_delete_discard_route (struct prefix_ipv4 *);
