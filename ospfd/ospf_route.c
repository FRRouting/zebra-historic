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

#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "linklist.h"
#include "log.h"
#include "if.h"
#include "command.h"
#include "sockunion.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_zebra.h"

struct ospf_route *
ospf_route_new ()
{
  struct ospf_route *new;

  new = XMALLOC (MTYPE_OSPF_ROUTE, sizeof (struct ospf_route));
  bzero (new, sizeof (struct ospf_route));

  return new;
}

void
ospf_route_free (struct ospf_route *or)
{
  if (or->path)
    list_delete_all (or->path);

  XFREE (MTYPE_OSPF_ROUTE, or);
}

struct ospf_path *
ospf_path_new ()
{
  struct ospf_path *new;

  new = XMALLOC (MTYPE_OSPF_PATH, sizeof (struct ospf_path));
  bzero (new, sizeof (struct ospf_path));

  return new;
}

struct ospf_path *
ospf_path_dup (struct ospf_path *path)
{
  struct ospf_path *new;

  new = ospf_path_new ();
  memcpy (new, path, sizeof (struct ospf_path));

  return new;
}

void
ospf_path_free (struct ospf_path *op)
{
  XFREE (MTYPE_OSPF_PATH, op);
}

void
ospf_delete_route (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct ospf_path *path;
  listnode pnode;

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
	if (or->type == OSPF_DESTINATION_NETWORK)
	  for (pnode = listhead (or->path); pnode; nextnode (pnode))
	    {
	      path = getdata (pnode);

	      if (path->nexthop.s_addr != INADDR_ANY)
		ospf_zebra_delete ((struct prefix_ipv4 *) &rn->p,
				   &path->nexthop);
	    }
	else if (or->type == OSPF_DESTINATION_DISCARD)
	  ospf_zebra_delete_discard ((struct prefix_ipv4 *) &rn->p);
      }
}

void
ospf_route_table_free (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  listnode pnode;

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
	if (or->path && listcount (or->path) > 0)
	  for (pnode = listhead (or->path); pnode; nextnode (pnode))
	    ospf_path_free (pnode->data);

	ospf_route_free (or);

	rn->info = NULL;
	route_unlock_node (rn);
      }
}

int ospf_match_same_route(struct route_table *rtable, int type,
			  struct prefix_ipv4 * prefix,
			  struct in_addr * nexthop )
{
  struct route_node  *rn;
  struct ospf_route  *or;
  struct ospf_path   *path;
  listnode pnode;

  if (! rtable || ! prefix) 
    return 0;

  for (rn = route_top (rtable); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL && (or->type == type))
      {
	if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    for (pnode = listhead (or->path); pnode; nextnode (pnode)) 
	      {
		path = getdata (pnode);

		if (path->nexthop.s_addr != INADDR_ANY && nexthop &&
		    !memcmp(&rn->p, prefix, sizeof(struct prefix_ipv4)) &&
		    !memcmp(&path->nexthop, nexthop, sizeof(struct in_addr))) 
		  {
		    route_unlock_node(rn);
		    return(1);
		  }
	      }
	  }
	else if (or->type == OSPF_DESTINATION_DISCARD)
	  {
	    if ( !memcmp(&rn->p, prefix, sizeof(struct prefix_ipv4)) ) 
	      {
		route_unlock_node(rn);
		return(1);
	      }
	  }
      }
  return(0);
}

void
ospf_delete_uniq_route (struct route_table *rt, struct route_table *cmprt)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct ospf_path *path;
  listnode pnode;

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL) 
      {
	if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    for (pnode = listhead (or->path); pnode; nextnode (pnode)) 
	      {
		path = getdata (pnode);

		if (path->nexthop.s_addr != INADDR_ANY &&
		    ! ospf_match_same_route(cmprt, or->type,
					    (struct prefix_ipv4 *) &rn->p, 
					    &path->nexthop))
		  {
		    ospf_zebra_delete ((struct prefix_ipv4 *) &rn->p, 
				       &path->nexthop);
		  }
	      }
	  }
	else if (or->type == OSPF_DESTINATION_DISCARD &&
		 ! ospf_match_same_route(cmprt, or->type,
					 (struct prefix_ipv4 *) &rn->p, 0))
	  {
	    ospf_zebra_delete_discard ((struct prefix_ipv4 *) &rn->p);
	  }
      }
}

void
ospf_install_route (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct ospf_path *path;
  listnode pnode;

  if (ospf_top->old_table)
    ospf_delete_uniq_route (ospf_top->old_table, rt);

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
    {
      if (or->type == OSPF_DESTINATION_NETWORK)
	for (pnode = listhead (or->path); pnode; nextnode (pnode))
	  {
	    path = getdata (pnode);

	    if (path->nexthop.s_addr != INADDR_ANY &&
		! ospf_match_same_route(ospf_top->old_table, or->type,
					(struct prefix_ipv4 *) &rn->p, 
					&path->nexthop))
	      {
		ospf_zebra_add ((struct prefix_ipv4 *) &rn->p, &path->nexthop);
	      }
	  }
      else if (or->type == OSPF_DESTINATION_DISCARD &&
	       !ospf_match_same_route(ospf_top->old_table, or->type,
				      (struct prefix_ipv4 *) &rn->p, 0))
	{
	  ospf_zebra_add_discard ((struct prefix_ipv4 *) &rn->p);
	}
    }

  if (ospf_top->old_table)
    ospf_route_table_free (ospf_top->old_table);

  ospf_top->old_table = ospf_top->new_table;
  ospf_top->new_table = rt;
}

void
ospf_intra_route_add (struct route_table *rt, struct vertex *v,
		      struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct prefix_ipv4 p;
  struct ospf_path *path;
  struct ospf_nexthop *nexthop;
  listnode nnode;

  p.family = AF_INET;
  p.prefix = v->id;
  if (v->type == OSPF_VERTEX_ROUTER)
    p.prefixlen = IPV4_MAX_BITLEN;
  else
    {
      struct network_lsa *lsa = (struct network_lsa *) v->lsa;
      p.prefixlen = ip_masklen (lsa->mask);
    }
  apply_mask_ipv4 (&p);

  rn = route_node_get (rt, (struct prefix *) &p);
  if (rn->info)
    {
      zlog_warn ("Same routing information exists for %s", inet_ntoa (v->id));
      route_unlock_node (rn);
      return;
    }

  or = ospf_route_new ();

  if (v->type == OSPF_VERTEX_NETWORK)
    {
      or->type = OSPF_DESTINATION_NETWORK;
      or->path = list_init ();

      for (nnode = listhead (v->nexthop); nnode; nextnode (nnode))
	{
	  nexthop = getdata (nnode);
	  path = ospf_path_new ();
	  path->nexthop = nexthop->router;
	  list_add_node (or->path, path);
	}
    }
  else
    or->type = OSPF_DESTINATION_ROUTER;

  or->id = v->id;
  or->area = area;
  or->path_type = OSPF_PATH_INTRA_AREA;
  or->cost = v->distance;

  rn->info = or;
}

/* RFC2328 16.1. (4). For "router". */
void
ospf_intra_add_router (struct route_table *rt, struct vertex *v,
		       struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct prefix_ipv4 p;
  struct router_lsa *lsa;

  zlog_info ("Z: ospf_intra_add_router: Start");

  lsa = (struct router_lsa *) v->lsa;

  zlog_info ("Z: ospf_intra_add_router: LS ID: %s",
	     inet_ntoa (lsa->header.id));

  ospf_check_vl_up (area, lsa->header.id, v);

  if (!CHECK_FLAG (lsa->flags, ROUTER_LSA_SHORTCUT))
    area->shortcut_capability = 0;

  /* If the newly added vertex is an area border router or AS boundary
     router, a routing table entry is added whose destination type is
     "router". */
  if (! IS_ROUTER_LSA_BORDER (lsa) && ! IS_ROUTER_LSA_EXTERNAL (lsa))
    {
      zlog_info ("Z: ospf_intra_add_router: "
		 "this router is neither ASBR nor ABR, skipping it");
      return;
    }

  /* The Options field found in the associated router-LSA is copied
     into the routing table entry's Optional capabilities field. Call
     the newly added vertex Router X. */
  or = ospf_route_new ();

  or->id = v->id;
  or->area = area;
  or->path_type = OSPF_PATH_INTRA_AREA;
  or->cost = v->distance;
  or->type = OSPF_DESTINATION_ROUTER;
  or->origin = (struct lsa_header*) lsa;
  or->options = lsa->header.options;
  or->flags   = lsa->flags;

  /* If Router X is the endpoint of one of the calculating router's
     virtual links, and the virtual link uses Area A as Transit area:
     the virtual link is declared up, the IP address of the virtual
     interface is set to the IP address of the outgoing interface
     calculated above for Router X, and the virtual neighbor's IP
     address is set to Router X's interface address (contained in
     Router X's router-LSA) that points back to the root of the
     shortest- path tree; equivalently, this is the interface that
     points back to Router X's parent vertex on the shortest-path tree
     (similar to the calculation in Section 16.1.1). */
  /* Ohh..  We don't support virtual link yet.  This should be added
     later on -- kunihiro. */

  p.family = AF_INET;
  p.prefix = v->id;
  p.prefixlen = IPV4_MAX_BITLEN;

  zlog_info ("Z: ospf_intra_add_router: talking about %s/%d",
	     inet_ntoa (p.prefix), p.prefixlen);

  rn = route_node_get (rt, (struct prefix *) &p);

  /* Note that we keep all routes to ABRs and ASBRs, not only the best */
  if (rn->info == NULL)
    rn->info = list_init ();
  else
    route_unlock_node (rn);

  ospf_route_copy_nexthops_from_vertex (or, v);

  list_add_node (rn->info, or);

  zlog_info ("Z: ospf_intra_add_router: Start");
}

/* RFC2328 16.1. (4).  For transit network. */
void
ospf_intra_add_transit (struct route_table *rt, struct vertex *v,
			struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct prefix_ipv4 p;
  struct network_lsa *lsa;

  lsa = (struct network_lsa*)v->lsa;

  /* If the newly added vertex is a transit network, the routing table
     entry for the network is located.  The entry's Destination ID is
     the IP network number, which can be obtained by masking the
     Vertex ID (Link State ID) with its associated subnet mask (found
     in the body of the associated network-LSA). */
  p.family = AF_INET;
  p.prefix = v->id;
  p.prefixlen = ip_masklen (lsa->mask);
  apply_mask_ipv4 (&p);

  rn = route_node_get (rt, (struct prefix *) &p);

  /* If the routing table entry already exists (i.e., there is already
     an intra-area route to the destination installed in the routing
     table), multiple vertices have mapped to the same IP network.
     For example, this can occur when a new Designated Router is being
     established.  In this case, the current routing table entry
     should be overwritten if and only if the newly found path is just
     as short and the current routing table entry's Link State Origin
     has a smaller Link State ID than the newly added vertex' LSA. */
  if (rn->info)
    {
      struct ospf_route *cur_or;

      route_unlock_node (rn);
      cur_or = rn->info;

      if (v->distance > cur_or->cost ||
          IPV4_ADDR_CMP (&cur_or->origin->id, &lsa->header.id) > 0)
	return;
      
      ospf_route_free (rn->info);
    }

  or = ospf_route_new ();

  or->id = v->id;
  or->area = area;
  or->path_type = OSPF_PATH_INTRA_AREA;
  or->cost = v->distance;
  or->type = OSPF_DESTINATION_NETWORK;
  or->origin = (struct lsa_header*) lsa;

  ospf_route_copy_nexthops_from_vertex (or, v);
  
  rn->info = or;
}

struct ospf_interface *
ospf_lookup_int_by_prefix (struct prefix_ipv4 *p)
{
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;
  struct prefix_ipv4 ip;

  zlog_info ("Z: ospf_lookup_int_by_prefix(): Start");

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (ifp== NULL)
	continue;

      zlog_info ("Z: ospf_lookup_int_by_prefix(): looking at %s", ifp->name);

      oi = ifp->info;
      if (oi == NULL)
	continue;

      if (oi->address == NULL)
	continue;

      prefix_copy ((struct prefix *) &ip, oi->address);

      zlog_info ("Z: ospf_lookup_int_by_prefix(): its prefix is %s/%d", 
		 inet_ntoa (ip.prefix), ip.prefixlen);

      apply_mask_ipv4 (&ip);

      if (prefix_same ((struct prefix *) &ip, (struct prefix *) p))
	return oi;
    }

  zlog_info ("Z: ospf_lookup_int_by_prefix(): I didn't find it");
  return NULL;
}

/* RFC2328 16.1. second stage. */
void
ospf_intra_add_stub (struct route_table *rt, struct router_lsa_link *link,
		     struct vertex *v, struct ospf_area *area)
{
  u_int16_t cost;
  struct route_node *rn;
  struct ospf_route *or;
  struct prefix_ipv4 p;
  struct router_lsa *lsa;
  struct ospf_interface *oi;
  struct ospf_path *path;

  zlog_info ("Z: ospf_intra_add_stub(): Start");

  lsa = (struct router_lsa *) v->lsa;

  p.family = AF_INET;
  p.prefix = link->link_id;
  p.prefixlen = ip_masklen (link->link_data);
  apply_mask_ipv4 (&p);

  zlog_info ("Z: ospf_intra_add_stub(): processing route to %s/%d", 
	     inet_ntoa (p.prefix), p.prefixlen);

  /* (1) Calculate the distance D of stub network from the root.  D is
     equal to the distance from the root to the router vertex
     (calculated in stage 1), plus the stub network link's advertised
     cost. */
  cost = v->distance + ntohs (link->m[0].metric);

  zlog_info ("Z: ospf_intra_add_stub(): calculated cost is %d + %d = %d", 
	     v->distance, ntohs(link->m[0].metric), cost);

  rn = route_node_get (rt, (struct prefix *) &p);

  /* Lookup current routing table. */
  if (rn->info)
    {
      struct ospf_route *cur_or;

      route_unlock_node (rn);

      cur_or = rn->info;

      zlog_info ("Z: ospf_intra_add_stub(): "
		 "another route to the same prefix found");

      /* Compare this distance to the current best cost to the stub
	 network.  This is done by looking up the stub network's
	 current routing table entry.  If the calculated distance D is
	 larger, go on to examine the next stub network link in the
	 LSA. */
      if (cost > cur_or->cost)
	{
	  zlog_info ("Z: ospf_intra_add_stub(): old route is better, exit");
	  return;
	}

      /* (2) If this step is reached, the stub network's routing table
	 entry must be updated.  Calculate the set of next hops that
	 would result from using the stub network link.  This
	 calculation is shown in Section 16.1.1; input to this
	 calculation is the destination (the stub network) and the
	 parent vertex (the router vertex). If the distance D is the
	 same as the current routing table cost, simply add this set
	 of next hops to the routing table entry's list of next hops.
	 In this case, the routing table already has a Link State
	 Origin.  If this Link State Origin is a router-LSA whose Link
	 State ID is smaller than V's Router ID, reset the Link State
	 Origin to V's router-LSA. */

      if (cost == cur_or->cost)
	{
	  zlog_info ("Z: ospf_intra_add_stub(): routes are equal, merge");

	  ospf_route_copy_nexthops_from_vertex (cur_or, v);

	  if (IPV4_ADDR_CMP (&cur_or->origin->id, &lsa->header.id) < 0)
	    cur_or->origin = (struct lsa_header*) lsa;
	  return;
	}

      /* Otherwise D is smaller than the routing table cost.
	 Overwrite the current routing table entry by setting the
	 routing table entry's cost to D, and by setting the entry's
	 list of next hops to the newly calculated set.  Set the
	 routing table entry's Link State Origin to V's router-LSA.
	 Then go on to examine the next stub network link. */

      if (cost < cur_or->cost)
	{
	  zlog_info ("Z: ospf_intra_add_stub(): new route is better, set it");

	  cur_or->cost = cost;

	  list_delete_all (cur_or->path);
	  cur_or->path = NULL;

	  ospf_route_copy_nexthops_from_vertex (cur_or, v);

	  cur_or->origin = (struct lsa_header *) lsa;
	  return;
	}
    }

  zlog_info ("Z: ospf_intra_add_stub(): installing new route");

  or = ospf_route_new ();

  or->id = v->id;
  or->area = area;
  or->path_type = OSPF_PATH_INTRA_AREA;
  or->cost = cost;
  or->type = OSPF_DESTINATION_NETWORK;
  or->origin = (struct lsa_header*) lsa;
  or->path = list_init ();

  /* Nexthop is depend on connection type. */
  if (v != area->spf)
    {
      zlog_info ("Z: ospf_intra_add_stub(): this network is on remote router");
      ospf_route_copy_nexthops_from_vertex (or, v);
    }
  else
    {
      zlog_info ("Z: ospf_intra_add_stub(): this network is on this router");

      oi = ospf_lookup_int_by_prefix (&p);
 
      if (oi) 
	{
	  zlog_info ("Z: ospf_intra_add_stub(): the interface is %s",
		     oi->ifp->name);

	  path = ospf_path_new ();
	  path->nexthop.s_addr = 0;
	  path->ifp = oi->ifp;
	  list_add_node (or->path, path);
	}
      else
	zlog_info ("Z: ospf_intra_add_stub(): where's the interface ?");
    }

  rn->info = or;

  zlog_info("Z: ospf_intra_add_stub(): Stop");
}

char *ospf_path_type_str[] =
{
  "unknown-type",
  "intra-area",
  "inter-area",
  "type1-external",
  "type2-external"
};

void
ospf_route_table_dump (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  listnode pnode;
  struct ospf_path *path;

#if 0
  zlog_info ("Type   Dest   Area   Path	 Type	 Cost	Next	 Adv.");
  zlog_info ("					Hop(s)	 Router(s)");
#endif /* 0 */

  zlog_info ("========== OSPF routing table ==========");
  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
        if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    zlog_info ("N %s/%d\t%s\t%s\t%d", 
		       inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		       rn->p.prefixlen,
		       inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		       ospf_path_type_str[or->path_type],
		       or->cost);
	    for (pnode = listhead (or->path); pnode; nextnode (pnode))
	      {
		path = getdata (pnode);
		zlog_info ("  -> %s", inet_ntoa (path->nexthop));
	      }
	  }
        else
	  zlog_info ("R %s\t%s\t%s\t%d", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     ospf_path_type_str[or->path_type],
		     or->cost);
      }
  zlog_info ("========================================");
}

void
ospf_terminate ()
{
  struct route_table *rt;

  if (ospf_top)
    {
      rt = ospf_top->new_table;

      if (rt)
	ospf_delete_route (rt);
    }
}


DEFUN (show_ip_ospf_route,
       show_ip_ospf_route_cmd,
       "show ip ospf route",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "OSPF routing table\n")
{
  struct route_table *rt, *rtrs;
  struct route_node *rn;
  struct ospf_route *or;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  listnode pnode, nnode;
  struct ospf_path *path;

  if (ospf_top == NULL)
    {
      vty_out (vty, "OSPF is not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  rt = ospf_top->new_table;
  rtrs = ospf_top->new_rtrs;

  if (rt == NULL)
    {
      vty_out (vty, "No OSPF routing information exist%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  zlog_info ("Z: show_ip_ospf_route(): showing networks");

  vty_out (vty, "========== OSPF network routing table ==========%s",
	   VTY_NEWLINE);
  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
	switch (or->path_type)
	  {
	  case OSPF_PATH_TYPE1_EXTERNAL:
	    vty_out (vty, "N E1 %s/%d \t[%d] area: %s, tag: %u%s", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     rn->p.prefixlen,
		     or->cost,
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     or->tag,
		     VTY_NEWLINE);
	    break;
	  case OSPF_PATH_TYPE2_EXTERNAL:
	    vty_out (vty, "N E2 %s/%d \t[%d/%d] area %s, tag: %u%s", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     rn->p.prefixlen,
		     or->cost, or->type2_cost,
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     or->tag,
		     VTY_NEWLINE);
	    break;
	  case OSPF_PATH_INTER_AREA:
	    if (or->type == OSPF_DESTINATION_NETWORK)
               vty_out (vty, "N IA %s/%d \t[%d] area: %s%s", 
		        inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		        rn->p.prefixlen, or->cost,
		        inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
			VTY_NEWLINE);

	    if (or->type == OSPF_DESTINATION_DISCARD)
               vty_out (vty, "D IA %s/%d \tDiscard entry%s", 
		        inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		        rn->p.prefixlen,
			VTY_NEWLINE);
	    break;
	  case OSPF_PATH_INTRA_AREA:
	    vty_out (vty, "N    %s/%d \t[%d] area: %s%s", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     rn->p.prefixlen,
		     or->cost,
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     VTY_NEWLINE);
	    break;
	  default:
	    break;
	  }

        if (or->type == OSPF_DESTINATION_NETWORK)
 	  for (pnode = listhead (or->path); pnode; nextnode (pnode))
	    {
	      path = getdata (pnode);

	      if (path->ifp == NULL)
		continue;

	      if (path->nexthop.s_addr == 0)
		vty_out (vty, "\t\t\tdirectly attached to %s%s",
			 path->ifp->name, VTY_NEWLINE);
	      else 
		vty_out (vty, "\t\t\tvia %s, %s%s",
			 inet_ntoa (path->nexthop), path->ifp->name,
			 VTY_NEWLINE);
	    }
      }

  zlog_info("Z: show_ip_ospf_route(): showing routers");

  vty_out (vty, "========== OSPF router routing table ==========%s",
	   VTY_NEWLINE);
  for (rn = route_top (rtrs); rn; rn = route_next (rn))
    {
      int flag;

      if (rn->info == NULL)
	continue;

      flag = 0;
      vty_out (vty, "R    %s \t", 
	       inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ));

      for (nnode = listhead ((list) rn->info); nnode; nextnode (nnode)) 
	{
	  or = getdata (nnode);
	  if (or == NULL)
	    continue;

          if (flag)
	    vty_out(vty,"      \t\t\t" );

          flag = 1;

	  switch (or->path_type)
	    {
	    case OSPF_PATH_INTRA_AREA:
	      vty_out (vty, "   [%d] area: %s", 
		       or->cost,
		       inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ));
	      break;
	    case OSPF_PATH_INTER_AREA:
	      vty_out (vty, "IA [%d] area: %s", 
		       or->cost,
		       inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ));
	      break;
	    default:
	      break;
	    }

	  if (or->flags & ROUTER_LSA_BORDER)
	    vty_out (vty, ", ABR");

	  if (or->flags & ROUTER_LSA_EXTERNAL)
	    vty_out (vty, ", ASBR");
	  vty_out (vty, "%s", VTY_NEWLINE);

	  for (pnode = listhead (or->path); pnode; nextnode (pnode))
	    {
	      path = getdata (pnode);
	      if (path->nexthop.s_addr == 0)
		vty_out (vty, "\t\t\t   directly attached to %s%s",
			 path->ifp->name, VTY_NEWLINE);
	      else 
		vty_out (vty, "\t\t\t   via %s, %s%s",
			 inet_ntoa (path->nexthop), path->ifp->name,
			 VTY_NEWLINE);
	    }
	}
    }

  return CMD_SUCCESS;
}


/* This is 16.4.1 implementation. */
int
ospf_cmp_asbr_routes (struct ospf_route *r1, struct ospf_route *r2)
{
  if (r1->path_type == OSPF_PATH_INTRA_AREA &&
      r2->path_type == OSPF_PATH_INTRA_AREA)
    {
      if (r1->area->area_id.s_addr != OSPF_AREA_BACKBONE)
	return 1;

      if (r2->area->area_id.s_addr != OSPF_AREA_BACKBONE)
	return -1;
    }
  else if (r1->path_type == OSPF_PATH_INTRA_AREA &&
	   r1->area->area_id.s_addr == OSPF_AREA_BACKBONE &&
	   r2->path_type == OSPF_PATH_INTER_AREA)
    return 0;

  else if (r2->path_type == OSPF_PATH_INTRA_AREA &&
	   r2->area->area_id.s_addr == OSPF_AREA_BACKBONE &&
	   r1->path_type == OSPF_PATH_INTER_AREA)
    return 0;

  else if (r1->path_type < r2->path_type)
    return 1;

  else if (r1->path_type > r2->path_type)
    return -1;

  return 0;
}


/*
  0 -- the same
  1 -- r1 is better
 -1 -- r2 is better
*/
int
ospf_cmp_routes (struct ospf_route *r1, struct ospf_route *r2)
{
  if (r1->path_type < r2->path_type)
    return 1;

  if (r1->path_type > r2->path_type)
    return -1;

  if (r1->path_type == OSPF_PATH_INTRA_AREA ||
      r1->path_type == OSPF_PATH_INTER_AREA)
    {
      if (r1->cost < r2->cost)
	return 1;
      if (r1->cost > r2->cost)
	return -1;

      return 0;
    }

  /* Compare Type-2 ext routes*/
  if (r1->path_type == OSPF_PATH_TYPE2_EXTERNAL)
    {
      int res;

      if (r1->type2_cost < r2->type2_cost)
	return 1;

      if (r1->type2_cost > r2->type2_cost)
	return -1;

      res = ospf_cmp_asbr_routes (r1->asbr, r2->asbr);
      if (res != 0)
	return res;

      if (r1->cost < r2->cost)
	return 1;

      if (r1->cost > r2->cost)
	return 1;

      return 0;
    }
  else
    { 
      /* Compare Type-1 ext routes*/
      int res;

      res = ospf_cmp_asbr_routes (r1->asbr, r2->asbr);
      if (res != 0)
	return res;
	
      if (r1->cost < r2->cost)
	return 1;
      
      if (r1->cost > r2->cost)
	return 1;

      return 0;
    }
}

void
ospf_route_copy_nexthops_from_vertex (struct ospf_route *to,
				      struct vertex *v)
{
  listnode nnode;
  struct ospf_path *path;
  struct ospf_nexthop *nexthop;

  if (to->path == NULL)
    to->path = list_init ();

  for (nnode = listhead (v->nexthop); nnode; nextnode (nnode))
    {
      nexthop = getdata (nnode);
      if (nexthop->ifp == NULL) 
	continue;

      path = ospf_path_new ();
      path->nexthop = nexthop->router;
      path->ifp = nexthop->ifp;
      list_add_node (to->path, path);
    }
}

void
ospf_route_copy_nexthops (struct ospf_route *to, list from)
{
  listnode pnode;
  struct ospf_path *path;

  if (to->path == NULL)
    to->path = list_init ();

  for (pnode = listhead (from); pnode; nextnode (pnode))
    {
      path = getdata (pnode);
      list_add_node (to->path, ospf_path_dup (path));
    }
}

void
ospf_route_subst_nexthops (struct ospf_route *to, list from)
{
  listnode node;
  struct ospf_path *op;

  LIST_ITERATOR (to->path, node)
    {
      op = getdata (node);
      if (op == NULL)
	continue;

      ospf_path_free (op);
      node->data = NULL;
    }

  list_delete_all_node (to->path);
  ospf_route_copy_nexthops (to, from);
}

void
ospf_subst_route (struct route_node *rn, struct ospf_route *new_or,
		  struct ospf_route *over)
{
  route_lock_node (rn);
  ospf_route_free (rn->info);

  ospf_route_copy_nexthops (new_or, over->path);
  rn->info = new_or;
  route_unlock_node (rn);
}

void
ospf_add_route (struct route_table *rt, struct prefix_ipv4 *p,
		struct ospf_route *new_or, struct ospf_route *over)
{
  struct route_node *rn;

  rn = route_node_get (rt, (struct prefix *) p);

  zlog_info ("Z: ospf_add_route(): rn->info != NULL: %d", (rn->info != NULL));

  ospf_route_copy_nexthops (new_or, over->path);

  if (rn->info)
    {
      zlog_info ("ospf_add_route():something's wrong !");
      route_unlock_node (rn);
      return;
    }

  rn->info = new_or;
}


void
ospf_prune_unreachable_networks (struct route_table *rt)
{
  struct route_node *rn, *next;
  struct ospf_route *or;

  zlog_info ("Z: Pruning unreachable networks");

  for (rn = route_top (rt); rn; rn = next)
    {
      next = route_next (rn);
      if (rn->info == NULL)
	continue;

      or = rn->info;
      if (listcount (or->path) == 0)
	{
	  zlog_info ("Z: Pruning route to %s/%d",
		     inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen);

	  ospf_route_free (or);
	  rn->info = NULL;
	  route_unlock_node (rn);
	}
    }
}

void
ospf_prune_unreachable_routers (struct route_table *rtrs)
{
  struct route_node *rn, *next;
  struct ospf_route *or;
  listnode node, nnext;
  list paths;

  zlog_info ("Z: Pruning unreachable routers");

  for (rn = route_top (rtrs); rn; rn = next)
    {
      next = route_next (rn);
      if (rn->info == NULL)
	continue;

      paths = rn->info;

      for (node = listhead (paths); node; node = nnext) 
	{
	  nnext = node->next;

	  or = getdata(node);

	  if (listcount (or->path) == 0)
	    {
	      zlog_info ("Z: Pruning route to rtr %s",
			 inet_ntoa (rn->p.u.prefix4));
	      zlog_info ("Z:               via area %s",
			 inet_ntoa (or->area->area_id));

	      list_delete_by_val (paths, or);
	      ospf_route_free (or);
	    }
	}

      if (listcount (paths) == 0)
	{
	  zlog_info ("Z: Pruning router node %s", inet_ntoa (rn->p.u.prefix4));

	  list_delete_all (paths);
	  rn->info = NULL;
	  route_unlock_node (rn);
	}
    }
}

int
ospf_add_discard_route (struct route_table *rt, struct ospf_area *area,
			struct prefix_ipv4 *p)
{
  struct route_node *rn;
  struct ospf_route *or, *new_or;

  rn = route_node_get (rt, (struct prefix *) p);

  if (rn == NULL)
    {
      zlog_info ("Z: ospf_add_discard_route(): router installation error");
      return 0;
    }

  if (rn->info) /* If the route to the same destination is found */
    {
      route_unlock_node (rn);

      or = rn->info;

      if (or->path_type == OSPF_PATH_INTRA_AREA)
	{
	  zlog_info ("Z: ospf_add_discard_route(): "
		     "an intra-area route exists");
	  return 0;
	}

      if (or->type == OSPF_DESTINATION_DISCARD)
	{
	  zlog_info ("Z: ospf_add_discard_route(): "
		     "discard entry already installed");
	  return 0;
	}

      ospf_route_free (rn->info);
  }

  new_or = ospf_route_new ();
  new_or->type = OSPF_DESTINATION_DISCARD;
  new_or->id.s_addr = 0;
  new_or->cost = 0;
  new_or->area = area;
  new_or->path_type = OSPF_PATH_INTER_AREA;
  rn->info = new_or;

  return 1;
}



void
ospf_route_init ()
{
  install_element (VIEW_NODE, &show_ip_ospf_route_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_route_cmd);
}
