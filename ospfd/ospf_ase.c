/*
 * OSPF ASE routing.
 * Copyright (C) 1999 Alex Zinin
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


#include <zebra.h>

#include "prefix.h"
#include "linklist.h"
#include "table.h"
#include "memory.h"
#include "thread.h"
#include "log.h"
#include "hash.h"
#include "if.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_lsdb.h"

#define DEBUG

struct ospf_route *
ospf_find_asbr_route (struct route_table *rtrs, struct prefix_ipv4 *asbr)
{
  struct route_node *rn;
  struct ospf_route *or, *best;
  listnode nnode;
  list chosen;

  rn = route_node_lookup (rtrs, (struct prefix *) asbr);
 
  if (rn == NULL)
    return NULL;

  route_unlock_node (rn);

  chosen = list_init ();

  /* First try to find intra-area non-bb paths */

  for (nnode = listhead ((list) rn->info); nnode; nextnode (nnode)) 
    {
      or = getdata (nnode);
      if (or == NULL)
	continue;

      if (or->cost >= OSPF_LS_INFINITY)
	continue;

      if (or->area->area_id.s_addr != OSPF_AREA_BACKBONE &&
	  or->path_type == OSPF_PATH_INTRA_AREA)
	list_add_node (chosen, or);
    }

  /* if none is found--look through all */
  if (listcount (chosen) == 0)
    {
      list_free (chosen);
      chosen = rn->info;
    }

  /* Now find the route with least cost */
  best = NULL;

  for (nnode = listhead (chosen); nnode; nextnode (nnode)) 
    {
      or = getdata (nnode);
      if (or == NULL)
	continue;

      if (or->cost >= OSPF_LS_INFINITY)
	continue;

      if (best == NULL)
	{
	  best = or;
	  continue;
	}

      if (best->cost > or->cost)
	{
	  best = or;
	  continue;
	}

      if (best->cost == or->cost &&
	  IPV4_ADDR_CMP (&best->area->area_id, &or->area->area_id) < 0)
	{
	  best = or;
	  continue;
	}
    }

  if (chosen != rn->info)
    list_delete_all (chosen);

  return best;
}

struct ospf_route * 
ospf_find_asbr_route_through_area (struct route_table *rtrs, 
				   struct prefix_ipv4 *asbr, 
				   struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  listnode nnode;

  rn = route_node_lookup (rtrs, (struct prefix *) asbr);
 
  if (rn == NULL)
    return NULL;

  route_unlock_node (rn);

  LIST_ITERATOR ((list) rn->info, nnode)
    {
      or = getdata (nnode);
      if (or == NULL)
	continue;

      if (or->area == area)
	return or;
    }

  return NULL;
}


void
ospf_ase_complete_direct_routes (struct ospf_route *ro, struct in_addr nexthop)
{
  listnode node;
  struct ospf_path *op;

  LIST_ITERATOR (ro->path, node)
    {
      op = getdata (node);
      if (op == NULL)
	continue;

      if (op->nexthop.s_addr == 0)
	op->nexthop.s_addr = nexthop.s_addr;
    }
}

int
ospf_ase_check_fwd_addr (struct in_addr fwd_addr)
{
  listnode if_node, cn_node;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct connected *co;

  LIST_ITERATOR (ospf_top->iflist, if_node)
    {
      ifp = getdata (if_node);
      if (ifp == NULL)
	continue;

      oi = ifp->info;
      if (oi == NULL)
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	continue;

      if (oi->flag == OSPF_IF_DISABLE)
	continue;

      LIST_ITERATOR (ifp->connected, cn_node)
	{
	  co = getdata (cn_node);
	  if (co == NULL)
	    continue;

	  if (IPV4_ADDR_SAME (&co->address->u.prefix4, &fwd_addr))
	    return 0; /* Hey, this address is ours !!! */
	}
    }

  return 1;
}


struct ase_args
{
  struct route_table *rt;
  struct route_table *rtrs;
};

int
process_ase_lsa (struct ospf_lsa *l, void *v, int i)
{
  /* struct route_node *rn; */
  struct route_node *rn1;
  struct ospf_route *or, *asbr_or, *new_or;
  struct as_external_lsa *lsa;
  u_int32_t metric, X, Y;
  struct prefix_ipv4 p, asbr;
  int type2;
  struct ase_args * args;

  if (l == NULL)
    return 0;

  lsa = (struct as_external_lsa *) l->data;

  args = (struct ase_args *) v;

  metric = GET_METRIC (lsa->e[0].metric);
   
  if (metric >= OSPF_LS_INFINITY)
    return 0;

  if (LS_AGE (l) == OSPF_LSA_MAX_AGE)
    return 0;

  if (CHECK_FLAG (l->flags, OSPF_LSA_SELF))
    return 0;

  p.family = AF_INET;
  p.prefix = lsa->header.id;
  p.prefixlen = ip_masklen (lsa->mask);
  apply_mask_ipv4 (&p);

  zlog_info ("Z: ospf_ase_routing(): processing ASE-LSA to %s/%d",
	     inet_ntoa (p.prefix), p.prefixlen);

  asbr.family = AF_INET;
  asbr.prefix = lsa->header.adv_router;
  asbr.prefixlen = IPV4_MAX_BITLEN;
  apply_mask_ipv4 (&asbr);

  asbr_or = ospf_find_asbr_route (args->rtrs, &asbr);

  if (asbr_or == NULL)
    {
      zlog_info ("Z: ospf_ase_routing(): route to ASBR not found");
      return 0;
    }

  if (!(asbr_or->flags & ROUTER_LSA_EXTERNAL))
    {
      zlog_info ("Z: ospf_ase_routing(): originating router is not an ASBR");
      return 0;
    }
   
  if (lsa->e[0].fwd_addr.s_addr != 0)
    {
      zlog_info ("Z: ospf_ase_routing(): fwd_addr is not 0, sanity check");

      if (! ospf_ase_check_fwd_addr (lsa->e[0].fwd_addr))
	{
	  zlog_info ("Z: ospf_ase_routing(): "
		     "fwd_addr is one of our addresses, ignore the route");
	  return 0;
        }

      zlog_info ("Z: ospf_ase_routing(): "
		 "fwd_addr is not 0, looking up in the RT");

      /* Find the path to the fwd_addr */
      asbr.family = AF_INET;
      asbr.prefix = lsa->e[0].fwd_addr;
      asbr.prefixlen = IPV4_MAX_BITLEN;

      rn1 = route_node_match (args->rt, (struct prefix *) &asbr);
   
      if (rn1 == NULL)
	{
	  zlog_info ("Z: ospf_ase_routing(): "
		     "couldn't find a route to the fwd_addr");
	  return 0;
	}

      asbr_or = rn1->info;
      route_unlock_node (rn1);

      if (asbr_or == NULL)
	{
	  zlog_info ("Z: ospf_ase_routing(): "
		     "somehow OSPF route to ASBR is lost");
	  return 0;
	}
    }

  new_or = ospf_route_new ();
  new_or->type = OSPF_DESTINATION_NETWORK;
  new_or->id = lsa->header.id;
  new_or->mask = lsa->mask;
  new_or->options = lsa->header.options;
  new_or->area = asbr_or->area;
  new_or->tag = ntohl (lsa->e[0].route_tag.s_addr);

  X = asbr_or->cost;
  Y = metric;
 
  type2 = IS_EXTERNAL_METRIC (lsa->e[0].tos);

  if (type2)
    {
      zlog_info ("Z: ospf_ase_routing(): this is Type-2 route");
      new_or->path_type = OSPF_PATH_TYPE2_EXTERNAL;
      new_or->cost = X;
      new_or->type2_cost = Y;
    }
  else
    {
      zlog_info ("Z: ospf_ase_routing(): this is Type-1 route");
      new_or->path_type = OSPF_PATH_TYPE1_EXTERNAL;
      new_or->cost = Y + X;
    }

  new_or->asbr = asbr_or;

  /* Find a route to the same dest */
  rn1 = route_node_lookup (args->rt, (struct prefix *) &p); 
   
  if (rn1)
    {
      int res;
	  
      route_unlock_node (rn1);
      or = rn1->info;
	
      if (or)
	{
	  zlog_info ("Z: ospf_ase_routing(): "
		     "another route to the same destination is found");

	  /* Check the existing route */
	  res = ospf_cmp_routes (new_or, or);

	  switch (res)
	    {
	    case 1:
	      ospf_subst_route (rn1, new_or, asbr_or);
	      if (lsa->e[0].fwd_addr.s_addr)
		ospf_ase_complete_direct_routes (new_or, lsa->e[0].fwd_addr);

	      zlog_info("Z: ospf_ase_routing(): "
			"substituted old route with the new one");
	      break;

	    case -1:
	      ospf_route_free (new_or);
	      zlog_info ("Z: ospf_ase_routing(): the old route is better");

	      return 0; /* Sorry, you're worse*/
	    case 0: 
	      route_lock_node (rn1);
	      zlog_info ("Z: ospf_ase_routing(): "
			 "the routes are equal, merging");
	      ospf_route_copy_nexthops (or, asbr_or->path);
	      if (lsa->e[0].fwd_addr.s_addr)
		ospf_ase_complete_direct_routes (or, lsa->e[0].fwd_addr);

	      ospf_route_free (new_or);
	      route_unlock_node (rn1);

	    default:
	      break;
	    }; /* switch() */
	} /* if (or)*/
    } /*if (rn1)*/
  else
    { /* no route */
      zlog_info ("Z: ospf_ase_routing(): adding the new route");
      ospf_add_route (args->rt, &p, new_or, asbr_or);

      if (lsa->e[0].fwd_addr.s_addr)
	ospf_ase_complete_direct_routes (new_or, lsa->e[0].fwd_addr);
    }
  return 0;
}

void
ospf_ase_routing (struct route_table *rt, struct route_table *rtrs)
{
  struct ase_args args;

  args.rt = rt;
  args.rtrs = rtrs;

  zlog_info ("Z: ospf_ase_routing(): start");

  ospf_lsdb_iterator (ospf_top->external_lsa, &args, 0, process_ase_lsa);
}

