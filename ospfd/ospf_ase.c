/*
 * OSPF AS external route calculation.
 * Copyright (C) 1999, 2000 Alex Zinin, Toshiaki Takada
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

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"

#define DEBUG

struct ospf_route *
ospf_find_asbr_route (struct route_table *rtrs, struct prefix_ipv4 *asbr)
{
  struct route_node *rn;
  struct ospf_route *or, *best = NULL;
  listnode node;
  list chosen;

  /* Sanity check. */
  if (rtrs == NULL)
    return NULL;

  rn = route_node_lookup (rtrs, (struct prefix *) asbr);
 
  if (rn == NULL)
    return NULL;

  route_unlock_node (rn);

  chosen = list_init ();

  /* First try to find intra-area non-bb paths. */
  if (ospf_top->RFC1583Compat == 0)
    for (node = listhead ((list) rn->info); node; nextnode (node))
      if ((or = getdata (node)) != NULL)
	if (or->cost < OSPF_LS_INFINITY)
	  if (!OSPF_IS_AREA_BACKBONE (or->u.std.area) &&
	      or->path_type == OSPF_PATH_INTRA_AREA)
	    list_add_node (chosen, or);

  /* If none is found -- look through all. */
  if (listcount (chosen) == 0)
    {
      list_free (chosen);
      chosen = rn->info;
    }

  /* Now find the route with least cost. */
  for (node = listhead (chosen); node; nextnode (node))
    if ((or = getdata (node)) != NULL)
      if (or->cost < OSPF_LS_INFINITY)
	{
	  if (best == NULL)
	    best = or;
	  else if (best->cost > or->cost)
	    best = or;
	  else if (best->cost == or->cost &&
		   IPV4_ADDR_CMP (&best->u.std.area->area_id,
				  &or->u.std.area->area_id) < 0)
	    best = or;
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

  /* Sanity check. */
  if (rtrs == NULL)
    return NULL;

  rn = route_node_lookup (rtrs, (struct prefix *) asbr);
 
  if (rn != NULL)
    {
      listnode node;
      struct ospf_route *or;

      route_unlock_node (rn);

      for (node = listhead ((list) rn->info); node; nextnode (node))
	if ((or = getdata (node)) != NULL)
	  if (or->u.std.area == area)
	    return or;
    }

  return NULL;
}

void
ospf_ase_complete_direct_routes (struct ospf_route *ro, struct in_addr nexthop)
{
  listnode node;
  struct ospf_path *op;

  for (node = listhead (ro->path); node; nextnode (node))
    if ((op = getdata (node)) != NULL)
      if (op->nexthop.s_addr == 0)
	op->nexthop.s_addr = nexthop.s_addr;
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
      if ((ifp = getdata (if_node)) == NULL)
	continue;

      if (! if_is_up (ifp))
	continue;

      if ((oi = ifp->info) == NULL)
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	continue;

      if (oi->flag == OSPF_IF_DISABLE)
	continue;

      for (cn_node = listhead (ifp->connected); cn_node; nextnode (cn_node))
	if ((co = getdata (cn_node)) != NULL)
	  /* Hey, this address is ours !!! */
	  if (IPV4_ADDR_SAME (&co->address->u.prefix4, &fwd_addr))
	    return 0;
    }

  return 1;
}

/* Calculate ASBR route. */
struct ospf_route *
ospf_ase_calculate_asbr_route (struct route_table *rt_network,
			       struct route_table *rt_router,
			       struct as_external_lsa *al)
{
  struct prefix_ipv4 asbr;
  struct ospf_route *asbr_route;
  struct route_node *rn;

  /* Find ASBR route from Router routing table. */
  asbr.family = AF_INET;
  asbr.prefix = al->header.adv_router;
  asbr.prefixlen = IPV4_MAX_BITLEN;
  apply_mask_ipv4 (&asbr);

zlog_info ("T: asbr.prefix = al->header.adv_router: %s",
	   inet_ntoa (al->header.adv_router));
  asbr_route = ospf_find_asbr_route (rt_router, &asbr);

  if (asbr_route == NULL)
    {
      zlog_info ("Z: ospf_ase_calculate(): Route to ASBR %s not found",
		 inet_ntoa (asbr.prefix));
      return NULL;
    }

  if (!(asbr_route->u.std.flags & ROUTER_LSA_EXTERNAL))
    {
      zlog_info ("Z: ospf_ase_calculate(): Originating router is not an ASBR");
      return NULL;
    }
   
  if (al->e[0].fwd_addr.s_addr != 0)
    {
      zlog_info ("Z: ospf_ase_calculate(): "
		 "Forwarding address is not 0.0.0.0.");

      if (! ospf_ase_check_fwd_addr (al->e[0].fwd_addr))
	{
	  zlog_info ("Z: ospf_ase_calculate(): "
		     "Forwarding address is one of our addresses, Ignore.");
	  return NULL;
        }

      zlog_info ("Z: ospf_ase_calculate(): "
		 "Looking up in the Network Routing Table.");

      /* Looking up the path to the fwd_addr from Network route. */
      asbr.family = AF_INET;
      asbr.prefix = al->e[0].fwd_addr;
      asbr.prefixlen = IPV4_MAX_BITLEN;

      rn = route_node_match (rt_network, (struct prefix *) &asbr);
   
      if (rn == NULL)
	{
	  zlog_info ("Z: ospf_ase_calculate(): "
		     "Couldn't find a route to the forwarding address.");
	  return NULL;
	}

      route_unlock_node (rn);

      if ((asbr_route = rn->info) == NULL)
	{
	  zlog_info ("Z: ospf_ase_calculate(): "
		     "Somehow OSPF route to ASBR is lost");
	  return NULL;
	}
    }

  return asbr_route;
}

struct ospf_route *
ospf_ase_calculate_new_route (struct ospf_lsa *lsa,
			      struct ospf_route *asbr_route,
			      u_int32_t metric)
{
  struct as_external_lsa *al;
  struct ospf_route *new;

  al = (struct as_external_lsa *) lsa->data;

  new = ospf_route_new ();

  /* Set redistributed type -- does make sense? */
  /* new->type = type; */
  new->id = al->header.id;
  new->mask = al->mask;

  if (!IS_EXTERNAL_METRIC (al->e[0].tos))
    {
      zlog_info ("Z: ospf_ase_calculate_new_route(): This is Type-1 route.");
      new->path_type = OSPF_PATH_TYPE1_EXTERNAL;
      new->cost = asbr_route->cost + metric;		/* X + Y */
    }
  else
    {
      zlog_info ("Z: ospf_ase_calculate_new_route(): This is Type-2 route.");
      new->path_type = OSPF_PATH_TYPE2_EXTERNAL;
      new->cost = asbr_route->cost;			/* X */
      new->u.ext.type2_cost = metric;			/* Y */
    }

  new->type = OSPF_DESTINATION_NETWORK;
  new->path = list_init ();
  new->u.ext.origin = lsa;
  new->u.ext.tag = ntohl (al->e[0].route_tag);
  new->u.ext.asbr = asbr_route;

  zlog_info ("T: new = %x", new);
  zlog_info ("T: asbr_route = %x", asbr_route);
  assert (new != asbr_route);

  return new;
}

struct ospf_route *
ospf_ase_calculate_route_add (struct ospf_route *new,
			      struct ospf_route *asbr_route,
			      struct as_external_lsa *al,
			      struct route_table *rt_external)
{
  struct prefix_ipv4 p, q;
  struct route_node *rn;
  struct ospf_route *or;
  listnode node;
  int ret;

  zlog_info ("T: ospf_ase_calculate_route_add(): start");

  /* Set prefix. */
  p.family = AF_INET;
  p.prefix = al->header.id;
  p.prefixlen = ip_masklen (al->mask);

  apply_mask_ipv4 (&p);

  /* Find a route to the same dest */
  /* If there is no route, create new one. */
  if ((rn = route_node_lookup (rt_external, (struct prefix *) &p)) == NULL)
    {
      zlog_info ("T: ospf_ase_calculate(): Adding the new route");

      ospf_route_add (rt_external, &p, new, asbr_route);

      if (al->e[0].fwd_addr.s_addr)
	ospf_ase_complete_direct_routes (new, al->e[0].fwd_addr);

      for (node = listhead (new->path); node; nextnode (node))
	{
	  struct ospf_path *path = node->data;
	  
	  if (path->nexthop.s_addr != INADDR_ANY &&
	      !ospf_route_match_same (rt_external, new->type,
				      (struct prefix_ipv4 *) &p,
				      &path->nexthop))
	    ospf_zebra_add ((struct prefix_ipv4 *) &p, &path->nexthop);
	}

      return new;
    }

  /* There is already route. */
  route_unlock_node (rn);
      
  /* This is sanity check. */
  if ((or = rn->info) == NULL)
    return new;

  zlog_info ("T: ospf_ase_calculate(): "
	     "Another route to the same destination is found");

  /* Check the existing route. */
  /* First check the old route's ASBR route is valid. */
  q.family = AF_INET;
  q.prefix = or->u.ext.asbr->id;
  q.prefixlen = ip_masklen (or->u.ext.asbr->mask);

  if (ospf_find_asbr_route (ospf_top->new_rtrs, (struct prefix_ipv4 *) &q))
    ret = ospf_route_cmp (new, or);
  else
    {
      zlog_info ("T: ospf_ase_calculate_route_add(): "
		 "ASBR route for %x is invalid, ignore it.", or);
      ret = -1;
    }

  /* New route is better. */
  if (ret < 0)
    {
      ospf_route_subst (rn, new, asbr_route);
      if (al->e[0].fwd_addr.s_addr)
	ospf_ase_complete_direct_routes (new, al->e[0].fwd_addr);

      zlog_info ("T: ospf_ase_calculate(): "
		 "Substituted old route with the new one");
      return new;
    }
  /* Old route is better. */
  else if (ret > 0)
    {
      zlog_info ("T: ospf_ase_calculate(): The old route is better.");

      /* Make sure setting newly calculated ASBR route.*/
      or->u.ext.asbr = asbr_route;
      ospf_route_free (new);
      return or;
    }
  /* Routes are the same. */
  else
    {
      zlog_info ("T: ospf_ase_calculate(): The routes are equal, merging.");

      /* route_lock_node (rn); */
      ospf_route_copy_nexthops (or, asbr_route->path);
      if (al->e[0].fwd_addr.s_addr)
	ospf_ase_complete_direct_routes (or, al->e[0].fwd_addr);

      /* Make sure setting newly calculated ASBR route.*/
      or->u.ext.asbr = asbr_route;
      ospf_route_free (new);
      /* route_unlock_node (rn); */

      return or;
    }

  /* Not reached.*/
  zlog_info ("T: Unreached Statemen.");
  ospf_route_free (new);
  return NULL;
}

void
ospf_ase_rtrs_register_lsa (struct ospf_lsa *lsa)
{
  struct prefix_ipv4 p, q;
  struct route_node *rn1, *rn2;

  zlog_info ("T: ospf_ase_rtrs_register_lsa() start");

  /* First, lookup table by AdvRouter. */
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.prefix = lsa->data->adv_router;

  rn1 = route_node_get (ospf_top->rtrs_external, (struct prefix *) &p);

  zlog_info ("T: ospf_ase_rtrs_register_lsa(): adv_router %s",
	     inet_ntoa (lsa->data->adv_router));

  if (rn1->info == NULL)
    rn1->info = route_table_init ();
  else
    route_unlock_node (rn1);

  /* Second, lookup table by Link State ID. */
  /* rt = (struct route_table *) rn1->info; */
  q.family = AF_INET;
  q.prefixlen = IPV4_MAX_BITLEN;
  q.prefix = lsa->data->id;

  zlog_info ("T: ospf_ase_rtrs_register_lsa(): lsa->data->id %s",
	     inet_ntoa (lsa->data->id));

  rn2 = route_node_get (rn1->info, (struct prefix *) &q);

  if (rn2->info != NULL)
    route_unlock_node (rn2);

  rn2->info = lsa;

  zlog_info ("T: ospf_ase_rtrs_register_lsa() stop");
}

/* Calculate an external route and install to table. */
int
ospf_ase_calculate (struct ospf_lsa *lsa,
		    struct route_table *rt_network,
		    struct route_table *rt_router)
{
  struct ospf_route *asbr_route;
  struct as_external_lsa *al;
  struct ospf_route *new;
  u_int32_t metric;

  /* This is sanity check. */
  if (lsa == NULL)
    return 0;

  al = (struct as_external_lsa *) lsa->data;
  metric = GET_METRIC (al->e[0].metric);

  /* Check and install new route. */
  if (metric < OSPF_LS_INFINITY)
    if (LS_AGE (lsa) != OSPF_LSA_MAX_AGE)
      if (!CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
	{
	  zlog_info ("T: ospf_ase_calculate(): "
		     "Calculate AS-external-LSA to %s/%d",
		     inet_ntoa (al->header.id), ip_masklen (al->mask));

	  /* Register AS-external-LSA for Looking up later. */
	  ospf_ase_rtrs_register_lsa (lsa);

	  if ((asbr_route = ospf_ase_calculate_asbr_route (rt_network,
							   rt_router, al)))
	    {
	      new = ospf_ase_calculate_new_route (lsa, asbr_route, metric);
	      lsa->route =
		ospf_ase_calculate_route_add (new, asbr_route, al,
					      ospf_top->external_route);
	      return 1;
	    }
	}

  return 0;
}

#define OSPF_ASE_CALC_INTERVAL 1

int
ospf_ase_calculate_timer (struct thread *t)
{
  struct ospf *ospf;
  struct route_node *rn1, *rn2, *rn3;

  ospf = THREAD_ARG (t);
  ospf->t_ase_calc = NULL;

  zlog_info ("T: ospf_ase_calculate_timer(): fired!");

  if (ospf->ase_calc)
    {
      ospf->ase_calc = 0;

      /* Sanity check. */
      if (ospf->new_rtrs == NULL)
	{
	  zlog_info ("T: ospf_ase_calculate() new_rtrs = NULL");
	  return 0;
	}

      /* Check newly installed Router route by timestamp. */
      for (rn1 = route_top (ospf->new_rtrs); rn1; rn1 = route_next (rn1))
	if (rn1->info != NULL)
	  {
	    struct ospf_route *or;

	    or = ospf_find_asbr_route (ospf->new_rtrs,
				       (struct prefix_ipv4 *) &rn1->p);
	    /* Sanity check. */
	    if (or == NULL)
	      {
		zlog_info ("T: ospf_ase_calculate() or = NULL");
		continue;
	      }

	    if (or->ctime >= ospf->ts_spf)
	      {
		rn2 = route_node_lookup (ospf->rtrs_external, &rn1->p);

		/* For each related AS-external-LSA,
		   calculate external route. */
		if (rn2 != NULL)
		  for (rn3 = route_top (rn2->info); rn3; rn3 = route_next (rn3))
		    if (rn3->info != NULL)
		      ospf_ase_calculate (rn3->info, ospf->new_table,
					  ospf->new_rtrs);
	      }
	  }
    }

  return 0;
}

void
ospf_ase_calculate_schedule ()
{
  if (! ospf_top)
    return;

  ospf_top->ase_calc = 1;
}

void
ospf_ase_calculate_timer_add ()
{
  if (! ospf_top)
    return;

  if (! ospf_top->t_ase_calc)
    ospf_top->t_ase_calc = thread_add_timer (master, ospf_ase_calculate_timer,
					     ospf_top, OSPF_ASE_CALC_INTERVAL);
}


