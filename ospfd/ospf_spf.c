/* OSPF calculation.
   Copyright (C) 1999 Kunihiro Ishiguro

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
#include "linklist.h"
#include "table.h"
#include "memory.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"

struct vertex *
ospf_vertex_new (struct ospf_lsa *lsa)
{
  struct vertex *new;

  new = XMALLOC (MTYPE_OSPF_VERTEX, sizeof (struct vertex));
  memset (new, 0, sizeof (struct vertex));

  new->type = lsa->type;
  new->id = lsa->id;
  new->lsa = lsa;
  new->nexthop = list_init ();
  new->distance = 0;
  new->parent = NULL;

  return new;
}

void
ospf_vertex_free (struct vertex *v)
{
  if (v->nexthop)
    list_free (v->nexthop);

  XFREE (MTYPE_OSPF_VERTEX, v);
}

void
ospf_spf_free (struct vertex *v)
{
  ;
}

void
ospf_vertex_add_parent (struct vertex *v)
{
  struct vertex *pv;

  pv = v->parent;

  list_add_node (pv->nexthop, v);
}

void
ospf_spf_init (struct ospf_area *area)
{
  struct vertex *v;
  struct ospf_lsa *lsa;

  lsa = ROUTER_LSA_SELF (area);

  /* Create root node. */
  v = ospf_vertex_new (lsa);

  area->spf = v;
}

int
ospf_spf_has_vertex (struct route_table *rt, struct ospf_lsa *lsa)
{
  struct prefix p;
  struct route_node *rn;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = lsa->id;

  rn = route_node_get (rt, &p);
  if (rn != NULL)
    {
      route_unlock_node (rn);
      return 1;
    }

  return 0;
}

struct vertex *
ospf_vertex_lookup (list list, struct in_addr id, int type)
{
  listnode node;
  struct vertex *v;

  for (node = listhead (list); node; nextnode (node))
    {
      v = (struct vertex *) getdata (node);
      if (IPV4_ADDR_SAME (&id, &v->id) && type == v->type)
	return v;
    }

  return NULL;
}

void
ospf_spf_next_router (struct vertex *v, struct ospf_area *area,
		      list candidate, struct route_table *rv)
{
  struct router_lsa *rl;
  struct ospf_lsa *w_lsa = NULL;
  struct vertex *w, *cw;
  int i, len, type = 0;

  rl = (struct router_lsa *) v->lsa;

  len = ntohs (rl->header.length);
  for (i = 0; i < ntohs (rl->links) || len <= 0; i++, len -= 12)
    {
      switch (rl->link[i].type)
	{
	case LSA_LINK_TYPE_POINTOPOINT:
	  w_lsa = ospf_lsa_lookup (area, OSPF_ROUTER_LSA,
				   rl->link[i].link_id);
	  break;
	case LSA_LINK_TYPE_TRANSIT:
	  w_lsa = ospf_lsa_lookup (area, OSPF_NETWORK_LSA,
				   rl->link[i].link_id);
	  break;
	case LSA_LINK_TYPE_STUB:
	  /* stub link will be considered in 2nd stage. */
	  continue;
	case LSA_LINK_TYPE_VIRTUALLINK:
	  break;
	default:
	  /* Illegal Link type. */
	  break;
	}
      /* LSA not exist. */
      if (w_lsa == NULL)
	continue;

      if (w_lsa->ls_age == OSPF_LSA_MAX_AGE)
	continue;

      /* W has link back to V? */

      /* W is already in SPF tree? */
      if (ospf_spf_has_vertex (rv, w_lsa))
	continue;

      /* prepare vertex W. */
      w = ospf_vertex_new (w_lsa);
      w->parent = v;
      w->distance = v->distance + rl->link[i].metric;

      /* calculate link cost D. */
      cw = ospf_vertex_lookup (candidate, w->id, type);
      if (cw != NULL)
	{
	  /* if D is greater than. */
	  if (w->distance > cw->distance)
	    {
	      ospf_vertex_free (w);
	      continue;
	    }
	  /* equal to. */
	  else if (w->distance == cw->distance)
	    {
	    }
	  /* less than. */
	  else
	    {
	      list_add_node (candidate, w);
	    }
	}
      else
	{
	}
    }
}

void
ospf_spf_next_network (struct vertex *v, struct ospf_area *area,
		       list candidate, struct route_table *nv)
{
  struct network_lsa *nl;
  struct ospf_lsa *w_lsa = NULL;
  struct vertex *w, *cw;
  int i, len, type = 0;

  nl = (struct network_lsa *) v->lsa;

  len = ntohs (nl->header.length);
  for (i = 0; len <= 0; i++, len -= 4)
    {
      w_lsa = ospf_lsa_lookup (area, OSPF_ROUTER_LSA, nl->routers[i]);

      /* LSA not exist. */
      if (w_lsa == NULL)
	continue;

      if (w_lsa->ls_age == OSPF_LSA_MAX_AGE)
	continue;

      /* W has link back to V? */

      /* W is already in SPF tree? */
      if (ospf_spf_has_vertex (nv, w_lsa))
	continue;

      /* prepare vertex W. */
      w = ospf_vertex_new (w_lsa);
      w->parent = v;
      w->distance = v->distance;
      /* network->router distance = 0. */

      /* calculate link cost D. */
      cw = ospf_vertex_lookup (candidate, w->id, type);
      if (cw != NULL)
	{
	  /* if D is greater than. */
	  if (w->distance > cw->distance)
	    {
	      ospf_vertex_free (w);
	      continue;
	    }
	  /* equal to. */
	  else if (w->distance == cw->distance)
	    {
	    }
	  /* less than. */
	  else
	    {
	      list_add_node (candidate, w);
	    }
	}
    }
}

struct vertex *
ospf_spf_closest_vertex (list list)
{
  struct vertex *v, *c = NULL;
  listnode node;

  if (list_isempty (list))
    return NULL;

  for (node = listhead (list); node; nextnode (node))
    {
      v = (struct vertex *) getdata (node);

      if (c == NULL)
	{
	  c = v;
	  continue;
	}

      if (v->distance < c->distance)
	c = v;
    }

  return c;
}

void
ospf_spf_calculate (struct ospf_area *area)
{
  list candidate;
  struct vertex *v, *c;
  struct route_table *rv;
  struct route_table *nv;

  /* SPF tree check table */
  rv = route_table_init ();
  nv = route_table_init ();

  /* Clear previous SPF tree. */
  ospf_spf_free (area->spf);

  candidate = list_init ();
  area->transit = OSPF_TRANSIT_FALSE;

  /* Initialize SPF tree for the area. */
  ospf_spf_init (area);
  v = area->spf;

  for (;;)
    {
      if (v->type == OSPF_VERTEX_ROUTER)
	{
	  /* check V bit in router-LSA. */
	  if (IS_ROUTER_LSA_VIRTUAL ((struct router_lsa *) v->lsa))
	    area->transit = OSPF_TRANSIT_TRUE;

	  ospf_spf_next_router (v, area, candidate, rv);
	}
      else if (v->type == OSPF_VERTEX_NETWORK)
	ospf_spf_next_network (v, area, candidate, nv);

      if (listcount (candidate) == 0)
	break;

      c = ospf_spf_closest_vertex (candidate);
      ospf_vertex_add_parent (c);
    }

  /* create routing table. */

  /* destroy route_table rv. */
  /* destroy route_table nv. */
}

