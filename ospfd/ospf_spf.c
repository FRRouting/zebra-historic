/* OSPF calculation.
   Copyright (C) 1999 Kunihiro Ishiguro, Toshiaki Takada

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
#include "thread.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"

#define DEBUG

struct ospf_nexthop *
ospf_nexthop_new (struct vertex *parent)
{
  struct ospf_nexthop *new;

  new = XMALLOC (MTYPE_OSPF_NEXTHOP, sizeof (struct ospf_nexthop));
  bzero (new, sizeof (struct ospf_nexthop));

  new->parent = parent;

  return new;
}

void
ospf_nexthop_free (struct ospf_nexthop *nh)
{
  XFREE (MTYPE_OSPF_NEXTHOP, nh);
}

struct ospf_nexthop *
ospf_nexthop_dup (struct ospf_nexthop *nh)
{
  struct ospf_nexthop *new;

  new = ospf_nexthop_new (nh->parent);

  new->ifp = nh->ifp;
  new->router = nh->router;

  return new;
}

struct vertex *
ospf_vertex_new (struct ospf_lsa *lsa)
{
  struct vertex *new;

  new = XMALLOC (MTYPE_OSPF_VERTEX, sizeof (struct vertex));
  memset (new, 0, sizeof (struct vertex));

  new->flag = OSPF_SPF_FALSE;
  new->type = lsa->data->type;
  new->id = lsa->data->id;
  new->lsa = lsa->data;
  new->distance = 0;
  new->child = list_init ();
  new->nexthop = list_init ();

  return new;
}

void
ospf_vertex_free (struct vertex *v)
{
  listnode node;

  if (listcount (v->child) > 0)
    list_free (v->child);

  if (listcount (v->nexthop) > 0)
    for (node = listhead (v->nexthop); node; nextnode (node))
      ospf_nexthop_free (node->data);

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
  struct ospf_nexthop *nh;
  listnode node;

  for (node = listhead (v->nexthop); node; nextnode (node))
    {
      nh = (struct ospf_nexthop *) getdata (node);
      list_add_node (nh->parent->child, v);
    }
}

void
ospf_spf_init (struct ospf_area *area)
{
  struct vertex *v;

  /* Create root node. */
  v = ospf_vertex_new (area->router_lsa_self);

  area->spf = v;
}

int
ospf_spf_has_vertex (struct route_table *rv, struct route_table *nv,
		     struct lsa_header *lsa)
{
  struct prefix p;
  struct route_node *rn;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = lsa->id;

  if (lsa->type == OSPF_ROUTER_LSA)
    rn = route_node_get (rv, &p);
  else
    rn = route_node_get (nv, &p);

  if (rn->info != NULL)
    {
      route_unlock_node (rn);
      return 1;
    }
  return 0;
}

listnode
ospf_vertex_lookup (list list, struct in_addr id, int type)
{
  listnode node;
  struct vertex *v;

  for (node = listhead (list); node; nextnode (node))
    {
      v = (struct vertex *) getdata (node);
      if (IPV4_ADDR_SAME (&id, &v->id) && type == v->type)
	return node;
    }

  return NULL;
}

int
ospf_lsa_has_link (struct lsa_header *w, struct lsa_header *v)
{
  int i;
  int length;
  struct router_lsa *rl;
  struct network_lsa *nl;

  /* In case of W is Network LSA. */
  if (w->type == OSPF_NETWORK_LSA)
    {
      if (v->type == OSPF_NETWORK_LSA)
	return 0;

      nl = (struct network_lsa *) w;
      length = (ntohs (w->length) - OSPF_LSA_HEADER_SIZE - 4) / 4;
      
      for (i = 0; i < length; i++)
	if (IPV4_ADDR_SAME (&nl->routers[i], &v->id))
	  return 1;
      return 0;
    }

  /* In case of W is Router LSA. */
  if (w->type == OSPF_ROUTER_LSA)
    {
      rl = (struct router_lsa *) w;

      length = ntohs (w->length);

      for (i = 0; i < ntohs (rl->links) || length >= 0; i++, length -= 12)
	{
	  switch (rl->link[i].type)
	    {
	    case LSA_LINK_TYPE_POINTOPOINT:
	    case LSA_LINK_TYPE_VIRTUALLINK:
	      /* Router LSA ID. */
	      if (v->type == OSPF_ROUTER_LSA &&
		  IPV4_ADDR_SAME (&rl->link[i].link_id, &v->id))
		return 1;
	      break;
	    case LSA_LINK_TYPE_TRANSIT:
	      /* Network LSA ID. */
	      if (v->type == OSPF_NETWORK_LSA &&
		  IPV4_ADDR_SAME (&rl->link[i].link_id, &v->id))
		return 1;
	      break;
	    case LSA_LINK_TYPE_STUB:
	      /* Not take into count? */
	      continue;
	    default:
	      break;
	    }
	}
    }
  return 0;
}

#define ROUTER_LSA_MIN_SIZE 12
#define ROUTER_LSA_TOS_SIZE 4

void
ospf_nexthop_out_if_addr (struct vertex *v, struct vertex *w,
			  struct in_addr *addr)
{
  u_char *p;
  u_char *lim;
  struct router_lsa_link *l;

  addr->s_addr = 0;

  if (w->type != OSPF_VERTEX_NETWORK)
    return;

  p = ((u_char *) v->lsa) + 24;
  lim = ((u_char *) v->lsa) + ntohs (v->lsa->length);

  while (p < lim)
    {
      l = (struct router_lsa_link *) p;

      p += (ROUTER_LSA_MIN_SIZE +
	    (l->m[0].tos_count * ROUTER_LSA_TOS_SIZE));

      if (l->m[0].type == LSA_LINK_TYPE_STUB)
	continue;

      if (IPV4_ADDR_SAME (&l->link_id, &w->id))
	{
	  *addr = l->link_data;
	  return;
	}

    }

  return;
}

/* Calculate nexthop from root to vertex W. */
void
ospf_nexthop_calculation (struct ospf_area *area,
			  struct vertex *v, struct vertex *w)
{
  listnode node;
  struct ospf_nexthop *nh, *x;
  struct ospf_interface *oi;
  struct in_addr addr;

  /* W's parent is root. */
  if (v == area->spf)
    {
      nh = ospf_nexthop_new (v);

      if (w->type == OSPF_VERTEX_NETWORK)
	{
	  ospf_nexthop_out_if_addr (v, w, &addr);
	  oi = ospf_if_lookup_by_addr (&addr);
	  if (oi != NULL)
	    nh->ifp = oi->ifp;
	}

      nh->router.s_addr = 0;

      list_add_node (w->nexthop, nh);
      return;
    }
  /* In case of W's parent is network connected to root. */
  else if (v->type == OSPF_VERTEX_NETWORK)
    {
      for (node = listhead (v->nexthop); node; nextnode (node))
	{
	  x = (struct ospf_nexthop *) getdata (node);
	  if (x->parent == area->spf)
	    {
	      nh = ospf_nexthop_new (v);

	      ospf_nexthop_out_if_addr (w, v, &addr);

	      nh->ifp = x->ifp;
	      nh->router = addr;

	      list_add_node (w->nexthop, nh);
	      return;
	    }
	}
    }

  /* Inherit V's nexthop. */
  for (node = listhead (v->nexthop); node; nextnode (node))
    {
      nh = ospf_nexthop_dup (node->data);
      nh->parent = v;
      list_add_node (w->nexthop, nh);
    }
}

void
ospf_install_candidate (list candidate, struct vertex *w)
{
  listnode node;
  struct vertex *cw;

  if (list_isempty (candidate))
    {
      list_add_node (candidate, w);
      return;
    }

  /* Install vertex with sorting by distance. */
  for (node = listhead (candidate); node; nextnode (node))
    {
      cw = (struct vertex *) getdata (node);
      if (cw->distance > w->distance)
	{
	  list_add_node_prev (candidate, node, w);
	  break;
	}
      else if (node->next == NULL)
	{
	  list_add_node_next (candidate, node, w);
	  break;
	}
    }
}

void
ospf_spf_next (struct vertex *v, struct ospf_area *area,
	       list candidate, struct route_table *rv,
	       struct route_table *nv)
{
  struct ospf_lsa *w_lsa = NULL;
  struct vertex *w, *cw;
  int ret;
  u_char *p;
  u_char *lim;
  struct router_lsa_link *l = NULL;
  struct in_addr *r;
  listnode node;

  p = ((u_char *) v->lsa) + OSPF_LSA_HEADER_SIZE + 4;
  lim =  ((u_char *) v->lsa) + ntohs (v->lsa->length);
    
#ifdef DEBUG
  zlog_info ("===== start =====");
  zlog_info ("V's ID %s", inet_ntoa (v->lsa->id));
  if (v->lsa->type == OSPF_ROUTER_LSA)
    zlog_info ("V's type ROUTER LSA");
  else
    zlog_info ("V's type NETWORK LSA");
#endif /* DEBUG */

  while (p < lim)
    {
      if (v->lsa->type == OSPF_ROUTER_LSA)
	{
	  l = (struct router_lsa_link *) p;

	  p += (ROUTER_LSA_MIN_SIZE + 
		(l->m[0].tos_count * ROUTER_LSA_TOS_SIZE));

#ifdef DEBUG
	  zlog_info ("type %d", l->m[0].type);
#endif /* DEBUG */

	  switch (l->m[0].type)
	    {
	    case LSA_LINK_TYPE_POINTOPOINT:
	      w_lsa = ospf_lsa_lookup (area, OSPF_ROUTER_LSA, l->link_id);
	      break;
	    case LSA_LINK_TYPE_TRANSIT:
	      w_lsa = ospf_lsa_lookup (area, OSPF_NETWORK_LSA, l->link_id);
	      break;
	    case LSA_LINK_TYPE_STUB:
	      /* stub link will be considered in 2nd stage. */
	      zlog_info ("Stub network");
	      continue;
	    case LSA_LINK_TYPE_VIRTUALLINK:
	      zlog_info ("Virtual link");
	      break;
	    default:
	      continue;
	    }
	}
      else
	{
	  r = (struct in_addr *) p ;
	  p += sizeof (struct in_addr);
	  w_lsa = ospf_lsa_lookup (area, OSPF_ROUTER_LSA, *r);
	}

      /* LSA does not exist. */
      if (w_lsa == NULL)
	continue;

#ifdef DEBUG
      if (w_lsa->data->type == OSPF_ROUTER_LSA)
	zlog_info ("W is ROUTER LSA");
      else
	zlog_info ("W is NETWORK LSA");
#endif /* DEBUG */

      if (w_lsa->data->ls_age == OSPF_LSA_MAX_AGE)
	continue;

      /* W has link back to V? */
      if (! ospf_lsa_has_link (w_lsa->data, v->lsa))
	continue;

      /* W is already in SPF tree? */
      ret = ospf_spf_has_vertex (rv, nv, w_lsa->data);

#ifdef DEBUG
      if (ret)
	zlog_info ("Link dup check: dup");
#endif /* DEBUG */
      
      if (ret)
	continue;

#ifdef DEBUG
      zlog_info ("ID %s", inet_ntoa (w_lsa->data->id));
#endif /* DEBUG */

      /* prepare vertex W. */
      w = ospf_vertex_new (w_lsa);

      /* calculate link cost D. */
      if (v->lsa->type == OSPF_ROUTER_LSA)
	w->distance = v->distance + ntohs (l->m[0].metric);
      else
	w->distance = v->distance;

      /* Is there already vertex W in candidate list? */
      node = ospf_vertex_lookup (candidate, w->id, w->type);
      if (node == NULL)
	{
	  /* Calculate nexthop to W. */
	  ospf_nexthop_calculation (area, v, w);

	  ospf_install_candidate (candidate, w);
	}
      else
	{
	  cw = (struct vertex *) getdata (node);

	  /* if D is greater than. */
	  if (cw->distance < w->distance)
	    {
	      ospf_vertex_free (w);
	      continue;
	    }
	  /* equal to. */
	  else if (cw->distance == w->distance)
	    {
	      /* Calculate nexthop to W. */
	      ospf_nexthop_calculation (area, v, w);
	      list_add_list (cw->nexthop, w->nexthop);
	      list_delete_all_node (w->nexthop);
	      ospf_vertex_free (w);
	    }
	  /* less than. */
	  else
	    {
	      /* Calculate nexthop. */
	      ospf_nexthop_calculation (area, v, w);

	      /* Remove old vertex from candidate list. */
	      ospf_vertex_free (cw);
	      list_delete_by_val (candidate, cw);

	      /* Install new to candidate. */
	      ospf_install_candidate (candidate, w);
	    }
	}
    }
}

void
ospf_spf_route_add (struct vertex *v, struct route_table *rv, 
		    struct route_table *nv)
{
  struct prefix p;
  struct route_node *rn;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = v->id;

  if (v->type == OSPF_VERTEX_ROUTER)
    rn = route_node_get (rv, &p);
  else
    rn = route_node_get (nv, &p);
  rn->info = v;
}

void
ospf_spf_route_free (struct route_table *table)
{
  struct route_node *rn;
  struct vertex *v;

  for (rn = route_top (table); rn; rn = route_next (rn))
    {
      if (rn->info)
	{
	  v = rn->info;

	  ospf_vertex_free (v);
	  rn->info = NULL;
	}
      route_unlock_node (rn);
    }
}

void
ospf_spf_dump (struct vertex *v, int i)
{
  listnode cnode;
  listnode nnode;
  struct ospf_nexthop *nexthop;

  if (v->type == OSPF_VERTEX_ROUTER)
    zlog_info ("SPF Result: %d [R] %s", i, inet_ntoa (v->lsa->id));
  else
    {
      struct network_lsa *lsa = (struct network_lsa *) v->lsa;
      zlog_info ("SPF Result: %d [N] %s/%d", i, inet_ntoa (v->lsa->id),
		 ip_masklen (lsa->mask));

      for (nnode = listhead (v->nexthop); nnode; nextnode (nnode))
	{
	  nexthop = getdata (nnode);
	  zlog_info (" nexthop %s", inet_ntoa (nexthop->router));
	}
    }

  i++;

  for (cnode = listhead (v->child); cnode; nextnode (cnode))
    {
      v = getdata (cnode);
      ospf_spf_dump (v, i);
    }
}

void
ospf_spf_calculate (struct ospf_area *area)
{
  list candidate;
  listnode node;
  struct vertex *v;
  struct route_table *new_table;
  struct route_table *rv;
  struct route_table *nv;

  /* SPF tree check table */
  rv = route_table_init ();
  nv = route_table_init ();

  new_table = route_table_init ();

  /* Clear previous SPF tree. */
  ospf_spf_free (area->spf);

  candidate = list_init ();
  area->transit = OSPF_TRANSIT_FALSE;

  /* Initialize SPF tree for the area. */
  ospf_spf_init (area);
  v = area->spf;
  ospf_spf_route_add (v, rv, nv);

  for (;;)
    {
      if (v->type == OSPF_VERTEX_ROUTER)
	{
	  /* check V bit in router-LSA. */
	  if (IS_ROUTER_LSA_VIRTUAL ((struct router_lsa *) v->lsa))
	    area->transit = OSPF_TRANSIT_TRUE;
	}

      ospf_spf_next (v, area, candidate, rv, nv);

      /* Terminate calculation when candidate list becomes empty. */
      if (listcount (candidate) == 0)
      	break;

      /* Get first vertex from cadidate list. */
      node = listhead (candidate);
      v = getdata (node);
      ospf_vertex_add_parent (v);

      /* Delete from candidate list. */
      list_delete_by_val (candidate, v);

      /* Add to SPF tree. */
      ospf_spf_route_add (v, rv, nv);

      /* Add to new routing table. */
      ospf_intra_route_add (new_table, v, area);
    }

  /* Debug. */
#ifdef DEBUG
  ospf_spf_dump (area->spf, 0);
  ospf_route_table_dump (new_table);
#endif /* DEBUG */

  /* Update routing table. */
  ospf_install_route (new_table);

  /* Destroy route_table rv. */
  ospf_spf_route_free (rv);

  /* Destroy route_table nv. */
  ospf_spf_route_free (nv);
}

#define OSPF_SPF_CALC_INTERVAL 10

void ospf_spf_calculate_timer_add ();

/* Add schedule for SPF calculation.  To avoid frequenst SPF calc, we
   set timer for SPF calc. */
void
ospf_spf_calculate_schedule ()
{
  if (! ospf_top)
    return;

  ospf_top->spf_calc = 1;
}

/* Timer for SPF calculation. */
int
ospf_spf_calculate_timer (struct thread *t)
{
  struct ospf *ospf;
  struct ospf_area *area;
  listnode node;
  
  ospf = THREAD_ARG (t);

  ospf->t_spf_calc = NULL;

  if (ospf->spf_calc)
    {
      ospf->spf_calc = 0;
      
      for (node = listhead (ospf->areas); node; node = nextnode (node))
	{
	  area = getdata (node);
	  zlog_info ("SPF calc call");
	  ospf_spf_calculate (area);
	}
    }

  /* Register myself. */
  ospf_spf_calculate_timer_add ();

  return 0;
}

void
ospf_spf_calculate_timer_add ()
{
  if (! ospf_top)
    return;

  if (! ospf_top->t_spf_calc)
    ospf_top->t_spf_calc = thread_add_timer (master, ospf_spf_calculate_timer,
					     ospf_top, OSPF_SPF_CALC_INTERVAL);
}
