/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
#include "vty.h"
#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "table.h"
#include "if.h"
#include "log.h"
#include "filter.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_asbr.h"

#if 0
/* Create new External route. */
struct ospf_external_route *
ospf_external_route_new ()
{
  struct ospf_external_route *new;

  new = XMALLOC (MTYPE_OSPF_EXTERNAL_ROUTE, 
		 sizeof (struct ospf_external_route));
  memset (new, 0, sizeof (struct ospf_external_route));

  new->ctime = time (NULL);
  new->mtime = new->ctime;

  return new;
}

/* Find External route. */
struct ospf_external_route *
ospf_external_route_lookup (struct prefix_ipv4 *p)
{
  struct route_node *rn;

  rn = route_node_get (ospf_top->external_self, (struct prefix *) p);

  if (rn->info != NULL)
    {
      route_unlock_node (rn);
      return rn->info;
    }

  return NULL;
}

/* Free External route. */
void
ospf_external_route_free (struct ospf_external_route *er)
{
  XFREE (MTYPE_OSPF_EXTERNAL_ROUTE, er);
}
#endif

/* Update ASBR status. */
void
ospf_asbr_status_update (u_char status)
{
  zlog_info ("K: ospf_ase_status_update(): Start");
  zlog_info ("K: ospf_ase_status_update(): new status %d", status);

  /* ASBR on. */
  if (status)
    {
      /* Already ASBR. */
      if (OSPF_IS_ASBR)
	{
	  zlog_info ("K: ospf_ase_status_update(): Already ASBR");
	  return;
	}
      SET_FLAG(ospf_top->flags, OSPF_FLAG_ASBR);
    }
  else
    {
      /* Already non ASBR. */
      if (! OSPF_IS_ASBR)
	{
	  zlog_info ("K: ospf_ase_status_update(): Already non ASBR");
	  return;
	}
      UNSET_FLAG (ospf_top->flags, OSPF_FLAG_ASBR);
    }

  ospf_spf_calculate_schedule ();
  ospf_schedule_update_router_lsas ();

  zlog_info ("K: ospf_ase_status_update(): Stop");
}

/* Check the prefix should be announced.
   0: deny, 1: permit. */
int
ospf_asbr_should_announce (struct prefix_ipv4 *p,
			   struct ospf_route *er)
     /*   u_char type, u_int ifindex, struct in_addr nexthop) */
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_char type = er->type;

  if (LIST_NAME (type))
    {
      if (LIST_PTR (type) == NULL)
	LIST_PTR (type) = access_list_lookup (AF_INET, LIST_NAME (type));

      if (LIST_PTR (type))
        if (access_list_apply (LIST_PTR (type), p) == FILTER_DENY)
	  {
	    zlog_info ("Z: ASBR: prefix %s/%d denied by ditribute-list",
		       inet_ntoa (p->prefix), p->prefixlen);
	    return 0;
	  }
    }

  /*
  if (nexthop.s_addr)
    return 1;
  */

  if (type != ZEBRA_ROUTE_CONNECT)
    return 1;

  /*
  if ((ifp = if_lookup_by_index (ifindex)) != NULL)
    if ((oi = ifp->info) != NULL)
      if (oi->flag != OSPF_IF_DISABLE)
	return 0;
  */

  return 1;
}

void
ospf_asbr_route_remove (struct route_node *rn, u_char type)
{
  struct ospf_lsa *lsa = NULL;
  struct ospf_route *er;

  zlog_info ("ospf_asbr_route_remove(): Start");

  if (! rn->info)
    return;

  zlog_info ("ospf_asbr_route_remove(): removing %s",
	     inet_ntoa (rn->p.u.prefix4));

  /* Lookup external route and LSA. */
  er = rn->info;
  lsa = er->u.ext.origin;

  if (er->type != type)
    {
      zlog_info ("ospf_asbr_route_remove(): type mismatch type %d er type %d",
		 type, er->type);
      return;
    }

  /* Flush LSA. */
  if (lsa)
    ospf_lsa_flush_as (lsa);

  /* Free external route. */
  /*  ospf_external_route_free (er); */
  ospf_route_free (er);

  rn->info = NULL;
  route_unlock_node (rn);

  zlog_info ("ospf_asbr_route_remove(): Stop");
}

void
ospf_asbr_route_delete (u_char type, struct prefix_ipv4 *p,
			unsigned int ifindex, struct in_addr nexthop)
{
  struct route_node *rn, *rn2;

  rn = route_node_lookup (ospf_top->external_self, (struct prefix *) p);
  if (! rn || ! rn->info)
    {
      zlog_info ("ospf_asbr_route_delete(): can't find route %s",
		 inet_ntoa (p->prefix));
      return;
    }

  ospf_asbr_route_remove (rn, type);

  rn2 = route_node_lookup (ospf_top->new_table, (struct prefix *) p);
  if (rn2)
    if (rn2->info)
      ospf_zebra_delete ((struct prefix_ipv4 *) &rn2->p, &nexthop);

  route_unlock_node (rn);
}

void
ospf_redistribute_withdraw (u_char type)
{
  struct route_node *rn;

  for (rn = route_top (ospf_top->external_self); rn; rn = route_next (rn))
    if (rn->info)
      ospf_asbr_route_remove (rn, type);
}

int
unapprove_lsa (struct ospf_lsa *lsa, void * v, int i)
{
  if (ospf_lsa_is_self_originated (lsa))
    UNSET_FLAG (lsa->flags, OSPF_LSA_APPROVED);

  return 0;
}

void
ospf_asbr_unapprove_lsas ()
{
  ospf_lsdb_iterator (ospf_top->external_lsa, NULL, 0, unapprove_lsa);
}

/* Check all AS external route. */
void
ospf_asbr_check_lsas ()
{
  struct route_node *rn;
  struct ospf_route *er;
  struct ospf_lsa *lsa = NULL;
  struct as_external_lsa *old_lsa;
  struct in_addr fwd_addr;

  RT_ITERATOR (ospf_top->external_self, rn)
    if ((er = rn->info) != NULL)
      {
	if (! ospf_asbr_should_announce ((struct prefix_ipv4 *) &rn->p, er))
	  {
	    if (er->u.ext.origin)
	      er->u.ext.origin = NULL; 
	    /* It remains in the LSDB and will be flushed*/
	    continue;
	  }

	/* We didn't announce it, but now we want to */
	if (er->u.ext.origin == NULL)
	  {
	    /* XXX: Temporarily comment out.
	    lsa = ospf_external_lsa ((struct prefix_ipv4 *) &rn->p,
				     er->metric_type, er->metric,
				     er->tag, er->nexthop, er->lsa);
	    lsa = ospf_external_lsa_install (lsa);
	    */
	    ospf_flood_through_as (NULL, lsa);
	    er->u.ext.origin = lsa;
	    SET_FLAG (er->u.ext.origin->flags, OSPF_LSA_APPROVED);
	  }
	else
	  {
	    /* er hold old lsa. */
	    old_lsa = (struct as_external_lsa *) er->u.ext.origin->data;

	    /*
	      ospf_forward_address_get (er->nexthop, &fwd_addr); */

	    /* Check the fwd_addr, as it may change since the last time
	       the LSA was originated. */
	    if (old_lsa->e[0].fwd_addr.s_addr != fwd_addr.s_addr)
	      {
		/* XXX: Temprarily comment out.
		lsa = ospf_external_lsa ((struct prefix_ipv4 *) &rn->p,
					 er->metric_type, er->metric,
					 er->tag, er->nexthop, er->lsa);

		zlog_info ("Z: ospf_asbr_check_lsas(): "
			   "fwd_addr changed for LSA ID: %s"
			   "originating the new one", inet_ntoa (lsa->data->id));
		if (lsa->refresh_list)
		  ospf_refresher_unregister_lsa (lsa);

		lsa = ospf_external_lsa_install (lsa);
		ospf_flood_through_as (NULL, lsa);
		*/
		er->u.ext.origin = lsa;
	      }
	    else /* LSA hasn't changed */
	      { 
		if (ospf_zlog)
		  zlog_info ("Z: ospf_asbr_check_lsas(): "
			     "fwd_addr is ok for LSA ID: %s",
			     inet_ntoa (er->u.ext.origin->data->id));
	      }
	    SET_FLAG (er->u.ext.origin->flags, OSPF_LSA_APPROVED);
	  }
      }
}

int
flush_unapproved (struct ospf_lsa *lsa, void * v, int i)
{
  if (ospf_lsa_is_self_originated (lsa))
    if (! CHECK_FLAG (lsa->flags, OSPF_LSA_APPROVED))
      {
	zlog_info ("Z: ospf_asbr_flush_unapproved(): Flushing LSA, ID: %s",
		   inet_ntoa (lsa->data->id));
	ospf_lsa_flush_as (lsa);
      }

  return 0;
}

void
ospf_asbr_flush_unapproved_lsas ()
{
  ospf_lsdb_iterator (ospf_top->external_lsa, NULL, 0, flush_unapproved);
}

/* This function performs checking of self-originated LSAs
   unapproved LSAs are flushed from the domain */
void 
ospf_asbr_check ()
{
  /* ospf_asbr_unapprove_lsas (); */
  ospf_asbr_check_lsas ();
  ospf_asbr_flush_unapproved_lsas ();
}

int 
ospf_asbr_check_timer (struct thread *thread)
{
  ospf_top->t_asbr_check = 0;
  ospf_asbr_check ();

  return 0;
}

void
ospf_schedule_asbr_check ()
{
  if (! ospf_top->t_asbr_check)
    ospf_top->t_asbr_check =
      thread_add_timer (master, ospf_asbr_check_timer,
			0, OSPF_ASBR_CHECK_DELAY);
}
