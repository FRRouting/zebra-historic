/*
 * OSPF ASBR functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#include "linklist.h"
#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "table.h"
#include "thread.h"
#include "if.h"
#include "filter.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_asbr.h"

struct ospf_external_route
{
  /* Route type such as static, connected, BGP. */
  u_char type;

  /* Metric type. */
  u_char metric_type;

  /* Metric value. */
  u_int32_t metric;

  /* Tag value. */
  u_int32_t tag;

  /* Interface */
  u_int ifindex;

  /* Nexthop address */
  struct in_addr nexthop;

  /* LSA. */
  struct ospf_lsa *lsa;
};

struct ospf_external_route *
ospf_external_route_new ()
{
  struct ospf_external_route *new;

  new = XMALLOC (MTYPE_OSPF_EXTERNAL_ROUTE, 
		 sizeof (struct ospf_external_route));
  memset (new, 0, sizeof (struct ospf_external_route));
  return new;
}

void
ospf_external_route_free (struct ospf_external_route *er)
{
  XFREE (MTYPE_OSPF_EXTERNAL_ROUTE, er);
}

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

int
ospf_asbr_should_announce (struct prefix_ipv4 *p,
			   u_char type, u_int ifindex, struct in_addr nexthop)
{
  struct interface *ifp;
  struct ospf_interface *oi;
  /*  struct in_addr mask; */

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

  if (nexthop.s_addr)
    return 1;

  if (type != ZEBRA_ROUTE_CONNECT)
    return 1;

  ifp = if_lookup_by_index (ifindex);

  if (ifp == NULL) 
    return 1;

  if ((oi = ifp->info) == NULL)
    return 1;

  if (oi->flag == OSPF_IF_DISABLE)
    return 1;

/*
  masklen2ip(oi->address->prefixlen, &mask);

  if (p->prefix.s_addr == (oi->address->u.prefix4.s_addr & mask.s_addr)){

     zlog_info("Z: skipping external route to %s/%d, since it"
               " should be announced as OSPF internal already",
               inet_ntoa(p->prefix), p->prefixlen);
     return 0;
  }

*/
  return 0;

/*  return 1; */
}

void
ospf_asbr_route_add (u_char type, struct prefix_ipv4 *p,
		     unsigned int ifindex, struct in_addr nexthop)
{
  struct ospf_lsa *lsa;
  struct ospf_external_route *er;
  struct route_node *rn;

  zlog_info ("Z: ospf_asbr_route_add(): adding external route to %s/%d",
             inet_ntoa (p->prefix), p->prefixlen);
  zlog_info ("Z: ospf_asbr_route_add(): nexthop info: ifindex:%d  addr:%s",
             ifindex, inet_ntoa (nexthop));

  /* Make new ospf external route. */
  er = ospf_external_route_new ();
  er->type = type;
  er->metric_type = EXTERNAL_METRIC_TYPE_2;
  er->metric = 1;
  er->tag = 0;
  er->nexthop = nexthop;
  er->ifindex = ifindex;

  rn = route_node_get (ospf_top->external_self, (struct prefix *) p);
  rn->info = er;

  if (! ospf_asbr_should_announce (p, type, ifindex, nexthop))
    return;

  /* First try to find self-originated LSA to the same prefix. */
  /*  lsa = ospf_find_self_external_lsa_by_prefix (p); */
  lsa = OSPF_EXTERNAL_LSA_SELF_FIND_BY_PREFIX (p);

  /* Make new external LSA. */
  lsa = ospf_external_lsa (p, er->metric_type, er->metric,
			   er->tag, er->nexthop, lsa);
  lsa = ospf_external_lsa_install (lsa);

  zlog_info ("Z: ospf_asbr_route_add(): adding ASE-LSA ID: %s",
             inet_ntoa (lsa->data->id));

  er->lsa = lsa;

  /* Flood AS-external-LSA. */
  ospf_flood_through_as (NULL, lsa);
}

void
ospf_asbr_route_remove (struct route_node *rn, u_char type)
{
  struct ospf_lsa *lsa;
  struct ospf_external_route *er;

  zlog_info ("ospf_asbr_route_remove(): Start");

  if (! rn->info)
    return;

  zlog_info ("ospf_asbr_route_remove(): removing %s",
	     inet_ntoa (rn->p.u.prefix4));

  /* Lookup external route and LSA. */
  er = rn->info;
  lsa = er->lsa;

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
  ospf_external_route_free (er);

  rn->info = NULL;
  route_unlock_node (rn);

  zlog_info ("ospf_asbr_route_remove(): Stop");
}

void
ospf_asbr_route_delete (u_char type, struct prefix_ipv4 *p,
			unsigned int ifindex)
{
  struct route_node *rn;

  rn = route_node_lookup (ospf_top->external_self, (struct prefix *) p);
  if (! rn || ! rn->info)
    {
      zlog_info ("ospf_asbr_route_delete(): can't find route %s",
		 inet_ntoa (p->prefix));
      return;
    }

  ospf_asbr_route_remove (rn, type);

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

void
ospf_asbr_check_lsas ()
{
  struct route_node *rn;
  struct ospf_external_route *er;
  struct ospf_lsa *lsa;
  struct as_external_lsa *ase_lsa, *old_lsa;

  RT_ITERATOR (ospf_top->external_self, rn)
    {
      if (rn->info == NULL)
	continue;

      er = (struct ospf_external_route *) rn->info;

      if (! ospf_asbr_should_announce ((struct prefix_ipv4 *) &rn->p,
				       er->type, er->ifindex, er->nexthop))
	{
	  if (er->lsa)
	    er->lsa = NULL; 
	  /* It remains in the LSDB and will be flushed*/
	  continue;
	}

      lsa = ospf_external_lsa ((struct prefix_ipv4 *) &rn->p, er->metric_type, 
			       er->metric, er->tag, er->nexthop, er->lsa);

      if (er->lsa == NULL)  /* We didn't announce it, but now we want to */
	{
	  lsa = ospf_external_lsa_install (lsa);
	  ospf_flood_through_as (NULL, lsa);
	  er->lsa = lsa;
	  SET_FLAG (er->lsa->flags, OSPF_LSA_APPROVED);
	}
      else
	{
	  /* er hold old lsa. */
	  old_lsa = (struct as_external_lsa *) er->lsa->data;
	  ase_lsa = (struct as_external_lsa *) lsa->data;

	  /* Check the fwd_addr, as it may change since the last time
	     the LSA was originated */
	  if (old_lsa->e[0].fwd_addr.s_addr != ase_lsa->e[0].fwd_addr.s_addr)
	    {
	      zlog_info ("Z: ospf_asbr_check_lsas(): "
			 "fwd_addr changed for LSA ID: %s"
			 "originating the new one", inet_ntoa (lsa->data->id));
	      if (lsa->refresh_list)
		ospf_refresher_unregister_lsa (lsa);
	      lsa = ospf_external_lsa_install (lsa);
	      ospf_flood_through_as (NULL, lsa);

	      er->lsa = lsa;
	    }
	  else /* LSA hasn't changed */
	    { 
	      zlog_info ("Z: ospf_asbr_check_lsas(): "
			 "fwd_addr is ok for LSA ID: %s",
			 inet_ntoa (lsa->data->id));
	      ospf_lsa_free (lsa);
	      zlog_info("Z: ospf_lsa_free() in ospf_asbr_check_lsas(): %x",
			lsa);
	    }
	  SET_FLAG (er->lsa->flags, OSPF_LSA_APPROVED);
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
  ospf_asbr_unapprove_lsas ();
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
