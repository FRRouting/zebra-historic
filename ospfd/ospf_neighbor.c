/*
 * OSPF Neighbor functions.
 * Copyright (C) 1999 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "thread.h"
#include "stream.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"

struct ospf_neighbor *
ospf_nbr_new (struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;

  /* Allcate new neighbor. */
  nbr = XMALLOC (MTYPE_OSPF_NEIGHBOR, sizeof (struct ospf_neighbor));
  bzero (nbr, sizeof (struct ospf_neighbor));

  /* Relate Neighbor to Interface. */
  nbr->oi = oi;

  /* Set default values. */
  nbr->status = NSM_Down;

  nbr->v_inactivity = oi->v_wait;
  nbr->v_db_desc = oi->retransmit_interval;
  nbr->v_ls_req = oi->retransmit_interval;
  nbr->v_ls_upd = oi->retransmit_interval;
  nbr->priority = -1;

  /* DD flags. */
  nbr->dd_flags = OSPF_DD_FLAG_MS|OSPF_DD_FLAG_M|OSPF_DD_FLAG_I;

  /* Last received and sent DD. */
  nbr->last_send = NULL;

  /* Initialize lists. */
  nbr->ls_retransmit = list_init ();
  nbr->db_summary = list_init ();
  nbr->ls_request = list_init ();

  /* */
  OSPF_NSM_TIMER_ON (nbr->t_ls_upd, ospf_ls_upd_timer, nbr->v_ls_upd);

  return nbr;
}

void
ospf_nbr_free (struct ospf_neighbor *nbr)
{
  if (nbr->ls_retransmit != NULL && listcount (nbr->ls_retransmit))
    list_delete_all (nbr->ls_retransmit);
  if (nbr->db_summary != NULL && listcount (nbr->db_summary))
    list_delete_all (nbr->db_summary);
  if (nbr->ls_request != NULL && listcount (nbr->ls_request))
    list_delete_all (nbr->ls_request);

/*  if (nbr->host)
    free (nbr->host); */

  /* Cancel threads. */
  OSPF_NSM_TIMER_OFF (nbr->t_inactivity);

  XFREE (MTYPE_OSPF_NEIGHBOR, nbr);
}

void
ospf_nbr_delete (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  struct route_node *rn;
  struct prefix p;

  oi = nbr->oi;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = nbr->address.u.prefix4;

  ospf_nbr_free (nbr);

  rn = route_node_get (oi->nbrs, &p);
  if (rn != NULL)
    {
      rn->info = NULL;
      while (rn->lock)
	route_unlock_node (rn);
    }
}

/* Check myself is in the neighbor list. */
int
ospf_nbr_bidirectional (struct in_addr *router_id,
			struct in_addr *neighbors, int size)
{
  int i;
  int max;

  max = size / sizeof (struct in_addr);

  for (i = 0; i < max; i ++)
    if (IPV4_ADDR_SAME (router_id, &neighbors[i]))
      return 1;

  return 0;
}

/* Add self to nbr list. */
void
ospf_nbr_add_self (struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;
  struct prefix p;
  struct route_node *rn;

  p.family = AF_INET;
  p.prefixlen = 32;
  p.u.prefix4 = oi->address->u.prefix4;

  rn = route_node_get (oi->nbrs, &p);
  if (rn->info)
    {
      /* There is already pseudo neighbor. */
      nbr = rn->info;
      route_unlock_node (rn);
    }
  else
    {
      nbr = ospf_nbr_new (oi);
      rn->info = nbr;
    }

  nbr->status = NSM_TwoWay;
  nbr->router_id = ospf_top->router_id;
  /*
  nbr->d_router = oi->d_router;
  nbr->bd_router = oi->bd_router;
  nbr->priority = oi->priority;
  */
  nbr->address = *oi->address;

  oi->nbr_self = nbr;
}

/* Get neighbor count by status. */
int
ospf_nbr_count (struct route_table *nbrs, int status)
{
  struct route_node *rn;
  struct ospf_neighbor *nbr;
  int count = 0;

  if (nbrs == NULL)
    return 0;

  for (rn = route_top (nbrs); rn; rn = route_next (rn))
    {
      if (rn->info == NULL)
	continue;
      nbr = rn->info;

      /* this is myself. */
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;

      if (status == 0 || nbr->status == status)
	count++;
    }

  return count;
}

struct ospf_neighbor *
ospf_nbr_lookup_by_addr (struct route_table *nbrs,
			 struct in_addr *addr)
{
  struct prefix p;
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = *addr;

  rn = route_node_get (nbrs, &p);
  if (rn == NULL)
    return NULL;
  if (rn->info == NULL)
    return NULL;

  nbr = (struct ospf_neighbor *) rn->info;
  route_unlock_node (rn);

  return nbr;
}

