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
ospf_nbr_new ()
{
  struct ospf_neighbor *nbr;

  /* Allcate new neighbor. */
  nbr = XMALLOC (MTYPE_OSPF_NEIGHBOR, sizeof (struct ospf_neighbor));
  bzero (nbr, sizeof (struct ospf_neighbor));

  /* file descriptor reset. */
  nbr->fd = -1;

  /* Set default values. */
  nbr->status = NSM_Down;

  nbr->v_inactivity = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;

  /* Initialize lists. */
  nbr->link_state_retransmission = list_init ();
  nbr->database_summary = list_init ();
  nbr->link_state_request = list_init ();

  return nbr;
}

void
ospf_nbr_free (struct ospf_neighbor *nbr)
{
  XFREE (MTYPE_OSPF_NEIGHBOR, nbr);
}

/* check myself is in the neighbor list. */
int
ospf_nbr_bidirectional (struct in_addr *router_id,
			struct in_addr *neighbors, int size)
{
  int i;
  int max;

  max = size / sizeof (struct in_addr);

  for (i = 0; i < max; i ++)
    if (!IPV4_ADDR_CMP (router_id, &neighbors[i]))
      return 1;

  return 0;
}

/* add myself to nbr list. */
void
ospf_nbr_add_myself (struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;
  struct prefix p;
  struct route_node *rn;

  p.family = AF_INET;
  p.prefixlen = 32;
  p.u.prefix4 = ospf_top->router_id;

  nbr = ospf_nbr_new ();
  nbr->oi = oi;
  nbr->status = NSM_TwoWay;
  nbr->router_id = ospf_top->router_id;
  nbr->d_router = oi->d_router;
  nbr->bd_router = oi->bd_router;
  nbr->priority = oi->priority;
  nbr->address = p;

  rn = route_node_get (oi->nbrs, &p);
  if (rn->info)
    {
      zlog (NULL, LOG_INFO, "There is already pseudo neighbor. */");
      route_unlock_node (rn);
    }
  else
    rn->info = nbr;
}

/* get neighbor count. */
int
ospf_nbr_count (struct route_table *nbrs)
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
      if (!IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id))
	continue;

      count++;
    }

  return count;
}

int
ospf_adjacent_count (struct route_table *nbrs)
{
  return 0;
}
