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
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_packet.h"

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
