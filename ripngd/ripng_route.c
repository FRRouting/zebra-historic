/* RIPng routes function.
   Copyright (C) 1998 Kunihiro Ishiguro

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

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "ripngd.h"
#include "table.h"
#include "memory.h"

ripng_slot_add (struct route_node *node)
{
  node->route = XMALLOC (MTYPE_RIPNG_SLOT, sizeof (struct ripng_slot));
  bzero (node->route, sizeof (struct ripng_slot));
}

ripng_slot_delete (struct route_node *node)
{
  XFREE (MTYPE_RIPNG_SLOT, node->route);
  node->route = NULL;
}

/* RIPng routes treatment. */
ripng_static_add (struct route_node *node, u_char metric)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->route)
    ripng_slot_add (node);

  slot = node->route;

  /* There is already same static route. */
  if (RIPNG_SLOT_STATIC(slot))
    return -1;

  /* Make new static route information. */
  rinfo = ripng_info_new ();
  rinfo->type = RIPNG_ROUTE_STATIC;
  rinfo->metric = metric;
  rinfo->timer = 0;
  rinfo->fib = 0;
  RIPNG_SLOT_STATIC(slot) = rinfo;

  return 0;
}

/* Delete RIPng static route. */
ripng_static_delete (struct route_node *node)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->route)
    return -1;
  
  slot = node->route;
  if (!slot || !RIPNG_SLOT_STATIC(slot))
    return -1;

  ripng_info_free (RIPNG_SLOT_STATIC(slot));
  RIPNG_SLOT_STATIC(slot) = NULL;

  return 0;
}

/* RIPng routes treatment. */
ripng_aggregate_add (struct route_node *node, u_char metric)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->route)
    ripng_slot_add (node);

  slot = node->route;

  /* There is already same static route. */
  if (RIPNG_SLOT_AGGREGATE(slot))
    return -1;

  /* Make new static route information. */
  rinfo = ripng_info_new ();
  rinfo->type = RIPNG_ROUTE_AGGREGATE;
  rinfo->metric = metric;
  rinfo->timer = 0;
  rinfo->fib = 0;
  RIPNG_SLOT_AGGREGATE(slot) = rinfo;

  return 0;
}

/* Delete RIPng static route. */
ripng_aggregate_delete (struct route_node *node)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->route)
    return -1;
  
  slot = node->route;
  if (!slot || !RIPNG_SLOT_AGGREGATE(slot))
    return -1;

  ripng_info_free (RIPNG_SLOT_AGGREGATE(slot));
  RIPNG_SLOT_AGGREGATE(slot) = NULL;

  return 0;
}
