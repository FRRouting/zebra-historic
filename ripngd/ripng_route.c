/*
 * RIPng routes function.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "prefix.h"
#include "table.h"
#include "memory.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"

void
ripng_slot_add (struct route_node *node)
{
  node->info = XMALLOC (MTYPE_RIPNG_SLOT, sizeof (struct ripng_slot));
  bzero (node->info, sizeof (struct ripng_slot));
}

void
ripng_slot_delete (struct route_node *node)
{
  XFREE (MTYPE_RIPNG_SLOT, node->info);
  node->info = NULL;
}

void
ripng_slot_check (struct route_node *node)
{
  struct ripng_slot *slot;

  slot = node->info;

  if (RIPNG_SLOT_RTE(slot) == NULL &&
      RIPNG_SLOT_STATIC(slot) == NULL &&
      RIPNG_SLOT_AGGREGATE(slot) == NULL)
    ripng_slot_delete (node);
}

/* RIPng routes treatment. */
int
ripng_static_add (struct route_node *node, u_char metric, int sub_type)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->info)
    ripng_slot_add (node);

  slot = node->info;

  /* There is already same static route. */
  if (RIPNG_SLOT_STATIC(slot))
    {
      ripng_info_free (RIPNG_SLOT_STATIC(slot));
      route_unlock_node (node);
    }

  /* Make new static route information. */
  rinfo = ripng_info_new ();
  rinfo->type = RIPNG_ROUTE_STATIC;
  rinfo->sub_type = sub_type;
  rinfo->metric = metric;
  rinfo->timer = 0;
  rinfo->fib = 0;
  RIPNG_SLOT_STATIC(slot) = rinfo;

  return 0;
}

/* Delete RIPng static route. */
int
ripng_static_delete (struct route_node *node)
{
  struct ripng_slot *slot;

  /* If there is no slot. */
  if (!node->info)
    return -1;
  
  slot = node->info;
  if (!slot || !RIPNG_SLOT_STATIC(slot))
    return -1;

  ripng_info_free (RIPNG_SLOT_STATIC(slot));
  RIPNG_SLOT_STATIC(slot) = NULL;
  ripng_slot_check (node);
  
  route_unlock_node (node);

  return 0;
}

/* RIPng routes treatment. */
int
ripng_aggregate_add (struct route_node *node, u_char metric)
{
  struct ripng_slot *slot;
  struct ripng_info *rinfo;

  /* If there is no slot. */
  if (!node->info)
    ripng_slot_add (node);

  slot = node->info;

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
int
ripng_aggregate_delete (struct route_node *node)
{
  struct ripng_slot *slot;

  /* If there is no slot. */
  if (!node->info)
    return -1;
  
  slot = node->info;
  if (!slot || !RIPNG_SLOT_AGGREGATE(slot))
    return -1;

  ripng_info_free (RIPNG_SLOT_AGGREGATE(slot));
  RIPNG_SLOT_AGGREGATE(slot) = NULL;
  ripng_slot_check (node);

  route_unlock_node (node);

  return 0;
}

extern struct route_table *ripng_table;

void
ripng_route_add (int type, struct prefix_ipv6 *p)
{
  int ret;
  int metric = 0;
  struct route_node *node;

  node = route_node_get (ripng_table, (struct prefix *)p);
  ret = ripng_static_add (node, metric, 0);
}

void
ripng_route_delete (int type, struct prefix_ipv6 *p)
{
  int ret;
  struct route_node *node;

  node = route_node_get (ripng_table, (struct prefix *) p);
  ret = ripng_static_delete (node);
  route_unlock_node (node);
}
