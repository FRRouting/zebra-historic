/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospf6d.h"

static struct ospf6_rtentry *
rtentry_new ()
{
  struct ospf6_rtentry *p;

  p = XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_rtentry));
  if (!p)
    {
      zvlog_warn ("can't alloc for rtentry");
      return NULL;
    }
  return p;
}

static void
rtentry_free (struct ospf6_rtentry *p)
{
  assert (p);
  XFREE (MTYPE_OSPF6_ROUTE, p);
  return;
}

static void
rtable_delete_all (struct ospf6_rtentry *rtable)
{
  struct ospf6_rtentry *p = NULL, *n = NULL;

  assert (rtable);
  p = rtable;
  while (p)
    {
      if (p->next)
        n = p->next;
      rtentry_free (p);
      p = n;
    }
  return;
}

struct ospf6_rtentry *
rtable_lookup (unsigned char dest_type, union dest_id *dest_id,
               struct ospf6_rtentry *top)
{
  struct ospf6_rtentry *p;

  for (p = top; p; p = p->next)
    {
      switch (dest_type)
        {
          case DTYPE_PREFIX:
            if (IN6_ARE_ADDR_EQUAL (&dest_id->prefix, &p->dest_id.prefix))
              return p;

          case DTYPE_ASBR:
            break;

          case DTYPE_INTRA_ROUTER:
            if (dest_id->router_id == p->dest_id.router_id)
              return p;

          case DTYPE_INTRA_LINK:
            if (dest_id->network_id[0] == p->dest_id.network_id[0] &&
                dest_id->network_id[1] == p->dest_id.network_id[1])
              return p;

          default:
            break;
        }
    }

  return NULL;
}

void
rtable_init (struct ospf6_rtable *rtable)
{
  assert (rtable->current_top);

  if (rtable->previous_top)
    {
      rtable_delete_all (rtable->previous_top);
      rtable->previous_top = NULL;
    }
  rtable->previous_top = rtable->current_top;
  rtable->current_top = NULL;
  return;
}

void
rtable_vty_entry (struct vty *vty, struct ospf6_rtentry *p)
{
  return;
}

