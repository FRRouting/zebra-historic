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

list pathlist;

void path_init ()
{
  pathlist = list_init ();;
}

static struct ospf6_path *
path_new ()
{
  struct ospf6_path *p;
  p = XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_path));
  if (!p)
    {
      zvlog_warn ("can't alloc for path");
      return NULL;
    }
  return p;
}

static void
path_free (struct ospf6_path *p)
{
  assert (p);
  XFREE (MTYPE_OSPF6_ROUTE, p);
  return;
}

static void
path_lock (struct ospf6_path *p)
{
  assert (p);
  p->lock++;
  return;
}

static void
path_unlock (struct ospf6_path *p)
{
  assert (p);
  assert (p->lock > 0);
  p->lock--;
  if (p->lock == 0)
    path_free (p);
  return;
}

static struct ospf6_path *
path_lookup (unsigned long ifindex, struct in6_addr *ipaddr,
             unsigned long advrtr)
{
  struct ospf6_path *p;
  listnode n;

  for (n = listhead (pathlist); n; nextnode (n))
    {
      p = getdata (n);
      if (p->ifindex == ifindex &&
          IN6_ARE_ADDR_EQUAL (&p->ipaddr, ipaddr) &&
          p->advrtr == advrtr)
        return p;
    }
  return NULL;
}

static struct ospf6_path *
path_make (unsigned long ifindex, struct in6_addr *ipaddr,
             unsigned long advrtr)
{
  struct ospf6_path *p;

  p = path_lookup (ifindex, ipaddr, advrtr);
  if (p)
    {
      path_lock (p);
      return p;
    }

  p = path_new ();
  p->ifindex = ifindex;
  memcpy (&p->ipaddr, ipaddr, sizeof (p->ipaddr));
  p->advrtr = advrtr;
  path_lock (p);
  return p;
}

static void path_delete (struct ospf6_path *p)
{
  path_unlock (p);
  return;
}

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
  struct ospf6_rtentry *p = NULL, *next = NULL;
  struct ospf6_path *q;
  listnode n;

  assert (rtable);
  p = rtable;
  while (p)
    {
      for (n = listhead (p->paths); n; nextnode (n))
        {
          q = getdata (n);
          path_unlock (q);
        }
      list_delete_all (p->paths);
      if (p->next)
        next = p->next;
      rtentry_free (p);
      p = next;
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

static void
rtable_add (struct ospf6_rtentry *p, struct ospf6_rtable *rtable)
{
  p->next = rtable->current_top;
  p->prev = NULL;
  if (rtable->current_top)
    rtable->current_top->prev = p;
  rtable->current_top = p;
  return;
}

static void
rtable_delete (struct ospf6_rtentry *p, struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *q;

  for (q = rtable->current_top; q; q = q->next)
    if (q == p)
      break;

  if (!q)
    {
      zvlog_warn ("Can't find entry %#x", p);
      return;
    }

  p->prev->next = p->next;
  p->next->prev = p->prev;
  return;
}

void rtable_install (unsigned char dest_type, union dest_id *dest_id,
                     cost_t cost, unsigned char path_type,
                     struct in6_addr *nexthop, unsigned long ifindex,
                     unsigned long advrtr,
                     struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r = rtentry_new();
  struct ospf6_path *p;

  r->dest_type = dest_type;
  memcpy (&r->dest_id, dest_id, sizeof (union dest_id));
  r->path_type = path_type;
  r->cost = cost;

  r->paths = list_init ();
  p = path_make (ifindex, nexthop, advrtr);
  list_add_node (r->paths, p);

  rtable_add (r, rtable);
  return;
}

void rtable_uninstall (unsigned char dest_type, union dest_id *dest_id,
                       struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r;
  listnode n;
  struct ospf6_path *p;

  r = rtable_lookup (dest_type, dest_id, rtable->current_top);
  if (!r)
    {
      zvlog_warn ("No such route!");
      return;
    }

  rtable_delete (r, rtable);
  for (n = listhead (r->paths); n; nextnode (n))
    {
      p = getdata (n);
      path_unlock (p);
    }
  list_delete_all (r->paths);

  rtentry_free (r);
  return;
}

void
rtable_vty_entry (struct vty *vty, struct ospf6_rtentry *p)
{
  return;
}

