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

list nexthoplist;

void nexthop_init ()
{
  nexthoplist = list_init ();;
}

static struct ospf6_nexthop *
nexthop_new ()
{
  struct ospf6_nexthop *p;
  p = XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct ospf6_nexthop));
  if (!p)
    {
      zvlog_warn ("can't alloc for nexthop");
      return NULL;
    }
  return p;
}

static void
nexthop_free (struct ospf6_nexthop *p)
{
  assert (p);
  XFREE (MTYPE_OSPF6_ROUTE, p);
  return;
}

static void
nexthop_lock (struct ospf6_nexthop *p)
{
  assert (p);
  p->lock++;
  return;
}

static void
nexthop_unlock (struct ospf6_nexthop *p)
{
  assert (p);
  assert (p->lock > 0);
  p->lock--;
  if (p->lock == 0)
    nexthop_free (p);
  return;
}

static struct ospf6_nexthop *
nexthop_lookup (unsigned long ifindex, struct in6_addr *ipaddr,
                unsigned long advrtr)
{
  struct ospf6_nexthop *p;
  listnode n;

  for (n = listhead (nexthoplist); n; nextnode (n))
    {
      p = getdata (n);
      if (p->ifindex == ifindex &&
          IN6_ARE_ADDR_EQUAL (&p->ipaddr, ipaddr) &&
          p->advrtr == advrtr)
        return p;
    }
  return NULL;
}

static struct ospf6_nexthop *
nexthop_make (unsigned long ifindex, struct in6_addr *ipaddr,
              unsigned long advrtr)
{
  struct ospf6_nexthop *p;

  p = nexthop_lookup (ifindex, ipaddr, advrtr);
  if (p)
    {
      nexthop_lock (p);
      return p;
    }

  p = nexthop_new ();
  p->ifindex = ifindex;
  memcpy (&p->ipaddr, ipaddr, sizeof (p->ipaddr));
  p->advrtr = advrtr;
  nexthop_lock (p);
  return p;
}

static void nexthop_delete (struct ospf6_nexthop *p)
{
  nexthop_unlock (p);
  return;
}

/* RFC2328 16.1.1 The next hop calculation */
void
nexthop_add_from_vertex (struct vertex *dst, struct vertex *parent, list l)
{
  listnode n, o;
  struct ospf6_nexthop *p;
  unsigned long ifindex;
  struct in6_addr ipaddr;
  char ifname[16];
  struct ospf6_if *o6if;
  struct lsa_internal *lsa;
  struct link_lsa *linklsa;

  if (dst->vtx_depth > 2 ||
      (dst->vtx_depth == 2 && IS_VTX_ROUTER_TYPE (parent)))
    {
      /* simply inherits from the parent */
      for (n = listhead (parent->vtx_nexthops); n; nextnode (n))
        {
          p = getdata (n);

          /* check if this is already on the nexthop list */
          for (o = listhead (l); o; nextnode (o))
            if (p == getdata (o))
              continue;

          nexthop_lock (p);
          list_add_node (l, p);
        }
      return;
    }
  else if (dst->vtx_depth == 1)
    {
      /* the parent is root */
      assert (parent->vtx_depth == 0);

      ifindex = get_ifindex_to_router (dst->vtx_rtrid, parent->vtx_lsa);
      assert (ifindex);
      memset (&ipaddr, 0, sizeof (struct in6_addr)); /* XXX P2MP not yet */
      p = nexthop_make (ifindex, &ipaddr, 0);
      list_add_node (l, p);
      return;
    }
  else if (dst->vtx_depth == 2)
    {
      assert (IS_VTX_ROUTER_TYPE (dst));
      assert (IS_VTX_NETWORK_TYPE (parent));

      /* simply inherit from the parent network */
      assert (listcount (parent->vtx_nexthops) == 1);
      p = getdata (listhead (parent->vtx_nexthops));
      ifindex = p->ifindex;
      assert (ifindex);

      if_indextoname (ifindex, ifname);
      o6if = ospf6_if_lookup (ifname);
      assert (o6if);
      lsa = get_linklocal_lsa (dst->vtx_rtrid, o6if);
      if (!lsa)
        {
          zvlog_err ("Can't find Link-LSA for %s, null nexthop",
                     inet4str (dst->vtx_rtrid));
          memset (&ipaddr, 0, sizeof (struct in6_addr));
        }
      else
        {
          linklsa = (struct link_lsa *)(lsa + 1);
          memcpy (&ipaddr, &linklsa->llsa_linklocal,
                  sizeof (struct in6_addr));
        }
      p = nexthop_make (ifindex, &ipaddr, 0);
      list_add_node (l, p);
      return;
    }
  else
    {
      assert (dst->vtx_depth == 0 && parent == NULL);
    }
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
  struct ospf6_nexthop *q;
  listnode n;

  assert (rtable);
  p = rtable;
  while (p)
    {
      for (n = listhead (p->nexthops); n; nextnode (n))
        {
          q = getdata (n);
          nexthop_unlock (q);
        }
      list_delete_all (p->nexthops);
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
                     cost_t cost, unsigned char path_type, list nexthops,
                     struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r = rtentry_new();
  struct ospf6_nexthop *p;
  listnode n;

  r->dest_type = dest_type;
  memcpy (&r->dest_id, dest_id, sizeof (union dest_id));
  r->path_type = path_type;
  r->cost = cost;

  r->nexthops = list_init ();
  for (n = listhead (nexthops); n; nextnode (n))
    {
      p = getdata (n);
      nexthop_lock (p);
      list_add_node (r->nexthops, p);
    }

  rtable_add (r, rtable);
  return;
}

void rtable_uninstall (unsigned char dest_type, union dest_id *dest_id,
                       struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r;
  listnode n;
  struct ospf6_nexthop *p;

  r = rtable_lookup (dest_type, dest_id, rtable->current_top);
  if (!r)
    {
      zvlog_warn ("No such route!");
      return;
    }

  rtable_delete (r, rtable);
  for (n = listhead (r->nexthops); n; nextnode (n))
    {
      p = getdata (n);
      nexthop_unlock (p);
    }
  list_delete_all (r->nexthops);

  rtentry_free (r);
  return;
}

void
rtable_vty_entry (struct vty *vty, struct ospf6_rtentry *p)
{
  char destination[64], ifid[32], gateway[32], netif[32], cost[32];
  listnode n;
  struct ospf6_nexthop *q;

  switch (p->dest_type)
    {
      case DTYPE_PREFIX:
        inet_ntop (AF_INET6, &p->dest_id.prefix,
                   destination, sizeof (destination));
        break;

      case DTYPE_ASBR:
        assert (0);
        return;        /* not yet */

      case DTYPE_INTRA_ROUTER:
        inet_ntop (AF_INET, &p->dest_id.router_id,
                   destination, sizeof (destination));
        strcat (destination, "(intra-router)");
        break;

      case DTYPE_INTRA_LINK:
        inet_ntop (AF_INET, &p->dest_id.network_id[0],
                   destination, sizeof (destination));
        sprintf (ifid, "[ifid %lu](intra-link)", p->dest_id.network_id[1]);
        strcat (destination, ifid);
        break;

      default:
        assert (0);
    }

  sprintf (cost, "%lu", p->cost);

  for (n = listhead (p->nexthops); n; nextnode (n))
    {
       q = getdata (n);
       if_indextoname (q->ifindex, netif);
       inet_ntop (AF_INET6, &q->ipaddr, gateway, sizeof (gateway));
       vty_out (vty, "%-26s %-39s %-3s %5s\r\n",
                destination, gateway, netif, cost);
    }
  return;
}

