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
  struct ospf6_lsa *lsa;
  struct link_lsa *linklsa;
  list m;

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
      m = list_init ();
      ospf6_lsdb_collect_type_advrtr (m, htons (LST_LINK_LSA),
                                      dst->vtx_rtrid, (void *)o6if);
      if (list_isempty (m))
        {
          o6log.rtable ("Can't find Link-LSA for %s, null nexthop",
                        inet4str (dst->vtx_rtrid));
          memset (&ipaddr, 0, sizeof (struct in6_addr));
        }
      else
        {
          lsa = (struct ospf6_lsa *) getdata (listhead (m));
          linklsa = (struct link_lsa *)(lsa + 1);
          memcpy (&ipaddr, &linklsa->llsa_linklocal,
                  sizeof (struct in6_addr));
        }
      p = nexthop_make (ifindex, &ipaddr, 0);
      list_add_node (l, p);
      list_delete_all (m);
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
          nexthop_delete (q);
        }
      list_delete_all (p->nexthops);
      if (p->next)
        next = p->next;
      else
        next = NULL;
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
            if (IN6_ARE_ADDR_EQUAL (&dest_id->prefix.prefix,
                                    &p->dest_id.prefix.prefix))
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
                     struct ospf6_lsa *origin,
                     struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r = rtentry_new();
  struct ospf6_nexthop *p;
  listnode n;
  char buf[256];

  r->dest_type = dest_type;
  memcpy (&r->dest_id, dest_id, sizeof (union dest_id));
  r->path_type = path_type;
  r->cost = cost;
  r->ls_origin = origin;

  r->nexthops = list_init ();
  for (n = listhead (nexthops); n; nextnode (n))
    {
      p = getdata (n);
      nexthop_lock (p);
      list_add_node (r->nexthops, p);
    }

  rtable_add (r, rtable);
  o6log.rtable ("installed %s in rtable",
                print_rtentry (r, buf, sizeof (buf)));
  return;
}

void rtable_uninstall (unsigned char dest_type, union dest_id *dest_id,
                       struct ospf6_rtable *rtable)
{
  struct ospf6_rtentry *r;
  listnode n;
  struct ospf6_nexthop *p;
  char buf[256];

  r = rtable_lookup (dest_type, dest_id, rtable->current_top);
  if (!r)
    {
      zvlog_warn ("No such route!");
      return;
    }

  o6log.rtable ("uninstall %s from rtable",
                print_rtentry (r, buf, sizeof (buf)));
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

static void
area_entry_install (struct ospf6_rtentry *r, struct ospf6 *ospf6)
{
  list l = list_init ();
  listnode n;
  struct intra_area_prefix_lsa *intra_prefix_lsa;
  struct ospf6_lsa *lsa;
  struct ospf6_prefix *prefix;
  int j;
  union dest_id dest_id;
  cost_t cost = 0;

  get_referencing_lsa (l, r->ls_origin);
  if (list_isempty (l))
    {
      o6log.rtable ("No reference to %s",
                    print_lsahdr (r->ls_origin->lsa_hdr));
      return;
    }

  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      intra_prefix_lsa = (struct intra_area_prefix_lsa *)(lsa->lsa_hdr + 1);
      o6log.rtable ("checking: %s", print_lsahdr (lsa->lsa_hdr));

      prefix = (struct ospf6_prefix *) (intra_prefix_lsa + 1);

      for (j = 0; j < ntohs (intra_prefix_lsa->intra_prefix_num); j++)
        {
          /* Should I check if this route already on the table? */

          if (r->dest_type == DTYPE_INTRA_ROUTER) /* Indicating router. */
            cost = r->cost + ntohs (prefix->o6p_prefix_metric);
          else if (r->dest_type == DTYPE_INTRA_LINK) /* network */
            cost = r->cost;
          else
            assert (0);

          dest_id.prefix.family = AF_INET6;
          dest_id.prefix.prefixlen = prefix->o6p_prefix_len;
          ospf6_prefix_in6_addr (prefix, &dest_id.prefix.prefix);
          rtable_install (DTYPE_PREFIX, &dest_id, cost, PTYPE_INTRA,
                          r->nexthops, lsa, &ospf6->rtable);
          prefix = OSPF6_NEXT_PREFIX (prefix);
        }
    }
  list_delete_all (l);
  return;
}

/* check prefixes of each entry in area, and install
   table in ospf top data structure */
static void
rtable_area_to_top (struct area *area)
{
  struct ospf6_rtentry *r;

  rtable_init (&area->ospf6->rtable); /* multi-area not yet */
  for (r = area->rtable.current_top; r; r = r->next)
    area_entry_install (r, area->ospf6);

  return;
}

/* XXX very stupid way */
static void
rtable_zebra_update (struct ospf6 *ospf6)
{
  struct ospf6_rtentry *r;

  for (r = ospf6->rtable.previous_top; r; r = r->next)
    {
      assert (r->dest_type == DTYPE_PREFIX);
      ospf6_zebra_delete (r);
    }

  for (r = ospf6->rtable.current_top; r; r = r->next)
    {
      assert (r->dest_type = DTYPE_PREFIX);
      ospf6_zebra_add (r);
    }

  return;
}

int
routing_table_calculation (struct thread *thread)
{
  struct area *area;

  area = (struct area *)THREAD_ARG (thread);
  assert (area);

  o6log.rtable ("routing table calculation for %s", area->str);

  area->route_calc = (struct thread *)NULL;
  rtable_area_to_top (area);
  rtable_zebra_update (area->ospf6);

  o6log.rtable ("routing table calculation for %s done", area->str);

  return 0;
}



char *
dtype_str (struct ospf6_rtentry *p, char *buf, int bufsize)
{
  char *ptr;

  switch (p->dest_type)
    {
      case DTYPE_PREFIX:
        inet_ntop (AF_INET6, &p->dest_id.prefix.prefix, buf, bufsize);
        ptr = index (buf, '\0');
        snprintf (ptr, bufsize - strlen (buf), "/%d",
                 p->dest_id.prefix.prefixlen);
        break;

      case DTYPE_ASBR:
        assert (0); /* not yet */

      case DTYPE_INTRA_ROUTER:
        inet_ntop (AF_INET, &p->dest_id.router_id, buf, bufsize);
        ptr = index (buf, '\0');
        snprintf (ptr, bufsize - strlen (buf), "(intra-router)");
        break;

      case DTYPE_INTRA_LINK:
        inet_ntop (AF_INET, &p->dest_id.network_id[0], buf, bufsize);
        ptr = index (buf, '\0');
        snprintf (ptr, bufsize - strlen (buf),
                  "[ifid %lu](intra-link)", p->dest_id.network_id[1]);
        break;

      default:
        assert (0);
    }
  return buf;
}

char *
ptype_str (struct ospf6_rtentry *p, char *buf, int bufsize)
{
  switch (p->path_type)
    {
      case PTYPE_INTRA:
        snprintf (buf, bufsize, "%s", "Intra");
        break;

      case PTYPE_INTER:
        snprintf (buf, bufsize, "%s", "Inter");
        break;

      case PTYPE_TYPE1_EXTERNAL:
        snprintf (buf, bufsize, "%s", "T1Ext");
        break;

      case PTYPE_TYPE2_EXTERNAL:
        snprintf (buf, bufsize, "%s", "T2Ext");
        break;

      default:
        snprintf (buf, bufsize, "%s", "Unknown");
        break;
    }
  return buf;
}

void
rtable_vty_entry (struct vty *vty, struct ospf6_rtentry *p)
{
  char destination[64], gateway[64];
  char path_type[16], netif[32], cost[32];
  listnode n;
  struct ospf6_nexthop *q;

  /* DestType */
  memset (destination, 0, sizeof (destination));
  dtype_str (p, destination, sizeof (destination));

  /* PathType */
  memset (path_type, 0, sizeof (path_type));
  ptype_str (p, path_type, sizeof (path_type));

  /* Cost */
  sprintf (cost, "%lu", p->cost);

  /* save root (myself) in area rtable */
  if (list_isempty (p->nexthops))
    vty_out (vty, "%-26s %-26s %-3s %5s %-5s\r\n",
             destination, "--", "--", "0", path_type);

  for (n = listhead (p->nexthops); n; nextnode (n))
    {
       q = getdata (n);
       if_indextoname (q->ifindex, netif);
       inet_ntop (AF_INET6, &q->ipaddr, gateway, sizeof (gateway));
       vty_out (vty, "%-26s %-26s %-3s %5s %-5s\r\n",
                destination, gateway, netif, cost, path_type);
    }

  return;
}

char *
print_rtentry (struct ospf6_rtentry *p, char *buf, int bufsize)
{
  int ptrsize;
  char *ptr, destination[64], gateway[32];
  char path_type[16], netif[32], cost[32];
  listnode n;
  struct ospf6_nexthop *q;

  /* DestType */
  memset (destination, 0, sizeof (destination));
  dtype_str (p, destination, sizeof (destination));

  /* PathType */
  memset (path_type, 0, sizeof (path_type));
  ptype_str (p, path_type, sizeof (path_type));

  /* Cost */
  sprintf (cost, "%lu", p->cost);

  snprintf (buf, bufsize, "[d:%s c:%s p:%s ",
            destination, cost, path_type);
  ptr = index (buf, '\0');
  ptrsize = bufsize - strlen (buf);

  /* save about root (myself) in area rtable */
  if (list_isempty (p->nexthops))
    {
      snprintf (ptr, ptrsize, "{g:-- i:--}]");
      return buf;
    }

  for (n = listhead (p->nexthops); n; nextnode (n))
    {
       if (ptrsize <= 2)
         break;
       q = getdata (n);
       if_indextoname (q->ifindex, netif);
       inet_ntop (AF_INET6, &q->ipaddr, gateway, sizeof (gateway));
       snprintf(ptr, ptrsize, "{g:%s i:%s}", gateway, netif);
       ptr = index (buf, '\0');
       ptrsize = bufsize - strlen (buf);
    }
  if (ptrsize >= 2)
    snprintf (ptr, ptrsize, "]");

  return buf;
}

