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

static void
print_vertex (struct vertex *W)
{
  log_spf ("    VertexID-1 = %s", inet4str (W->vtx_id[0]));
  log_spf ("    VertexID-2 = %s", inet4str (W->vtx_id[1]));
}

static struct vertex *
make_vertex (struct lsa_internal *lsa)
{
  struct vertex *v;

  assert (lsa && lsa->lsh);
  v = (struct vertex *)XMALLOC (MTYPE_OSPF6_ROUTE, sizeof (struct vertex));

  switch (ntohs (lsa->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      v->vtx_id[0] = lsa->lsh->lsh_advrtr;
      v->vtx_id[1] = 0;
      break;
    case LST_NETWORK_LSA:
      v->vtx_id[0] = lsa->lsh->lsh_advrtr;
      v->vtx_id[1] = lsa->lsh->lsh_id;
      break;
    default:
      return (struct vertex *)NULL;
    }
  v->vtx_lsa = lsa;
  v->vtx_nexthops = list_init();
  v->vtx_distance = 0;
  v->vtx_path = list_init();
  v->vtx_parent = (struct vertex *)NULL;
  v->vtx_depth = 0;

  return v;
}

static int
vertex_free (struct vertex *v)
{
  while (listcount (v->vtx_nexthops))
    {
      list_delete_node (v->vtx_nexthops, listhead (v->vtx_nexthops));
    }
  list_free (v->vtx_nexthops);

  while (listcount (v->vtx_path))
    {
      list_delete_node (v->vtx_path, listhead (v->vtx_path));
    }
  list_free (v->vtx_path);

  XFREE (MTYPE_OSPF6_ROUTE, v);
  return 0;
}

static int
spf_install (struct vertex *v, struct area *area)
{
  if (v->vtx_parent == (struct vertex *)NULL)
    {
      log_spf ("Installing Root...");
      print_vertex (v);
      area->spftree.root = v;
    }
  else
    {
      list_add_node (v->vtx_parent->vtx_path, v);
    }

  list_add_node (area->spftree.searchlist[hash (v->vtx_id[0])]
                                         [hash (v->vtx_id[1])], v);
  list_add_node (area->spftree.depthlist [v->vtx_depth], v);

  return 0;
}

static int
spf_init (struct area *area)
{
  int i, j;
  listnode n;
  struct vertex *v;

  /* Clear search list */
  for (i = 0; i < HASHVAL; i++)
    {
      for (j = 0; j < HASHVAL; j++)
        {
          if (area->spftree.searchlist[i][j] == NULL)
            area->spftree.searchlist[i][j] = list_init();

          while (listcount (area->spftree.searchlist[i][j]))
            {
              n = listhead (area->spftree.searchlist[i][j]);
              v = (struct vertex *)getdata (n);
              vertex_free (v);
              list_delete_node (area->spftree.searchlist[i][j], n);
            }
        }
    }

  /* Clear depth list */
  for (i = 0; i < MAXDEPTH; i++)
    {
      if (area->spftree.depthlist[i] == NULL)
        area->spftree.depthlist[i] = list_init();

      while (listcount (area->spftree.depthlist[i]))
        {
          list_delete_node (area->spftree.depthlist[i],
          listhead (area->spftree.depthlist[i]));
        }
    }

  /* Install myself as root */
  v = make_vertex (lsa_lookup (htons (LST_ROUTER_LSA),
                               htonl (MY_ROUTER_LSA_ID),
                               area->ospf6->router_id, area,
                               (struct ospf6_if *)NULL));
  v->vtx_parent = (struct vertex *)NULL;
  v->vtx_distance = 0;
  v->vtx_depth = 0;
  spf_install (v, area);

  rtable_init (&area->rtable);
  return 0;
}

static void
free_nexthop (struct nexthop_info *nh)
{
  XFREE (MTYPE_OSPF6_ROUTE, nh);
}

static struct nexthop_info *
make_nexthop (unsigned long ifindex, unsigned long id_one,
              unsigned long id_two)
{
  struct nexthop_info *nexthopinfo;
  struct lsa_internal *lsi = (struct lsa_internal *)NULL;
  struct link_lsa *linklsa;
  listnode n;
  char ifname[16];
  struct ospf6_if *ospf6_if;

  nexthopinfo = (struct nexthop_info *)XMALLOC (MTYPE_OSPF6_ROUTE,
                                                sizeof (struct nexthop_info));
  nexthopinfo->ifindex = ifindex;
  nexthopinfo->nexthop[0] = id_one;
  nexthopinfo->nexthop[1] = id_two;

  if_indextoname (ifindex, ifname);
  ospf6_if = ospf6_if_lookup (ifname);
  if (!ospf6_if)
    {
      zvlog_err ("can't find ospf6_if for ifid %lu, name %s",
                 ifindex, ifname);
    }

  if (id_one && !id_two)        /* Router */
    {
      for (n = listhead (ospf6_if->linklocal_lsa); n; nextnode (n))
        {
          lsi = (struct lsa_internal *) getdata (n);
          if (lsi->lsh->lsh_advrtr == id_one)
            break;
        }
      if (!lsi || !lsi->lsh)
        {
          zvlog_err ("Can't find Link-LSA for %s", inet4str (id_one));
          return NULL;
        }
      linklsa = (struct link_lsa *)(lsi->lsh + 1);
      memcpy (&nexthopinfo->nexthop_addr, &linklsa->llsa_linklocal,
              sizeof (struct in6_addr));
    }
  else
    {
      memset (&nexthopinfo->nexthop_addr, 0, sizeof (struct in6_addr ));
    }

  return nexthopinfo;
}

static struct vertex *
router_link (struct vertex *V)
{
  static struct router_lsd *currentlink;
  static struct lsa_internal *lsa;

  struct lsa_internal *w_lsa;
  void *end;
  rtr_id_t *attachedrtr;
  struct router_lsd *rlsd;
  int linkback;
  struct vertex *W;
  listnode n;

  assert (V);
  if (V->vtx_lsa != lsa)
    {
      lsa = V->vtx_lsa;
      currentlink = (struct router_lsd *)
                      ((struct router_lsa *)(lsa->lsh + 1) + 1);
    }
  end = (char *)lsa->lsh + ntohs (lsa->lsh->lsh_len);

 nextlink:

  if (currentlink == end)
    {
      lsa = (struct lsa_internal *)NULL;
      return (struct vertex *)NULL;
    }

  linkback = 0;
  switch (currentlink->rlsd_type)
    {
    case LSDT_TRANSIT_NETWORK:
      w_lsa = lsa_lookup (htons (LST_NETWORK_LSA),
                          currentlink->rlsd_neighbor_interface_id,
                          currentlink->rlsd_neighbor_router_id,
                          lsa->area, lsa->ospf6_if);
      if (!w_lsa || !w_lsa->lsh || calc_lsa_age_external (w_lsa) == MAXAGE)
        {
          currentlink++;
          goto nextlink;
        }

      /* Examin if this LSA have link back to V */
      for (attachedrtr = (rtr_id_t *)
                           (((struct network_lsa *)(w_lsa->lsh + 1)) + 1);
           (char *)attachedrtr < (char *)w_lsa->lsh +
                           ntohs (w_lsa->lsh->lsh_len);
           attachedrtr++)
        {
          if (*attachedrtr == lsa->lsh->lsh_advrtr)
          linkback++;
        }
      if (linkback == 0)
        {
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      W->vtx_parent = V;
      W->vtx_depth = V->vtx_depth + 1;
      if (W->vtx_depth == 1)
        {
          list_add_node (W->vtx_nexthops,
                         make_nexthop (ntohl (currentlink->rlsd_interface_id),
                                       0, 0));
        }
      else
        {
          for (n = listhead (V->vtx_nexthops);
               n;
               nextnode (n))
            {
              list_add_node (W->vtx_nexthops, getdata (n));
            }
        }

      currentlink++;
      return W;

    case LSDT_POINTTOPOINT:
      w_lsa = lsa_lookup (htons (LST_ROUTER_LSA), htonl (MY_ROUTER_LSA_ID),
                          currentlink->rlsd_neighbor_router_id,
                          lsa->area, lsa->ospf6_if);
      if (!w_lsa || !w_lsa->lsh || calc_lsa_age_external (w_lsa) == MAXAGE)
        {
          currentlink++;
          goto nextlink;
        }
      /* Examin if this LSA have link back to V */
      for (rlsd = (struct router_lsd *)
                    (((struct router_lsa *)(w_lsa->lsh + 1)) + 1);
           (char *)rlsd < (char *)w_lsa->lsh + ntohs (w_lsa->lsh->lsh_len);
           rlsd++)
        {
          /* XXX Should We check rlsd_neighbor_interface_id, too? */
          if (rlsd->rlsd_type == LSDT_POINTTOPOINT &&
              rlsd->rlsd_neighbor_router_id == lsa->lsh->lsh_advrtr)
            {
              linkback++;
              break;
            }
        }
      if (linkback == 0)
        {
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      W->vtx_parent = V;
      W->vtx_depth = V->vtx_depth + 1;
      if (W->vtx_depth == 1)
        {
          list_add_node (W->vtx_nexthops,
                         make_nexthop (ntohl (currentlink->rlsd_interface_id),
                                       W->vtx_id[0], W->vtx_id[1]));
        }
      else
        {
          for (n = listhead (V->vtx_nexthops);
               n;
               nextnode (n))
            {
              list_add_node (W->vtx_nexthops, getdata (n));
            }
        }
      currentlink++;
      return W;

    default:
      zvlog_warn ("Some thing has gone wrong in SPF calculation"
                  " for Area[%s], reset",
                  inet4str (V->vtx_lsa->area->area_id));
      lsa = (struct lsa_internal *)NULL;
      return (struct vertex *)NULL;
    }
}

static struct vertex *
network_link (struct vertex *V)
{
  static rtr_id_t *currentlink;
  static struct lsa_internal *lsa;

  struct lsa_internal *w_lsa;
  void *end;
  struct router_lsd *rlsd;
  int linkback;
  struct vertex *W;
  listnode n;

  assert (V);
  if (V->vtx_lsa != lsa)
    {
      lsa = V->vtx_lsa;
      currentlink = (rtr_id_t *)((struct network_lsa *)(lsa->lsh + 1) + 1);
    }
  end = (char *)lsa->lsh + ntohs (lsa->lsh->lsh_len);

 nextlink_of_this_network:

  if (currentlink == end)
    {
      lsa = (struct lsa_internal *)NULL;
      return (struct vertex *)NULL;
    }

  linkback = 0;
  w_lsa = lsa_lookup (htons (LST_ROUTER_LSA), htonl (MY_ROUTER_LSA_ID),
                      *currentlink, lsa->area, lsa->ospf6_if);
  if (!w_lsa || !w_lsa->lsh || calc_lsa_age_external (w_lsa) == MAXAGE)
    {
      currentlink++;
      goto nextlink_of_this_network;
    }
  /* Examin if this LSA have link back to V */
  for (rlsd = (struct router_lsd *)
                (((struct router_lsa *)(w_lsa->lsh + 1)) + 1);
       (char *)rlsd < (char *)w_lsa->lsh + ntohs (w_lsa->lsh->lsh_len);
       rlsd++)
    {
      if (rlsd->rlsd_type == LSDT_TRANSIT_NETWORK &&
          rlsd->rlsd_neighbor_router_id == lsa->lsh->lsh_advrtr &&
          rlsd->rlsd_neighbor_interface_id == lsa->lsh->lsh_id)
        {
          linkback++;
          break;
        }
    }
  if (linkback == 0)
    {
      currentlink++;
      goto nextlink_of_this_network;
    }

  W = make_vertex(w_lsa);
  assert (W);
  W->vtx_distance = V->vtx_distance + 0;
  W->vtx_parent = V;
  W->vtx_depth = V->vtx_depth + 1;
  if (W->vtx_depth == 1 /* Not Happen!? */
      || W->vtx_depth == 2)
    {
      list_add_node (W->vtx_nexthops, make_nexthop
                     (((struct nexthop_info *) getdata
                     (listhead (V->vtx_nexthops)))->ifindex,
                     W->vtx_id[0], W->vtx_id[1]));
    }
  else
    {
      for (n = listhead (V->vtx_nexthops);
           n;
           nextnode (n))
        {
          list_add_node (W->vtx_nexthops, getdata (n));
        }
    }
  currentlink++;
  return W;
}

struct vertex *
linktovertex (struct vertex *V)
{
  assert (V);
  switch (ntohs (V->vtx_lsa->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      return router_link (V);
    case LST_NETWORK_LSA:
      return network_link (V);
    default:
      break;
    }
  return (struct vertex *)NULL;
}

/* RFC2328 section 16.1 */
int
spf_calculation (struct thread *thread)
{
  listnode n;
  struct area *area;

  list candidatelist;
  struct vertex *V, *W, *p, *closest;
  int already;

  area = (struct area *)THREAD_ARG (thread);
  assert (area);

  area->spf_calc = (struct thread *)NULL;

  /* Commented out due to compilation error. */
  zvlog_info ("Doing SPF Calculation for area %s", area->str);

  /* (1) */
  spf_init (area);
  candidatelist = list_init ();
  V = area->spftree.root;             /* Myself */

  /* (2) */
  while (1)
    {
      for (W = linktovertex (V); W; W = linktovertex (V))     /* (b) */
        {
          log_spf ("Current Candidate:");
          print_vertex (W);

          already = 0;
          /* (c) */
          for (n = listhead (area->spftree.searchlist
                             [hash(W->vtx_id[0])][hash(W->vtx_id[1])]);
               n;
               nextnode (n))
            {
              p = getdata (n);
              if (p->vtx_id[0] == W->vtx_id[0] &&
                  p->vtx_id[1] == W->vtx_id[1])
                already++;
            }
          if (already)
            {
              log_spf ("Already on the SPF Tree");
              vertex_free (W);
              continue;
            }

          /* (d) */
          for (n = listhead (candidatelist);
               n;
               nextnode (n))
            {
              p = getdata (n);
              if (p->vtx_id[0] == W->vtx_id[0] &&
                  p->vtx_id[1] == W->vtx_id[1])
                {
                  if (p->vtx_distance <= W->vtx_distance)
                    goto not_candidate;
                  if (p->vtx_distance > W->vtx_distance)
                    {
                      list_delete_by_val (candidatelist, p);
                      break;
                    }
                }
            }
          list_add_node (candidatelist, W);

        not_candidate:
        }

      /* (3) */
      if (listcount (candidatelist) == 0)
        break;

      closest = (struct vertex *)NULL;
      for (n = listhead (candidatelist);
           n;
           nextnode (n))
        {
          p = getdata (n);
          if (!closest || p->vtx_distance < closest->vtx_distance)
            closest = p;
        }
      list_delete_by_val (candidatelist, closest);
      log_spf ("Installing ...");
      print_vertex (closest);
      spf_install (closest, area);
      V = closest;
    }

  assert (listcount (candidatelist) == 0);
  list_free (candidatelist);

  zvlog_info ("SPF Calculation Done for area %s", area->str);
  return 0;
}

void
route_install_internal (struct ospf6_prefix *dst, cost_t cost,
                        struct in6_addr *nexthop, unsigned long ifindex,
                        struct area *area)
{
#if 0
  char str[64];

  /* Install Internal Routing Table */
  memcpy (&area->rt_table[area->tablesize].destination,
          (dst + 1),
          OSPF6_PREFIX_SPACE (dst->o6p_prefix_len));
  inet_ntop (AF_INET6, &area->rt_table[area->tablesize].destination,
             str, sizeof (str));
  zvlog_debug ("Installed %s in internal table", str);
  area->rt_table[area->tablesize].cost = cost;
  area->rt_table[area->tablesize].prefixlength
    = dst->o6p_prefix_len;

  zvlog_debug ("ifindex: %lu", ifindex);
  area->rt_table[area->tablesize].ifindex
    = ifindex;
  if (nexthop)
    memcpy (&area->rt_table[area->tablesize].next_hop,
            nexthop, sizeof (struct in6_addr));
  else
    {
      char str[64];
      inet_ntop (AF_INET6, &area->rt_table[area->tablesize].destination,
                 str, sizeof (str));
      zvlog_err ("nexthop not found for destination %s", str);
      memset (&area->rt_table[area->tablesize].next_hop, 0,
              sizeof (struct in6_addr));
    }
  area->tablesize++;
#endif
  return;
}

list
get_prefix_lsa_of_vertex (struct vertex *v, struct area *area)
{
  list retlist = NULL;
  struct lsa_internal *lsi;

  switch (ntohs (v->vtx_lsa->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      retlist = lsa_lookup_by_advrtr (ntohs (LST_INTRA_AREA_PREFIX_LSA),
                                      v->vtx_lsa->lsh->lsh_advrtr, area);
      break;
    case LST_NETWORK_LSA:
      lsi = lsa_lookup (ntohs (LST_INTRA_AREA_PREFIX_LSA),
                        v->vtx_lsa->lsh->lsh_id,
                        v->vtx_lsa->lsh->lsh_advrtr,
                        area, (struct ospf6_if *)NULL);
      if (lsi)
        {
          retlist = list_init ();
          list_add_node (retlist, lsi);
        }
      break;
    default:
      assert (0);
    }

  return retlist;
}

void
add_route_internal_table (struct vertex *v, struct area *area)
{
#if 0
  list lsalist = NULL;
  listnode n;
  struct intra_area_prefix_lsa *intra_prefix_lsa;
  struct lsa_internal *lsi;
  struct ospf6_prefix *prefix;
  struct nexthop_info *nhinfo;
  int j;
  cost_t cost;

  zvlog_debug ("ROUTECALC:    V->lsa = [%s]",
               print_lsahdr (v->vtx_lsa->lsh));

  lsalist = get_prefix_lsa_of_vertex (v, area);
  if (!lsalist)
    {
      zvlog_debug ("ROUTECALC: Intra-Area-Prefix-LSA Not"
                   " Found for %s",
                   print_lsahdr (v->vtx_lsa->lsh));
      return;
    }

  for (n = listhead (lsalist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      intra_prefix_lsa = (struct intra_area_prefix_lsa *)(lsi->lsh + 1);
      zvlog_debug ("ROUTECALC:    Prefix-LSA: %s",
                   print_lsahdr (lsi->lsh));

      /* Back pointer check */
      if (intra_prefix_lsa->intra_prefix_refer_lstype !=
          v->vtx_lsa->lsh->lsh_type
          || intra_prefix_lsa->intra_prefix_refer_lsid !=
          v->vtx_lsa->lsh->lsh_id
          || intra_prefix_lsa->intra_prefix_refer_advrtr !=
          v->vtx_lsa->lsh->lsh_advrtr)
        {
          struct lsa_hdr tmplsh;
          tmplsh.lsh_type = intra_prefix_lsa->intra_prefix_refer_lstype;
          tmplsh.lsh_id = intra_prefix_lsa->intra_prefix_refer_lsid;
          tmplsh.lsh_advrtr = intra_prefix_lsa->intra_prefix_refer_advrtr;
          zvlog_debug ("ROUTECALC:    no back pointer(%s)",
                       print_lsahdr (&tmplsh));
          continue;
        }

      prefix = (struct ospf6_prefix *) (intra_prefix_lsa + 1);

      /* nexthop */
      if (v->vtx_depth != 0)
        {
          assert (!list_isempty (v->vtx_nexthops));
          /* XXX ECMP not yet */
          nhinfo =
            (struct nexthop_info *) getdata (listhead (v->vtx_nexthops));
        }
      else
        {
          /* This vertex is root, use LS-ID. I can't find any
             other way to calculate route which is in 
             Intra-Area-Prefix-LSA of myself */
          nhinfo = make_nexthop (ntohl (lsi->lsh->lsh_id), 0, 0);
        }

      for (j = 0; j < ntohs (intra_prefix_lsa->intra_prefix_num); j++)
        {
          if (area->tablesize >= MAX_ENTRY)
            {
              zvlog_warn ("Routing Table MAX Limit!!");
              return;
            }

          if (rtable_lookup (XXX))
            {
              zvlog_debug ("ROUTECALC: already installed");
              continue;
            }

          if (v->vtx_id[1] == 0) /* Indicating router. */
            cost = v->vtx_distance + ntohs (prefix->o6p_prefix_metric);
          else                   /* network */
            cost = v->vtx_distance;
          route_install_internal (prefix, cost,
                                  &nhinfo->nexthop_addr, nhinfo->ifindex,
                                  area);
          prefix = OSPF6_NEXT_PREFIX (prefix);
        }
    }

  list_delete_all (lsalist);
#endif
  return;
}

int
routing_table_calculation (struct thread *thread)
{
  int i;
  listnode n;
  struct vertex *v;
  struct area *area;

  area = (struct area *)THREAD_ARG (thread);
  assert (area);

  area->route_calc = (struct thread *)NULL;

  for (i = 0; i < MAXDEPTH; i++)
    {
      zvlog_debug ("ROUTECALC: depth[%d]", i);
      if (list_isempty (area->spftree.depthlist[i]))
        break;
      for (n = listhead (area->spftree.depthlist[i]); n; nextnode (n))
        {
          v = (struct vertex *) getdata (n);
          add_route_internal_table (v, area);
        }
    }

  install_route (area);
  return 0;
}

#define INSTALL     1
#define NOT_INSTALL -1
#define DELETE      0
int install_route (struct area *area)
{
#if 0
  int i, j, remain;
  struct routing_table_entry *current;
  struct prefix_ipv6 p;
  char strbuf[64];

  if (!area->ospf6->isinstall)
    return 0;

  /* Initialize */
  for (i = 0; i < area->tablesize; i++)
    area->rt_table[i].flag = DELETE;

  for (i = 0; i < area->tablesize; i++)
    {
      current = &area->rt_table[i];
      remain = 0;
      for (j = 0; j < area->tablesize_prev; j++)
        {
          if (!memcmp (current, &area->rt_table[j],
                       sizeof (struct routing_table_entry)))
            {
              current->flag = NOT_INSTALL;
              remain++;
              break;
            }
        }
      if (remain)
        continue;
      else
        current->flag = INSTALL;
    }

  p.family = AF_INET6;
  for (i = 0; i < area->tablesize; i++)
    {
      current = &area->rt_table[i];
      p.prefixlen = current->prefixlength;
      memcpy (&p.prefix, &current->destination, sizeof (struct in6_addr));

      switch (current->flag)
        {
        case INSTALL:
          zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_OSPF6, &p,
                          &current->next_hop, current->ifindex);
          zvlog_debug ("ROUTECALC: %s installed",
                       inet_ntop (AF_INET6, &p.prefix, strbuf,
                                  sizeof (strbuf)));
          break;
        case NOT_INSTALL:
          break;
        case DELETE:
          zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_OSPF6, &p,
                             &current->next_hop, current->ifindex);
          zvlog_debug ("ROUTECALC: %s deleted",
                       inet_ntop (AF_INET6, &p.prefix, strbuf,
                                  sizeof (strbuf)));
        default:
        }
    }

#endif
  return 0;
}

int noinstall_route (struct area *area)
{
#if 0
  int i;
  struct routing_table_entry *current;
  struct prefix_ipv6 p;

  assert (area->ospf6->isinstall == NOINSTALL);

  p.family = AF_INET6;
  for (i = 0; i < area->tablesize; i++)
    {
      current = &area->rt_table[i];
      p.prefixlen = current->prefixlength;
      memcpy (&p.prefix, &current->destination, sizeof (struct in6_addr));
      zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_OSPF6, &p,
                         &current->next_hop, current->ifindex);
      zvlog_debug ("ROUTECALC: %s deleted",
                   inet_ntop (AF_INET6, &p.prefix, strbuf,
                              sizeof (strbuf)));
    }

  XFREE (MTYPE_OSPF6_ROUTE, area->rt_table_prev);
  area->tablesize_prev = 0;
#endif
  return 0;
}

