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

void
print_vertex (struct vertex *W)
{
  ospf6_debug ("SPFCALC:    VertexID-1 = %s\n", inet4str (W->vtx_id[0]));
  ospf6_debug ("SPFCALC:    VertexID-2 = %s\n", inet4str (W->vtx_id[1]));
}

struct vertex *
make_vertex (struct lsa_internal *lsa)
{
  struct vertex *v;

  assert (lsa && lsa->lsh);
  v = (struct vertex *)XMALLOC (MTYPE_OSPF_ROUTE, sizeof (struct vertex));

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

int
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

  XFREE (MTYPE_OSPF_ROUTE, v);
  return 0;
}

int
spf_install (struct vertex *v, struct area *area)
{
  if (v->vtx_parent == (struct vertex *)NULL)
    {
      ospf6_debug ("SPFCALC: Installing Root...\n");
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

int
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

  if (area->rt_table)
    XFREE (MTYPE_OSPF_ROUTE, area->rt_table);
  area->rt_table = (struct routing_table_entry *)
    XMALLOC (MTYPE_OSPF_ROUTE, ROUTING_TABLE_SIZE);
  area->tablesize = 0;
  memset (area->rt_table, 0, ROUTING_TABLE_SIZE);

  return 0;
}

struct nexthop_info *
make_nexthop (unsigned long ifindex, unsigned long id_one,
              unsigned long id_two)
{
  struct nexthop_info *nexthopinfo;
  struct lsa_internal *lsi = (struct lsa_internal *)NULL;
  struct link_lsa *linklsa;
  listnode n;
  char ifname[16];
  struct ospf6_if *ospf6_if;

  nexthopinfo = (struct nexthop_info *)XMALLOC (MTYPE_OSPF_ROUTE,
                                                sizeof (struct nexthop_info));
  nexthopinfo->ifindex = ifindex;
  nexthopinfo->nexthop[0] = id_one;
  nexthopinfo->nexthop[1] = id_two;

  if_indextoname (ntohl(ifindex), ifname);
  ospf6_if = ospf6_if_lookup (ifname);

  if (id_one && !id_two)        /* Router */
    {
      for (n = listhead (ospf6_if->linklocal_lsa); n; nextnode (n))
        {
          lsi = (struct lsa_internal *) getdata (n);
          if (lsi->lsh->lsh_advrtr == id_one)
          break;
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

struct vertex *
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
          make_nexthop (currentlink->rlsd_interface_id, 0, 0));
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
                         make_nexthop (currentlink->rlsd_interface_id, 0, 0));
          /* No Nexthop Required */
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
      zlog (NULL, LOG_WARNING,"WARN: Some thing has gone wrong in SPFCALC"
                  " for Area[%s], reset",
                  inet4str (V->vtx_lsa->area->area_id));
      lsa = (struct lsa_internal *)NULL;
      return (struct vertex *)NULL;
    }
}

struct vertex *
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
  if (W->vtx_depth == 1) /* Not Happen!? */
    {
      list_add_node (W->vtx_nexthops, make_nexthop
                     (((struct nexthop_info *) getdata
                     (listhead (V->vtx_nexthops)))->ifindex,
                     W->vtx_id[0], W->vtx_id[1]));
    }
  else if (W->vtx_depth == 2)
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

  ospf6_info ("SPFCALC: Doing SPF Calculation ...\n");

  /* (1) */
  spf_init (area);
  candidatelist = list_init ();
  V = area->spftree.root;             /* Myself */

  /* (2) */
  while (1)
    {
      for (W = linktovertex (V); W; W = linktovertex (V))     /* (b) */
        {
          ospf6_debug ("SPFCALC: Current Candidate:\n");
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
              ospf6_debug ("SPFCALC:  Already on the SPF Tree\n");
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
      ospf6_debug ("SPFCALC: Installing ...\n");
      print_vertex (closest);
      spf_install (closest, area);
      V = closest;
    }

  assert (listcount (candidatelist) == 0);
  list_free (candidatelist);

  ospf6_debug ("SPFCALC: SPF Calculation Done!!\n");
  return 0;
}

int
routing_table_calculation (struct thread *thread)
{
  int i, j;
  listnode n;
  struct vertex *v;
  struct lsa_internal *lsi;
  struct intra_area_prefix_lsa *intra_prefix_lsa;
  struct ospf6_prefix *prefix;
  struct nexthop_info *nh;
  struct area *area;

  area = (struct area *)THREAD_ARG (thread);
  assert (area);

  area->route_calc = (struct thread *)NULL;

  for (i = 0; i < MAXDEPTH; i++)
    {
      ospf6_debug ("ROUTECALC: depth[%d]\n", i);
      for (n = listhead (area->spftree.depthlist[i]); n; nextnode (n))
        {
          v = (struct vertex *) getdata (n);
          ospf6_debug ("ROUTECALC:    V->lsa = [%s]\n",
                       print_lsahdr (v->vtx_lsa->lsh));
          switch (ntohs (v->vtx_lsa->lsh->lsh_type))
            {
            case LST_NETWORK_LSA:
              lsi = lsa_lookup (ntohs (LST_INTRA_AREA_PREFIX_LSA),
                                v->vtx_lsa->lsh->lsh_id,
                                v->vtx_lsa->lsh->lsh_advrtr,
                                area, (struct ospf6_if *)NULL);
              if (!lsi)
                {
                  ospf6_debug ("SPFCALC: Intra-Area-Prefix-LSA Not"
                               " Found for %s\n",
                               print_lsahdr (v->vtx_lsa->lsh));
                  break;
                }
              intra_prefix_lsa =
                  (struct intra_area_prefix_lsa *)(lsi->lsh + 1);
              /* XXX Back pointer check */
              prefix = (struct ospf6_prefix *) (intra_prefix_lsa + 1);
              /* XXX */
              if (listcount (v->vtx_nexthops))
                nh = (struct nexthop_info *)
                    (getdata (listhead (v->vtx_nexthops)));
              else
                nh = (struct nexthop_info *)NULL;
              for (j = 0; j < ntohs (intra_prefix_lsa->intra_prefix_num); j++)
                {
                  if (area->tablesize >= MAX_ENTRY)
                    {
                      zlog (NULL, LOG_WARNING,"WARN: Routing Table MAX Limit!!");
                      return 0;
                    }

                  /* Install Internal Routing Table */
                  memcpy (&area->rt_table[area->tablesize].destination,
                          (prefix + 1),
                          OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len));
                  area->rt_table[area->tablesize].cost = v->vtx_distance;
                  area->rt_table[area->tablesize].prefixlength
                      = prefix->o6p_prefix_len;
                  if (nh)
                    {
                      area->rt_table[area->tablesize].ifindex
                          = ntohl (nh->ifindex);
                      memcpy (&area->rt_table[area->tablesize].next_hop,
                              &nh->nexthop_addr,
                              sizeof (struct in6_addr));
                    }
                  area->tablesize++;
                  prefix = OSPF6_NEXT_PREFIX (prefix);
                }
              break;
            case LST_ROUTER_LSA:
              break;
            default:
              zlog (NULL, LOG_ERR, "BUG: spf_calculation ()");
            }
        }
    }
  return 0;
}

