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
  o6log.spf (" vtx %s[%lu]", inet4str (W->vtx_id[0]), W->vtx_id[1]);
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
  v->vtx_nexthops = list_init ();
  v->vtx_distance = 0;
  v->vtx_path = list_init ();
  v->vtx_parent = list_init ();
  v->vtx_depth = 0;

  return v;
}

static int
vertex_free (struct vertex *v)
{

  list_delete_all (v->vtx_nexthops);
  list_delete_all (v->vtx_path);
  list_delete_all (v->vtx_parent);

  XFREE (MTYPE_OSPF6_ROUTE, v);
  return 0;
}

/* hold the intermediate results on area routing table */
static void
transit_vertex_rtable_install (struct vertex *v, struct area *area)
{
  unsigned char dtype;
  union dest_id did;

  if (IS_VTX_ROUTER_TYPE (v))
    {
      dtype = DTYPE_INTRA_ROUTER;
      did.router_id = v->vtx_id[0];
    }
  else if (IS_VTX_NETWORK_TYPE (v))
    {
      dtype = DTYPE_INTRA_LINK;
      did.network_id[0] = v->vtx_id[0];
      did.network_id[1] = ntohl (v->vtx_id[1]);
    }
  else
    {
      o6log.spf ("!Unkown vertex type");
      assert (0);
    }

  rtable_install (dtype, &did, v->vtx_distance, PTYPE_INTRA,
                  v->vtx_nexthops, v->vtx_lsa, &area->rtable);
  return;
}

static int
spf_install (struct vertex *v, struct area *area)
{
  listnode n;
  struct vertex *parent;

  o6log.spf ("SPF install, depth:%lu, distance:%lu",
             v->vtx_depth, v->vtx_distance);
  print_vertex (v);

  if (v->vtx_depth == 0)
    area->spftree.root = v;

  for (n = listhead (v->vtx_parent); n; nextnode (n))
    {
      parent = getdata (n);
      list_add_node (parent->vtx_path, v);
      nexthop_add_from_vertex (v, parent, v->vtx_nexthops);
    }

  list_add_node (area->spftree.searchlist[hash (v->vtx_id[0])]
                                         [hash (v->vtx_id[1])], v);
  list_add_node (area->spftree.depthlist [v->vtx_depth], v);

  transit_vertex_rtable_install (v, area);
  return 0;
}

static int
spf_init (struct area *area)
{
  int i, j;
  listnode n;
  struct vertex *v;

  rtable_init (&area->rtable);

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
  v->vtx_distance = 0;
  v->vtx_depth = 0;

  spf_install (v, area);

  return 0;
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
          o6log.spf ("can't find NetworkLSA of %s[%d]",
                     inet4str (currentlink->rlsd_neighbor_router_id),
                     ntohl (currentlink->rlsd_neighbor_interface_id));
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
          o6log.spf ("no link back to %s",
                     inet4str (w_lsa->lsh->lsh_advrtr));
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      list_add_node (W->vtx_parent, V);
      W->vtx_depth = V->vtx_depth + 1;

      currentlink++;
      return W;

    case LSDT_POINTTOPOINT:
      /* XXX multiple RouterLSA not yet */
      w_lsa = lsa_lookup (htons (LST_ROUTER_LSA), htonl (MY_ROUTER_LSA_ID),
                          currentlink->rlsd_neighbor_router_id,
                          lsa->area, lsa->ospf6_if);
      if (!w_lsa || !w_lsa->lsh || calc_lsa_age_external (w_lsa) == MAXAGE)
        {
          o6log.spf ("can't find RouterLSA of %s",
                     inet4str (currentlink->rlsd_neighbor_router_id));
          currentlink++;
          goto nextlink;
        }
      /* Examin if this LSA have link back to V */
      for (rlsd = (struct router_lsd *)
                    (((struct router_lsa *)(w_lsa->lsh + 1)) + 1);
           (char *)rlsd < (char *)w_lsa->lsh + ntohs (w_lsa->lsh->lsh_len);
           rlsd++)
        {
          /* XXX Should we check rlsd_neighbor_interface_id, too? */
          if (rlsd->rlsd_type == LSDT_POINTTOPOINT &&
              rlsd->rlsd_neighbor_router_id == lsa->lsh->lsh_advrtr)
            {
              linkback++;
              break;
            }
        }
      if (linkback == 0)
        {
          o6log.spf ("no link back to %s",
                     inet4str (lsa->lsh->lsh_advrtr));
          currentlink++;
          goto nextlink;
        }

      W = make_vertex(w_lsa);
      assert (W);
      W->vtx_distance = V->vtx_distance + ntohs (currentlink->rlsd_metric);
      list_add_node (W->vtx_parent, V);
      W->vtx_depth = V->vtx_depth + 1;

      currentlink++;
      return W;

    default:
      o6log.spf ("!unknown link type, stop calculation for area %s",
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
      o6log.spf ("can't find RouterLSA of %s",
                 inet4str (*currentlink));
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
      o6log.spf ("no link back to %s[%lu]",
                 inet4str (lsa->lsh->lsh_advrtr),
                 ntohl (lsa->lsh->lsh_id));
      currentlink++;
      goto nextlink_of_this_network;
    }

  W = make_vertex(w_lsa);
  assert (W);
  W->vtx_distance = V->vtx_distance + 0;
  list_add_node (W->vtx_parent, V);
  W->vtx_depth = V->vtx_depth + 1;

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

/* should be added to linklist.c */
void
list_add_list (list l, list m)
{
  listnode n;

  for (n = listhead (m); n; nextnode (n))
    list_add_node (l, n);

  return;
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

  o6log.spf ("Doing SPF Calculation for area %s", area->str);

  /* (1) */
  spf_init (area);
  candidatelist = list_init ();
  V = area->spftree.root;             /* Myself */

  /* (2) */
  while (1)
    {
      for (W = linktovertex (V); W; W = linktovertex (V))     /* (b) */
        {
          o6log.spf ("checking link to...");
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
              o6log.spf ("already on SPF tree");
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
                  if (p->vtx_distance < W->vtx_distance)
                    {
                      vertex_free (W);
                      goto not_candidate;
                    }
                  if (p->vtx_distance > W->vtx_distance)
                    {
                      list_delete_by_val (candidatelist, p);
                      break;
                    }
                  if (p->vtx_distance == W->vtx_distance)
                    {
                      /* This is ECMP */
                      list_add_list (p->vtx_parent, W->vtx_parent);
                      vertex_free (W);
                      goto not_candidate;
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
          else if (p->vtx_distance == closest->vtx_distance &&
                   IS_VTX_ROUTER_TYPE (closest))
            closest = p;
        }
      list_delete_by_val (candidatelist, closest);
      spf_install (closest, area);
      V = closest;
    }

  assert (listcount (candidatelist) == 0);
  list_free (candidatelist);

  o6log.spf ("SPF Calculation for area %s done", area->str);
  return 0;
}

list
get_prefix_lsa_of_vertex (struct vertex *v, struct area *area)
{
  list retlist = NULL;
  struct lsa_internal *lsi;

  switch (ntohs (v->vtx_lsa->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      retlist = lsa_lookup_by_advrtr (htons (LST_INTRA_AREA_PREFIX_LSA),
                                      v->vtx_lsa->lsh->lsh_advrtr, area);
      break;
    case LST_NETWORK_LSA:
      lsi = lsa_lookup (htons (LST_INTRA_AREA_PREFIX_LSA),
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

