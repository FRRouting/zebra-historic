/*
 * OSPFv3 Redistribute
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

#include <zebra.h>


#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "vty.h"
#include "memory.h"
#include "log.h"

#include "ospf6_top.h"
#include "ospf6_redistribute.h"
#include "ospf6_dump.h"

/* xxx */
extern struct ospf6 *ospf6;

u_int32_t
ospf6_redistribute_ls_id_lookup (int type, int ifindex,
                                 struct prefix_ipv6 *p, struct ospf6 *o6)
{
  struct route_node *rn;
  list l;
  listnode n;
  struct ospf6_redistribute_info *info;

  rn = route_node_lookup (o6->redistribute_map, (struct prefix *) p);
  if (! rn)
    return 0;

  l = (list) rn->info;
  if (! l)
    return 0;

  for (n = listhead (l); n; nextnode (n))
    {
      info = (struct ospf6_redistribute_info *) getdata (n);
      if (info->type == type && info->ifindex == ifindex)
        return info->ls_id;
    }

  return 0;
}

u_int32_t
ospf6_redistribute_ls_id_new (int type, int ifindex,
                              struct prefix_ipv6 *p, struct ospf6 *o6)
{
  struct route_node *rn;
  list l;
  struct ospf6_redistribute_info *info;

  rn = route_node_get (o6->redistribute_map, (struct prefix *) p);

  l = (list) rn->info;
  if (! l)
    {
      l = list_init ();
      rn->info = l;
    }

  info = (struct ospf6_redistribute_info *)
    XMALLOC (MTYPE_OSPF6_OTHER, sizeof (struct ospf6_redistribute_info));

  o6->ase_ls_id ++;

  info->type = type;
  info->ifindex = ifindex;
  info->ls_id = o6->ase_ls_id;

  list_add_node (l, info);

  return info->ls_id;
}

void
ospf6_redistribute_ls_id_free (u_int32_t ls_id, int type, int ifindex,
                               struct prefix_ipv6 *p, struct ospf6 *o6)
{
  struct route_node *rn;
  list l;
  listnode n;
  struct ospf6_redistribute_info *info;
  struct ospf6_redistribute_info *delete;

  rn = route_node_lookup (o6->redistribute_map, (struct prefix *) p);
  if (! rn)
    return;

  l = (list) rn->info;
  if (! l)
    return;

  delete = (struct ospf6_redistribute_info *) NULL;
  for (n = listhead (l); n; nextnode (n))
    {
      info = (struct ospf6_redistribute_info *) getdata (n);
      if (info->ls_id == ls_id && info->type == type &&
          info->ifindex == ifindex)
        {
          delete = info;
          break;
        }
    }

  if (! delete)
    return;

  list_delete_by_val (l, delete);
  XFREE (MTYPE_OSPF6_OTHER, delete);
}

void
ospf6_redistribute_route_add (int type, int ifindex, struct prefix_ipv6 *p)
{
  char buf[128];
  struct ospf6_lsa *lsa = NULL;
  u_int32_t ls_id;

  /* log */
  if (IS_OSPF6_DUMP_ROUTE)
    {
      zlog_info ("Redistribute add: type:%d index:%d %s/%d", type, ifindex,
                 inet_ntop (AF_INET6, &p->prefix, buf, sizeof (buf)),
                 p->prefixlen);
    }

  /* XXX */
  if (type == ZEBRA_ROUTE_CONNECT)
    {
      ospf6_redist_connected_route_add (type, ifindex, p);
      return;
    }

  ls_id = ospf6_redistribute_ls_id_lookup (type, ifindex, p, ospf6);
  if (! ls_id)
    ls_id = ospf6_redistribute_ls_id_new (type, ifindex, p, ospf6);

  lsa = ospf6_lsa_create_as_external (ls_id, type, ifindex, p);
  if (!lsa)
    return;

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
}

void
ospf6_redistribute_route_remove (int type, int ifindex, struct prefix_ipv6 *p)
{
  char buf[128];
  struct ospf6_lsa *lsa = NULL;
  u_int32_t ls_id;

  /* log */
  if (IS_OSPF6_DUMP_ROUTE)
    {
      zlog_info ("Redistribute remove: type:%d index:%d %s/%d", type,
                 ifindex, inet_ntop (AF_INET6, &p->prefix, buf, sizeof (buf)),
                 p->prefixlen);
    }

  ls_id = ospf6_redistribute_ls_id_lookup (type, ifindex, p, ospf6);
  if (! ls_id)
    return;

  ospf6_redistribute_ls_id_free (ls_id, type, ifindex, p, ospf6);

  lsa = ospf6_lsdb_lookup (htons (LST_AS_EXTERNAL_LSA), htonl (ls_id),
                           ospf6->router_id, (void *) ospf6);
  if (! lsa)
    return;

  ospf6_premature_aging (lsa);
}

void
ospf6_redistribute_init (struct ospf6 *o6)
{
  o6->redistribute_map = route_table_init ();
}

void
ospf6_redistribute_finish (struct ospf6 *o6)
{
  struct route_node *rn;
  list l;
  listnode n;
  struct ospf6_redistribute_info *info;

  for (rn = route_top (o6->redistribute_map); rn; rn = route_next (rn))
    {
      l = (list) rn->info;
      while ((n = listhead (l)) != NULL)
        {
          info = (struct ospf6_redistribute_info *) getdata (n);
          ospf6_redistribute_route_remove (info->type, info->ifindex,
                                           (struct prefix_ipv6 *) &rn->p);
        }
      list_delete_all (l);
      rn->info = NULL;
    }
  route_table_finish (o6->redistribute_map);
}

