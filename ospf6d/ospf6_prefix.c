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

static struct ospf6_prefix *
ospf6_prefix_new (size_t size)
{
  struct ospf6_prefix *new;
  new = (struct ospf6_prefix *) XMALLOC (MTYPE_OSPF6_PREFIX, size);
  if (!new)
    zvlog_warn ("prefix_new failed, size:%d", size);
  else
    memset (new, 0, size);
  return new;
}

void
ospf6_prefix_free (struct ospf6_prefix *p)
{
  XFREE (MTYPE_OSPF6_PREFIX, p);
}

struct ospf6_prefix *
ospf6_prefix_make (unsigned short metric, struct prefix_ipv6 *p)
{
  struct ospf6_prefix *o6p;
  size_t o6psize;

  o6psize = OSPF6_PREFIX_SPACE (p->prefixlen) + sizeof (struct ospf6_prefix);
  o6p = ospf6_prefix_new (o6psize);

  o6p->o6p_prefix_len = p->prefixlen;
  /* XXX, o6p->o6p_prefix_opt */
  o6p->o6p_prefix_metric = htons (metric);

  memcpy (o6p + 1, &p->prefix, OSPF6_PREFIX_SPACE (p->prefixlen));

  return o6p;
}

static int
ospf6_prefix_issame (struct ospf6_prefix *p1, struct ospf6_prefix *p2)
{
  if (p1->o6p_prefix_len != p2->o6p_prefix_len)
    return 0;
  if (memcmp (p1 + 1, p2 + 1, OSPF6_PREFIX_SPACE (p1->o6p_prefix_len)))
    return 0;
  return 1;
}

void
ospf6_prefix_add (list l, struct ospf6_prefix *add)
{
  listnode n;
  struct ospf6_prefix *p;
  int already = 0;

  for (n = listhead (l); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      if (ospf6_prefix_issame (add, p))
        {
          already++;
          break;
        }
    }

  if (already)
    return;

  list_add_node (l, add);
}

static void
ospf6_prefix_delete (list l, struct ospf6_prefix *del)
{
  listnode n;
  struct ospf6_prefix *p;

  for (n = listhead (l); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      if (ospf6_prefix_issame (p, del))
        break;
    }

  if (!n)
    {
      zvlog_err ("no such prefix");
      assert (0);
    }

  ospf6_prefix_free (getdata (n));
  list_delete_node (l, n);
}

void
ospf6_prefix_in6_addr (struct ospf6_prefix *o6p, struct in6_addr *in6)
{
  memset (in6, 0, sizeof (struct in6_addr));
  memcpy (in6, o6p + 1, OSPF6_PREFIX_SPACE (o6p->o6p_prefix_len));
  return;
}

void
ospf6_prefix_str (struct ospf6_prefix *p, char *buf, size_t bufsize)
{
  struct in6_addr in6;
  char tmpbuf[128];

  ospf6_prefix_in6_addr (p, &in6);
  memset (tmpbuf, 0, sizeof (tmpbuf));
  inet_ntop (AF_INET6, &in6, tmpbuf, sizeof (tmpbuf));

  snprintf (buf, bufsize, "opt:%s metric:%d %s/%d",
            "xxx", ntohs (p->o6p_prefix_metric),
            tmpbuf, p->o6p_prefix_len);
  return;
}

void
ospf6_redist_route_add (int type, int ifindex, struct prefix_ipv6 *p)
{
  char *type_str = NULL, o6p_str[128];
  int redist_conf;
  unsigned short cost;
  struct route_table *rt;
  struct route_node *rn;
  struct ospf6_route_node_info info;
  unsigned char dest_type;
  list nhlist_dummy = list_init ();
  struct ospf6_lsa *new;
  struct ospf6_if *o6if;
  struct ospf6_nexthop *nh;
  struct in6_addr in6;
  listnode i;

  prefix2str ((struct prefix *)p, o6p_str, sizeof (o6p_str));
  dest_type = DTYPE_NONE;
  cost = 0;
  rt = NULL;

  switch (type)
    {
      case ZEBRA_ROUTE_CONNECT:
        type_str = "connected";
        dest_type = DTYPE_PREFIX;
        rt = ospf6->table_connected;
        redist_conf = ospf6->redist_connected;
        cost = 0;
        memset (&in6, 0, sizeof (in6));
        nh = nexthop_make (ifindex, &in6, 0);
        list_add_node (nhlist_dummy, nh);
        break;

      case ZEBRA_ROUTE_STATIC:
        type_str = "static";
        dest_type = DTYPE_STATIC_REDISTRIBUTE;
        rt = ospf6->table_external;
        redist_conf = ospf6->redist_static;
        cost = ospf6->cost_static;
        break;

      case ZEBRA_ROUTE_RIPNG:
        type_str = "ripng";
        dest_type = DTYPE_RIPNG_REDISTRIBUTE;
        rt = ospf6->table_external;
        redist_conf = ospf6->redist_ripng;
        cost = ospf6->cost_ripng;
        break;

      case ZEBRA_ROUTE_BGP:
        type_str = "bgp";
        dest_type = DTYPE_BGP_REDISTRIBUTE;
        rt = ospf6->table_external;
        redist_conf = ospf6->redist_bgp;
        cost = ospf6->cost_bgp;
        break;

      default:
        dest_type = DTYPE_NONE;
        redist_conf = 0;
        type_str = "unknown";
        break;
    }

  /* set info */
  memset (&info, 0, sizeof (info));
  info.dest_type = dest_type;
  if (redist_conf == 1)
    info.path_type = PTYPE_TYPE1_EXTERNAL;
  else if (redist_conf == 2)
    info.path_type = PTYPE_TYPE2_EXTERNAL;
  info.cost = cost;
  /* xxx, make lsa and set info.ls_origin */
  info.nhlist = nhlist_dummy;

  /* add redistribute routing table */
  if (redist_conf)
    {
      ospf6_route_add (p, &info, rt);
      rn = route_node_get (rt, (struct prefix *)p);
      if (rt == ospf6->table_external)
        new = ospf6_make_as_external_lsa (rn);
      else if (rt == ospf6->table_connected)
        {
          o6if = ospf6_if_lookup_by_index (ifindex);
          assert (o6if);
          new = ospf6_make_link_lsa (o6if);
        }
      else
        new = (struct ospf6_lsa *) NULL;

      /* if new lsa was constructed, flood and install db */
      if (new)
        {
          ospf6_lsa_flood (new);
          ospf6_lsdb_install (new);
          ospf6_lsa_unlock (new);
        }
    }

  for (i = listhead (nhlist_dummy); i; nextnode (i))
    {
      nh = (struct ospf6_nexthop *) getdata (i);
      nexthop_delete (nh);
    }
  list_delete_all (nhlist_dummy);

  /* log */
  o6log.zebra ("redist_add: %d %s %s", ifindex, type_str, o6p_str);

  return;
}

void
ospf6_redist_route_delete (int type, int ifindex, struct prefix_ipv6 *p)
{
  /* xxx */

  /* log */
#if 0
  o6log.zebra ("redist_delete: %d %s %s", ifindex, type_str, o6p_str);
#else
  o6log.zebra ("redist_delete:");
#endif

  return;
}

void
ospf6_prefix_copy (struct ospf6_prefix *dst, struct ospf6_prefix *src,
                   size_t dstsize)
{
  size_t srcsize;

  memset (dst, 0, dstsize);

  srcsize = OSPF6_PREFIX_SIZE (src);
  if (dstsize < srcsize)
    memcpy (dst, src, dstsize);
  else
    memcpy (dst, src, srcsize);

  return;
}

