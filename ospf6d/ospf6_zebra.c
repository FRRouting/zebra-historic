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

/* information about zebra. */
struct zebra *zebra = NULL;

/* redistribute function */
void
ospf6_zebra_redistribute (int type)
{
  if (zebra->redist[type])
    return;

  zebra->redist[type] = 1;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, type);
}

void
ospf6_zebra_no_redistribute (int type)
{
  if (!zebra->redist[type])
    return;

  zebra->redist[type] = 0;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zebra->sock, type);
}

/* send all ospf6 routes to zebra */
static void
ospf6_zebra_redistribute_ospf6_add ()
{
  struct route_node *rn;
  struct ospf6_route_node_info *info;
  struct ospf6_nexthop *nh;
  listnode n;

  for (rn = route_top (ospf6->table_zebra); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info)
        continue;

      assert (!list_isempty (info->nhlist));

      for (n = listhead (info->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);

          /* log */
          if (IS_OSPF6_DUMP_ZEBRA)
            {
              char prefixstr[64], nhstr[64];

              prefix2str (&rn->p, prefixstr, sizeof (prefixstr));
              inet_ntop (AF_INET6, &nh->ipaddr, nhstr, sizeof (nhstr));
              zlog_info ("Zebra Send add route: %s nh:%s ifindex:%d",
                         prefixstr, nhstr, nh->ifindex);
            }

          zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_OSPF6, 0,
                          (struct prefix_ipv6 *)&rn->p,
                          &nh->ipaddr, nh->ifindex);
        }
    }
}

/* withdraw all ospf6 routes from zebra */
static void
ospf6_zebra_redistribute_ospf6_delete ()
{
  struct route_node *rn;
  struct ospf6_route_node_info *info;
  struct ospf6_nexthop *nh;
  listnode n;

  for (rn = route_top (ospf6->table_zebra); rn; rn = route_next (rn))
    {
      info = (struct ospf6_route_node_info *) rn->info;
      if (!info)
        continue;

      assert (!list_isempty (info->nhlist));

      for (n = listhead (info->nhlist); n; nextnode (n))
        {
          nh = (struct ospf6_nexthop *) getdata (n);

          /* log */
          if (IS_OSPF6_DUMP_ZEBRA)
            {
              char prefixstr[64], nhstr[64];

              prefix2str (&rn->p, prefixstr, sizeof (prefixstr));
              inet_ntop (AF_INET6, &nh->ipaddr, nhstr, sizeof (nhstr));
              zlog_info ("Zebra Send delete route: %s nh:%s ifindex:%d",
                         prefixstr, nhstr, nh->ifindex);
            }

          zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_OSPF6, 0,
                             (struct prefix_ipv6 *)&rn->p,
                             &nh->ipaddr, nh->ifindex);
        }
    }
}

/* Inteface addition message from zebra. */
int
ospf6_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zebra->ibuf);

  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("Zebra I/F add: %s index %d flags %d metric %d mtu %d",
               ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  {
    struct ospf6_if *o6if = (struct ospf6_if *)ifp->info;
    if (!o6if)
      o6if = make_ospf6_if (ifp);
    else if (o6if->area)
      {
        /* Already attached to area. start OSPF6 */
        thread_add_event (master, interface_up, o6if, 0);
      }
  }

  return 0;
}

int
ospf6_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  return 0;
}

int
ospf6_interface_address_add (int command, struct zebra *zebra,
                             zebra_size_t length)
{
  struct connected *c;
  struct interface *ifp;

  c = zebra_interface_address_add_read (zebra->ibuf);

  if (c == NULL)
    return 0;

  if (IS_OSPF6_DUMP_ZEBRA)
    {
      struct prefix *p;
      char buf[128];

      p = c->address;
      if (p->family == AF_INET6)
        {
          inet_ntop (p->family, &p->u.prefix6, buf, sizeof (buf));
          zlog_info ("Zebra connected address add: %s/%d",
                     buf, p->prefixlen);
        }
    }

  ifp = c->ifp;

  {
    struct ospf6_if *o6if = (struct ospf6_if *)ifp->info;
    if (!o6if)
      o6if = make_ospf6_if (ifp);
    else if (o6if->area)
      {
        /* interface already started. (re)make Link-LSA */
        struct ospf6_lsa *lsa = NULL;

        lsa = ospf6_make_link_lsa (o6if);
        if (lsa)
          {
            ospf6_lsa_flood (lsa);
            ospf6_lsdb_install (lsa);
            ospf6_lsa_unlock (lsa);
          }
      }
  }

  return 0;
}

int
ospf6_interface_address_delete (int command, struct zebra *zebra,
                                zebra_size_t length)
{
  return 0;
}


void
ospf6_zebra_route_add (struct prefix_ipv6 *dst,
                       struct ospf6_route_node_info *info)
{
  struct ospf6_nexthop *nh;
  listnode n;
  char dstprefix[128], nhaddr[128];

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_OSPF6])
    return;

  /* write added routes to zebra */
  /* for each nexthop */
  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);

      /* log */
      if (IS_OSPF6_DUMP_ZEBRA)
        {
          prefix2str ((struct prefix *)dst, dstprefix, sizeof (dstprefix));
          inet_ntop (AF_INET6, &nh->ipaddr, nhaddr, sizeof (nhaddr));
          zlog_info ("Zebra Send add route: %s nh:%s ifindex:%d",
                     dstprefix, nhaddr, nh->ifindex);
        }

      if (!IN6_IS_ADDR_V4MAPPED (&dst->prefix))
        zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_OSPF6, 0, dst,
                        &nh->ipaddr, nh->ifindex);
      else
        {
          struct prefix_ipv4 dst4;
          struct in_addr nh4;

          dst4.family = AF_INET;
          dst4.prefixlen = dst->prefixlen - 96;
          ospf6_ipv6_decode_ipv4 (&dst->prefix, &dst4.prefix);

          /* find IPv4 nexthop address */
          if (IN6_IS_ADDR_UNSPECIFIED (&nh->ipaddr))
            memset (&nh4, 0, sizeof (struct in_addr));
          else
            ospf6_ipv4_nexthop_from_linklocal (&nh->ipaddr, &nh4, nh->ifindex);

          inet_ntop (AF_INET, &dst4.prefix, dstprefix, sizeof (dstprefix));
          if (!IN6_IS_ADDR_UNSPECIFIED (&nh->ipaddr) &&
              nh4.s_addr == 0)
            zlog_warn (" *** Can't FIND IPv4 NEXTHOP for %s/%d, IGNORE",
                       dstprefix, dst4.prefixlen);
          else
            zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_OSPF6, 0, &dst4,
                            &nh4, nh->ifindex);
        }
    }

  ospf6_route_add (dst, info, ospf6->table_zebra);
}

void
ospf6_zebra_route_delete (struct prefix_ipv6 *dst,
                          struct ospf6_route_node_info *info)
{
  struct ospf6_nexthop *nh;
  listnode n;
  char dstprefix[128], nhaddr[128];

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_OSPF6])
    return;

  /* write deleted routes to zebra */
  /* for each nexthop */
  for (n = listhead (info->nhlist); n; nextnode (n))
    {
      nh = (struct ospf6_nexthop *) getdata (n);

      /* log */
      if (IS_OSPF6_DUMP_ZEBRA)
        {
          prefix2str ((struct prefix *)dst, dstprefix, sizeof (dstprefix));
          inet_ntop (AF_INET6, &nh->ipaddr, nhaddr, sizeof (nhaddr));
          zlog_info ("Zebra Send delete route: %s nh:%s ifindex:%d",
                     dstprefix, nhaddr, nh->ifindex);
        }

      if (!IN6_IS_ADDR_V4MAPPED (&dst->prefix))
        zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_OSPF6, 0, dst,
                           &nh->ipaddr, nh->ifindex);
    }

  ospf6_route_delete (dst, info, ospf6->table_zebra);
}

/* add/delete redistribution from zebra */
void
ospf6_redist_route_add (int type, int ifindex, struct prefix_ipv6 *p)
{
  char *type_str = NULL, p_str[128];
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

  prefix2str ((struct prefix *)p, p_str, sizeof (p_str));
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
        type_str = "unknown";
        dest_type = DTYPE_NONE;
        redist_conf = 0;
        break;
    }

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("Zebra Receive add route: %s %s ifindex:%d",
               type_str, p_str, ifindex);

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

      /* LSA construction */
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

      /* if new LSA was constructed, flood and install db */
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
}

void
ospf6_redist_route_delete (int type, int ifindex, struct prefix_ipv6 *p)
{
  char *type_str = NULL, p_str[128];
  struct route_table *rt;
  struct route_node *rn;
  struct ospf6_route_node_info *info;
  unsigned char dest_type;
  struct ospf6_lsa *lsa, *new;
  struct ospf6_if *o6if;

  prefix2str ((struct prefix *)p, p_str, sizeof (p_str));
  dest_type = DTYPE_NONE;
  rt = NULL;

  switch (type)
    {
      case ZEBRA_ROUTE_CONNECT:
        type_str = "connected";
        rt = ospf6->table_connected;
        break;

      case ZEBRA_ROUTE_STATIC:
        type_str = "static";
        rt = ospf6->table_external;
        break;

      case ZEBRA_ROUTE_RIPNG:
        type_str = "ripng";
        rt = ospf6->table_external;
        break;

      case ZEBRA_ROUTE_BGP:
        type_str = "bgp";
        rt = ospf6->table_external;
        break;

      default:
        type_str = "unknown";
        break;
    }

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("Zebra Receive delete route: %s %s ifindex:%d",
               type_str, p_str, ifindex);

  /* check route existence of current routing table */
  rn = route_node_get (rt, (struct prefix *)p);
  if (!rn->info)
    {
      zlog_warn (" !don't know route about to delete");
      return;
    }
  info = (struct ospf6_route_node_info *) rn->info;
  lsa = info->ls_origin;
  if (!lsa)
    zlog_warn (" !can't find as-external lsa");

  /* if AS-external route deleted, do premature aging LSA
     advertising the route */
  if (rt == ospf6->table_external)
    if (lsa)
      ospf6_premature_aging (lsa);

  /* if connected routes changed, simply reconstruct Link-LSA */
  if (rt == ospf6->table_connected)
    {
      o6if = ospf6_if_lookup_by_index (ifindex);
      assert (o6if);
      new = ospf6_make_link_lsa (o6if);
      /* if new LSA was constructed, flood and install db */
      if (new)
        {
          ospf6_lsa_flood (new);
          ospf6_lsdb_install (new);
          ospf6_lsa_unlock (new);
        }
      else if (lsa)
        ospf6_premature_aging (lsa);
    }

  /* delete from redistribute routing table */
  ospf6_route_add (p, info, rt);
}


int
ospf6_zebra_read_ipv6 (int command, struct zebra *zebra,
                       zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in6_addr nexthop;
  u_char *lim;
  struct stream *s;

  s = zebra->ibuf;

  lim = stream_pnt (s) + length;

  /* get type and gateway */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in6_addr));

  /* get IPv6 prefixes */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      unsigned int ifindex;

      ifindex = stream_getl (s);

      memset (&p, 0, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (command == ZEBRA_IPV6_ROUTE_ADD)
        ospf6_redist_route_add (type, ifindex, &p);
      else
        ospf6_redist_route_delete (type, ifindex, &p);
    }
  return 0;
}

int
ospf6_zebra_read_ipv4 (int command, struct zebra *zebra,
                       zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *lim;
  struct stream *s;
  unsigned int ifindex;

  s = zebra->ibuf;
  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in_addr));

  /* Then fetch IPv4 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv4 p;
      struct prefix_ipv6 p6;
      char buf1[64];

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

inet_ntop (AF_INET, &p.prefix, buf1, sizeof (buf1));
zlog_info ("IPv4 connected Prefix %s", buf1);

      /* convert address to "ipv4-mapped-address" */
      memset (&p6, 0, sizeof (struct prefix_ipv6));
      p6.family = AF_INET6;
      p6.prefixlen = p.prefixlen + 96;
      ospf6_ipv4_encode_ipv6 (&p.prefix, &p6.prefix);

inet_ntop (AF_INET6, &p6.prefix, buf1, sizeof (buf1));
zlog_info ("IPv6 converted connected Prefix %s", buf1);

      if (command == ZEBRA_IPV4_ROUTE_ADD)
        ospf6_redist_route_add (type, ifindex, &p6);
      else
        ospf6_redist_route_delete (type, ifindex, &p6);
    }
  return 0;
}


DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  int ret;

  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: router zebra");

  vty->node = ZEBRA_NODE;

  /* Set router zebra is enabled. */
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    {
      vty_out (vty, "Already connected to zebra\r\n");
      return CMD_WARNING;
    }

  vty_out (vty, "Connecting zebra...\r\n");

  /* Connect to zebra. */
  ret = zebra_create (zebra);
  if (ret < 0)
    {
      vty_out (vty, "Can't connect to zebra\r\n");
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (redistribute_ospf6,
       redistribute_ospf6_cmd,
       "redistribute ospf6",
       "Redistribute control\n"
       "OSPF6 route\n")
{
  /* log */
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: redistribute ospf6");

  zebra->redist[ZEBRA_ROUTE_OSPF6] = 1;

  /* set zebra route table */
  ospf6_zebra_redistribute_ospf6_add ();

  return CMD_SUCCESS;
}

DEFUN (no_redistribute_ospf6,
       no_redistribute_ospf6_cmd,
       "no redistribute ospf6",
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")
{
  /* log */
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: no redistribute ospf6");

  zebra->redist[ZEBRA_ROUTE_OSPF6] = 0;

  /* clean up zebra route table */
  ospf6_zebra_redistribute_ospf6_delete ();

  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")
{
  /* log */
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("no router zebra");

  /* xxx */
  zebra->enable = 0;
  return CMD_SUCCESS;
}

/* Zebra configuration write function. */
int
ospf6_zebra_config_write (struct vty *vty)
{
  if (! zebra->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zebra->redist[ZEBRA_ROUTE_OSPF6])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ospf6%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-zebra)# ",
};

void
ospf6_zebra_start ()
{
  zlog_info ("Connecting Zebra...");

  zebra_create (zebra);

  /* redistribute connected route by default */
  ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT);
}

void
ospf6_zebra_init ()
{
  /* Allocate zebra structure. */
  zebra = zebra_new ();

  /* Set default values. */
  zebra->enable = 1;
  zebra->sock = -1;
  zebra->redist_default = ZEBRA_ROUTE_OSPF6;
  zebra->redist[ZEBRA_ROUTE_OSPF6] = 1;

  /* Set call back functions. */
  zebra->interface_add = ospf6_interface_add;
  zebra->interface_delete = ospf6_interface_delete;
  zebra->interface_address_add = ospf6_interface_address_add;
  zebra->interface_address_delete = ospf6_interface_address_delete;

  zebra->ipv4_route_add = ospf6_zebra_read_ipv4;
  zebra->ipv4_route_delete = ospf6_zebra_read_ipv4;
  zebra->ipv6_route_add = ospf6_zebra_read_ipv6;
  zebra->ipv6_route_delete = ospf6_zebra_read_ipv6;

  /* zebra->get_all_interface = ospf6_zebra_get_interface; */

  /* Install zebra node. */
  install_node (&zebra_node, ospf6_zebra_config_write);

  /* Install command element for zebra node. */
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);

  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &redistribute_ospf6_cmd);
  install_element (ZEBRA_NODE, &no_redistribute_ospf6_cmd);

  return;
}

