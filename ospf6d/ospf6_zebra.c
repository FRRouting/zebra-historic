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

int
ospf6_zebra_get_interface (int command, struct zebra *zebra,
                           zebra_size_t length)
{
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;
  unsigned long endp;
  struct stream *s;

  s = zebra->ibuf;
  endp = stream_get_endp (s);

  while (stream_get_getp(s) < endp)
    {
      u_char tmpnam[INTERFACE_NAMSIZ + 1];

      bzero (tmpnam, sizeof (tmpnam));

      /* Get interface's name */
      stream_strncpy (tmpnam, s, INTERFACE_NAMSIZ);

      /* create interface structure */
      ifp = if_get_by_name (tmpnam);

      /* Get interface's index and values. */
      ifp->index = stream_getc (s);
      ifp->flags = stream_getl (s);
      ifp->metric = stream_getl (s);
      ifp->mtu = stream_getl (s);

      /* Get interface's address. */
      connected_count = stream_getl (s);

      while (connected_count--)
        {
#ifdef DEBUG
          char debug_str[64];
#endif /*DEBUG*/
          struct prefix *p;
          int plen;

          connected = connected_new ();

          p = prefix_new ();
          p->family = stream_getc (s);

          plen = prefix_blen (p);
          memcpy (&p->u.prefix, stream_pnt (s), plen);
          stream_forward (s, plen);
          p->prefixlen = stream_getc (s);
          connected->address = p;
#ifdef DEBUG
          inet_ntop (AF_INET6, &connected->address->u.prefix6,
                     debug_str, sizeof (debug_str));
          zvlog_debug ("%s", debug_str);
#endif /*DEBUG*/

          p = prefix_new ();
          memcpy (&p->u.prefix, stream_pnt (s), plen);
          stream_forward (s, plen);

          connected->destination = p;
#ifdef DEBUG
          inet_ntop (AF_INET6, &connected->destination->u.prefix6,
                     debug_str, sizeof (debug_str));
          zvlog_debug ("%s", debug_str);
#endif /*DEBUG*/

          connected_add (ifp, connected);
        }

      /* XXX Daemon specific process. should be replaced by hook. */
      {
        struct ospf6_if *o6if = (struct ospf6_if *)ifp->if_data;
        if (o6if && o6if->area)
          {
            /* Already attached to area. start OSPF6 */
            thread_add_event (master, interface_up, o6if, 0);
          }
      }

    }
  return 0;
}


void
ospf6_zebra_add (struct ospf6_rtentry *p)
{
  listnode n;
  struct ospf6_nexthop *q;
  char buf[128];

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_OSPF6])
    return;

  if (p->dest_type != DTYPE_PREFIX)
    return;

  for (n = listhead (p->nexthops); n; nextnode (n))
    {
      q = getdata (n);
      zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_OSPF6, 0, &p->dest_id.prefix,
                      &q->ipaddr, q->ifindex);
      prefix2str ((struct prefix *)&p->dest_id.prefix, buf, sizeof (buf));
      o6log.zebra ("zebra add %s", buf);
    }
}

void
ospf6_zebra_delete (struct ospf6_rtentry *p)
{
  listnode n;
  struct ospf6_nexthop *q;
  char buf[128];

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_OSPF6])
    return;

  if (p->dest_type != DTYPE_PREFIX)
    return;

  for (n = listhead (p->nexthops); n; nextnode (n))
    {
      q = getdata (n);
      zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_OSPF6, 0, &p->dest_id.prefix,
                         &q->ipaddr, q->ifindex);
      prefix2str ((struct prefix *)&p->dest_id.prefix, buf, sizeof (buf));
      o6log.zebra ("zebra delete %s", buf);
    }
}


DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  int ret;

  vty->node = ZEBRA_NODE;

  /* Set router zebra is enabled. */
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    {
      vty_out (vty, "Already connected to zebra\r\n");
      return CMD_WARNING;
    }

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
  zebra->redist[ZEBRA_ROUTE_OSPF6] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_redistribute_ospf6,
       no_redistribute_ospf6_cmd,
       "no redistribute ospf6",
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")
{
  zebra->redist[ZEBRA_ROUTE_OSPF6] = 0;
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")
{
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
zebra_start ()
{
  zebra_create (zebra);
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
  zebra->ipv4_route_add = NULL;
  zebra->ipv4_route_delete = NULL;
  zebra->ipv6_route_add = NULL;
  zebra->ipv6_route_delete = NULL;
  zebra->get_all_interface = ospf6_zebra_get_interface;

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

