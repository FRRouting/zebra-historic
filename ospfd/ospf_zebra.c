/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro, Toshiaki Takada
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

#include <zebra.h>

#include "zebra/zebra.h"
#include "thread.h"
#include "linklist.h"
#include "vector.h"
#include "buffer.h"
#include "network.h"
#include "prefix.h"
#include "if.h"
#include "stream.h"
#include "client.h"
#include "command.h"
#include "memory.h"
#include "zclient.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_asbr.h"

/* Zebra structure to hold current status. */
struct zebra *zebra = NULL;

/* For registering threads. */
extern struct thread_master *master;

/* Inteface addition message from zebra. */
int
ospf_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zebra->ibuf);

#if 0
  if (IS_OSPF_DEBUG_ZEBRA)
    zlog_info ("OSPF interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);
#endif /* 0 */  

  ospf_if_update ();

  return 0;
}

int
ospf_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  return 0;
}

int
ospf_interface_address_add (int command, struct zebra *zebra,
			     zebra_size_t length)
{
  struct connected *c;

  c = zebra_interface_address_add_read (zebra->ibuf);

  if (c == NULL)
    return 0;

#if 0
  if (IS_OSPF_DEBUG_ZEBRA)
    {
      struct prefix *p;

      p = c->address;
      if (p->family == AF_INET)
	zlog_info (" connected address %s/%d", 
		   inet_atop (p->u.prefix4), p->prefixlen);
    }
#endif /* 0 */

  ospf_if_update ();

  return 0;
}

int
ospf_interface_address_delete (int command, struct zebra *zebra,
			       zebra_size_t length)
{
  return 0;
}

void
ospf_zebra_add (struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zebra->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);
}

void
ospf_zebra_delete (struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zebra->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_delete (zebra->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);
}

void
ospf_zebra_add_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (zebra->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		    p, &lo_addr, 0);

}

void
ospf_zebra_delete_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (zebra->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_delete (zebra->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		       p, &lo_addr, 0);
}



int
ospf_redistribute_set (int type)
{
  if (zebra->redist[type])
    return CMD_SUCCESS;

  zebra->redist[type] = 1;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, type);

  ospf_asbr_status_update (++ospf_top->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_unset (int type)
{
  if (! zebra->redist[type])
    return CMD_SUCCESS;

  zebra->redist[type] = 0;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zebra->sock, type);

  /* Remove the routes from OSPF table. */
  ospf_redistribute_withdraw (type);

  ospf_asbr_status_update (--ospf_top->redistribute);

  return CMD_SUCCESS;
}

/* Zebra route add and delete treatment. */
int
ospf_zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
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

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	ospf_asbr_route_add (type, &p, ifindex);
      else 
	ospf_asbr_route_delete (type, &p, ifindex);
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

DEFUN (ospf_redistribute_ospf,
       ospf_redistribute_ospf_cmd,
       "redistribute OSPF",
       "Redistribute control\n"
       "OSPF route\n")
{
  zebra->redist[ZEBRA_ROUTE_OSPF] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ospf_redistribute_ospf,
       no_ospf_redistribute_ospf_cmd,
       "no redistribute OSPF",
       NO_STR
       "Redistribute control\n"
       "OSPF route\n")
{
  zebra->redist[ZEBRA_ROUTE_OSPF] = 0;
  return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_static,
       ospf_redistribute_static_cmd,
       "redistribute static",
       "Redistribute control\n"
       "Static route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_STATIC);
}

DEFUN (no_ospf_redistribute_static,
       no_ospf_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute control\n"
       "Static route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_STATIC);
}

DEFUN (ospf_redistribute_connected,
       ospf_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute control\n"
       "Connected route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_CONNECT);
}

DEFUN (no_ospf_redistribute_connected,
       no_ospf_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute control\n"
       "Connected route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_CONNECT);
}

DEFUN (ospf_redistribute_rip,
       ospf_redistribute_rip_cmd,
       "redistribute rip",
       "Redistribute control\n"
       "RIP route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_RIP);
}

DEFUN (no_ospf_redistribute_rip,
       no_ospf_redistribute_rip_cmd,
       "no redistribute rip",
       NO_STR
       "Redistribute control\n"
       "RIP route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_RIP);
}

DEFUN (ospf_redistribute_bgp,
       ospf_redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_BGP);
}

DEFUN (no_ospf_redistribute_bgp,
       no_ospf_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_BGP);
}

/* Zebra configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zebra->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zebra->redist[ZEBRA_ROUTE_OSPF])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ospf%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

int
config_write_ospf_redistribute (struct vty *vty)
{
  int i;
  char *str[] = { "system", "kernel", "connected", "static", "rip",
		  "ripng", "ospf", "ospf6", "bgp"};

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zebra->redist_default && zebra->redist[i])
      vty_out (vty, " redistribute %s%s", str[i], VTY_NEWLINE);
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)#",
};

void
zebra_start ()
{
  zebra_create (zebra);
}

void
zebra_init ()
{
  /* Allocate zebra structure. */
  zebra = zebra_new ();

  /* Set default values. */
  zebra->enable = 1;
  zebra->sock = -1;
  zebra->redist_default = ZEBRA_ROUTE_OSPF;
  zebra->redist[ZEBRA_ROUTE_OSPF] = 1;

  zebra->interface_add = ospf_interface_add;
  zebra->interface_delete = ospf_interface_delete;
  zebra->interface_address_add = ospf_interface_address_add;
  zebra->interface_address_delete = ospf_interface_address_delete;
  zebra->ipv4_route_add = ospf_zebra_read_ipv4;
  zebra->ipv4_route_delete = ospf_zebra_read_ipv4;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */
  install_element (CONFIG_NODE, &router_zebra_cmd);

  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &ospf_redistribute_rip_cmd);
  install_element (ZEBRA_NODE, &no_ospf_redistribute_rip_cmd);

  install_element (OSPF_NODE, &ospf_redistribute_static_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_static_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_connected_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_connected_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_rip_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_rip_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_bgp_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_bgp_cmd);
}
