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

  /* zebra->get_all_interface = ospf_zebra_get_interface; */

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */
  install_element (CONFIG_NODE, &router_zebra_cmd);

  install_default (ZEBRA_NODE);
}
