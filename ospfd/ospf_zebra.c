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

#include "command.h"
#include "network.h"
#include "prefix.h"
#include "stream.h"
#include "filter.h"
#include "memory.h"
#include "zclient.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_asbr.h"

/* Zebra structure to hold current status. */
struct zebra *zclient = NULL;

/* For registering threads. */
extern struct thread_master *master;

/* Inteface addition message from zebra. */
int
ospf_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

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

  c = zebra_interface_address_add_read (zclient->ibuf);

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
  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);
}

void
ospf_zebra_delete (struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_OSPF, 0, p, nexthop, 0);
}

void
ospf_zebra_add_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		    p, &lo_addr, 0);

}

void
ospf_zebra_delete_discard (struct prefix_ipv4 *p)
{
  struct in_addr lo_addr;

  lo_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (zclient->redist[ZEBRA_ROUTE_OSPF])
    zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_OSPF, ZEBRA_FLAG_BLACKHOLE, 
		       p, &lo_addr, 0);
}



int
ospf_redistribute_set (int type)
{
  if (zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 1;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, type);

  ospf_asbr_status_update (++ospf_top->redistribute);

  return CMD_SUCCESS;
}

int
ospf_redistribute_unset (int type)
{
  if (! zclient->redist[type])
    return CMD_SUCCESS;

  zclient->redist[type] = 0;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock, type);

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

  s = zclient->ibuf;
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
	ospf_asbr_route_add (type, &p, ifindex, nexthop);
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
  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Disable a routing process\n"
       "Stop connection to zebra daemon\n")
{
  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_ospf,
       ospf_redistribute_ospf_cmd,
       "redistribute OSPF",
       "Redistribute control\n"
       "OSPF route\n")
{
  zclient->redist[ZEBRA_ROUTE_OSPF] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ospf_redistribute_ospf,
       no_ospf_redistribute_ospf_cmd,
       "no redistribute OSPF",
       NO_STR
       "Redistribute control\n"
       "OSPF route\n")
{
  zclient->redist[ZEBRA_ROUTE_OSPF] = 0;
  return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_kernel,
       ospf_redistribute_kernel_cmd,
       "redistribute kernel",
       "Redistribute control\n"
       "Kernel route\n")
{
  return ospf_redistribute_set (ZEBRA_ROUTE_KERNEL);
}

DEFUN (no_ospf_redistribute_kernel,
       no_ospf_redistribute_kernel_cmd,
       "no redistribute kernel",
       NO_STR
       "Redistribute control\n"
       "Kernel route\n")
{
  return ospf_redistribute_unset (ZEBRA_ROUTE_KERNEL);
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


int
ospf_set_distribute_list_out (struct vty *vty, int type, char * list_name)
{
  struct access_list *list;
  list = access_list_lookup(AF_INET, list_name);

  ospf_top->dist_lists_proto[type].list = list;

  if (ospf_top->dist_lists_proto[type].name)
    free (ospf_top->dist_lists_proto[type].name);

  ospf_top->dist_lists_proto[type].name = strdup (list_name);
  ospf_schedule_asbr_check ();

  return CMD_SUCCESS;
}

int
ospf_unset_distribute_list_out (struct vty *vty, int type, char * list_name)
{
  ospf_top->dist_lists_proto[type].list = 0;

  if (ospf_top->dist_lists_proto[type].name)
    free (ospf_top->dist_lists_proto[type].name);

  ospf_top->dist_lists_proto[type].name = NULL;
  ospf_schedule_asbr_check ();

  return CMD_SUCCESS;
}



#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"

DEFUN (ospf_distribute_list_out_kernel,
       ospf_distribute_list_out_kernel_cmd,
       "distribute-list NAME out kernel",
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Kernel routes\n")
{
  return ospf_set_distribute_list_out (vty, ZEBRA_ROUTE_KERNEL, argv[0]);
}

DEFUN (no_ospf_distribute_list_out_kernel,
       no_ospf_distribute_list_out_kernel_cmd,
       "no distribute-list NAME out kernel",
       NO_STR
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Kernel routes\n")
{
  return ospf_unset_distribute_list_out (vty, ZEBRA_ROUTE_KERNEL, argv[0]);
}


DEFUN (ospf_distribute_list_out_connected,
       ospf_distribute_list_out_connected_cmd,
       "distribute-list NAME out connected",
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Static routes\n")
{
  return ospf_set_distribute_list_out (vty, ZEBRA_ROUTE_CONNECT, argv[0]);
}

DEFUN (no_ospf_distribute_list_out_connected,
       no_ospf_distribute_list_out_connected_cmd,
       "no distribute-list NAME out connected",
       NO_STR
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Connected routes\n")
{
  return ospf_unset_distribute_list_out (vty, ZEBRA_ROUTE_CONNECT, argv[0]);
}


DEFUN (ospf_distribute_list_out_static,
       ospf_distribute_list_out_static_cmd,
       "distribute-list NAME out static",
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Static routes\n")
{
  return ospf_set_distribute_list_out (vty, ZEBRA_ROUTE_STATIC, argv[0]);
}

DEFUN (no_ospf_distribute_list_out_static,
       no_ospf_distribute_list_out_static_cmd,
       "no distribute-list NAME out static",
       NO_STR
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "Static routes\n")
{
  return ospf_unset_distribute_list_out (vty, ZEBRA_ROUTE_STATIC, argv[0]);
}


DEFUN (ospf_distribute_list_out_rip,
       ospf_distribute_list_out_rip_cmd,
       "distribute-list NAME out rip",
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "RIP routes\n")
{
  return ospf_set_distribute_list_out (vty, ZEBRA_ROUTE_RIP, argv[0]);
}

DEFUN (no_ospf_distribute_list_out_rip,
       no_ospf_distribute_list_out_rip_cmd,
       "no distribute-list NAME out rip",
       NO_STR
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "RIP routes\n")
{
  return ospf_unset_distribute_list_out (vty, ZEBRA_ROUTE_RIP, argv[0]);
}

DEFUN (ospf_distribute_list_out_bgp,
       ospf_distribute_list_out_bgp_cmd,
       "distribute-list NAME out bgp",
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "BGP routes\n")
{
  return ospf_set_distribute_list_out (vty, ZEBRA_ROUTE_BGP, argv[0]);
}

DEFUN (no_ospf_distribute_list_out_bgp,
       no_ospf_distribute_list_out_bgp_cmd,
       "no distribute-list NAME out bgp",
       NO_STR
       "Specify distribute list\n"
       "Name of the access-list\n"
       OUT_STR
       "BGP routes\n")
{
  return ospf_unset_distribute_list_out (vty, ZEBRA_ROUTE_BGP, argv[0]);
}

void
ospf_acl_hook ()
{
  int i, inv = 0;

  if (ospf_top)
    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
      if (ospf_top->dist_lists_proto[i].name)
	{
	  ospf_top->dist_lists_proto[i].list = NULL; /* Invalidate */
	  inv++;
	}

  if (OSPF_IS_ASBR && inv)
    ospf_schedule_asbr_check ();
}

/* Zebra configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_OSPF])
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
    if (i != zclient->redist_default && zclient->redist[i])
      vty_out (vty, " redistribute %s%s", str[i],
	       VTY_NEWLINE);


  if (ospf_top)
     for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
         if (ospf_top->dist_lists_proto[i].name)
            vty_out (vty, " distribute-list %s out %s%s", 
                     ospf_top->dist_lists_proto[i].name,
		     str[i], VTY_NEWLINE);

  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)#",
};

void
zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_OSPF);
  zclient->interface_add = ospf_interface_add;
  zclient->interface_delete = ospf_interface_delete;
  zclient->interface_address_add = ospf_interface_address_add;
  zclient->interface_address_delete = ospf_interface_address_delete;
  zclient->ipv4_route_add = ospf_zebra_read_ipv4;
  zclient->ipv4_route_delete = ospf_zebra_read_ipv4;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &ospf_redistribute_rip_cmd);
  install_element (ZEBRA_NODE, &no_ospf_redistribute_rip_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_connected_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_connected_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_static_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_static_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_kernel_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_kernel_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_rip_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_rip_cmd);
  install_element (OSPF_NODE, &ospf_redistribute_bgp_cmd);
  install_element (OSPF_NODE, &no_ospf_redistribute_bgp_cmd);
  install_element (OSPF_NODE, &ospf_distribute_list_out_kernel_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_kernel_cmd);
  install_element (OSPF_NODE, &ospf_distribute_list_out_connected_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_connected_cmd);
  install_element (OSPF_NODE, &ospf_distribute_list_out_static_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_static_cmd);
  install_element (OSPF_NODE, &ospf_distribute_list_out_rip_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_rip_cmd);
  install_element (OSPF_NODE, &ospf_distribute_list_out_bgp_cmd);
  install_element (OSPF_NODE, &no_ospf_distribute_list_out_bgp_cmd);

  access_list_add_hook (ospf_acl_hook);
  access_list_delete_hook (ospf_acl_hook);
}
