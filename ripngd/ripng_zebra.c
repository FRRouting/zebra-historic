/*
 * RIPngd and zebra interface.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "zebra/zebra.h"
#include "thread.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "buffer.h"
#include "log.h"
#include "network.h"
#include "client.h"
#include "zclient.h"

#include "ripngd/ripngd.h"

/* All information about zebra. */
struct zebra *zebra = NULL;

extern struct thread_master *master;

int ripng_zebra_get_interface (int, struct zebra *, zebra_size_t);

void
ripng_zebra_ipv6_add (struct prefix_ipv6 *p, struct in6_addr *nexthop,
		      unsigned int ifindex)
{
  if (zebra->redist[ZEBRA_ROUTE_RIPNG])
    zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_RIPNG, 0, p, nexthop, ifindex);
}

void
ripng_zebra_ipv6_delete (struct prefix_ipv6 *p, struct in6_addr *nexthop,
			 unsigned int ifindex)
{
  if (zebra->redist[ZEBRA_ROUTE_RIPNG])
    zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_RIPNG, 0, p, nexthop, ifindex);
}

/* Zebra route add and delete treatment. */
int
ripng_zebra_read_ipv6 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in6_addr nexthop;
  u_char *lim;
  struct stream *s;

  s = zebra->ibuf;

  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  memcpy (&nexthop, stream_pnt (s), sizeof (struct in6_addr));
  stream_forward (s, sizeof (struct in6_addr));

  /* Then fetch IPv6 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      unsigned int ifindex;

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      memcpy (&p.prefix, stream_pnt (s), size);
      stream_forward (s, size);

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	ripng_redistribute_add (type, 0, &p, ifindex);
      else
	ripng_redistribute_delete (type, 0, &p, ifindex);
    }
  return 0;
}

int
ripng_redistribute_set (int type)
{
  if (zebra->redist[type])
    return CMD_SUCCESS;

  zebra->redist[type] = 1;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, type);

  return CMD_SUCCESS;
}

int
ripng_redistribute_unset (int type)
{
  if (! zebra->redist[type])
    return CMD_SUCCESS;

  zebra->redist[type] = 0;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zebra->sock, type);

  return CMD_SUCCESS;
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  vty->node = ZEBRA_NODE;
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    return CMD_SUCCESS;

  /* Try to create zebra connection. */
  if (zebra_create (zebra) < 0)
    {
      vty_out (vty, "Can't connect to zebra.\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_ripng,
       ripng_redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute control\n"
       "RIPng route\n")
{
  zebra->redist[ZEBRA_ROUTE_RIPNG] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_ripng,
       no_ripng_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute control\n"
       "RIPng route\n")
{
  zebra->redist[ZEBRA_ROUTE_RIPNG] = 0;
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_static,
       ripng_redistribute_static_cmd,
       "redistribute static",
       "Redistribute control\n"
       "Static route\n")
{
  return ripng_redistribute_set (ZEBRA_ROUTE_STATIC);
}

DEFUN (no_ripng_redistribute_static,
       no_ripng_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute control\n"
       "Static route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_STATIC);
}

DEFUN (ripng_redistribute_connected,
       ripng_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute control\n"
       "Connected route\n")
{
  return ripng_redistribute_set (ZEBRA_ROUTE_CONNECT);
}

DEFUN (no_ripng_redistribute_connected,
       no_ripng_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute control\n"
       "Connected route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_CONNECT);
}

DEFUN (ripng_redistribute_bgp,
       ripng_redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  return ripng_redistribute_set (ZEBRA_ROUTE_BGP);
}

DEFUN (no_ripng_redistribute_bgp,
       no_ripng_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  return ripng_redistribute_unset (ZEBRA_ROUTE_BGP);
}

void
ripng_redistribute_write (struct vty *vty)
{
  int i;
  char *str[] = { "system", "kernel", "connected", "static", "rip",
		  "ripng", "ospf", "ospf6", "bgp"};

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zebra->redist_default && zebra->redist[i])
      vty_out (vty, " redistribute %s%s", str[i], VTY_NEWLINE);
}

/* RIPng configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zebra->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zebra->redist[ZEBRA_ROUTE_RIPNG])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ripng%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

/* Start related zebra thread. */
void
zebra_start ()
{
  zebra_create (zebra);
}

/* Initialize zebra structure and it's commands. */
void
zebra_init ()
{
  /* Allocate zebra structure. */
  zebra = zebra_new ();

  /* Set default value to the zebra structure. */
  zebra->enable = 1;
  zebra->sock = -1;
  zebra->redist_default = ZEBRA_ROUTE_RIPNG;
  zebra->redist[ZEBRA_ROUTE_RIPNG] = 1;

  /* Set call back functions. */
  zebra->get_all_interface = ripng_zebra_get_interface;
  zebra->ipv6_route_add = ripng_zebra_read_ipv6;
  zebra->ipv6_route_delete = ripng_zebra_read_ipv6;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &ripng_redistribute_ripng_cmd);
  install_element (ZEBRA_NODE, &no_ripng_redistribute_ripng_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_static_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_static_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_connected_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_connected_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_bgp_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_bgp_cmd);
}
