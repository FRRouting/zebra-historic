/*
 * RIPd and zebra interface.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
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
#include "ripd.h"
#include "buffer.h"
#include "network.h"
#include "client.h"
#include "stream.h"
#include "log.h"
#include "zclient.h"

/* All information about zebra. */
struct zebra *zebra = NULL;

extern struct thread_master *master;

int rip_zebra_get_interface (int, struct zebra *, zebra_size_t);

/* RIPd to zebra command interface. */
void
rip_zebra (int command, struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zebra->sock < 0)
    return;

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      if (zebra->redist[ZEBRA_ROUTE_RIP])
	zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_RIP, 0, p, nexthop, 0);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      if (zebra->redist[ZEBRA_ROUTE_RIP])
	zebra_ipv4_delete (zebra->sock, ZEBRA_ROUTE_RIP, 0, p, nexthop, 0);
      break;
    }
}

/* Zebra route add and delete treatment. */
int
rip_zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *pnt;
  u_char *lim;
  struct stream *s;

  s = zebra->ibuf;

  pnt = stream_pnt (s);
  lim = pnt + length;

  /* Fetch type and nexthop first. */
  type = *pnt++;
  flags = *pnt++;
  memcpy(&nexthop, pnt, 4);
  pnt += 4;

  /* Then fetch IPv4 prefixes. */
  while (pnt < lim)
    {
      int size;
      struct prefix_ipv4 p;
      struct rip_info *rinfo;

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      size = PSIZE (p.prefixlen);
      memcpy (&p.prefix, pnt, size);
      pnt += size;

      rinfo = rip_info_new ();
      rinfo->pref = -10;
      rinfo->fib = 1;
      rinfo->type = type;
      rinfo->metric = 1;

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	rip_add_route (&p, rinfo, NULL, NULL);
      else
	;
    }
  return 0;
}

int
rip_redistribute_set (int type)
{
  if (zebra->redist[type])
    return CMD_SUCCESS;

  zebra->redist[type] = 1;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, type);

  return CMD_SUCCESS;
}

int
rip_redistribute_unset (int type)
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
       "Make connection to zebra daemon\n"
       "\n")
{
  vty->node = ZEBRA_NODE;
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    return CMD_WARNING;

  /* Connect to zebra. */
  if (zebra_create (zebra) < 0)
    {
      vty_out (vty, "Can't connect to zebra\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (rip_redistribute_rip,
       rip_redistribute_rip_cmd,
       "redistribute RIP",
       "Redistribute control\n"
       "RIP route\n")
{
  zebra->redist[ZEBRA_ROUTE_RIP] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_rip_redistribute_rip,
       no_rip_redistribute_rip_cmd,
       "no redistribute RIP",
       NO_STR
       "Redistribute control\n"
       "RIP route\n")
{
  zebra->redist[ZEBRA_ROUTE_RIP] = 0;
  return CMD_SUCCESS;
}

DEFUN (rip_redistribute_static,
       rip_redistribute_static_cmd,
       "redistribute static",
       "Redistribute control\n"
       "Static route\n")
{
  return rip_redistribute_set (ZEBRA_ROUTE_STATIC);
}

DEFUN (no_rip_redistribute_static,
       no_rip_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute control\n"
       "Static route\n")
{
  return rip_redistribute_unset (ZEBRA_ROUTE_STATIC);
}

DEFUN (rip_redistribute_connected,
       rip_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute control\n"
       "Connected route\n")
{
  return rip_redistribute_set (ZEBRA_ROUTE_CONNECT);
}

DEFUN (no_rip_redistribute_connected,
       no_rip_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute control\n"
       "Connected route\n")
{
  return rip_redistribute_unset (ZEBRA_ROUTE_CONNECT);
}

DEFUN (rip_redistribute_bgp,
       rip_redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  return rip_redistribute_set (ZEBRA_ROUTE_BGP);
}

DEFUN (no_rip_redistribute_bgp,
       no_rip_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  return rip_redistribute_unset (ZEBRA_ROUTE_BGP);
}

/* RIP configuration write function. */
int
config_write_zebra (struct vty *vty)
{
  if (! zebra->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zebra->redist[ZEBRA_ROUTE_RIP])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute rip%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

int
config_write_rip_redistribute (struct vty *vty)
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
  "%s(config-router)# ",
};

/* Start related zebra thread. */
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

  /* Set default value to the zebra structure. */
  zebra->enable = 1;
  zebra->sock = -1;
  zebra->redist_default = ZEBRA_ROUTE_RIP;
  zebra->redist[ZEBRA_ROUTE_RIP] = 1;

  /* Set call back functions. */
  zebra->ipv4_route_add = rip_zebra_read_ipv4;
  zebra->ipv4_route_delete = rip_zebra_read_ipv4;
  zebra->get_all_interface = rip_zebra_get_interface;

  /* Install zebra node. */
  install_node (&zebra_node, config_write_zebra);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &rip_redistribute_rip_cmd);
  install_element (ZEBRA_NODE, &no_rip_redistribute_rip_cmd);
  install_element (RIP_NODE, &rip_redistribute_static_cmd);
  install_element (RIP_NODE, &no_rip_redistribute_static_cmd);
  install_element (RIP_NODE, &rip_redistribute_connected_cmd);
  install_element (RIP_NODE, &no_rip_redistribute_connected_cmd);
  install_element (RIP_NODE, &rip_redistribute_bgp_cmd);
  install_element (RIP_NODE, &no_rip_redistribute_bgp_cmd);
}
