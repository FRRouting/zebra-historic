/*
 * zebra connect library 
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include <config.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "client.h"
#include "roken.h"
#include "log.h"
#include "thread.h"

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_attr.h"
#include "zebra/zebra.h"

/* Bgpd's zebra connection status. */
struct zebra
{
  int enable;
  int sock;

  struct thread *t_read;
  struct thread *t_write;

  struct stream *ibuf;
} zebra;

void
zebra_close ()
{
  if (zebra.sock > 0)
    {
      close (zebra.sock);
      zebra.sock = -1;
    }

  stream_free (zebra.ibuf);

  zebra.t_read = NULL;
  zebra.t_write = NULL;
}

/* Read packet from zebra. */
int
zebra_read (struct thread *t)
{
  int nbytes;
  int sock;
  zebra_size_t length;
  zebra_command_t command;

  sock = THREAD_FD(t);

  /* Read zebra header. */
  nbytes = stream_read (zebra.ibuf, sock, ZEBRA_HEADER_SIZE);

  /* zebra socket is closed. */
  if (nbytes == 0) 
    {
      log ("connection closed socket [%d]\n", sock);
      zebra_close ();
      return -1;
    }

  /* zebra read error. */
  if (nbytes < 0)
    {
      log ("cant read all packet\n");
      zebra_close ();
      return -1;
    }

  /* Fetch length and command. */
  length = stream_getw (zebra.ibuf);
  command = stream_getc (zebra.ibuf);

  /* Read rest of zebra packet. */
  stream_read (zebra.ibuf, sock, length - ZEBRA_HEADER_SIZE);

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
    case ZEBRA_IPV4_ROUTE_DELETE:
    case ZEBRA_IPV6_ROUTE_ADD:
    case ZEBRA_IPV6_ROUTE_DELETE:
    case ZEBRA_GET_ALL_INTERFACE:
      break;
    default:
      break;
    }

  /* Re-register myself. */
  zebra.t_read = thread_add_read (master, zebra_read, NULL, zebra.sock);

  return 0;
}

/* Make zebra connection. */
int
zebra_create ()
{
  /* Make socket. */
  zebra.sock = zebra_connect ();
  if (zebra.sock < 0)
    return -1;

  /* Input buffer. */
  zebra.ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  
  /* Create read thread. */
  zebra.t_read = thread_add_read (master, zebra_read, NULL, zebra.sock);

  /* Get all interfaces. */
  zebra_get_all_interface (zebra.sock);

  return 0;
}

void
bgp_zebra_announce (struct prefix *p, struct bgp_info *info)
{
  if (zebra.sock < 0)
    return;

  if (p->family == AF_INET)
    zebra_ipv4_add (zebra.sock, ZEBRA_ROUTE_BGP, (struct prefix_ipv4 *)p,
		    &info->attr->nexthop, 0);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    zebra_ipv6_add (zebra.sock, ZEBRA_ROUTE_BGP, (struct prefix_ipv6 *)p,
		    &info->attr->mp_nexthop_global, 0);
#endif /* HAVE_IPV6 */
}

void
bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info)
{
  if (zebra.sock < 0)
    return;

  if (p->family == AF_INET)
    zebra_ipv4_delete (zebra.sock, ZEBRA_ROUTE_BGP, (struct prefix_ipv4 *)p,
		       &info->attr->nexthop, 0);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    zebra_ipv6_delete (zebra.sock, ZEBRA_ROUTE_BGP, (struct prefix_ipv6 *)p,
		       &info->attr->mp_nexthop_global, 0);
#endif /* HAVE_IPV6 */
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  int ret;

  /* Set router zebra is enabled. */
  zebra.enable = 1;

  /* If already has socket then return. */
  if (zebra.sock >= 0)
    {
      vty_out (vty, "already connected to zebra\r\n");
      return CMD_WARNING;
    }

  /* Connect to zebra. */
  ret = zebra_create ();

  if (ret < 0)
    {
      vty_out (vty, "can't connect to zebra\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (zebra.enable)
    vty_out (vty, "router zebra%s", VTY_NEWLINE);
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

void
zebra_init (int enable)
{
  zebra.enable = 0;
  zebra.sock = -1;
  zebra.t_read = NULL;
  zebra.t_write = NULL;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
}
