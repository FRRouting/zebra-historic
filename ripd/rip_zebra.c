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
      zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_RIP, p, nexthop, 0);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      zebra_ipv4_delete (zebra->sock, ZEBRA_ROUTE_RIP, p, nexthop, 0);
      break;
    }
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
  zebra->get_all_interface = rip_zebra_get_interface;

  /* Install zebra node. */
  install_node (&zebra_node, config_write_zebra);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
}
