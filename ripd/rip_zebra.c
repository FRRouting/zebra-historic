/*
 * RIPd and zebra interface.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include "thread.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "ripd.h"
#include "buffer.h"
#include "network.h"
#include "client.h"
#include "log.h"

#include "zebra/zebra.h"

extern struct thread_master *master;

/* Zebra configuration structure. */
struct zebra
{
  /* Flag for router zebra is enabled or not. */
  int enable;			

  /* Socket of zebra. */
  int sock;			

  struct thread *t_read;
  struct thread *t_write;
} zebra;

/* RIPd to zebra command interface. */
void
rip_zebra (int command, struct prefix_ipv4 *p, struct in_addr *nexthop)
{
  if (zebra.sock < 0)
    return;

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      zebra_ipv4_add (zebra.sock, ZEBRA_ROUTE_RIP, p, nexthop, 0);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      zebra_ipv4_delete (zebra.sock, ZEBRA_ROUTE_RIP, p, nexthop, 0);
      break;
    }
}

/* Here, zebra may send interface information or redistributed route. */
int
zebra_read (struct thread *thread)
{
  int ret;
  u_char buf [512];
  u_int16_t length;
  u_int8_t command;
  int nbytes;
  int sock;
  u_char *pnt = buf;

  sock = thread->u.fd;
  nbytes = readn (sock, buf, 3);

  /* zebra socket is closed. */
  if (nbytes == 0) 
    {
      zlog (NULL, LOG_INFO, "connection closed socket [%d]", sock);
      close (sock);
      zebra.sock = -1;
      return nbytes;
    }

  GETW (length, pnt);
  GETC (command, pnt);

  if (command != ZEBRA_GET_ALL_INTERFACE)
    return -1;

  ret = zebra_get_interface (sock, length);

  /* zebra socket is closed. */
  if (ret == 0)
    {
      zlog (NULL, LOG_INFO, "connection closed socket [%d]", sock);
      close (sock);
      zebra.sock = -1;
      return ret;
    }

  zebra.t_read = thread_add_read (master, zebra_read, NULL, 
				   zebra.sock);

  return 0;
}

/* Create new zebra connection. */
void
zebra_create ()
{
  struct thread t;

  zebra.enable = 0;
  zebra.sock = zebra_connect ();
  if (zebra.sock < 0)
    {
      zlog (NULL, LOG_INFO, "can't make socket to zebra");
      exit (1);
    }

  zebra_get_all_interface (zebra.sock);

  t.u.fd = zebra.sock;
  zebra_read (&t);
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Make connection to zebra daemon\n"
       "\n")
{
  vty->node = ZEBRA_NODE;
  zebra.enable = 1;

  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
config_write_zebra (struct vty *vty)
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
zebra_init ()
{
  /* Connect to zebra and get interface information. */
  zebra_create ();

  /* Install zebra node. */
  install_node (&zebra_node, config_write_zebra);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
}
