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

#include "ripngd/ripngd.h"

#include "zebra/zebra.h"

extern struct thread_master *master;

/* Zebra configuration structure. */
struct zebra
{
  int enable;			/* Flag for router zebra is enabled or not. */
  int sock;			/* Socket to zebra. */

  u_char redist_static;		/* Redistribute static route. */
  u_char redist_connect;	/* Redistribute connected route. */
  u_char redist_ospf;		/* Redistribute ospf route. */
  u_char redist_bgp;		/* Redistribute bgp route. */
  u_char redist_ripng;		/* Redistribute ripng route. Default is on. */

  struct thread *t_read;	/* Read thead of zebra connection. */
  struct thread *t_write;	/* Write thread of zebra connection. */

  struct stream *ibuf;
} zebra;

/* Read packet from zebra. */
int
zebra_read (struct thread *t)
{
  int nbytes;
  int sock;
  zebra_size_t length;
  zebra_command_t command;

  sock = THREAD_FD(t);

  /* Clear input buffer. */
  stream_reset (zebra.ibuf);

  /* Read zebra header. */
  nbytes = stream_read (zebra.ibuf, sock, ZEBRA_HEADER_SIZE);

  /* zebra socket is closed. */
  if (nbytes == 0) 
    {
      zlog (NULL, LOG_ERR, "connection closed socket [%d]", sock);
      /* zebra_close (); */
      return -1;
    }

  /* zebra read error. */
  if (nbytes < 0)
    {
      zlog (NULL, LOG_ERR, "cant read all packet");
      /* zebra_close (); */
      return -1;
    }

  /* Fetch length and command. */
  length = stream_getw (zebra.ibuf);
  command = stream_getc (zebra.ibuf);

  length -= ZEBRA_HEADER_SIZE;

  /* Read rest of zebra packet. */
  stream_read (zebra.ibuf, sock, length);

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      printf ("IPv4 route is added from zebra\n");
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      printf ("IPv4 route is deleted from zebra\n");
      break;
    case ZEBRA_IPV6_ROUTE_ADD:
      printf ("IPv6 route is added from zebra\n");
      break;
    case ZEBRA_IPV6_ROUTE_DELETE:
      printf ("IPv6 route is deleted from zebra\n");
      break;
    case ZEBRA_GET_ALL_INTERFACE:
      ripng_zebra_get_interface (zebra.ibuf);
      break;
    default:
      break;
    }

  /* Re-register myself. */
  zebra.t_read = thread_add_read (master, zebra_read, NULL, zebra.sock);

  return 0;
}

int
zebra_sock ()
{
  return zebra.sock;
}

/* Write buffer to zebra socket. */
int
zebra_write (struct stream *s)
{
  int nbytes;

  nbytes = 0;

  if (zebra.sock >= 0)
    {
      nbytes = writen (zebra.sock, STREAM_DATA (s), stream_get_endp (s));
      if (nbytes != stream_get_endp (s))
	{
	  zlog (NULL, LOG_ERR, "can't write enough packet");
	  return nbytes;
	}

      if (nbytes < 0)
	{
	  close (zebra.sock);
	  zebra.sock = -1;
	  return nbytes;
	}
    }
  return nbytes;
}

/* Make zebra connection. */
int
zebra_create ()
{
  if (zebra.sock < 0)
    {
      zebra.sock = zebra_connect ();

      if (zebra.sock < 0)
	return zebra.sock;
  
      zebra.ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
      zebra.t_read = thread_add_read (master, zebra_read, NULL, zebra.sock);
      zebra_get_all_interface (zebra.sock);
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
  zebra.enable = 1;

  /* If already has socket then return. */
  if (zebra.sock >= 0)
    return CMD_SUCCESS;

  /* Try to create zebra connection. */
  if (zebra_create () < 0)
    {
      vty_out (vty, "Can't connect to zebra.\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_redistribute_ripng,
       no_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute control\n"
       "RIPng route\n")
{
  zebra.redist_ripng = 0;
  return CMD_SUCCESS;
}

/* RIPng configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zebra.redist_ripng)
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ripng%s", VTY_NEWLINE);
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

/* Initialize zebra structure and it's commands. */
void
zebra_init ()
{
  /* Clear all variables. */
  bzero (&zebra, sizeof (struct zebra));

  /* Set default value to the zebra structure. */
  zebra.enable = 1;
  zebra.redist_ripng = 1;

  /* Socket is not active at this point. */
  zebra.sock = -1;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (ZEBRA_NODE, &config_end_cmd);
  install_element (ZEBRA_NODE, &config_exit_cmd);
  install_element (ZEBRA_NODE, &config_help_cmd);
  install_element (ZEBRA_NODE, &no_redistribute_ripng_cmd);
}
