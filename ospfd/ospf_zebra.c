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

#include "vector.h"
#include "memory.h"
#include "thread.h"
#include "buffer.h"
#include "network.h"
#include "prefix.h"
#include "linklist.h"
#include "client.h"
#include "stream.h"
#include "command.h"
#include "if.h"
#include "log.h"

#include "zebra/zebra.h"
#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_zebra.h"

/* Zebra structure to hold current status. */
extern struct thread_master *master;

void
ospf_zebra_get_interface (struct stream *s, u_int16_t length)
{
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;

  while (s->sp < s->ep)
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

	  p = prefix_new ();
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);

	  connected->destination = p;

	  connected_add (ifp, connected);
	}
    }
}

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

int
zebra_read (struct thread *t)
{
  int nbytes;
  int sock;
  u_int16_t length;
  u_int8_t command;

  sock = THREAD_FD (t);

  /* Read zebra header. */
  nbytes = stream_read (zebra.ibuf, sock, ZEBRA_HEADER_SIZE);

  /* zebra socket is closed. */
  if (nbytes == 0)
    {
      zlog (NULL, LOG_INFO, "connection closed socket [%d]\n", sock);
      close (sock);
      return -1;
    }

  /* zebra read error. */
  if (nbytes < 0)
    {
      zlog (NULL, LOG_INFO, "can't read all packet\n");
      zebra_close ();
      return -1;
    }

  length = stream_getw (zebra.ibuf);
  command = stream_getc (zebra.ibuf);

  /* Read rest of zebra packet. */
  nbytes = stream_read (zebra.ibuf, sock, length - ZEBRA_HEADER_SIZE);

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
    case ZEBRA_IPV4_ROUTE_DELETE:
    case ZEBRA_IPV6_ROUTE_ADD:
    case ZEBRA_IPV6_ROUTE_DELETE:
      return -1;
      break;
    case ZEBRA_GET_ALL_INTERFACE:
      ospf_zebra_get_interface (zebra.ibuf, nbytes);
      break;
    default:
      return -1;
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

  /* Get all interface. */
  zebra_get_all_interface (zebra.sock);

  return 0;
}



DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  int ret;

  /* Set router zebrfa is enabled. */
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

/* Zebra configuration write function. */
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
  "%s(config-router)#",
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

