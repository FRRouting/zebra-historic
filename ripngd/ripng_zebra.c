/* RIPngd and zebra interface.
   Copyright (C) 1998 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "thread.h"
#include "ripngd.h"
#include "zebra.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "route.h"
#include "buffer.h"

extern struct thread_master *master;

/* Zebra configuration structure. */
struct zebra
{
  int enable;			/* Flag for router zebra is enabled or not. */
  int sock;			/* Socket to zebra. */
  int r_ripng;			/* Redistribute ripng. */

  struct thread *t_read;
  struct thread *t_write;
} _zebra;

/* Zebra structure to hold current status. */
struct zebra *zebra = &_zebra;

/* Here, zebra may send interface information or redistributed route. */
zebra_read (struct thread *thread)
{
  u_char buf [512];
  u_int32_t length;
  u_int32_t command;
  int nbyte;
  int sock;
  u_char *pnt = buf;

  sock = thread->u.fd;
  nbyte = readn (sock, buf, 8);

  /* zebra socket is closed. */
  if (nbyte == 0) 
    {
      log ("connection closed socket [%d]\n", sock);
      close (sock);
      zebra->sock = -1;
      return;
    }

  ld_4byte (length, pnt);
  ld_4byte (command, pnt);

  switch (command)
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      break;
    case ZEBRA_GET_ALL_INTERFACE:
      zebra_get_interface (sock, length);
    defautl:
      break;
    }

  zebra->t_read = thread_add_read (master, zebra_read, NULL, 
				   zebra->sock);
}

/* Write buffer to zebra socket. */
zebra_write (struct stream *s)
{
  int nbytes;

  if (zebra->sock >= 0)
    {
      nbytes = writen (zebra->sock, s->data, s->ep);
      if (nbytes != s->ep)
	log ("can't write enough packet\n");

      if (nbytes < 0)
	{
	  close (zebra->sock);
	  zebra->sock = -1;
	}
    }
}

/* RIP configuration write function. */
zebra_config_write (struct vty *vty, vector v)
{
  if (zebra->enable)
    vty_out (vty, "router zebra%s", VTY_NEWLINE);
  if (zebra->r_ripng)
    vty_out (vty, " redistribute ripng%s", VTY_NEWLINE);
}

DEFUN (redistribute_ripng,
       redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute ripng route to zebra daemon\n")
{
  /* Set ripng redistribute flag. */
  zebra->r_ripng;
  return CMD_SUCCESS;
}

/* Make zebra connection. */
zebra_create ()
{
  zebra->sock = zebra_connect ();

  if (zebra->sock < 0)
    return zebra->sock;
  
  zebra->t_read = thread_add_read (master, zebra_read, NULL, 
				   zebra->sock);
  zebra_get_all_interface (zebra->sock);

  return 1;
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Make connection to zebra daemon.")
{
  int ret;

  /* Set router zebra is enabled. */
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    {
      vty_out (vty, "already connected to zebra\r\n");
      return;
    }

  ret = zebra_create ();
  if (ret < 0)
    {
      vty_out (vty, "can't connect to zebra\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

zebra_init ()
{
  /* Set default value to zebra structure. */
  zebra->enable = 0;
  zebra->sock = -1;
  zebra->r_ripng = 0;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (ZEBRA_NODE, &redistribute_ripng_cmd);
}
