/*
 * Additional zebra's client library.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <zebra.h>

#include "zebra/zebra.h"
#include "stream.h"
#include "network.h"
#include "thread.h"
#include "memory.h"
#include "prefix.h"
#include "if.h"
#include "client.h"
#include "zclient.h"
#include "log.h"

/* Vty events */
enum event {ZEBRA_READ, ZEBRA_WRITE};

static void zebra_event (enum event, struct zebra *);

/* Allocate zebra structure. */
struct zebra *
zebra_new ()
{
  struct zebra *new;

  new = XMALLOC (MTYPE_ZEBRA, sizeof (struct zebra));
  bzero (new, sizeof (struct zebra));
  return new;
}

/* Make zebra connection. */
int
zebra_create (struct zebra *zebra)
{
  int i;

  /* Check enable flag and socket. */
  if (! zebra->enable || zebra->sock >= 0)
    return 0;

  /* Make socket. */
  zebra->sock = zebra_connect ();
  if (zebra->sock < 0)
    return -1;

  /* Input buffer. */
  zebra->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  
  /* Create read thread. */
  zebra_event (ZEBRA_READ, zebra);

  /* Get all interfaces.  Now interface information is automatically
     send from zebra so this isn't needed. */
  /* zebra_get_all_interface (zebra->sock); */

  /* Flush all redistribute request. */
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zebra->redist_default && zebra->redist[i])
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, i);

  return 0;
}

/* Close zebra connection. */
void
zebra_close (struct zebra *zebra)
{
  /* Close socket. */
  if (zebra->sock > 0)
    {
      close (zebra->sock);
      zebra->sock = -1;
    }

  stream_free (zebra->ibuf);

  zebra->t_read = NULL;
  zebra->t_write = NULL;
}

/* zebra message read function. */
int
zebra_read (struct thread *thread)
{
  int nbytes;
  int sock;
  zebra_size_t length;
  zebra_command_t command;
  struct zebra *zebra;
  int ret;

  /* Get socket to zebra. */
  sock = THREAD_FD (thread);
  zebra = THREAD_ARG (thread);

  /* Clear input buffer. */
  stream_reset (zebra->ibuf);

  /* Read zebra header. */
  nbytes = stream_read (zebra->ibuf, sock, ZEBRA_HEADER_SIZE);

  /* zebra socket is closed. */
  if (nbytes == 0) 
    {
      zlog (NULL, LOG_ERR, "zebra connection closed socket [%d].", sock);
      zebra_close (zebra);
      return -1;
    }

  /* zebra read error. */
  if (nbytes < 0)
    {
      zlog (NULL, LOG_ERR, "Can't read all packet.");
      zebra_close (zebra);
      return -1;
    }

  /* Fetch length and command. */
  length = stream_getw (zebra->ibuf);
  command = stream_getc (zebra->ibuf);

  /* Length check. */
  if (length >= zebra->ibuf->size)
    {
      stream_free (zebra->ibuf);
      zebra->ibuf = stream_new (length + 1);
    }

  length -= ZEBRA_HEADER_SIZE;

  /* Read rest of zebra packet. */
  stream_read (zebra->ibuf, sock, length);

  switch (command)
    {
    case ZEBRA_INTERFACE_ADD:
      if (zebra->interface_add)
	ret = (*zebra->interface_add) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_DELETE:
      if (zebra->interface_delete)
	ret = (*zebra->interface_delete) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_ADDRESS_ADD:
      if (zebra->interface_address_add)
	ret = (*zebra->interface_address_add) (command, zebra, length);
      break;
    case ZEBRA_INTERFACE_ADDRESS_DELETE:
      if (zebra->interface_address_delete)
	ret = (*zebra->interface_address_delete) (command, zebra, length);
      break;
    case ZEBRA_IPV4_ROUTE_ADD:
      if (zebra->ipv4_route_add)
	ret = (*zebra->ipv4_route_add) (command, zebra, length);
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      if (zebra->ipv4_route_delete)
	ret = (*zebra->ipv4_route_delete) (command, zebra, length);
      break;
    case ZEBRA_IPV6_ROUTE_ADD:
      if (zebra->ipv6_route_add)
	ret = (*zebra->ipv6_route_add) (command, zebra, length);
      break;
    case ZEBRA_IPV6_ROUTE_DELETE:
      if (zebra->ipv6_route_delete)
	ret = (*zebra->ipv6_route_delete) (command, zebra, length);
      break;
#if 0
    case ZEBRA_GET_ALL_INTERFACE:
      if (zebra->get_all_interface)
	ret = (*zebra->get_all_interface) (command, zebra, length);
      break;
#endif /* 0 */
    default:
      break;
    }

  /* Register read thread. */
  zebra_event (ZEBRA_READ, zebra);

  return 0;
}

extern struct thread_master *master;

static void
zebra_event (enum event event, struct zebra *zebra)
{
  switch (event)
    {
    case ZEBRA_READ:
      zebra->t_read = thread_add_read (master, zebra_read, zebra, zebra->sock);
      break;
    case ZEBRA_WRITE:
      break;
    }
}
