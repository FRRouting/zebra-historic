/*
 * Copyright (C) 1999 Yasuhiro Ohara
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

#include "ospf6d.h"

/* Global Interface List, list of (struct interface *) */
list iflist;

struct zebra
{
  int sockfd;

  struct thread *t_read;
  struct thread *t_write;
} zebra;

void
zebra_get_interface (int sock, u_int16_t length)
{
  struct stream *s;
  int nbyte;
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;
  unsigned long endp;

  /* Allocate read buffer */
  s = stream_new (length + 1);
  nbyte = stream_read (s, sock, length - 3);

  if (nbyte == 0)
    {
      zlog (NULL, LOG_INFO, "connection closed\n");
      return;
    }
  if (nbyte < 0)
    return;

  endp = stream_get_endp (s);

  while (stream_get_getp (s) < endp)
    {
      char tmpnam[INTERFACE_NAMSIZ];

      /* Get interface's name */
      stream_strncpy (tmpnam, s, INTERFACE_NAMSIZ);
      stream_forward (s, INTERFACE_NAMSIZ);

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

	  memcpy ((void *)&(p->u.prefix), stream_pnt (s), plen);
	  stream_forward (s, plen);
          p->prefixlen = stream_getc (s);
          connected->address = p;

          p = prefix_new ();
	  memcpy ((void *)&(p->u.prefix), stream_pnt (s), plen);
	  stream_forward (s, plen);
          connected->destination = p;

          connected_add (ifp, connected);
        }
    }

  stream_free (s);

#ifdef DEBUG_OSPF
  if_dump_all ();
#endif
}

int
ospf_zebra_read (struct thread *thread)
{
  u_int16_t length;
  u_int8_t command;
  int nbyte;
  int sock;
  struct stream *s;

  zebra.t_read = (struct thread *)NULL;
  sock = THREAD_FD (thread);

  s = stream_new (3);
  nbyte = stream_read (s, sock, 3);

  /* zebra socket is closed. */
  if (nbyte == 0)
    {
      zlog (NULL, LOG_INFO, "connection closed socket [%d]\n", sock);
      close (sock);
      return -1;
    }

  length = stream_getw (s);
  command = stream_getc (s);

  switch (command)
    {
    case ZEBRA_GET_ALL_INTERFACE:
      zebra_get_interface (sock, length);
      break;
    default:
      return -1;
    }

  zebra.t_read = thread_add_read (master, ospf_zebra_read,
				  NULL, zebra.sockfd);
  stream_free (s);
  return 0;
}

int
ospf_zebra_init ()
{
  int sockfd = -1;

  iflist = list_init ();
  zebra.sockfd = zebra_connect ();
  if (zebra.sockfd < 0)
    {
      zlog (NULL, LOG_WARNING, "Can't connect zebra.\n");
      return zebra.sockfd;
    }

  zebra_get_all_interface (zebra.sockfd);
  zebra.t_read = thread_add_read (master, ospf_zebra_read, NULL, zebra.sockfd);

  return sockfd;
}

#ifdef TEST
struct thread_master *master;

int main()
{
  struct thread thread;

  iflist = list_init ();
  zlog_default = openzlog ("hoge", ZLOG_STDOUT, ZLOG_OSPF,
                          LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  master = thread_make_master ();
  ospf_zebra_init ();

  while (thread_fetch (master, &thread))
    {
      thread_call (&thread);
#ifdef DEBUG
      thread_master_debug (master);
#endif /* DEBUG */
    }

  return;
}
#endif
