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

struct zebra zebra; /* information about zebra. */

void
ospf6_zebra_get_interface (struct stream *s)
{
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;
  unsigned long endp;

  endp = stream_get_endp (s);

  while (stream_get_getp(s) < endp)
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
#ifdef DEBUG
          char debug_str[64];
#endif /*DEBUG*/
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
#ifdef DEBUG
          inet_ntop (AF_INET6, &connected->address->u.prefix6,
                     debug_str, sizeof (debug_str));
          zvlog_debug ("%s", debug_str);
#endif /*DEBUG*/

          p = prefix_new ();
          memcpy (&p->u.prefix, stream_pnt (s), plen);
          stream_forward (s, plen);

          connected->destination = p;
#ifdef DEBUG
          inet_ntop (AF_INET6, &connected->destination->u.prefix6,
                     debug_str, sizeof (debug_str));
          zvlog_debug ("%s", debug_str);
#endif /*DEBUG*/

          connected_add (ifp, connected);
        }
    }
}

int
ospf6_zebra_read (struct thread *thread)
{
  unsigned long  tmpl;
  unsigned short length;
  unsigned char  command;
  int nbyte;
  struct stream *s = zebra.s;

  zebra.t_read = (struct thread *)NULL;

  nbyte = stream_read (s, zebra.sockfd, 3);

  length = stream_getw (s);
  command = stream_getc (s);

  switch (command)
    {
    case ZEBRA_GET_ALL_INTERFACE:
      nbyte = stream_read (zebra.s, zebra.sockfd, length - 3);
      if (nbyte == 0)
        {
          zvlog_info ("connection closed");
          return -1;
        }
      if (nbyte < 0)
        {
          zvlog_err ("stream_read() failed");
          return -1;
        }

      ospf6_zebra_get_interface (zebra.s);
      break;
    default:
      zvlog_err ("Unknown command from zebra");
      return -1;
    }
  tmpl = command;
  list_add_node (zebra.history, (void *)tmpl);

  zebra.t_read = thread_add_read (master, ospf6_zebra_read,
                                  NULL, zebra.sockfd);
  stream_free (s);
  return 0;
}

int
ospf6_zebra_init ()
{
  int sockfd = -1;
  struct thread thread;

  iflist = list_init ();
  zebra.s = stream_new(ZEBRA_MAX_PACKET_SIZ);
  zebra.history = list_init ();
  zebra.sockfd = zebra_connect ();
  if (zebra.sockfd < 0)
    {
      zlog (NULL, LOG_WARNING, "Can't connect zebra.");
      return zebra.sockfd;
    }

  zebra_get_all_interface (zebra.sockfd);
  zebra.t_read = thread_add_read (master, ospf6_zebra_read,
                                  NULL, zebra.sockfd);

  zvlog_notice ("Waiting for reply from zebra...");
  while (!list_lookup_node (zebra.history, (void *)ZEBRA_GET_ALL_INTERFACE))
    {
      thread_fetch (master, &thread);
      thread_call (&thread);
    }

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
