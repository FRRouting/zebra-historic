/* zebra's client library.
   Copyright (C) 1997, 1998 Kunihiro Ishiguro

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
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <netdb.h>

#include "zebra.h"
#include "route.h"
#include "buffer.h"

/* Make a IPv4 route add/delete packet and send it to zebra. */
void
zebra_ipv4_route_nexthop (u_char command, 
			  int sock, 
			  struct prefix_in *pin,
			  struct in_addr nexthop)
{
  struct stream *s;
  u_short size;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Length place holder. */
  stream_putw (s, 0);

  /* Put command, type and nexthop. */
  stream_putc (s, command);
  stream_putc (s, pin->type);
  stream_write (s, (u_char *)&nexthop, 4);

  /* Put prefix information. */
  size = PSIZE (pin->mask);
  stream_putc (s, pin->mask);
  stream_write (s, (u_char *)&pin->prefix, size);

  /* Put length at the first point of the stream. */
  size = htons (s->ep);
  stream_set_cursor (s, 0);
  stream_write (s, (u_char *)&size, 2);

  writen (sock, s->data, s->ep);

  stream_free (s);
}

/* In case of pin has nexthop. */
void
zebra_ipv4_route (u_char command, int sock, struct prefix_in *pin)
{
  zebra_ipv4_route_nexthop (command, sock, pin, pin->gate.addr);
}

#ifdef HAVE_IPV6
/* Make a IPv6 route add/delete packet and send it to zebra. */
void
zebra_ipv6_route_nexthop (u_char command, 
			  int sock, 
			  struct prefix_in6 *pin6,
			  struct in6_addr *nexthop)
{
  struct stream *s;
  u_short size;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);
  stream_putw (s, 0);
  stream_putc (s, command);
  stream_putc (s, pin6->type);
  stream_write (s, (u_char *)nexthop, 16);

  /* Dummy index */
  stream_putc (s, 0);
  size = PSIZE (pin6->mask);
  stream_putc (s, pin6->mask);
  stream_write (s, (u_char *)&pin6->prefix, size);

  size = htons (s->ep);
  stream_set_cursor (s, 0);
  stream_write (s, (u_char *)&size, 2);

  writen (sock, s->data, s->ep);

  stream_free (s);
}

/* In case of pin6 has nexthop. */
void
zebra_ipv6_route (u_char command, int sock, struct prefix_in6 *pin6)
{
  zebra_ipv6_route_nexthop (command, sock, pin6, &pin6->gate.addr);
}
#endif /* HAVE_IPV6 */

void
zebra_get_all_interface (int sock)
{
  u_char mes[] = {0, 3, ZEBRA_GET_ALL_INTERFACE};

  writen (sock, mes, 3);
}

void
zebra_get_hostinfo (int sock)
{
  u_char mes[] = {0, 3, ZEBRA_GET_HOSTINFO};
  
  writen (sock, mes, 3);
}

/* Make socket to zebra daemon. Return zebra socket. */
int
zebra_connect ()
{
  int sock;
  int ret;
  struct sockaddr_in serv;
  struct hostent *hp;

  /* We should think about IPv6 connection. */
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    return sock;
  
  /* Make server socket. */ 
  serv.sin_family = AF_INET;
  serv.sin_port = htons (ZEBRA_PORT);
#ifdef HAVE_SINLEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SINLEN */

  /* Lookup hostname. */
  hp = gethostbyname ("localhost");
  if (hp == NULL)
    {
      fprintf (stderr, "can't lookup hostname.\n");
      return -1;
    }
  else
    memcpy (&serv.sin_addr, hp->h_addr, hp->h_length);

  ret = connect (sock, (struct sockaddr *) &serv, sizeof (serv));
  if (ret < 0)
    return ret;

  return sock;
}
