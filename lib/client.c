/*
 * zebra's client library.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
#include "prefix.h"
#include "client.h"
#include "stream.h"
#include "network.h"
#include "roken.h"

int
zebra_redistribute_send (int command, int sock, int type)
{
  int ret;
  struct stream *s;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Total length of the messages. */
  stream_putw (s, 4);
  
  stream_putc (s, command);
  stream_putc (s, type);

  ret = writen (sock, s->data, 4);

  stream_free (s);

  return ret;
}

struct zmsg_ipv4
{
  int commnad;
  int type;
  int flags;
  struct prefix_ipv4 *p;
  struct in_addr *nexthop;
  unsigned int ifindex;
};

/* Make a IPv4 route add/delete packet and send it to zebra. */
static int
zebra_ipv4_route (int sock, int command, int type, int flags,
		  struct prefix_ipv4 *p, struct in_addr *nexthop, 
		  unsigned int ifindex)
{
  int ret;
  struct stream *s;
  u_short psize;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Length place holder. */
  stream_putw (s, 0);

  /* Put command, type and nexthop. */
  stream_putc (s, command);
  stream_putc (s, type);
  stream_putc (s, flags);
  stream_write (s, (u_char *)nexthop, 4);

  /* Put prefix information. */
  stream_putl (s, ifindex);
  psize = PSIZE (p->prefixlen);
  stream_putc (s, p->prefixlen);
  stream_write (s, (u_char *)&p->prefix, psize);

  /* Put length at the first point of the stream. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

int
zebra_ipv4_add (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv4_route (sock, ZEBRA_IPV4_ROUTE_ADD, type, flags, p, 
			   nexthop, ifindex);
}

int
zebra_ipv4_delete (int sock, int type, int flags, struct prefix_ipv4 *p,
		struct in_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv4_route (sock, ZEBRA_IPV4_ROUTE_DELETE, type, flags, p,
			   nexthop, ifindex);
}

#ifdef HAVE_IPV6
/* Make a IPv6 route add/delete packet and send it to zebra. */
static int
zebra_ipv6_route (int command, int sock, int type, int flags,
		  struct prefix_ipv6 *p, struct in6_addr *nexthop, 
		  unsigned int ifindex)
{
  int ret;
  struct stream *s;
  u_short psize;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  /* Reserve size area then set command, type and nexthop.  */
  stream_putw (s, 0);
  stream_putc (s, command);
  stream_putc (s, type);
  stream_putc (s, flags);
  stream_write (s, (u_char *)nexthop, 16);

  /* Put prefix information. */
  stream_putl (s, ifindex);
  psize = PSIZE (p->prefixlen);
  stream_putc (s, p->prefixlen);
  stream_write (s, (u_char *)&p->prefix, psize);

  /* Write packet size. */
  stream_set_putp (s, 0);
  stream_putw (s, stream_get_endp (s));

  ret = writen (sock, s->data, stream_get_endp (s));

  stream_free (s);

  return ret;
}

int
zebra_ipv6_add (int sock, int type, int flags, struct prefix_ipv6 *p,
		struct in6_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, sock, type, flags, p, 
			   nexthop, ifindex);
}

int
zebra_ipv6_delete (int sock, int type, int flags, struct prefix_ipv6 *p,
		   struct in6_addr *nexthop, unsigned int ifindex)
{
  return zebra_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, sock, type, flags, p, 
			   nexthop, ifindex);
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
  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
  serv.sin_port = htons (ZEBRA_PORT);
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

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
