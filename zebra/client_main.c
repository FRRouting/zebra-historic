/* GNU Zebra client test main routine.
   Copyright (C) 1997 Kunihiro Ishiguro

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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <netdb.h>
#include <arpa/inet.h>
#include "zebra.h"
#include "route.h"

/* Zebra test client program name. */
char *progname;

/* IPv4 route add and delete test. */
void
zebra_test_v4 (int sock)
{
  struct prefix_in pin;

  str2prefix_in ("10.0.0.0/8", &pin);
  inet_aton ("203.181.89.241", &pin.gate.addr);
  pin.type = ZEBRA_ROUTE_STATIC;
  
  zebra_ipv4_route (ZEBRA_IPV4_ROUTE_ADD, sock, &pin);
  sleep (5);
  zebra_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, sock, &pin);
}

#ifdef HAVE_IPV6
/* IPv6 route add and delete test. */
void
zebra_test_v6 (int sock)
{
  struct prefix_in6 *pin6;

  pin6 = (struct prefix_in6 *) str2routev6 ("fe80:800::/64");
  inet_pton (AF_INET6, "::1", &(pin6->gate.addr));
  pin6->type = ZEBRA_ROUTE_STATIC;

  zebra_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, sock, pin6);
  sleep (5);
  zebra_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, sock, pin6);
}
#endif /* HAVE_IPV6 */

int
main (int argc, char **argv)
{
  char *p;
  int sock;

  /* Preserve my name. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Establish connection to zebra. */
  sock = zebra_connect ();
  if (sock < 0) 
    {
      fprintf (stderr, "Can't connect to zebra daemon\n");
      exit (1);
    }

  /* OK, test now */
  zebra_test_v4 (sock);

#ifdef HAVE_IPV6
  zebra_test_v6 (sock);
#endif /* HAVE_IPV6 */

  /* Finish connection. */
  close (sock);

  return 0;
}
