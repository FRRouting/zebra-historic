/* zebra connect library 
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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
#include <netdb.h>
#include <arpa/inet.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "bgpd.h"
#include "zebra.h"

/* Socket to communicate with zebra daemon */
static zebra_socket;

zebra_init (int enable)
{
  if (!enable)
    return;

  zebra_socket = zebra_connect ();
}

zebra_connect ()
{
  int sock;
  static int connected = 0;
  struct sockaddr_in serv;
  struct hostent *hp;

  if (connected)
    return;

  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0) 
    {
      perror ("sock");
      exit (1);
    }
  
  serv.sin_family = AF_INET;
  serv.sin_port = htons (ZEBRA_PORT);

  if ((hp = gethostbyname ("localhost")) == NULL)
    log_warn ("can't lookup localhost\n");
  else
    bcopy(hp->h_addr, (char *)&serv.sin_addr, hp->h_length);

  if (connect (sock, (struct sockaddr *) & serv, sizeof (serv)) < 0) 
    perror ("connect");

  return sock;
}

#ifdef HAVE_IPV6
zebra_route_ip6 (command, dest, netmask, gateway)
     int command;
     struct in6_addr dest;
     struct in6_addr gateway;
     struct in6_addr netmask;
{
  int size;
  char buf[512];

  switch (command) {
  case ZEBRA_IPV6_ROUTE_ADD:
  case ZEBRA_IPV6_ROUTE_DELETE:
    size = zebra_make_request_ip6 (buf, command, dest, netmask, gateway);
    break;
  }
  writen (zebra_socket, buf, size);
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_IPV6
zebra_make_request_ip6 (buf, command, dest, netmask, gateway)
     char *buf;
     int command;
     struct in6_addr dest;
     struct in6_addr netmask;
     struct in6_addr gateway;
{
  char bb[64];
  char *pnt = buf;
  size_t size = sizeof (struct in6_addr);

  st_4byte (size, pnt);
  st_4byte (command, pnt);

  bcopy (&dest, pnt, size);
  pnt += size;
  bcopy (&netmask, pnt, size);
  pnt += size;
  bcopy (&gateway, pnt, size);
  pnt += size;

  size = pnt - buf;
  pnt = buf;

  st_4byte (size, pnt);

  return size;
}
#endif /* HAVE_IPV6 */
