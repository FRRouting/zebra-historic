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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "log.h"
#include "buffer.h"
#include "network.h"
#include "prefix.h"
#include "client.h"
#include "roken.h"

#include "bgpd.h"
#include "zebra.h"

/* Socket to communicate with zebra daemon */
static int zebra_socket;

void
zebra_init (int enable)
{
  if (!enable)
    return;

  zebra_socket = zebra_connect ();
}

#ifdef HAVE_IPV6
int
zebra_make_request_ip6 (char *buf, int command, 
			struct in6_addr dest, struct in6_addr netmask, 
			struct in6_addr gateway)
{
  char *pnt = buf;
  size_t size = sizeof (struct in6_addr);

  PUTL (size, pnt);
  PUTL (command, pnt);

  bcopy (&dest, pnt, size);
  pnt += size;
  bcopy (&netmask, pnt, size);
  pnt += size;
  bcopy (&gateway, pnt, size);
  pnt += size;

  size = pnt - buf;
  pnt = buf;

  PUTL (size, pnt);

  return size;
}

void
zebra_route_ip6 (command, dest, netmask, gateway)
     int command;
     struct in6_addr dest;
     struct in6_addr gateway;
     struct in6_addr netmask;
{
  int size;
  char buf[512];
  
  size = 0;

  switch (command) {
  case ZEBRA_IPV6_ROUTE_ADD:
  case ZEBRA_IPV6_ROUTE_DELETE:
    size = zebra_make_request_ip6 (buf, command, dest, netmask, gateway);
    break;
  }
  writen (zebra_socket, buf, size);
}
#endif /* HAVE_IPV6 */
