/* OSPF network related functions
   Copyright (C) 1999 Toshiaki Takada

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

#include <zebra.h>

#include "thread.h"
#include "log.h"
#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"

/* Make ospfd's server socket. */
int
ospf_serv_sock (struct interface *ifp, int family)
{
  int ospf_sock;

  ospf_sock = socket (family, SOCK_RAW, IPPROTO_OSPFIGP);
  if (ospf_sock < 0)
    return ospf_sock;

  return ospf_sock;
}

/* Join to the OSPF ALL SPF ROUTERS multicast group. */
int
ospf_if_add_allspfrouters (int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  inet_aton (OSPF_ALLSPFROUTERS, &m.imr_multiaddr);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	      (char *) &m, sizeof (struct ip_mreq));

  if (ret < 0)
    zlog (NULL, LOG_WARNING, "can't setsockopt IP_ADD_MEMBERSHIP:%s\n",
	  strerror (errno));

  return ret;
}

/* Join to the OSPF ALL Designated ROUTERS multicast group. */
int
ospf_if_add_alldrouters (int sock, struct prefix *p)
{
  struct ip_mreq m;
  int ret;

  bzero (&m, sizeof (m));

  inet_aton (OSPF_ALLDROUTERS, &m.imr_multiaddr);
  m.imr_interface = p->u.prefix4;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (char *) &m, sizeof (struct ip_mreq));
  if (ret < 0)
    zlog (NULL, LOG_WARNING, "can't setsockopt IP_ADD_MEMBERSHIP:%s\n",
	  strerror (errno));

  return ret;
}
