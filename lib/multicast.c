/* Multicast related function.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "log.h"

int
ipv4_multicast_join (int sock, struct in_addr group, struct in_addr ifa)
{
  int ret;
  struct ip_mreq mreq;

  mreq.imr_multiaddr.s_addr = group.s_addr;
  mreq.imr_interface.s_addr = ifa.s_addr;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		    (char *)&mreq, sizeof (mreq));

  if (ret < 0) 
    log_warn ("setsockopt IP_ADD_MEMBERSHIP");

  return ret;
}
