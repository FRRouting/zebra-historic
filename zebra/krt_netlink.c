/* Kernel routing table updates using netlink over Linux/GNU system.
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
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <errno.h>
/* #include <linux/route.h> */
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "linklist.h"
#include "vector.h"
#include "if.h"
#include "log.h"
#include "zebra.h"

#ifndef _PATH_DEV_ROUTE
#define _PATH_DEV_ROUTE          "/dev/route"
#endif /* _PATH_DEV_ROUTE */

#ifndef _PATH_DEV_IPV6_ROUTE
#define _PATH_DEV_IPV6_ROUTE     "/dev/ipv6_route"
#endif /* _PATH_DEV_IPV6_ROUTE */

/* This information coming from /usr/include/linux/route.h */
struct netlink_rtinfo
{
	unsigned long	rtmsg_type;
	struct sockaddr rtmsg_dst;
	struct sockaddr rtmsg_gateway;
	struct sockaddr rtmsg_genmask;
	short 		rtmsg_flags;
	short		rtmsg_metric;
	char		rtmsg_device[16];
};

#define RTMSG_NEWROUTE		0x01
#define RTMSG_DELROUTE		0x02
#define RTMSG_NEWDEVICE		0x11
#define RTMSG_DELDEVICE		0x12

/* Socket interface to kernel */
static int routing_socket;
static int routing_socket_v6;

/* Open netlink socket */
#if 0
int
zebra_routing_socket ()
{
  routing_socket = open (_PATH_DEV_ROUTE, O_RDWR);
  if (routing_socket < 0)
    {
      if (errno == ENODEV)
	log_warn ("There is no %s device\n", _PATH_DEV_ROUTE);
      else
	log_warn ("Can't open %s device.\n%s\n", _PATH_DEV_ROUTE, 
		  strerror (errno));
      return -1;
    }

  /* 
     {
     int val = 1;
     ioctl (routing_socket, FIONBIO, &val);
     }
     fd_checkin (routing_socket); ??
  */
  return routing_socket;
}
#endif /* 0 */

#ifdef HAVE_IPV6
/* Open netlink socket for ipv6. */
int
zebra_routing_socket_v6 ()
{
  routing_socket_v6 = open (_PATH_DEV_IPV6_ROUTE, O_RDWR);

  if (routing_socket_v6 < 0)
    {
      if (errno == ENODEV)
	log_warn ("There is no %s device\n", _PATH_DEV_IPV6_ROUTE);
      else
	log_warn ("Can't open %s device.\n%s\n", _PATH_DEV_IPV6_ROUTE,
		  strerror (errno));
      return -1;
    }
  return routing_socket_v6;
}
#endif /* HAVE_IPV6 */

/* Read data from netlink interface. */
void
netlink_read ()
{
  int ret;
  struct netlink_rtinfo netlink;
  struct sockaddr dest, gate, mask;
  short flags, metric;
  struct interface *ifp;

  /* Reading up struct netlink_rtinfo from netlink. */
  ret = read (routing_socket, &netlink, sizeof (netlink));
  if (ret < 0)
    {
      log_warn ("read : %s\n", strerror (errno));
      return -1;
    }
  if (ret != sizeof (netlink))
    {
      log_warn ("netlink message size mismatch\n");
      return -1;
    }

  flags = netlink.rtmsg_flags;
  metric = netlink.rtmsg_metric;

  switch (netlink.rtmsg_type)
    {
    case RTMSG_NEWROUTE:
    case RTMSG_DELROUTE:
      dest = netlink.rtmsg_dst;
      gate = netlink.rtmsg_gateway;
      mask = netlink.rtmsg_genmask;
      break;
    case RTMSG_NEWDEVICE:
      ifp = if_lookup_by_name (netlink.rtmsg_device);
      if (ifp == NULL)
	ifp = if_new ();
      else
	if_up (ifp);
      break;
    case RTMSG_DELDEVICE:
      ifp = if_lookup_by_name (netlink.rtmsg_device);
      if_down (ifp);
      break;
    default:
      break;
    }
}

/**/
void
netlink_write (int type,
	       struct sockaddr_in *dest,
	       struct sockaddr_in *mask,
	       struct sockaddr_in *gate)
{
  int ret;
  struct netlink_rtinfo netlink;

  bzero (&netlink, sizeof (netlink));

  netlink.rtmsg_type = type;

  memcpy (&netlink.rtmsg_dst, dest, sizeof (struct sockaddr_in));
  memcpy (&netlink.rtmsg_genmask, mask, sizeof (struct sockaddr_in));
  memcpy (&netlink.rtmsg_gateway, gate, sizeof (struct sockaddr_in));

  printf ("ok netlink start\n");

  ret = write (routing_socket, &netlink, sizeof (netlink));
  if (ret != sizeof (netlink))
    {
      perror ("write");
    }
}

static struct sockaddr_in in_proto = {
#ifdef HAVE_SIN_LEN
  sizeof (struct sockaddr_in), 
#endif /* HAVE_SIN_LEN */
  AF_INET, 0, 0, 0};

/* Low level OS interface using netlink interface */
#if 0
kernel_rt_ip (int type,
	      struct in_addr addr_dest,
	      struct in_addr addr_mask,
	      struct in_addr addr_gate)
{
  int message;
  struct sockaddr_in dest, mask, gate;

  dest = gate = mask = in_proto;

  dest.sin_addr = addr_dest;
  mask.sin_addr = addr_mask;
  gate.sin_addr = addr_gate;

  switch (type)
    {
    case ZEBRA_ROUTE_ADD:
      message = RTMSG_NEWROUTE;
      break;
    case ZEBRA_ROUTE_DELETE:
      message = RTMSG_DELROUTE;
      break;
    default:
      break;
    }
  netlink_write (message, &dest, &mask, &gate);
}
#endif /* 0 */
