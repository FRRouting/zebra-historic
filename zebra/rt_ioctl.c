/* kernel routing table update by ioctl(). Almost for Linux.
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
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>
#include <net/route.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */
#ifdef LINUX_IPV6
#include <linux/in6.h>
#include <linux/ipv6_route.h>
#endif /* LINUX_IPV6 */

#include "zebra.h"
#include "route.h"

/* Routing socket fucntion. If we have netlink use it. */
kernel_routing_socket ()
{
  ;
}

/* Dummy function of routing socket. */
kernel_read (int sock)
{
  ;
}

/* Initialization prototype of struct sockaddr_in. */
static struct sockaddr_in in_proto =
{
#ifdef HAVE_SIN_LEN
  sizeof (struct sockaddr_in), 
#endif /* HAVE_SIN_LEN */
  AF_INET, 0, 0, 0
};

/* Low level OS interface independent routine for updating kernel
   routit table. */
kernel_rt_ip (int type,
	      struct in_addr addr_dest,
	      struct in_addr addr_mask,
	      struct in_addr addr_gate)
{
  int message;
  int ret;
  struct sockaddr_in dest;
  struct sockaddr_in mask;
  struct sockaddr_in gate;

  dest = gate = in_proto;
  dest.sin_addr = addr_dest;
  gate.sin_addr = addr_gate;
  bzero (&mask, sizeof (struct sockaddr_in));
  mask.sin_addr = addr_mask; 
  
  switch (type) 
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      message = SIOCADDRT;
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      message = SIOCDELRT;
      break;
    default:
      log_warn ("Invalid type to kernel_rt_ip %d\n", type);
      return;
      break;
    }
  
  ret = route_ioctl (message, &dest, &mask, &gate);
  return ret;
}	      

kernel_rt_in (int command, struct prefix_in *pin)
{
  int message;
  int ret;
  struct sockaddr_in dest, mask, gate;

  dest = gate = in_proto;
  dest.sin_addr = pin->prefix;
  gate.sin_addr = pin->gate.addr;

  /* Mask setup. */
  bzero (&mask, sizeof (struct sockaddr_in));
  mask.sin_family = AF_INET;
  masklen2ip (pin->mask, &mask.sin_addr);
  
  switch (command) 
    {
    case ZEBRA_IPV4_ROUTE_ADD:
      message = SIOCADDRT;
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
      message = SIOCDELRT;
      break;
    default:
      log_warn ("Invalid command to kernel_rt_ip %d\n", command);
      return;
      break;
    }
  
  ret = route_ioctl (message, &dest, &mask, &gate);
  return ret;
}	      

#ifdef HAVE_IPV6
/* OK, I'm changing basic interface to the kernel. */
kernel_in6 (int type,
            struct in6_addr *prefix,
            u_char prefixlen,
            struct in6_addr *gateway,
            unsigned int ifindex)
{
  int ret;
  int sock;
  struct in6_rtmsg rtm;
    
  bzero (&rtm, sizeof (struct in6_rtmsg));

  rtm.rtmsg_flags |= RTF_UP;
  rtm.rtmsg_metric = 1;
  memcpy (&rtm.rtmsg_dst, prefix, sizeof (struct in6_addr));
  rtm.rtmsg_dst_len = prefixlen;

  rtm.rtmsg_flags |= RTF_GATEWAY;
  memcpy (&rtm.rtmsg_gateway, gateway, sizeof (struct in6_addr));

  if (ifindex != 0)
    rtm.rtmsg_ifindex = ifindex;
  else
    rtm.rtmsg_ifindex = 0;
  
  sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      log ("can't make socket\n");
      return -1;
    }

  if (type == ZEBRA_IPV6_ROUTE_ADD)
    {
      /* rtm.rtmsg_type = RTMSG_NEWROUTE; */
      ret = ioctl (sock, SIOCADDRT, &rtm);
      if (ret < 0)
	{
	  log ("can't add ipv6 route: %s\n", strerror(errno));
	  ret = errno;
	  close (sock);
	  return ret;
	}
    }
  else
    {
      /* rtm.rtmsg_type = RTMSG_DELROUTE; */
      ret = ioctl (sock, SIOCDELRT, &rtm);
      if (ret < 0)
	{
	  log ("can't delete ipv6 route: %s\n", strerror(errno));
	  ret = errno;
	  close (sock);
	  return ret;
	}
    }
  close (sock);

  return ret;
}

kernel_add_in6 (struct in6_addr *prefix,
		u_char prefixlen,
		struct in6_addr *gateway,
		unsigned int ifindex)
{
  kernel_in6 (ZEBRA_IPV6_ROUTE_ADD, prefix, prefixlen, gateway, ifindex);
}

kernel_delete_in6 (struct in6_addr *prefix,
		   u_char prefixlen,
		   struct in6_addr *gateway,
		   unsigned int ifindex)
{
  kernel_in6 (ZEBRA_IPV6_ROUTE_DELETE, prefix, prefixlen, gateway, ifindex);
}

#if 0
/* Hmm. never called... */
kernel_rt_ip6 (int type,
	       struct in6_addr addr_dest,
	       struct in6_addr addr_mask,
	       struct in6_addr addr_gate)
{
  ;
}
#endif

/* Same as kernel_rt_ip() but this function is IPv6 version. */
kernel_rt_in6_index (int type, struct prefix_in6 *pin6, unsigned int ifindex)
{
  int ret;
  int sock;
  struct in6_rtmsg rtm;
    
  bzero (&rtm, sizeof (struct in6_rtmsg));

  rtm.rtmsg_flags |= RTF_UP;
  rtm.rtmsg_metric = 1;
  memcpy (&rtm.rtmsg_dst, &pin6->prefix, sizeof (struct in6_addr));
  rtm.rtmsg_dst_len = pin6->mask;

  rtm.rtmsg_flags |= RTF_GATEWAY;
  memcpy (&rtm.rtmsg_gateway, &pin6->gate.addr, sizeof (struct in6_addr));


  if (ifindex != 0)
    rtm.rtmsg_ifindex = ifindex;

#if 0
  if (IN6_IS_ADDR_LINKLOCAL(&rtm.rtmsg_gateway))
    {
      index = if_index_address (&rtm.rtmsg_gateway);
      rtm.rtmsg_ifindex = index;
    }
  else
    rtm.rtmsg_ifindex = 0;
#endif /* 0 */
  
  sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      log ("can't make socket\n");
      return -1;
    }

  if (type == ZEBRA_IPV6_ROUTE_ADD)
    {
      /* rtm.rtmsg_type = RTMSG_NEWROUTE; */
      ret = ioctl (sock, SIOCADDRT, &rtm);
      if (ret < 0)
	{
	  log ("can't add ipv6 route: %s\n", strerror(errno));
	  ret = errno;
	  close (sock);
	  return ret;
	}
    }
  else
    {
      /* rtm.rtmsg_type = RTMSG_DELROUTE; */
      ret = ioctl (sock, SIOCDELRT, &rtm);
      if (ret < 0)
	{
	  log ("can't delete ipv6 route: %s\n", strerror(errno));
	  ret = errno;
	  close (sock);
	  return ret;
	}
    }
  close (sock);

  return ret;
}

kernel_rt_in6 (int type, struct prefix_in6 *pin6)
{
  kernel_rt_in6_index (type, pin6, 0);
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_OLD_RTENTRY
#define rtentry ortentry
#endif /* HAVE_OLD_RTENTRY */

route_ioctl (int type,
	     struct sockaddr_in *dest,
	     struct sockaddr_in *mask,
	     struct sockaddr_in *gate)
{
  int sock;
  int ret;
  struct rtentry rtentry;
  
  bzero (&rtentry, sizeof (struct rtentry));

  memcpy (&rtentry.rt_dst, dest, sizeof (struct sockaddr_in));
#ifndef SUNOS_5
  memcpy (&rtentry.rt_genmask, mask, sizeof (struct sockaddr_in));
#endif /* SUNOS_5 */
  memcpy (&rtentry.rt_gateway, gate, sizeof (struct sockaddr_in));

  /* Flag settings. */
  if (ip_masklen (mask->sin_addr) == 32)
    rtentry.rt_flags |= RTF_HOST;
  if (gate->sin_addr.s_addr != INADDR_ANY)
    rtentry.rt_flags |= RTF_GATEWAY;
  rtentry.rt_flags |= RTF_UP;

  /* Open socket for ioctl. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      log ("can't make socket\n");
      return -1;
    }

  ret = ioctl (sock, type, &rtentry);

  if (ret < 0)
    {
      if (errno == EEXIST)
	{
	  close (sock);
	  return ZEBRA_ERR_RTEXIST;
	}
      if (errno == ENETUNREACH)
	{
	  close (sock);
	  return ZEBRA_ERR_RTUNREACH;
	}
      if (errno == EPERM)
	{
	  close (sock);
	  return ZEBRA_ERR_EPERM;
	}

      close (sock);
      log_warn ("write : %s (%d)\n", strerror (errno), errno);
      return 1;
    }
  close (sock);

  return ret;
}
