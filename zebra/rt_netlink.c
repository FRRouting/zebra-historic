/* Kernel routing table updates using netlink over GNU/Linux system.
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
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#include <asm/types.h>
#include <linux/rtnetlink.h>

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "zebra.h"
#include "prefix.h"
#include "connected.h"
#include "rib.h"

/* Socket interface to kernel */
struct 
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
} netlink = { -1, 0, {0} };

/* Make socket for Linux netlink inteface. */
int
netlink_socket ()
{
  int ret;
  struct sockaddr_nl snl;

  netlink.sock = socket (AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (netlink.sock < 0)
    {
      log ("Can't open netlink socket: %s\n", strerror (errno));
      return -1;
    }

  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;
  snl.nl_groups = 0;
  
  /* Bind the socket to the netlink structure for anything. */
  ret = bind (netlink.sock, (struct sockaddr *) &snl, sizeof snl);
  if (ret < 0)
    {
      log ("Can't bind netlink socket to group 0: %s\n", strerror (errno));
      close (netlink.sock);
      netlink.sock = -1;
      return -1;
    }
  return ret;
}

/* Get type specified information from netlink. */
int
netlink_request (int family, int type)
{
  int ret;
  struct sockaddr_nl snl;

  struct
  {
    struct nlmsghdr nlh;
    struct rtgenmsg g;
  } req;


  /* Check netlink socket. */
  if (netlink.sock < 0)
    {
      log ("netlink socket isn't active.\n");
      return -1;
    }

  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;

  req.nlh.nlmsg_len = sizeof req;
  req.nlh.nlmsg_type = type;
  req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
  req.nlh.nlmsg_pid = 0;
  req.nlh.nlmsg_seq = ++netlink.seq;
  req.g.rtgen_family = family;
  
  ret = sendto (netlink.sock, (void*) &req, sizeof req, 0, 
		(struct sockaddr*) &snl, sizeof snl);
  if (ret < 0)
    {
      log ("netlink sendto failed: %s\n", strerror (errno));
      return -1;
    }
  return 0;
}

/* Recieve message from netlink interface and pass those information
   to the given function. */
int
netlink_parse_info (int (*filter) (struct sockaddr_nl *, struct nlmsghdr *))
{
  int status;
  int ret;

  while (1)
    {
      char buf[4096];
      struct iovec iov = { buf, sizeof buf };
      struct sockaddr_nl snl;
      struct msghdr msg = { (void*)&snl, sizeof snl, &iov, 1, NULL, 0, 0};
      struct nlmsghdr *h;

      status = recvmsg (netlink.sock, &msg, 0);

      if (status < 0)
	{
	  if (errno == EINTR)
	    continue;
	  log ("netlink recvmsg overrun\n");
	  continue;
	}

      if (status == 0)
	{
	  log ("netlink EOF\n");
	  return -1;
	}

      if (msg.msg_namelen != sizeof snl)
	{
	  log ("netlink sender address length error: length %d\n",
	       msg.msg_namelen);
	  return -1;
	}

      for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, status); 
	   h = NLMSG_NEXT (h, status))
	{
	  /* pid and seq check. */
	  if (h->nlmsg_seq != netlink.seq)
	    continue;

	  /* Finish of reading. */
	  if (h->nlmsg_type == NLMSG_DONE)
	    return 0;

	  /* Error handling. */
	  if (h->nlmsg_type == NLMSG_ERROR)
	    {
	      struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
	      if (h->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)))
		log ("netlink error: message truncated\n");
	      else
		log ("netlink error: %s\n", strerror (-err->error));
	      return -1;
	    }

	  /* OK we got netlink message. */
	  ret = (*filter) (&snl, h);
	  if (ret < 0)
	    {
	      log ("netlink filter function error\n");
	      return ret;
	    }
	}

      /* After error care. */
      if (msg.msg_flags & MSG_TRUNC)
	{
	  log ("netlink error: message truncated\n");
	  continue;
	}
      if (status)
	{
	  log ("netlink error: data remnant size %d\n", status);
	  return -1;
	}
    }

  return 0;
}

/* Utility function for parse rtattr. */
static void
netlink_parse_rtattr (struct rtattr **tb, int max, struct rtattr *rta, int len)
{
  while (RTA_OK(rta, len)) 
    {
      if (rta->rta_type <= max)
	tb[rta->rta_type] = rta;
      rta = RTA_NEXT(rta,len);
    }
}

/* Parse netlink interface information. */
int
netlink_interface (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifinfomsg *ifi;
  struct rtattr *tb [IFLA_MAX + 1];
  struct interface *ifp;
  char *name;

  ifi = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWLINK)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH (sizeof (struct ifinfomsg));
  if (len < 0)
    return -1;

  /* Looking up interface name. */
  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, IFLA_MAX, IFLA_RTA (ifi), len);
  if (tb[IFLA_IFNAME] == NULL)
    return -1;
  name = (char *)RTA_DATA(tb[IFLA_IFNAME]);

  /* Add interface. */
  ifp = if_get_by_name (name);
  
  ifp->index = ifi->ifi_index;
  ifp->flags = ifi->ifi_flags & 0x0000fffff;
  ifp->mtu = *(int *)RTA_DATA (tb[IFLA_MTU]);
  ifp->metric = 1;

  /* If verbose mode log interface index. */
  if (log_mode)
    log ("interface %s index %d.\n", ifp->name, ifp->index);

  return 0;
}

/* Lookup interface IPv4/IPv6 address. */
int
netlink_interface_addr (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct ifaddrmsg *ifa;
  struct rtattr *tb [IFA_MAX + 1];
  struct interface *ifp;
  void *addr;
  void *broad;

  ifa = NLMSG_DATA (h);

  if (ifa->ifa_family != AF_INET 
#ifdef HAVE_IPV6
      && ifa->ifa_family != AF_INET6
#endif /* HAVE_IPV6 */
      )
    return 0;

  if (h->nlmsg_type != RTM_NEWADDR)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct ifaddrmsg));
  if (len < 0)
    return -1;

  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, IFA_MAX, IFA_RTA (ifa), len);

  ifp = if_lookup_by_index (ifa->ifa_index);
  if (ifp == NULL)
    {
      log ("netlink_interface_addr can't find interface by index %d\n",
	   ifa->ifa_index);
      return -1;
    }

  if (tb[IFA_ADDRESS] == NULL)
    tb[IFA_ADDRESS] = tb[IFA_LOCAL];

  if (tb[IFA_ADDRESS])
    addr = RTA_DATA (tb[IFA_ADDRESS]);
  else
    addr = NULL;

  if (tb[IFA_BROADCAST])
    broad = RTA_DATA(tb[IFA_BROADCAST]);
  else
    broad = NULL;

  /* Register interface address to the interface. */
  if (ifa->ifa_family == AF_INET)
    connected_add_ipv4 (ifp, 
			(struct in_addr *) addr, ifa->ifa_prefixlen, 
			(struct in_addr *) broad);

#ifdef HAVE_IPV6
  if (ifa->ifa_family == AF_INET6)
    connected_add_ipv6 (ifp, 
			(struct in6_addr *) addr, ifa->ifa_prefixlen, 
			(struct in6_addr *) broad);
#endif /* HAVE_IPV6*/

  return 0;
}

/* Looking up routing table by netlink interface. */
int
netlink_routing_table (struct sockaddr_nl *snl, struct nlmsghdr *h)
{
  int len;
  struct rtmsg *rtm;
  struct rtattr *tb [RTA_MAX + 1];
  
  /* char buf[BUFSIZ]; */
  char anyaddr[16] = {0};

  int index;
  void *dest;
  void *gate;

  rtm = NLMSG_DATA (h);

  if (h->nlmsg_type != RTM_NEWROUTE)
    return 0;
  if (rtm->rtm_table != RT_TABLE_MAIN)
    return 0;
  if (rtm->rtm_type != RTN_UNICAST)
    return 0;

  len = h->nlmsg_len - NLMSG_LENGTH(sizeof (struct rtmsg));
  if (len < 0)
    return -1;

  bzero (tb, sizeof tb);
  netlink_parse_rtattr (tb, RTA_MAX, RTM_RTA (rtm), len);

  if (rtm->rtm_flags & RTM_F_CLONED)
    return 0;
  if (rtm->rtm_protocol == RTPROT_REDIRECT)
    return 0;
  if (rtm->rtm_protocol == RTPROT_KERNEL)
    return 0;
  if (rtm->rtm_src_len != 0)
    return 0;
  
  index = 0;
  dest = NULL;
  gate = NULL;

  if (tb[RTA_OIF])
    index = *(int *) RTA_DATA (tb[RTA_OIF]);

  if (tb[RTA_DST])
    dest = RTA_DATA (tb[RTA_DST]);
  else
    dest = anyaddr;

  if (tb[RTA_GATEWAY])
    gate = RTA_DATA (tb[RTA_GATEWAY]);
  else
    return 0;

  if (rtm->rtm_family == AF_INET)
    {
      struct prefix_ipv4 p;
      p.family = rtm->rtm_family;
      memcpy (&p.prefix, dest, 4);
      p.prefixlen = rtm->rtm_dst_len;
      rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, &p, gate, index);
    }
#ifdef HAVE_IPV6
  if (rtm->rtm_family == AF_INET6)
    {
      struct prefix_ipv6 p;
      p.family = rtm->rtm_family;
      memcpy (&p.prefix, dest, 16);
      p.prefixlen = rtm->rtm_dst_len;
      rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, &p, gate, index);
    }
#endif /* HAVE_IPV6 */

  return 0;
}

/* Interface lookup by netlink socket. */
int
interface_lookup_netlink ()
{
  int ret;

  /* Get interface information. */
  ret = netlink_request (AF_PACKET, RTM_GETLINK);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface);
  if (ret < 0)
    return ret;

  /* Get IPv4 address of the interfaces. */
  ret = netlink_request (AF_INET, RTM_GETADDR);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 address of the interfaces. */
  ret = netlink_request (AF_INET6, RTM_GETADDR);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_interface_addr);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}

/* Routing table read function using netlink interface. */
int
netlink_route_read ()
{
  int ret;

  /* Get IPv4 routing table. */
  ret = netlink_request (AF_INET, RTM_GETROUTE);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table);
  if (ret < 0)
    return ret;

#ifdef HAVE_IPV6
  /* Get IPv6 routing table. */
  ret = netlink_request (AF_INET6, RTM_GETROUTE);
  if (ret < 0)
    return ret;
  ret = netlink_parse_info (netlink_routing_table);
  if (ret < 0)
    return ret;
#endif /* HAVE_IPV6 */

  return 0;
}


/* Utility function  comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr_l (struct nlmsghdr *n, int maxlen, int type, void *data, int alen)
{
  int len;
  struct rtattr *rta;

  len = RTA_LENGTH(alen);

  if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

/* Utility function comes from iproute2. 
   Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru> */
int
addattr32 (struct nlmsghdr *n, int maxlen, int type, int data)
{
  int len;
  struct rtattr *rta;
  
  len = RTA_LENGTH(4);
  
  if (NLMSG_ALIGN (n->nlmsg_len) + len > maxlen)
    return -1;

  rta = (struct rtattr*) (((char*)n) + NLMSG_ALIGN (n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy (RTA_DATA(rta), &data, 4);
  n->nlmsg_len = NLMSG_ALIGN (n->nlmsg_len) + len;

  return 0;
}

/* sendmsg() to netlink socket then recvmsg(). */
int
netlink_talk (struct nlmsghdr *n)
{
  int status;
  struct sockaddr_nl snl;
  struct iovec iov = { (void*) n, n->nlmsg_len };
  struct msghdr msg = {(void*) &snl, sizeof snl, &iov, 1, NULL, 0, 0};
  char   buf[4096];
  struct nlmsghdr *h;

  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;
  
  n->nlmsg_seq = ++netlink.seq;

  /* Send message to netlink interface. */
  status = sendmsg (netlink.sock, &msg, 0);
  if (status < 0)
    {
      log ("netlink_talk sendmsg() error: %s", strerror (errno));
      return -1;
    }

  /* At this point we don't detect error.  Because if sendmsg success,
     there will be no error so recvmsg() blocks. */
  return 0;
  
  /* Result of netlink message. */
  iov.iov_base = buf;
  iov.iov_len = sizeof buf;

  while (1)
    {
      /* Call recvmsg ().  But it block when sendmsg result is success... */
      status = recvmsg (netlink.sock, &msg, 0);
      if (status < 0)
	{
	  if (errno == EINTR)
	    continue;
	  log ("netlink_talk recvmsg() error: %s", strerror (errno));
	  return -1;
	}
      if (status == 0)
	{
	  log ("netlink_talk EOF on netlink: %s", strerror (errno));
	  return -1;
	}
      if (msg.msg_namelen != sizeof snl) 
	{
	  log ("netlink_talk sender address length %d\n", msg.msg_namelen);
	  return -1;
	}

      /* Parse return value. */
      for (h = (struct nlmsghdr*) buf; status >= sizeof (struct nlmsghdr); ) {
	int len = h->nlmsg_len;
	pid_t pid = h->nlmsg_pid;
	int l = len - sizeof(*h);
	unsigned seq = h->nlmsg_seq;

	/* Chech length. */
	if (l < 0 || len > status) 
	  {
	    if (msg.msg_flags & MSG_TRUNC) 
	      {
		log ("netlink_talk truncated message\n");
		return -1;
	      }
	    log ("netlink_talk malformed message: len=%d\n", len);
	    return -1;
	  }
	
	if (h->nlmsg_pid != pid || h->nlmsg_seq != seq) 
	  continue;

	if (h->nlmsg_type == NLMSG_ERROR) 
	  {
	    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);

	    if (l < sizeof(struct nlmsgerr)) 
	      log ("netlink_talk message truncated\n");
	    else 
	      log ("netlink_talk error: %s", strerror (-err->error));
	    return -1;
	  }

	log ("netlink_talk unexpected reply.\n");
	
	status -= NLMSG_ALIGN(len);
	h = (struct nlmsghdr*) ((char*)h + NLMSG_ALIGN(len));
      }

      if (msg.msg_flags & MSG_TRUNC) 
	{
	  log ("netlink_talk message truncated\n");
	  continue;
      }

      if (status) 
	{
	  log ("netlink_talk error remnant of size %d\n", status);
	  return -1;
	}
    }
  
  return 0;
}

/* Routing table change via netlink interface. */
int
netlink_route (int cmd, unsigned long flags, int family,
	       void *dest, int length, void *gate, int index)
{
  int ret;
  int bytelen;
  struct sockaddr_nl snl;

  struct 
  {
    struct nlmsghdr n;
    struct rtmsg r;
    char buf[1024];
  } req;

  bzero (&req, sizeof req);

  bytelen = (family == AF_INET ? 4 : 16);

  req.n.nlmsg_len = NLMSG_LENGTH (sizeof (struct rtmsg));
  req.n.nlmsg_flags = NLM_F_REQUEST | flags;
  req.n.nlmsg_type = cmd;
  req.r.rtm_family = family;
  req.r.rtm_table = RT_TABLE_MAIN;
  req.r.rtm_dst_len = length;

  if (cmd != RTM_DELROUTE) 
    {
      req.r.rtm_protocol = RTPROT_ZEBRA;
      req.r.rtm_scope = RT_SCOPE_UNIVERSE;
      /* req.r.rtm_scope = RT_SCOPE_HOST; */
      /* req.r.rtm_scope = RT_SCOPE_LINK; */
      req.r.rtm_type = RTN_UNICAST;
    }

  if (gate)
    addattr_l (&req.n, sizeof req, RTA_GATEWAY, gate, bytelen);
  if (dest)
    addattr_l (&req.n, sizeof req, RTA_DST, dest, bytelen);
  if (index > 0)
    addattr32 (&req.n, sizeof req, RTA_OIF, index);

  /* Destination netlink address. */
  bzero (&snl, sizeof snl);
  snl.nl_family = AF_NETLINK;

  /* Talk to netlink socket. */
  ret = netlink_talk (&req.n);
  if (ret < 0)
    return -1;

  return 0;
}

/* Add IPv4 route to the kernel. */
int
kernel_add_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		 int index, int metric)
{
  int ret;

  ret = netlink_route (RTM_NEWROUTE, NLM_F_CREATE, AF_INET, 
		       &dest->prefix, dest->prefixlen, gate, index);
  return ret;
}

/* Delete IPv4 route from the kernel. */
int
kernel_delete_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		    int index, int metruc)
{
  int ret;

  ret = netlink_route (RTM_DELROUTE, NLM_F_CREATE, AF_INET, 
		       &dest->prefix, dest->prefixlen, gate, index);
  return ret;
}

#ifdef HAVE_IPV6
/* Add IPv6 route to the kernel. */
int
kernel_add_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int metruc)
{
  int ret;

  ret = netlink_route (RTM_NEWROUTE, NLM_F_CREATE, AF_INET6,
		       &dest->prefix, dest->prefixlen, gate, index);
  return ret;
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int metruc)
{
  int ret;

  ret = netlink_route (RTM_DELROUTE, NLM_F_CREATE, AF_INET6,
		       &dest->prefix, dest->prefixlen, gate, index);
  return ret;
}
#endif /* HAVE_IPV6 */

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void
kernel_init ()
{
  netlink_socket ();
}
