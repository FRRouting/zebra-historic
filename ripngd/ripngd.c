/* RIPng daemon
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "prefix.h"
#include "filter.h"
#include "log.h"
#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "if.h"
#include "stream.h"
#include "table.h"
#include "roken.h"
#include "client.h"
#include "command.h"
#include "sockopt.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"
#include "ripngd/ripng_debug.h"
#include "zebra/zebra.h"

/* RIPng timer on/off macro. */
#define RIPNG_TIMER_ON(T,F,V) \
   if (!(T)) \
      (T) = thread_add_timer (master, (F), rinfo, (V))

#define RIPNG_TIMER_OFF(T) \
   if (T) \
     { \
       thread_cancel(T); \
       (T) = NULL; \
     }

/* RIPng structure which includes many parameters related to RIPng
   protocol. If ripng couldn't active or ripng doesn't configured,
   ripng->fd must be negative value. */
struct ripng *ripng = NULL;

/* RIPng routing table which hold routing table entry and static
   network configuration. */
struct route_table *ripng_table;

/* RIPng only static route table. */
struct route_table *ripng_static;

/* RIPng aggregate route. */
struct route_table *ripng_aggregate;

/* Master of the thread. */
extern struct thread_master *master;

enum
{
  output_all_route,
  output_changed_route,
  output_split_horizon,
  output_no_split_horizon
};

/* Prototypes. */
void
ripng_output_process (struct interface *, struct sockaddr_in6 *, int, int);

int
ripng_triggered_update (struct thread *);

/* RIPng next hop specification. */
struct ripng_nexthop
{
  enum ripng_nexthop_type
  {
    RIPNG_NEXTHOP_UNSPEC,
    RIPNG_NEXTHOP_ADDRESS
  } flag;
  struct in6_addr address;
};

/* Utility function for making IPv6 address string. */
const char *
inet6_ntop (struct in6_addr *p)
{
  static char buf[INET6_BUFSIZ];

  return inet_ntop (AF_INET6, p, buf, INET6_BUFSIZ);
}

/* Allocate new ripng information. */
struct ripng_info *
ripng_info_new ()
{
  struct ripng_info *new;

  new = XMALLOC (MTYPE_RIPNG_ROUTE, sizeof (struct ripng_info));
  bzero (new, sizeof (struct ripng_info));
  return new;
}

/* Free ripng information. */
void
ripng_info_free (struct ripng_info *rinfo)
{
  XFREE (MTYPE_RIPNG_ROUTE, rinfo);
}

/* Set multicast loop zero to the socket. */
static int
setsockopt_ipv6_multicast_loop (int sock)
{
  int ret;
  int val = 0;
    
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &val, sizeof(val));
  if (ret < 0)
      zlog (NULL, LOG_ERR, "can't setsockopt IPV6_MULTICAST_LOOP");
  return ret;
}

static int
setsockopt_so_recvbuf (int sock, int size)
{
  int ret;

  ret = setsockopt (sock, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof (int));
  if (ret < 0)
    zlog (NULL, LOG_ERR, "can't setsockopt SO_RCVBUF");
  return ret;
}

/* Create ripng socket. */
int 
ripng_make_socket ()
{
  int ret;
  int sock;
  struct sockaddr_in6 ripaddr;

  sock = socket (AF_INET6, SOCK_DGRAM, 0);
  if (sock < 0) 
    {
      zlog (NULL, LOG_ERR, "Can't make ripng socket");
      return sock;
    }

  ret = setsockopt_so_recvbuf (sock, 8096);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_pktinfo (sock, 1);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_hops (sock, 255);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_loop (sock);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_hoplimit (sock, 1);

  bzero (&ripaddr, sizeof (ripaddr));
  ripaddr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  ripaddr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  ripaddr.sin6_port = htons (RIPNG_PORT_DEFAULT);

  ret = bind (sock, (struct sockaddr *) &ripaddr, sizeof (ripaddr));
  if (ret < 0)
    {
      zlog (NULL, LOG_ERR, "Can't bind ripng socket: %s.", strerror (errno));
      return ret;
    }
  return sock;
}

/* Send RIPng packet. */
int
ripng_send_packet (caddr_t buf, int bufsize, struct sockaddr_in6 *to, 
		   struct interface *ifp)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  char adata [sizeof (struct cmsghdr) + sizeof (struct in6_pktinfo)];
  struct in6_pktinfo *pkt;
  struct sockaddr_in6 addr;

  memset (&addr, 0, sizeof (struct sockaddr_in6));
  addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  addr.sin6_flowinfo = htonl (RIPNG_PRIORITY_DEFAULT);

  /* When destination is specified. */
  if (to != NULL)
    {
      addr.sin6_addr = to->sin6_addr;
      addr.sin6_port = to->sin6_port;
    }
  else
    {
      inet_pton(AF_INET6, RIPNG_GROUP, &addr.sin6_addr);
      addr.sin6_port = htons (RIPNG_PORT_DEFAULT);
    }

  msg.msg_name = (void *) &addr;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;

  iov.iov_base = buf;
  iov.iov_len = bufsize;

  cmsgptr = (struct cmsghdr *)adata;
  cmsgptr->cmsg_len = sizeof adata;
  cmsgptr->cmsg_level = IPPROTO_IPV6;
  cmsgptr->cmsg_type = IPV6_PKTINFO;

  pkt = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
  bzero (&pkt->ipi6_addr, sizeof (struct in6_addr));
  pkt->ipi6_ifindex = ifp->ifindex;

  ret = sendmsg (ripng->sock, &msg, 0);

  if (ret < 0)
    zlog_warn ("RIPng send fail on %s: %s", ifp->name, strerror (errno));

  return ret;
}

/* Receive UDP RIPng packet from socket. */
int
ripng_recv_packet (int sock, u_char *buf, int bufsize,
		   struct sockaddr_in6 *from, unsigned int *ifindex, 
		   int *hoplimit)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  struct in6_addr dst;

  /* Ancillary data.  This store cmsghdr and in6_pktinfo.  But at this
     point I can't determine size of cmsghdr */
  char adata[1024];

  /* Fill in message and iovec. */
  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in6);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = bufsize;

  /* If recvmsg fail return minus value. */
  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
       cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) 
    {
      /* I want interface index which this packet comes from. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_PKTINFO) 
	{
	  struct in6_pktinfo *ptr;
	  
	  ptr = (struct in6_pktinfo *) CMSG_DATA (cmsgptr);
	  *ifindex = ptr->ipi6_ifindex;
	  dst = ptr->ipi6_addr;
        }

      /* Incoming packet's multicast hop limit. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_HOPLIMIT)
	*hoplimit = (int)(* ((u_char *) CMSG_DATA (cmsgptr)));
    }

  /* Hoplimit check shold be done when destination address is
     multicast address. */
  if (! IN6_IS_ADDR_MULTICAST (&dst))
    *hoplimit = -1;

  return ret;
}

/* Dump rip packet */
void
ripng_packet_dump (struct ripng_packet *packet, int size)
{
  caddr_t lim;
  struct rte *rte;
  char *command_str;

  /* Set command string. */
  if (packet->command == RIPNG_REQUEST)
    command_str = "request";
  else if (packet->command == RIPNG_RESPONSE)
    command_str = "response";
  else
    command_str = "unknown";

  /* Dump packet header. */
  zlog_info ("RIPng command %s version %d packet size %d", 
	     command_str, packet->version, size);

  /* Dump each routing table entry. */
  rte = packet->rte;

  for (lim = (caddr_t) packet + size; (caddr_t) rte < lim; rte++)
    {
      if (rte->metric == RIPNG_METRIC_NEXTHOP)
	zlog_info ("  nexthop %s/%d", inet6_ntop (&rte->addr), rte->prefixlen);
      else
	zlog_info ("  %s/%d metric %d tag %d", 
		   inet6_ntop (&rte->addr), rte->prefixlen, 
		   rte->metric, ntohs (rte->tag));
    }
}

/* RIPng next hop address RTE (Route Table Entry). */
void
ripng_nexthop_rte (struct rte *rte,
		   struct sockaddr_in6 *from,
		   struct ripng_nexthop *nexthop)
{
  char buf[INET6_BUFSIZ];

  /* Logging before checking RTE. */
  if (IS_RIPNG_DEBUG_RECV)
    zlog_info ("RIPng nexthop RTE address %s tag %d prefixlen %d",
	       inet6_ntop (&rte->addr), ntohs (rte->tag), rte->prefixlen);

  /* RFC2080 2.1.1 Next Hop: 
   The route tag and prefix length in the next hop RTE must be
   set to zero on sending and ignored on receiption.  */
  if (ntohs (rte->tag) != 0)
    zlog_warn ("RIPng nexthop RTE with non zero tag value %d from %s",
	       ntohs (rte->tag), inet6_ntop (&from->sin6_addr));

  if (rte->prefixlen != 0)
    zlog_warn ("RIPng nexthop RTE with non zero prefixlen value %d from %s",
	       rte->prefixlen, inet6_ntop (&from->sin6_addr));

  /* Specifying a value of 0:0:0:0:0:0:0:0 in the prefix field of a
   next hop RTE indicates that the next hop address should be the
   originator of the RIPng advertisement.  An address specified as a
   next hop must be a link-local address.  */
  if (IN6_IS_ADDR_UNSPECIFIED (&rte->addr))
    {
      nexthop->flag = RIPNG_NEXTHOP_UNSPEC;
      memset (&nexthop->address, 0, sizeof (struct in6_addr));
      return;
    }

  if (IN6_IS_ADDR_LINKLOCAL (&rte->addr))
    {
      nexthop->flag = RIPNG_NEXTHOP_ADDRESS;
      IPV6_ADDR_COPY (&nexthop->address, &rte->addr);
      return;
    }

  /* The purpose of the next hop RTE is to eliminate packets being
   routed through extra hops in the system.  It is particularly useful
   when RIPng is not being run on all of the routers on a network.
   Note that next hop RTE is "advisory".  That is, if the provided
   information is ignored, a possibly sub-optimal, but absolutely
   valid, route may be taken.  If the received next hop address is not
   a link-local address, it should be treated as 0:0:0:0:0:0:0:0.  */
  zlog_warn ("RIPng nexthop RTE with non link-local address %s from %s",
	     inet6_ntop (&rte->addr),
	     inet_ntop (AF_INET6, &from->sin6_addr, buf, INET6_BUFSIZ));

  nexthop->flag = RIPNG_NEXTHOP_UNSPEC;
  memset (&nexthop->address, 0, sizeof (struct in6_addr));

  return;
}

/* If ifp has same link-local address then return 1. */
int
ripng_lladdr_check (struct interface *ifp, struct in6_addr *addr)
{
  listnode listnode;
  struct connected *connected;
  struct prefix *p;

  for (listnode = listhead (ifp->connected); listnode; nextnode (listnode))
    if ((connected = getdata (listnode)) != NULL)
      {
	p = connected->address;

	if (p->family == AF_INET6 &&
	    IN6_IS_ADDR_LINKLOCAL (&p->u.prefix6) &&
	    IN6_ARE_ADDR_EQUAL (&p->u.prefix6, addr))
	  return 1;
      }
  return 0;
}

/* RIPng route garbage collect timer. */
int
ripng_garbage_collect (struct thread *t)
{
  struct ripng_info *rinfo;
  struct route_node *rp;

  rinfo = THREAD_ARG (t);
  rinfo->t_garbage_collect = NULL;

  /* Off timeout timer. */
  RIPNG_TIMER_OFF (rinfo->t_timeout);
  
  /* Get route_node pointer. */
  rp = rinfo->rp;

  /* Delete this route from the kernel. */
  ripng_zebra_ipv6_delete ((struct prefix_ipv6 *)&rp->p, 
			   &rinfo->nexthop, rinfo->ifindex);
  rinfo->flags &= ~RIPNG_RTF_FIB;

  /* Aggregate count decrement. */
  ripng_aggregate_decrement (rp, rinfo);

  /* Unlock route_node. */
  rp->info = NULL;
  route_unlock_node (rp);

  /* Free RIPng routing information. */
  ripng_info_free (rinfo);

  return 0;
}

/* Timeout RIPng routes. */
int
ripng_timeout (struct thread *t)
{
  struct ripng_info *rinfo;
  struct route_node *rp;

  rinfo = THREAD_ARG (t);
  rinfo->t_timeout = NULL;

  /* Get route_node pointer. */
  rp = rinfo->rp;

  /* - The garbage-collection timer is set for 120 seconds. */
  RIPNG_TIMER_ON (rinfo->t_garbage_collect, ripng_garbage_collect, 
		  ripng->garbage_time);

  /* - The metric for the route is set to 16 (infinity).  This causes
     the route to be removed from service. */
  rinfo->metric = RIPNG_METRIC_INFINITY;

  /* - The route change flag is to indicate that this entry has been
     changed. */
  rinfo->flags |= RIPNG_RTF_CHANGED;

  /* - The output process is signalled to trigger a response. */
  ripng_event (RIPNG_TRIGGERED_UPDATE, 0);

  return 0;
}

void
ripng_timeout_update (struct ripng_info *rinfo)
{
  if (rinfo->metric != RIPNG_METRIC_INFINITY)
    {
      RIPNG_TIMER_OFF (rinfo->t_timeout);
      RIPNG_TIMER_ON (rinfo->t_timeout, ripng_timeout, ripng->timeout_time);
    }
}

/* Process RIPng route according to RFC2080. */
void
ripng_route_process (struct rte *rte, struct sockaddr_in6 *from,
		     struct ripng_nexthop *ripng_nexthop,
		     struct interface *ifp)
{
  struct prefix_ipv6 p;
  struct route_node *rp;
  struct ripng_info *rinfo;
  struct in6_addr *nexthop;
  u_char oldmetric;
  int same = 0;

  /* Make prefix structure. */
  p.family = AF_INET6;
  p.prefix = rte->addr;
  p.prefixlen = rte->prefixlen;

  /* Make sure mask is applied. */
  apply_mask_ipv6 (&p);

  /* Apply input distribute-list filter. */
  if (distribute_apply_in (ifp, (struct prefix *) &p) == FILTER_DENY)
    {
      if (IS_RIPNG_DEBUG_PACKET)
	zlog_info ("RIPng %s/%d is filtered by distribute in",
		   inet6_ntop (&p.prefix), p.prefixlen);
      return;
    }

  /* Set nexthop pointer. */
  if (ripng_nexthop->flag == RIPNG_NEXTHOP_ADDRESS)
    nexthop = &ripng_nexthop->address;
  else
    nexthop = &from->sin6_addr;

  /* Lookup RIPng routing table. */
  rp = route_node_get (ripng_table, (struct prefix *) &p);

  if (rp->info == NULL)
    {
      /* Now, check to see whether there is already an explicit route
	 for the destination prefix.  If there is no such route, add
	 this route to the routing table, unless the metric is
	 infinity (there is no point in adding a route which
	 unusable). */
      if (rte->metric != RIPNG_METRIC_INFINITY)
	{
	  rinfo = ripng_info_new ();
	  
	  /* - Setting the destination prefix and length to those in
	     the RTE. */
	  rp->info = rinfo;
	  rinfo->rp = rp;

	  /* - Setting the metric to the newly calculated metric (as
	     described above). */
	  rinfo->metric = rte->metric;
	  rinfo->tag = ntohs (rte->tag);

	  /* - Set the next hop address to be the address of the router
	     from which the datagram came or the next hop address
	     specified by a next hop RTE. */
	  IPV6_ADDR_COPY (&rinfo->nexthop, nexthop);
	  IPV6_ADDR_COPY (&rinfo->from, &from->sin6_addr);
	  rinfo->ifindex = ifp->ifindex;

	  /* - Initialize the timeout for the route.  If the
	     garbage-collection timer is running for this route, stop it
	     (see section 2.3 for a discussion of the timers). */
	  ripng_timeout_update (rinfo);

	  /* - Set the route change flag. */
	  rinfo->flags |= RIPNG_RTF_CHANGED;

	  /* - Signal the output process to trigger an update (see section
	     2.5). */
	  ripng_event (RIPNG_TRIGGERED_UPDATE, 0);

	  /* Finally, route goes into the kernel. */
	  rinfo->type = ZEBRA_ROUTE_RIPNG;
	  rinfo->sub_type = RIPNG_ROUTE_RTE;

	  ripng_zebra_ipv6_add (&p, &rinfo->nexthop, rinfo->ifindex);
	  rinfo->flags |= RIPNG_RTF_FIB;

	  /* Aggregate check. */
	  ripng_aggregate_increment (rp, rinfo);
	}
    }
  else
    {
      rinfo = rp->info;
	  
      /* If there is an existing route, compare the next hop address
	 to the address of the router from which the datagram came.
	 If this datagram is from the same router as the existing
	 route, reinitialize the timeout.  */
      /* same = IN6_ARE_ADDR_EQUAL (&rinfo->from, &from->sin6_addr); */
      if (rinfo->ifindex == ifp->ifindex)
	same = 1;

      if (same)
	ripng_timeout_update (rinfo);

      /* Next, compare the metrics.  If the datagram is from the same
	 router as the existing route, and the new metric is different
	 than the old one; or, if the new metric is lower than the old
	 one; do the following actions: */
      if ((same && rinfo->metric != rte->metric) ||
	  rte->metric < rinfo->metric)
	{
	  /* - Adopt the route from the datagram.  That is, put the
	     new metric in, and adjust the next hop address (if
	     necessary). */
	  oldmetric = rinfo->metric;
	  rinfo->metric = rte->metric;
	  rinfo->tag = ntohs (rte->tag);

	  if (! IN6_ARE_ADDR_EQUAL (&rinfo->nexthop, nexthop))
	    {
	      ripng_zebra_ipv6_delete (&p, &rinfo->nexthop, rinfo->ifindex);
	      ripng_zebra_ipv6_add (&p, nexthop, ifp->ifindex);
	      rinfo->flags |= RIPNG_RTF_FIB;

	      IPV6_ADDR_COPY (&rinfo->nexthop, nexthop);
	    }
	  IPV6_ADDR_COPY (&rinfo->from, &from->sin6_addr);
	  rinfo->ifindex = ifp->ifindex;

	  /* - Set the route change flag and signal the output process
	     to trigger an update. */
	  rinfo->flags |= RIPNG_RTF_CHANGED;
	  ripng_event (RIPNG_TRIGGERED_UPDATE, 0);

	  /* - If the new metric is infinity, start the deletion
	     process (described above); */
	  if (rinfo->metric == RIPNG_METRIC_INFINITY)
	    {
	      /* If the new metric is infinity, the deletion process
		 begins for the route, which is no longer used for
		 routing packets.  Note that the deletion process is
		 started only when the metric is first set to
		 infinity.  If the metric was already infinity, then a
		 new deletion process is not started. */
	      if (oldmetric != RIPNG_METRIC_INFINITY)
		{
		  /* - The garbage-collection timer is set for 120 seconds. */
		  RIPNG_TIMER_ON (rinfo->t_garbage_collect, 
				  ripng_garbage_collect, ripng->garbage_time);
		  RIPNG_TIMER_OFF (rinfo->t_timeout);

		  /* - The metric for the route is set to 16
		     (infinity).  This causes the route to be removed
		     from service.*/
		  /* - The route change flag is to indicate that this
		     entry has been changed. */
		  /* - The output process is signalled to trigger a
                     response. */
		  ;  /* Above processes are already done previously. */
		}
	    }
	  else
	    {
	      /* otherwise, re-initialize the timeout. */
	      ripng_timeout_update (rinfo);

	      /* Should a new route to this network be established
		 while the garbage-collection timer is running, the
		 new route will replace the one that is about to be
		 deleted.  In this case the garbage-collection timer
		 must be cleared. */
	      RIPNG_TIMER_OFF (rinfo->t_garbage_collect);
	    }
	}
      /* Unlock tempolary lock of the route. */
      route_unlock_node (rp);
    }
}

/* Add redistributed route to RIPng table. */
void
ripng_redistribute_add (int type, int sub_type, struct prefix_ipv6 *p, 
			unsigned int ifindex)
{
  struct route_node *rp;
  struct ripng_info *rinfo;

  /* Redistribute route  */
  if (IN6_IS_ADDR_LINKLOCAL (&p->prefix))
    return;
  if (IN6_IS_ADDR_LOOPBACK (&p->prefix))
    return;

  rp = route_node_get (ripng_table, (struct prefix *) p);
  rinfo = rp->info;

  if (rinfo)
    {
      RIPNG_TIMER_OFF (rinfo->t_timeout);
      RIPNG_TIMER_OFF (rinfo->t_garbage_collect);
      route_unlock_node (rp);
    }
  else
    {
      rinfo = ripng_info_new ();
      ripng_aggregate_increment (rp, rinfo);
    }

  rinfo->type = type;
  rinfo->sub_type = sub_type;
  rinfo->ifindex = ifindex;
  rinfo->metric = 1;
  rinfo->flags |= RIPNG_RTF_FIB;

  rinfo->rp = rp;
  rp->info = rinfo;
}

/* Delete redistributed route to RIPng table. */
void
ripng_redistribute_delete (int type, int sub_type, struct prefix_ipv6 *p, 
			   unsigned int ifindex)
{
  struct route_node *rp;
  struct ripng_info *rinfo;

  if (IN6_IS_ADDR_LINKLOCAL (&p->prefix))
    return;
  if (IN6_IS_ADDR_LOOPBACK (&p->prefix))
    return;

  rp = route_node_lookup (ripng_table, (struct prefix *) p);

  if (rp && (rinfo = rp->info) != NULL)
    {
      if (rinfo->type == type &&
	  rinfo->sub_type == sub_type &&
	  rinfo->ifindex == ifindex)
	{
	  rp->info = NULL;
	  ripng_info_free (rinfo);

	  route_unlock_node (rp);
	  route_unlock_node (rp);
	}
    }
}

/* Withdraw redistributed route. */
void
ripng_redistribute_withdraw (int type)
{
  struct route_node *rp;
  struct ripng_info *rinfo;

  for (rp = route_top (ripng_table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      {
	if (rinfo->type == type)
	  {
	    rinfo->rp->info = NULL;
	    route_unlock_node (rp);

	    ripng_info_free (rinfo);
	  }
      }
}

/* RIP routing information. */
void
ripng_response_process (struct ripng_packet *packet, int size, 
			struct sockaddr_in6 *from, struct interface *ifp,
			int hoplimit)
{
  caddr_t lim;
  struct rte *rte;
  struct ripng_nexthop nexthop;

  /* RFC2080 2.4.2  Response Messages:
   The Response must be ignored if it is not from the RIPng port.  */
  if (ntohs (from->sin6_port) != RIPNG_PORT_DEFAULT)
    {
      zlog_warn ("RIPng packet comes from non RIPng port %d from %s",
		 ntohs (from->sin6_port), inet6_ntop (&from->sin6_addr));
      return;
    }

  /* The datagram's IPv6 source address should be checked to see
   whether the datagram is from a valid neighbor; the source of the
   datagram must be a link-local address.  */
  if (! IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr))
   {
      zlog_warn ("RIPng packet comes from non link local address %s",
		 inet6_ntop (&from->sin6_addr));
      return;
    }

  /* It is also worth checking to see whether the response is from one
   of the router's own addresses.  Interfaces on broadcast networks
   may receive copies of their own multicasts immediately.  If a
   router processes its own output as new input, confusion is likely,
   and such datagrams must be ignored. */
  if (ripng_lladdr_check (ifp, &from->sin6_addr))
    {
      zlog_warn ("RIPng packet comes from my own link local address %s",
		 inet6_ntop (&from->sin6_addr));
      return;
    }

  /* As an additional check, periodic advertisements must have their
   hop counts set to 255, and inbound, multicast packets sent from the
   RIPng port (i.e. periodic advertisement or triggered update
   packets) must be examined to ensure that the hop count is 255. */
  if (hoplimit >= 0 && hoplimit != 255)
    {
      zlog_warn ("RIPng packet comes with non 255 hop count %d from %s",
		 hoplimit, inet6_ntop (&from->sin6_addr));
      return;
    }

  /* Reset nexthop. */
  bzero (&nexthop, sizeof (struct ripng_nexthop));
  nexthop.flag = RIPNG_NEXTHOP_UNSPEC;

  /* Set RTE pointer. */
  rte = packet->rte;

  for (lim = ((caddr_t) packet) + size; (caddr_t) rte < lim; rte++) 
    {
      /* First of all, we have to check this RTE is next hop RTE or
         not.  Next hop RTE is completely different with normal RTE so
         we need special treatment. */
      if (rte->metric == RIPNG_METRIC_NEXTHOP)
	{
	  ripng_nexthop_rte (rte, from, &nexthop);
	  continue;
	}

      /* RTE information validation. */

      /* - is the destination prefix valid (e.g., not a multicast
         prefix and not a link-local address) A link-local address
         should never be present in an RTE. */
      if (IN6_IS_ADDR_MULTICAST (&rte->addr))
	{
	  zlog_warn ("Destination prefix is a multicast address %s/%d [%d]",
		     inet6_ntop (&rte->addr), rte->prefixlen, rte->metric);
	  continue;
	}
      if (IN6_IS_ADDR_LINKLOCAL (&rte->addr))
	{
	  zlog_warn ("Destination prefix is a link-local address %s/%d [%d]",
		     inet6_ntop (&rte->addr), rte->prefixlen, rte->metric);
	  continue;
	}
      if (IN6_IS_ADDR_LOOPBACK (&rte->addr))
	{
	  zlog_warn ("Destination prefix is a loopback address %s/%d [%d]",
		     inet6_ntop (&rte->addr), rte->prefixlen, rte->metric);
	  continue;
	}

      /* - is the prefix length valid (i.e., between 0 and 128,
         inclusive) */
      if (rte->prefixlen > 128)
	{
	  zlog_warn ("Invalid prefix length %s/%d",
		     inet6_ntop (&rte->addr), rte->prefixlen);
	  continue;
	}

      /* - is the metric valid (i.e., between 1 and 16, inclusive) */
      if (! (rte->metric >= 1 && rte->metric <= 16))
	{
	  zlog_warn ("Invalid metric %d", rte->metric);
	  continue;
	}

      /* Metric calculation. */
      rte->metric += ifp->metric;
      if (rte->metric > RIPNG_METRIC_INFINITY)
	rte->metric = RIPNG_METRIC_INFINITY;

      /* Routing table updates. */
      ripng_route_process (rte, from, &nexthop, ifp);
    }
}

/* Response to request message. */
void
ripng_request_process (struct ripng_packet *packet,int size, 
		       struct sockaddr_in6 *from, struct interface *ifp)
{
  caddr_t lim;
  struct rte *rte;
  struct prefix_ipv6 p;
  struct route_node *rp;
  struct ripng_info *rinfo;
  struct ripng_interface *ri;

  /* Check RIPng process is enabled on this interface. */
  ri = ifp->info;
  if (! ri->running)
    return;

  lim = ((caddr_t) packet) + size;
  rte = packet->rte;

  /* The Request is processed entry by entry.  If there are no
     entries, no response is given. */
  if (lim == (caddr_t) rte)
    return;

  /* There is one special case.  If there is exactly one entry in the
     request, and it has a destination prefix of zero, a prefix length
     of zero, and a metric of infinity (i.e., 16), then this is a
     request to send the entire routing table.  In that case, a call
     is made to the output process to send the routing table to the
     requesting address/port. */
  if (lim == ((caddr_t) (rte + 1)) &&
      IN6_IS_ADDR_UNSPECIFIED (&rte->addr) &&
      rte->prefixlen == 0 &&
      rte->metric == RIPNG_METRIC_INFINITY)
    {	
      /* All route with split horizon */
      ripng_output_process (ifp, from, output_all_route, output_split_horizon);
    }
  else
    {
      /* Except for this special case, processing is quite simple.
	 Examine the list of RTEs in the Request one by one.  For each
	 entry, look up the destination in the router's routing
	 database and, if there is a route, put that route's metric in
	 the metric field of the RTE.  If there is no explicit route
	 to the specified destination, put infinity in the metric
	 field.  Once all the entries have been filled in, change the
	 command from Request to Response and send the datagram back
	 to the requestor. */
      p.family = AF_INET6;

      for (; ((caddr_t) rte) < lim; rte++)
	{
	  p.prefix = rte->addr;
	  p.prefixlen = rte->prefixlen;
	  apply_mask_ipv6 (&p);
	  
	  rp = route_node_lookup (ripng_table, (struct prefix *) &p);

	  if (rp)
	    {
	      rinfo = rp->info;
	      rte->metric = rinfo->metric;
	      route_unlock_node (rp);
	    }
	  else
	    rte->metric = RIPNG_METRIC_INFINITY;
	}
      packet->command = RIPNG_RESPONSE;

      ripng_send_packet ((caddr_t) packet, size, from, ifp);
    }
}

/* First entry point of reading RIPng packet. */
int
ripng_read (struct thread *thread)
{
  int len;
  int sock;
  struct sockaddr_in6 from;
  struct ripng_packet *packet;
  unsigned int ifindex;
  struct interface *ifp;
  int hoplimit = -1;

  /* Check ripng is active and alive. */
  assert (ripng != NULL);
  assert (ripng->sock >= 0);

  /* Fetch thread data and set read pointer to empty for event
     managing.  `sock' sould be same as ripng->sock. */
  sock = THREAD_FD (thread);
  ripng->t_read = NULL;

  /* Add myself to the next event. */
  ripng_event (RIPNG_READ, sock);

  /* Read RIPng packet. */
  len = ripng_recv_packet (sock, STREAM_DATA (ripng->ibuf), 
			   STREAM_SIZE (ripng->ibuf), &from, &ifindex,
			   &hoplimit);
  if (len < 0) 
    {
      zlog_warn ("RIPng recvfrom failed: %s.", strerror (errno));
      return len;
    }

  /* Check RTE boundary.  RTE size (Packet length - RIPng header size
     (4)) must be multiple size of one RTE size (20). */
  if (((len - 4) % 20) != 0)
    {
      zlog_warn ("RIPng invalid packet size %d from %s", len,
		 inet6_ntop (&from.sin6_addr));
      return 0;
    }

  packet = (struct ripng_packet *) STREAM_DATA (ripng->ibuf);
  ifp = if_lookup_by_index (ifindex);

  /* RIPng packet received. */
  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng packet received from %s port %d on %s",
	       inet6_ntop (&from.sin6_addr), ntohs (from.sin6_port), 
	       ifp ? ifp->name : "unknown");

  /* Logging before packet checking. */
  if (IS_RIPNG_DEBUG_PACKET)
    ripng_packet_dump (packet, len);

  /* Packet comes from unknown interface. */
  if (ifp == NULL)
    {
      zlog_warn ("RIPng packet comes from unknown interface %s", ifindex);
      return 0;
    }

  /* Packet version mismatch checking. */
  if (packet->version != ripng->version) 
    {
      zlog_warn ("RIPng packet version %d doesn't fit to my version %d", 
		 packet->version, ripng->version);
      return 0;
    }

  /* Process RIPng packet. */
  switch (packet->command)
    {
    case RIPNG_REQUEST:
      ripng_request_process (packet, len, &from, ifp);
      break;
    case RIPNG_RESPONSE:
      ripng_response_process (packet, len, &from, ifp, hoplimit);
      break;
    default:
      zlog_warn ("Invalid RIPng command %d", packet->command);
      break;
    }
  return 0;
}

/* Walk down the RIPng routing table then clear changed flag. */
void
ripng_clear_changed_flag ()
{
  struct route_node *rp;
  struct ripng_info *rinfo;

  for (rp = route_top (ripng_table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      if (rinfo->flags & RIPNG_RTF_CHANGED)
	rinfo->flags &= ~RIPNG_RTF_CHANGED;
}

/* Regular update of RIPng route.  Send all routing formation to RIPng
   enabled interface. */
int
ripng_update (struct thread *t)
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;

  /* Clear update timer thread. */
  ripng->t_update = NULL;

  /* Logging update event. */
  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng update timer expired!");

  /* Supply routes to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->info;

      if (if_is_loopback (ifp) || ! if_is_up (ifp))
	continue;

      if (! ri->running)
	continue;

#if RIPNG_ADVANCED
      if (ri->ri_send == RIPNG_SEND_OFF)
	{
	  if (IS_RIPNG_DEBUG_EVENT)
	    zlog (NULL, LOG_INFO, 
		  "[Event] RIPng send to if %d is suppressed by config",
		 ifp->ifindex);
	  continue;
	}
#endif /* RIPNG_ADVANCED */

      ripng_output_process (ifp, NULL, output_all_route, output_split_horizon);
    }

  /* Triggered updates may be suppressed if a regular update is due by
     the time the triggered update would be sent. */
  if (ripng->t_triggered_interval)
    {
      thread_cancel (ripng->t_triggered_interval);
      ripng->t_triggered_interval = NULL;
    }
  ripng->trigger = 0;

  /* Reset flush event. */
  ripng_event (RIPNG_UPDATE_EVENT, 0);

  return 0;
}

/* Triggered update interval timer. */
int
ripng_triggered_interval (struct thread *t)
{
  ripng->t_triggered_interval = NULL;

  if (ripng->trigger)
    {
      ripng->trigger = 0;
      ripng_triggered_update (t);
    }
  return 0;
}     

/* Execute triggered update. */
int
ripng_triggered_update (struct thread *t)
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;
  int interval;

  ripng->t_triggered_update = NULL;

  /* Cancel interval timer. */
  if (ripng->t_triggered_interval)
    {
      thread_cancel (ripng->t_triggered_interval);
      ripng->t_triggered_interval = NULL;
    }
  ripng->trigger = 0;

  /* Logging triggered update. */
  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng triggered update!");

  /* Split Horizon processing is done when generating triggered
     updates as well as normal updates (see section 2.6). */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->info;

      if (if_is_loopback (ifp) || ! if_is_up (ifp))
	continue;

      if (! ri->running)
	continue;

      ripng_output_process (ifp, NULL, output_changed_route,
			    output_split_horizon);
    }

  /* Once all of the triggered updates have been generated, the route
     change flags should be cleared. */
  ripng_clear_changed_flag ();

  /* After a triggered update is sent, a timer should be set for a
     random interval between 1 and 5 seconds.  If other changes that
     would trigger updates occur before the timer expires, a single
     update is triggered when the timer expires. */
  interval = (random () % 5) + 1;

  ripng->t_triggered_interval = 
    thread_add_timer (master, ripng_triggered_interval, NULL, interval);

  return 0;
}

/* Write routing table entry to the stream and return next index of
   the routing table entry in the stream. */
int
ripng_write_rte (int num, struct stream *s, struct prefix_ipv6 *p,
		 u_int16_t tag, u_char metric)
{
  /* RIPng packet header. */
  if (num == 0)
    {
      stream_putc (s, RIPNG_RESPONSE);
      stream_putc (s, RIPNG_V1);
      stream_putw (s, 0);
    }

  /* Write routing table entry. */
  stream_write (s, (caddr_t) &p->prefix, sizeof (struct in6_addr));
  stream_putw (s, tag);
  stream_putc (s, p->prefixlen);
  stream_putc (s, metric);

  return ++num;
}

/* Send RESPONSE message to specified destination. */
void
ripng_output_process (struct interface *ifp, struct sockaddr_in6 *to,
		      int route_type, int split_horizon)
{
  int ret;
  struct stream *s;
  struct route_node *rp;
  struct ripng_info *rinfo;
  struct ripng_aggregate *aggregate;
  struct prefix_ipv6 *p;
  int num;
  int rtemax;

  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng update routes on interface %s", ifp->name);

  /* Output stream get from ripng structre.  XXX this should be
     interface structure. */
  s = ripng->obuf;

  /* Reset stream and RTE counter. */
  stream_reset (s);
  num = 0;
  rtemax = (STREAM_SIZE(s) - 4) / 20;

  for (rp = route_top (ripng_table); rp; rp = route_next (rp))
    {
      if ((rinfo = rp->info) != NULL && rinfo->suppress == 0)
	{
	  p = (struct prefix_ipv6 *) &rp->p;

	  /* Output distribute-list filter.*/
	  if (distribute_apply_out (ifp, (struct prefix *) p) == FILTER_DENY)
	    {
	      if (IS_RIPNG_DEBUG_PACKET)
		zlog_info ("RIPng %s/%d is filtered by distribute out",
			   inet6_ntop (&p->prefix), p->prefixlen);
	      continue;
	    }

	  /* Changed route only output. */
	  if (route_type == output_changed_route &&
	      (! (rinfo->flags & RIPNG_RTF_CHANGED)))
	    continue;

	  /* Split horizon. */
	  if (split_horizon == output_split_horizon &&
	      rinfo->ifindex == ifp->ifindex)
	    continue;
	
	  /* Write RTE to the stream. */
	  num = ripng_write_rte (num, s, p, rinfo->tag, rinfo->metric);
	  if (num == rtemax)
	    {
	      ret = ripng_send_packet (STREAM_DATA (s), stream_get_endp (s),
				       to, ifp);

	      if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
		ripng_packet_dump ((struct ripng_packet *)STREAM_DATA (s),
				   stream_get_endp(s));
	      num = 0;
	      stream_reset (s);
	    }
	}
      if ((aggregate = rp->aggregate) != NULL && 
	  aggregate->count > 0 && 
	  aggregate->suppress == 0)
	{
	  p = (struct prefix_ipv6 *) &rp->p;

	  /* Output distribute-list filter.*/
	  if (distribute_apply_out (ifp, (struct prefix *) p) == FILTER_DENY)
	    {
	      if (IS_RIPNG_DEBUG_PACKET)
		zlog_info ("RIPng %s/%d is filtered by distribute out",
			   inet6_ntop (&p->prefix), p->prefixlen);
	      continue;
	    }

	  /* Changed route only output. */
	  if (route_type == output_changed_route)
	    continue;

	  /* Write RTE to the stream. */
	  num = ripng_write_rte (num, s, p, aggregate->tag, aggregate->metric);
	  if (num == rtemax)
	    {
	      ret = ripng_send_packet (STREAM_DATA (s), stream_get_endp (s),
				       to, ifp);

	      if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
		ripng_packet_dump ((struct ripng_packet *)STREAM_DATA (s),
				   stream_get_endp(s));
	      num = 0;
	      stream_reset (s);
	    }
	}

    }
  
  /* If unwritten RTE exist, flush it. */
  if (num != 0)
    {
      ret = ripng_send_packet (STREAM_DATA (s), stream_get_endp (s),
			       to, ifp);

      if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
	ripng_packet_dump ((struct ripng_packet *)STREAM_DATA (s),
			   stream_get_endp (s));
      num = 0;
      stream_reset (s);
    }
}

/* Create new RIPng instance and set it to global variable. */
int
ripng_create ()
{
  /* ripng should be NULL. */
  assert (ripng == NULL);

  /* Allocaste RIPng instance. */
  ripng = XMALLOC (0, sizeof (struct ripng));
  memset (ripng, 0, sizeof (struct ripng));

  /* Default version and timer values. */
  ripng->version = RIPNG_V1;
  ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
  ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
  ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;
  
  /* XXX Make buffer.  Size should be calculated by MTU. */
  ripng->ibuf = stream_new (1500 * 5);
  ripng->obuf = stream_new (1500);

  /* Make socket. */
  ripng->sock = ripng_make_socket ();
  if (ripng->sock < 0)
    return ripng->sock;

  /* Threads. */
  ripng_event (RIPNG_READ, ripng->sock);
  ripng_event (RIPNG_UPDATE_EVENT, 1);

  return 0;
}

/* Sned RIPng request to the interface. */
int
ripng_request (struct interface *ifp)
{
  struct rte *rte;
  struct ripng_packet ripng_packet;

  if (IS_RIPNG_DEBUG_EVENT)
    zlog_info ("RIPng send request to %s", ifp->name);

  bzero (&ripng_packet, sizeof (ripng_packet));
  ripng_packet.command = RIPNG_REQUEST;
  ripng_packet.version = RIPNG_V1;
  rte = ripng_packet.rte;
  rte->metric = RIPNG_METRIC_INFINITY;

  return ripng_send_packet ((caddr_t) &ripng_packet, sizeof (ripng_packet), 
			    NULL, ifp);
}

/* Clean up installed RIPng routes. */
void
ripng_terminate ()
{
  struct route_node *rp;
  struct ripng_info *rinfo;

  for (rp = route_top (ripng_table); rp; rp = route_next (rp))
    if ((rinfo = rp->info) != NULL)
      {
	if (rinfo->type == ZEBRA_ROUTE_RIPNG &&
	    rinfo->sub_type == RIPNG_ROUTE_RTE)
	  ripng_zebra_ipv6_delete ((struct prefix_ipv6 *)&rp->p,
				   &rinfo->nexthop, rinfo->ifindex);
      }
}

int
ripng_update_jitter (int time)
{
  return ((rand () % (time + 1)) - (time / 2));
}

void
ripng_event (enum ripng_event event, int sock)
{
  int ripng_request_all (struct thread *);
  int jitter = 0;

  switch (event)
    {
    case RIPNG_READ:
      if (!ripng->t_read)
	ripng->t_read = thread_add_read (master, ripng_read, NULL, sock);
      break;
    case RIPNG_UPDATE_EVENT:
      if (ripng->t_update)
	{
	  thread_cancel (ripng->t_update);
	  ripng->t_update = NULL;
	}
      /* Update timer jitter. */
      jitter = ripng_update_jitter (ripng->update_time);

      ripng->t_update = 
	thread_add_timer (master, ripng_update, NULL, 
			  sock ? 1 : ripng->update_time + jitter);
      break;
    case RIPNG_TRIGGERED_UPDATE:
      if (ripng->t_triggered_interval)
	ripng->trigger = 1;
      else if (! ripng->t_triggered_update)
	ripng->t_triggered_update = 
	  thread_add_event (master, ripng_triggered_update, NULL, 0);
      break;
    default:
      break;
    }
}

/* Each route type's strings and default preference. */
struct
{  
  int key;
  char *str;
  char *str_long;
  int distance;
} route_info[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X", "system",    10},
  { ZEBRA_ROUTE_KERNEL,  "K", "kernel",    20},
  { ZEBRA_ROUTE_CONNECT, "C", "connected", 30},
  { ZEBRA_ROUTE_STATIC,  "S", "static",    40},
  { ZEBRA_ROUTE_RIP,     "R", "rip",       50},
  { ZEBRA_ROUTE_RIPNG,   "R", "ripng",     50},
  { ZEBRA_ROUTE_OSPF,    "O", "ospf",      60},
  { ZEBRA_ROUTE_OSPF6,   "O", "ospf6",     60},
  { ZEBRA_ROUTE_BGP,     "B", "bgp",       70},
};

/* For messages. */
struct message
{
  int key;
  char *str;
} ripng_route_info[] =
{
  { RIPNG_ROUTE_RTE,       " "},
  { RIPNG_ROUTE_STATIC,    "S"},
  { RIPNG_ROUTE_AGGREGATE, "a"}
};

/* Print out routes update time. */
static void
ripng_vty_out_uptime (struct vty *vty, struct ripng_info *rinfo)
{
  struct timeval timer_now;
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];
  struct thread *thread;
  
  gettimeofday (&timer_now, NULL);

  if ((thread = rinfo->t_timeout) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "%M:%S", tm);
      vty_out (vty, "%5s", timebuf);
    }
  else if ((thread = rinfo->t_garbage_collect) != NULL)
    {
      clock = thread->u.sands.tv_sec - timer_now.tv_sec;
      tm = gmtime (&clock);
      strftime (timebuf, TIME_BUF, "%M:%S", tm);
      vty_out (vty, "%5s", timebuf);
    }
}

DEFUN (show_ipv6_ripng,
       show_ipv6_ripng_cmd,
       "show ipv6 ripng",
       SHOW_STR
       IP_STR
       "Show RIPng routes\n")
{
  struct route_node *rp;
  struct ripng_info *rinfo;
  struct ripng_aggregate *aggregate;
  struct prefix_ipv6 *p;
  int len;

  /* Header of display. */ 
  vty_out (vty, "\r\nCodes: R - RIPng\r\n\r\n"
	   "   Network                            "
	   "Next Hop                Metric Tag Time\r\n");
  
  for (rp = route_top (ripng_table); rp; rp = route_next (rp))
    {
      if ((aggregate = rp->aggregate) != NULL)
	{
	  p = (struct prefix_ipv6 *) &rp->p;

#ifdef DEBUG
	  len = vty_out (vty, "Ra %d/%d %s/%d ",
			 aggregate->count, aggregate->suppress,
			 inet6_ntop (&p->prefix), p->prefixlen);
#else
	  len = vty_out (vty, "Ra %s/%d ", 
			 inet6_ntop (&p->prefix), p->prefixlen);
#endif /* DEBUG */

	  len = 38 - len;
	  if (len > 0)
	    vty_out (vty, "%*s", len, " ");

	  vty_out (vty, "%*s", 26, " ");
	  vty_out (vty, "%4d %3d\r\n", aggregate->metric, aggregate->tag);
	}

      if ((rinfo = rp->info) != NULL)
	{
	  p = (struct prefix_ipv6 *) &rp->p;

#ifdef DEBUG
	  len = vty_out (vty, "%s%s 0/%d %s/%d ",
			 route_info[rinfo->type].str,
			 rinfo->suppress ? "s" : " ",
			 rinfo->suppress,
			 inet6_ntop (&p->prefix), p->prefixlen);
#else
	  len = vty_out (vty, "%s%s %s/%d ",
			 route_info[rinfo->type].str,
			 rinfo->suppress ? "s" : " ",
			 inet6_ntop (&p->prefix), p->prefixlen);
#endif /* DEBUG */
	  len = 38 - len;
	  if (len > 0)
	    vty_out (vty, "%*s", len, " ");

	  len = vty_out (vty, "%s", inet6_ntop (&rinfo->nexthop));

	  len = 26 - len;
	  if (len > 0)
	    vty_out (vty, "%*s", len, " ");

	  vty_out (vty, "%4d %3d ", rinfo->metric, rinfo->tag);

	  if (rinfo->sub_type == RIPNG_ROUTE_RTE)
	    ripng_vty_out_uptime (vty, rinfo);

	  vty_out (vty, "\r\n");
	}
    }

  return CMD_SUCCESS;
}

DEFUN (router_ripng,
       router_ripng_cmd,
       "router ripng",
       "Enable a routing process\n"
       "Make RIPng instance command\n")
{
  int ret;

  vty->node = RIPNG_NODE;

  if (!ripng)
    {
      ret = ripng_create ();

      /* Notice to user we couldn't create RIPng. */
      if (ret < 0)
	{
	  zlog_warn ("can't create RIPng");
	  return CMD_WARNING;
	}
    }

  return CMD_SUCCESS;
}

DEFUN (ripng_route,
       ripng_route_cmd,
       "route IPV6ADDR",
       "Static route setup\n"
       "Set static RIPng route announcement\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_node *rp;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }
  apply_mask_ipv6 (&p);

  rp = route_node_get (ripng_static, (struct prefix *) &p);
  if (rp->info)
    {
      vty_out (vty, "There is already same static route.\r\n");
      route_unlock_node (rp);
      return CMD_WARNING;
    }
  rp->info = (void *)1;

  ripng_redistribute_add (ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);

  return CMD_SUCCESS;
}

DEFUN (no_ripng_route,
       no_ripng_route_cmd,
       "no route IPV6ADDR",
       NO_STR
       "Static route setup\n"
       "Delete static RIPng route announcement\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct route_node *rp;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }
  apply_mask_ipv6 (&p);

  rp = route_node_lookup (ripng_static, (struct prefix *) &p);
  if (rp->info == NULL)
    {
      vty_out (vty, "Can't find static route.\r\n");
      route_unlock_node (rp);
      return CMD_WARNING;
    }

  ripng_redistribute_delete (ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);
  route_unlock_node (rp);

  rp->info = NULL;
  route_unlock_node (rp);

  return CMD_SUCCESS;
}

DEFUN (ripng_aggregate_address,
       ripng_aggregate_address_cmd,
       "aggregate-address IPV6ADDR",
       "Set aggregate RIPng route announcement\n"
       "Aggregate network\n")
{
  int ret;
  struct prefix p;
  struct route_node *node;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }

  /* Check aggregate alredy exist or not. */
  node = route_node_get (ripng_aggregate, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same aggregate route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }
  node->info = (void *)1;

  ripng_aggregate_add (&p);

  return CMD_SUCCESS;
}

DEFUN (no_ripng_aggregate_address,
       no_ripng_aggregate_address_cmd,
       "no aggregate-address IPV6ADDR",
       NO_STR
       "Delete aggregate RIPng route announcement\n"
       "Aggregate network")
{
  int ret;
  struct prefix p;
  struct route_node *node;

  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *) &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }

  node = route_node_lookup (ripng_aggregate, &p);
  if (! node)
    {
      vty_out (vty, "Can't find aggregate route.\r\n");
      return CMD_WARNING;
    }
  route_unlock_node (node);
  node->info = NULL;
  route_unlock_node (node);

  ripng_aggregate_delete (&p);

  return CMD_SUCCESS;
}

#if 0
/* RIPng update timer setup. */
DEFUN (ripng_update_timer,
       ripng_update_timer_cmd,
       "update-timer SECOND",
       "Set RIPng update timer in seconds\n"
       "Seconds\n")
{
  unsigned long update;
  char *endptr = NULL;

  update = strtoul (argv[0], &endptr, 10);
  if (update == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "update timer value error\r\n");
      return CMD_WARNING;
    }

  ripng->update_time = update;

  ripng_event (RIPNG_UPDATE_EVENT, 0);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_update_timer,
       no_ripng_update_timer_cmd,
       "no update-timer SECOND",
       NO_STR
       "Unset RIPng update timer in seconds\n"
       "Seconds\n")
{
  ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
  ripng_event (RIPNG_UPDATE_EVENT, 0);
  return CMD_SUCCESS;
}

/* RIPng timeout timer setup. */
DEFUN (ripng_timeout_timer,
       ripng_timeout_timer_cmd,
       "timeout-timer SECOND",
       "Set RIPng timeout timer in seconds\n"
       "Seconds\n")
{
  unsigned long timeout;
  char *endptr = NULL;

  timeout = strtoul (argv[0], &endptr, 10);
  if (timeout == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "timeout timer value error\r\n");
      return CMD_WARNING;
    }

  ripng->timeout_time = timeout;

  return CMD_SUCCESS;
}

DEFUN (no_ripng_timeout_timer,
       no_ripng_timeout_timer_cmd,
       "no timeout-timer SECOND",
       NO_STR
       "Unset RIPng timeout timer in seconds\n"
       "Seconds\n")
{
  ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
  return CMD_SUCCESS;
}

/* RIPng garbage timer setup. */
DEFUN (ripng_garbage_timer,
       ripng_garbage_timer_cmd,
       "garbage-timer SECOND",
       "Set RIPng garbage timer in seconds\n"
       "Seconds\n")
{
  unsigned long garbage;
  char *endptr = NULL;

  garbage = strtoul (argv[0], &endptr, 10);
  if (garbage == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "garbage timer value error\r\n");
      return CMD_WARNING;
    }

  ripng->garbage_time = garbage;

  return CMD_SUCCESS;
}

DEFUN (no_ripng_garbage_timer,
       no_ripng_garbage_timer_cmd,
       "no garbage-timer SECOND",
       NO_STR
       "Unset RIPng garbage timer in seconds\n"
       "Seconds\n")
{
  ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;
  return CMD_SUCCESS;
}
#endif /* 0 */

DEFUN (ripng_timers,
       ripng_timers_cmd,
       "timers basic <update> <timeout> <garbage>",
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
  unsigned long update;
  unsigned long timeout;
  unsigned long garbage;
  char *endptr = NULL;

  update = strtoul (argv[0], &endptr, 10);
  if (update == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "update timer value error\r\n");
      return CMD_WARNING;
    }
  
  timeout = strtoul (argv[1], &endptr, 10);
  if (timeout == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "timeout timer value error\r\n");
      return CMD_WARNING;
    }
  
  garbage = strtoul (argv[2], &endptr, 10);
  if (garbage == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "garbage timer value error\r\n");
      return CMD_WARNING;
    }

  /* Set each timer value. */
  ripng->update_time = update;
  ripng->timeout_time = timeout;
  ripng->garbage_time = garbage;

  /* Reset update timer thread. */
  ripng_event (RIPNG_UPDATE_EVENT, 0);

  return CMD_SUCCESS;
}

DEFUN (no_ripng_timers,
       no_ripng_timers_cmd,
       "no timers basic",
       NO_STR
       "RIPng timers setup\n"
       "Basic timer\n")
{
  /* Set each timer value to the default. */
  ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
  ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
  ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;

  /* Reset update timer thread. */
  ripng_event (RIPNG_UPDATE_EVENT, 0);

  return CMD_SUCCESS;
}

/*

Routing Protocol is "rip"
  Sending updates every 30 seconds, next due in 23 seconds
  Invalid after 180 seconds, hold down 180, flushed after 240
  Outgoing update filter list for all interfaces is not set
  Incoming update filter list for all interfaces is not set
  Redistributing: connected, rip
  Default version control: send version 2, receive version 2
    Interface        Send  Recv   Key-chain
    Ethernet0        2     2                      
    Ethernet1        2     2                      
  Routing for Networks:
    203.181.89.0
    202.227.9.0
  Routing Information Sources:
    Gateway         Distance      Last Update
    Gateway         Distance      Last Update
    203.181.89.5         120      4d11h
    203.181.89.27        120      1w3d
    203.181.89.26        120      3d07h
    203.181.89.99        120      1w4d
    202.227.9.102        120      3d07h
    203.181.89.94        120      3d08h
  Distance: (default is 120)

*/

DEFUN (show_ipv6_protocols, show_ipv6_protocols_cmd,
       "show ipv6 protocols",
       SHOW_STR
       IP_STR
       "Routing protocol information")
{
  if (! ripng)
    return CMD_SUCCESS;

  vty_out (vty, "Routing Protocol is \"ripng\"\r\n");
  
  vty_out (vty, "Sending updates every %d seconds, next due in %d seconds\r\n",
	   ripng->update_time, 0);

  vty_out (vty, "Timerout after %d seconds, garbage correct %d\r\n",
	   ripng->timeout_time, ripng->garbage_time);

  vty_out (vty, "Outgoing update filter list for all interfaces is not set");
  vty_out (vty, "Incoming update filter list for all interfaces is not set");

  return CMD_SUCCESS;
}

/* Please be carefull to use this command. */
DEFUN (default_information_originate,
       default_information_originate_cmd,
       "default-information originate",
       "Default route information\n"
       "Distribute default route\n")
{
  struct prefix_ipv6 p;

  ripng->default_information = 1;

  str2prefix_ipv6 ("::/0", &p);
  ripng_redistribute_add (ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);

  return CMD_SUCCESS;
}

DEFUN (no_default_information_originate,
       no_default_information_originate_cmd,
       "no default-information originate",
       NO_STR
       "Default route information\n"
       "Distribute default route\n")
{
  struct prefix_ipv6 p;

  ripng->default_information = 0;

  str2prefix_ipv6 ("::/0", &p);
  ripng_redistribute_delete (ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);

  return CMD_SUCCESS;
}

/* RIPng configuration write function. */
int
ripng_config_write (struct vty *vty)
{
  int ripng_network_write (struct vty *);
  void ripng_redistribute_write (struct vty *);
  int write = 0;
  struct route_node *rp;

  if (ripng)
    {

      /* RIPng router. */
      vty_out (vty, "router ripng%s", VTY_NEWLINE);

      if (ripng->default_information)
	vty_out (vty, " default-information originate%s", VTY_NEWLINE);

      ripng_network_write (vty);

      ripng_redistribute_write (vty);
      
      /* RIPng aggregate routes. */
      for (rp = route_top (ripng_aggregate); rp; rp = route_next (rp))
	if (rp->info != NULL)
	  vty_out (vty, " aggregate-address %s/%d%s", 
		   inet6_ntop (&rp->p.u.prefix6), rp->p.prefixlen, 
		   VTY_NEWLINE);

      /* RIPng static routes. */
      for (rp = route_top (ripng_static); rp; rp = route_next (rp))
	if (rp->info != NULL)
	  vty_out (vty, " route %s/%d%s", inet6_ntop (&rp->p.u.prefix6),
		   rp->p.prefixlen, VTY_NEWLINE);

      /* RIPng timers configuration. */
      if (ripng->update_time != RIPNG_UPDATE_TIMER_DEFAULT ||
	  ripng->timeout_time != RIPNG_TIMEOUT_TIMER_DEFAULT ||
	  ripng->garbage_time != RIPNG_GARBAGE_TIMER_DEFAULT)
	{
	  vty_out (vty, " timers basic %d %d %d%s",
		   ripng->update_time,
		   ripng->timeout_time,
		   ripng->garbage_time,
		   VTY_NEWLINE);
	}
#if 0
      if (ripng->update_time != RIPNG_UPDATE_TIMER_DEFAULT)
	vty_out (vty, " update-timer %d%s", ripng->update_time, VTY_NEWLINE);
      if (ripng->timeout_time != RIPNG_TIMEOUT_TIMER_DEFAULT)
	vty_out (vty, " timeout-timer %d%s", ripng->timeout_time, VTY_NEWLINE);
      if (ripng->garbage_time != RIPNG_GARBAGE_TIMER_DEFAULT)
	vty_out (vty, " garbage-timer %d%s", ripng->garbage_time, VTY_NEWLINE);
#endif /* 0 */

      write++;
    }
  return write;
}

/* RIPng node structure. */
struct cmd_node cmd_ripng_node =
{
  RIPNG_NODE,
  "%s(config-router)# ",
};

/* Initialize ripng structure and set commands. */
void
ripng_init ()
{
  /* Randomize. */
  srand (time (NULL));

  /* RIPng routig table. */
  ripng_table = route_table_init ();
  ripng_static = route_table_init ();
  ripng_aggregate = route_table_init ();

  /* Install RIPNG_NODE. */
  install_node (&cmd_ripng_node, ripng_config_write);

  /* Install ripng commands. */
  install_element (VIEW_NODE, &show_ipv6_ripng_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ripng_cmd);

  install_element (CONFIG_NODE, &router_ripng_cmd);

  install_default (RIPNG_NODE);
  install_element (RIPNG_NODE, &ripng_route_cmd);
  install_element (RIPNG_NODE, &no_ripng_route_cmd);
  install_element (RIPNG_NODE, &ripng_aggregate_address_cmd);
  install_element (RIPNG_NODE, &no_ripng_aggregate_address_cmd);

  install_element (RIPNG_NODE, &ripng_timers_cmd);
  install_element (RIPNG_NODE, &no_ripng_timers_cmd);
#if 0
  install_element (RIPNG_NODE, &ripng_update_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_update_timer_cmd);
  install_element (RIPNG_NODE, &ripng_timeout_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_timeout_timer_cmd);
  install_element (RIPNG_NODE, &ripng_garbage_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_garbage_timer_cmd);
#endif /* 0 */

  install_element (RIPNG_NODE, &default_information_originate_cmd);
  install_element (RIPNG_NODE, &no_default_information_originate_cmd);

  /* Interface related function init. */
  ripng_if_init ();
  ripng_debug_init ();

  /* Access list install. */
  access_list_init ();

  /* Distribute list install. */
  distribute_init ();
}
