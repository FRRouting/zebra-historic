/*
 * RIPng daemon
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"
#include "ripngd/ripng_debug.h"
#include "zebra/zebra.h"

/* RIPng structure which includes many parameters related to RIPng
   protocol. If ripng couldn't active or ripng doesn't configured,
   ripng->fd must be negative value. */

struct ripng *ripng = NULL;

/* RIPng routing table which hold routing table entry and static and
   aggregate network configuration. */

struct route_table *ripng_table;

/* Prototypes. */
void ripng_supply (struct interface *);

/* Set multicast hops 255 to the socket. */
static int
setsockopt_ipv6_multicast_hops (int sock)
{
  int ret;
  int val = 255;

  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
  if (ret < 0)
    zlog (NULL, LOG_ERR, "can't setsockopt IPV6_MULTICAST_HOPS");
  return ret;
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

/* Set IPv6 packet info to the socket. */
static int
setsockopt_ipv6_pktinfo (int sock)
{
  int ret;
  int val = 1;
    
#ifdef INRIA_IPV6
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val));
#else
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
#endif /* INIA_IPV6 */
  if (ret < 0)
    zlog (NULL, LOG_ERR, 
	  "can't setsockopt IPV6_PKTINFO : %s", strerror (errno));
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
  ret = setsockopt_ipv6_pktinfo (sock);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_hops (sock);
  if (ret < 0)
    return ret;
  ret = setsockopt_ipv6_multicast_loop (sock);
  if (ret < 0)
    return ret;

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

int
ripng_send_packet (caddr_t buf, int bufsize, struct in6_addr *to, 
		   unsigned int ifindex)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;
  char adata [sizeof (struct cmsghdr) + sizeof (struct in6_pktinfo)];
  struct in6_pktinfo *pkt;
  struct sockaddr_in6 addr;

#ifdef SIN6_LEN
  addr.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons (RIPNG_PORT_DEFAULT);
  addr.sin6_flowinfo = htonl (RIPNG_PRIORITY_DEFAULT);
  if (to != NULL)
    addr.sin6_addr = *to;
  else
    inet_pton(AF_INET6, RIPNG_GROUP, &addr.sin6_addr);

  SET_IN6_LINKLOCAL_IFINDEX (addr.sin6_addr, ifindex);

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
  pkt->ipi6_ifindex = ifindex;

  ret = sendmsg (ripng->sock, &msg, 0);
  if (ret < 0)
    {
      struct interface *ifp;

      ifp = if_lookup_by_index (ifindex);
      zlog (NULL, LOG_ERR, "*Error* RIPng send fail on %s : %s", 
	    ifp->name, strerror (errno));
    }

  return ret;
}


/* Receive UDP RIPng packet from socket. */
int
ripng_recv_packet (int sock, u_char *buf, int bufsize,
		   struct sockaddr_in6 *from, unsigned int *ifindex)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr  *cmsgptr;

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
      /* I want interface index this packet comes from. */
      if (cmsgptr->cmsg_level == IPPROTO_IPV6 &&
	  cmsgptr->cmsg_type == IPV6_PKTINFO) 
	{
	  struct in6_pktinfo *ptr;

	  ptr = (struct in6_pktinfo *) CMSG_DATA(cmsgptr);
	  *ifindex = ptr->ipi6_ifindex;
        }
    }
  return ret;
}

/* Dump rip packet */
void
ripng_packet_dump (struct ripng_packet *rp, int size)
{
  u_char *lim;
  struct rte *rte;
  char buf[BUFSIZ];
  char *cmd_str[] = {"NULL", "RIP_REQUEST", "RIP_RESPONSE"};

  /* Dump packet header. */
  zlog (NULL, LOG_INFO, "[Packet] RIPng version %d %s packet size %d",
	rp->version, cmd_str[rp->command], size);

  rte = rp->rte;
  lim = (caddr_t) rp + size;
  
  while ((u_char *) rte < lim)
    {
      if (rte->metric == RIPNG_METRIC_NEXTHOP)
	zlog (NULL, LOG_INFO, "  nexthop %s/%d",
	     inet_ntop (AF_INET6, &rte->addr, buf, BUFSIZ), 
	     rte->masklen);
      else
	zlog (NULL, LOG_INFO, "  %s/%d metric %d tag %d",
	     inet_ntop (AF_INET6, &rte->addr, buf, BUFSIZ), 
	     rte->masklen, rte->metric, ntohs (rte->tag));
      rte++;
    }
}

/* Check packet's validity. */
int
ripng_check_packet (struct ripng_packet *rp, struct sockaddr_in6 *sin6)
{
  int ret;

  /* Check version number of incoming packet. */
  if (rp->version != ripng->version) 
    {
      zlog (NULL, LOG_INFO, 
	    "This packet's version[%d] doesn't fit to my version.", 
	    rp->version);
      return -1;
    }

  /* Check port number of incoming packet. */
  if (ntohs (sin6->sin6_port) != RIPNG_PORT_DEFAULT) 
    {
      zlog (NULL, LOG_INFO, 
	    "This packet doesn't come from ripng port : %d", 
	    ntohs (sin6->sin6_port));
      return -1;
    }
  
  /* Check packet comes from linklocal address. */
  ret = IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr);
  if (!ret)
    {
      zlog (NULL, LOG_INFO,
	    "This packet is coming from not link local address");
      return -1;
    }
  
  /* Is this packet coming from myself? */

  /* Does this packet's hop counts set to 255? */

  return 1;
}

/* Set nexthop address. */
void
ripng_nexthop_route (struct rte *rte, 
		     struct sockaddr_in6 *from,
		     struct in6_addr *nexthop)
{
  assert (rte->tag == 0);
  assert (rte->masklen == 0);

  /* If nexthop address is not link local address ignore it. */
  if (!IN6_IS_ADDR_LINKLOCAL (&rte->addr))
    return;
  IPV6_ADDR_COPY (nexthop, &rte->addr);
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

/* RIP packet adding routine. */
void
ripng_add_route (struct rte *rte, struct sockaddr_in6 *from,
		 struct in6_addr *nexthop, unsigned int ifindex,
		 time_t gettime)
{
  struct ripng_info *rinfo;
  struct ripng_slot *slot;
  struct route_node *node;
  char buf[INET6_ADDRSTRLEN];
  struct interface *ifp;
  struct ripng_interface *ri;
  struct prefix p;

  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      zlog (NULL, LOG_WARNING, 
	    "Can't lookup interface by index [%d]", ifindex);
      return;
    }
  ri = ifp->if_data;

  /* Multicast address check. */
  if (IN6_IS_ADDR_MULTICAST (&rte->addr))
    {
      zlog (NULL, LOG_WARNING ,
	    "Destination prefix is a multicast address %s/%d. "
	    "Ignore this routing entry.",
	    inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
	    rte->masklen);
      return;
    }

  /* Link local address check. */
  if (IN6_IS_ADDR_LINKLOCAL (&rte->addr))
    {
      zlog (NULL, LOG_WARNING, 
	    "Destination prefix is a link-local address %s/%d. "
	    "Ignore this routing entry.",
	    inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
	    rte->masklen);
      return;
    }

  /* Prefix length check. We don't need negative check for masklen
     because masklen is define as u_char. */
  if (rte->masklen > 128)
    {
      zlog (NULL, LOG_WARNING,
	    "Invalid prefix length %s/%d. Ignore this routing entry.",
	    inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
	    rte->masklen);
      return;
    }

  /* Default route check. */
  if (IN6_IS_ADDR_UNSPECIFIED (&rte->addr))
    {
      if (ri->ri_default_receive != RIPNG_DEFAULT_ACCEPT)
	{
	  if (IS_RIPNG_DEBUG_PACKET)
	    zlog (NULL, LOG_INFO, "Filtered default route");
	  return;
	}
    }

  if (ri->ri_receive == RIPNG_RECEIVE_OFF)
    {
      if (IS_RIPNG_DEBUG_EVENT)
	zlog (NULL, LOG_INFO, "[Event] RIPng route is filtered by configuration.");
      return;
    }

  /* Lookup routing table of RIPng, if there is no prefix in the table
     this function create it.  The node is locked by
     route_node_lokup function. */
  p.family = AF_INET6;
  p.u.prefix6 = rte->addr;
  p.prefixlen = rte->masklen;

  node = route_node_get (ripng_table, &p);

  if (!node->info)
    ripng_slot_add (node);

  slot = node->info;
  
  rinfo = RIPNG_SLOT_RTE(slot);
  if (rinfo)
    {
      /* If route already exist in routing table then update timer of
         the route. */
      if (IS_RIPNG_DEBUG_ZEBRA)
	zlog (NULL, LOG_INFO, "ripng update route %s/%d",
	      inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN), 
	      rte->masklen);

      /* XXX Maybe we need nexthop and incoming address check here. */

      rinfo->timer = gettime;

      /* We have to unlock route node. */
      route_unlock_node (node);

      return;
    }

  /* Fetch information into ripng_info structure */
  rinfo = ripng_info_new ();

  /* If there is no previous nexthop setting from address should be
     nexthop. */
  if (!IN6_IS_ADDR_UNSPECIFIED (nexthop))
    IPV6_ADDR_COPY (&rinfo->nexthop, nexthop);
  else
    IPV6_ADDR_COPY (&rinfo->nexthop, &from->sin6_addr);

  /* We preserve incoming hosts address. */
  IPV6_ADDR_COPY (&rinfo->gateway, &from->sin6_addr);
  rinfo->type = RIPNG_ROUTE_RTE;
  rinfo->metric = rte->metric;
  rinfo->rip_tag = ntohs (rte->tag);
  rinfo->ifindex = ifindex;
  rinfo->timer = gettime;
  rinfo->fib = 1;
  RIPNG_SLOT_RTE(slot) = rinfo;
  
  if (IS_RIPNG_DEBUG_ZEBRA)
    zlog (NULL, LOG_INFO, 
	  "ripng add route %s/%d", 
	 inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
	 rte->masklen);

  /* Add zebra event. */
  ripng_event (RIPNG_ZEBRA, 0);
}

/* Process delete of route. */
void
ripng_delete_route (struct rte *rte,
		    struct sockaddr_in6 *from)
{
  struct prefix p;
  char buf[INET6_ADDRSTRLEN];
  struct route_node *find;

  /* If route is alread exist update timer. */
  zlog (NULL, LOG_INFO,
	"rip delete route %s/%d", 
	inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN), 
	rte->masklen);

  p.family = AF_INET6;
  p.u.prefix6 = rte->addr;
  p.prefixlen = rte->masklen;
  
  find = route_node_get (ripng_table, &p);

  if (find->info == NULL)
    {
      zlog (NULL, LOG_WARNING, "route is already deleted");
      return;
    }

  ripng_info_free (find->info);
  find->info = NULL;
  route_unlock_node (find);
  ripng_event (RIPNG_ZEBRA, 0);
}

/* RIP routing information. */
void
ripng_response_process (struct ripng_packet *rp, int size, 
			struct sockaddr_in6 *from, unsigned int ifindex)
{
  u_char *lim;
  time_t gettime;
  struct rte *rte;
  struct in6_addr nexthop;

  /* Clear time and nexthop address. */
  time (&gettime);
  bzero (&nexthop, sizeof (struct in6_addr));

  rte = rp->rte;
  lim = ((u_char *) rp) + size;

  while ((u_char *) rte < lim) 
    {
      switch (rte->metric)
	{
	case 0: case 1: case 2: case 3: case 4: case 5:	case 6: case 7:
	case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15:
	  ripng_add_route (rte, from, &nexthop, ifindex, gettime);
	  break;
	case RIPNG_METRIC_INFINITY:
	  ripng_delete_route (rte, from);
	  break;
	case RIPNG_METRIC_NEXTHOP:
	  ripng_nexthop_route (rte, from, &nexthop);
	  break;
	default:
	  break;
	}
      rte++;
    }
}

/* Response to request. */
void
ripng_request_process (struct ripng_packet *rp,int size, 
		       struct sockaddr_in6 *from, unsigned int ifindex)
{
  struct interface *ifp;

  ifp = if_lookup_by_index (ifindex);

  if (IS_RIPNG_DEBUG_EVENT)
    zlog (NULL, LOG_INFO,
	  "[Event] RIPng REQUEST recieved from %s", ifp->name);

  if (ifp)
    ripng_supply (ifp);
}

/* First entry point of reading RIPng packet. */
int
ripng_read (struct thread *thread)
{
  int ret;
  int len;
  int sock;
  struct sockaddr_in6 from;
  struct ripng_packet *packet;
  unsigned int ifindex;

  /* Check ripng is active and alive. */
  assert (ripng != NULL);
  assert (ripng->sock >= 0);

  /* Fetch thread data and set read pointer to empty for event
     managing.  `sock' sould be same as ripng->sock. */
  sock = THREAD_FD (thread);
  ripng->t_read = NULL;

  len = ripng_recv_packet (sock, 
			   STREAM_DATA (ripng->ibuf),
			   STREAM_SIZE (ripng->ibuf), 
			   &from, &ifindex);

  /* If we can't read RIPng packet, logging it and cancel to add new
     read thread. */
  if (len < 0) 
    {
      zlog (NULL, LOG_WARNING, "recvfrom failed by %s.", strerror (errno));
      return len;
    }

  packet = (struct ripng_packet *) STREAM_DATA (ripng->ibuf);

  /* OK I'm called so if debug option is set tell it to the user. */
  if (IS_RIPNG_DEBUG_EVENT)
    {
      struct interface *ifp;
      char buf[BUFSIZ];

      ifp = if_lookup_by_index (ifindex);

      zlog (NULL, LOG_INFO, 
	    "[Event] RIPng received on %s %s port %d", ifp->name,
	    inet_ntop (AF_INET6, &from.sin6_addr, buf, BUFSIZ), 
	    ntohs (from.sin6_port));
    }

  /* Dump packet rte. */
  if (IS_RIPNG_DEBUG_PACKET)
    ripng_packet_dump (packet, len);

  /* Is this packet is valid for this router. */
  ret = ripng_check_packet (packet, &from);
  if (ret < 0)
    return ret;

  switch (packet->command)
    {
    case RIPNG_REQUEST:
      ripng_request_process (packet, len, &from, ifindex);
      break;
    case RIPNG_RESPONSE:
      ripng_response_process (packet, len, &from, ifindex);
      break;
    default:
      zlog (NULL, LOG_WARNING, "Invalid RIPng command %d", packet->command);
      break;
    }
  
  /* Add itself to the next event. */
  ripng_event (RIPNG_READ, sock);

  return 0;
}

/* Age ripng routes. */
void
ripng_age ()
{
  struct route_node *node;
  time_t current_time;

  /* Set current time. */
  time (&current_time);

  /* Walk down routing table. */
  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;

      /* Get routing information from routing table. */
      slot = node->info;

      if (!slot)
	continue;

      /* Get RIPng routing entry. */
      rinfo = RIPNG_SLOT_RTE (slot);

      /* Check RIPng routing entry is aged. */
      if (rinfo)
	if (rinfo->timer < (current_time - ripng->timeout_time))
	  {
	    ripng_zebra_ipv6_delete ((struct prefix_ipv6 *) &node->p,
				     &rinfo->nexthop, rinfo->ifindex);

	    ripng_info_free (rinfo);
	    RIPNG_SLOT_RTE (slot) = NULL;
	    ripng_slot_check (node);
	    
	    route_unlock_node (node);
	  }
    }
}

/* Write routing table entry to the stream and return next index of
   the routing table entry in the stream. */
int
ripng_write_rte (int index, struct stream *s, struct prefix_ipv6 *p,
		 u_int16_t tag, u_int8_t metric)
{
  /* RIPng packet header. */
  if (index == 0)
    {
      stream_putc (s, RIPNG_RESPONSE);
      stream_putc (s, RIPNG_V1);
      stream_putw (s, 0);
    }

  /* Write routing table entry. */
  stream_write (s, (u_char *)&p->prefix, sizeof (struct in6_addr));
  stream_putw (s, 0);
  stream_putc (s, p->prefixlen);
  stream_putc (s, metric);

  /* Increment counter. */
  index++;

  return index;
}

/* If prefix is permitted return 1. */
int
ripng_distribute_out (struct interface *ifp, struct prefix *p)
{
  int ret;

  /* Apply distribute-list out. */
  if (ifp->distribute_out)
    {
      ret = access_list_apply (ifp->distribute_out, p);
      if (!ret)
	{
	  char buf[BUFSIZ];
	  
	  if (IS_RIPNG_DEBUG_PACKET)
	    zlog (NULL, LOG_INFO, "  %s/%d filtered by distribute-list",
		  inet_ntop (AF_INET6, &p->u.prefix6, buf, BUFSIZ), 
		  p->prefixlen);
	  return ret;
	}
    }
  return 1;
}

/* Supply route to the interface. */
void
ripng_supply (struct interface *ifp)
{
  int ret;
  struct route_node *node;
  struct ripng_slot *slot;
  struct ripng_info *rinfo;
  int nrte;
  int maxrte;
  u_char metric;
  struct stream *s;
  
  /* Number of written routing table entry */
  nrte = 0;

  /* Set buffer and it's size. */
  s = ripng->obuf;
  maxrte = (STREAM_SIZE(s) - 4) / 20;

  if (IS_RIPNG_DEBUG_EVENT)
    zlog (NULL, LOG_INFO,
	  "[Event] RIPng supply routes to interface %s", ifp->name);

  /* Write each routing information. */
  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      slot = node->info;

      if (slot == NULL)
	continue;
	
      rinfo = RIPNG_SLOT_AGGREGATE(slot);
      if (rinfo)
	{
	  ;
	}

      rinfo = RIPNG_SLOT_STATIC(slot);

      if (rinfo)
	{
	  ret = ripng_distribute_out (ifp, &node->p);
	  if (!ret)
	    continue;
  
	  metric = rinfo->metric + ifp->metric;
	  if (metric > RIPNG_METRIC_INFINITY)
	    metric = RIPNG_METRIC_INFINITY;

	  nrte = ripng_write_rte (nrte, s, (struct prefix_ipv6 *)&node->p, 
				  0, metric);
	  if (nrte == maxrte)
	    {
	      nrte = 0;
	      ret = ripng_send_packet (STREAM_DATA (s),
				       stream_get_endp (s),
				       NULL, ifp->index);

	      if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
		ripng_packet_dump ((struct ripng_packet *)STREAM_DATA (s),
				   stream_get_endp(s));

	      stream_reset (s);
	    }
	}

      rinfo = RIPNG_SLOT_RTE(slot);
      if (rinfo)
	{
	  /* Split horizon. */
	  if (rinfo->ifindex != ifp->index)
	    {
	      ret = ripng_distribute_out (ifp, &node->p);
	      if (!ret)
		continue;
  
	      metric = rinfo->metric + ifp->metric;
	      if (metric > RIPNG_METRIC_INFINITY)
		metric = RIPNG_METRIC_INFINITY;

	      nrte = ripng_write_rte (nrte, s, (struct prefix_ipv6 *)&node->p, 
				      0, metric);

	      if (nrte == maxrte)
		{
		  nrte = 0;

		  ret = ripng_send_packet (STREAM_DATA (s),
					   stream_get_endp (s), NULL,
					   ifp->index);

		  if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
		    ripng_packet_dump ((struct ripng_packet *)STREAM_DATA(s),
				       stream_get_endp(s));
		  stream_reset (s);
		}
	    }
	}
    }

  /* If written routing entry exists, flush it. */
  if (nrte != 0)
    {
      ret = ripng_send_packet (STREAM_DATA (s),
			       stream_get_endp (s), NULL, ifp->index);

      if (ret >= 0 && IS_RIPNG_DEBUG_PACKET)
	ripng_packet_dump ((struct ripng_packet *)STREAM_DATA (s),
			   stream_get_endp (s));
    }
  stream_reset (s);
}

/* Flush route. */
int
ripng_flush ()
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;

  /* Clear thread. */
  ripng->t_flush = NULL;

  /* Log flush event. */
  if (IS_RIPNG_DEBUG_EVENT)
    zlog (NULL, LOG_INFO, "[Event] RIPng flush timer expired!");

  /* Age of rte routes. */
  ripng_age ();

  /* Supply routes to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp) || !if_is_up (ifp))
	continue;

      ri = ifp->if_data;
      if (ri->ri_send == RIPNG_SEND_OFF)
	{
	  if (IS_RIPNG_DEBUG_EVENT)
	    zlog (NULL, LOG_INFO, 
		  "[Event] RIPng send to if %d is suppressed by config",
		 ifp->index);
	  continue;
	}

      if (!ri->enable)
	continue;

      ripng_supply (ifp);
    }

  /* Reset flush event. */
  ripng_event (RIPNG_FLUSH_EVENT, 0);

  return 0;
}

/* Create new RIP instance and set it to global variable rip. */
int
ripng_create ()
{
  /* ripng should be NULL. */
  assert (ripng == NULL);

  /* Allocaste RIP instance. */
  ripng = XMALLOC (0, sizeof (struct ripng));
  bzero (ripng, sizeof (struct ripng));

  /* Default version and timer values. */
  ripng->version = RIPNG_V1;
  ripng->flush_time = RIPNG_FLUSH_TIMER;
  ripng->timeout_time = RIPNG_TIMEOUT_TIMER;
  ripng->garbage_time = RIPNG_GARBAGE_TIMER;
  
  /* XXX Make buffer.  Size should be calculated by MTU. */
  ripng->ibuf = stream_new (1500 * 5);
  ripng->obuf = stream_new (1500);

  /* Make socket. */
  ripng->sock = ripng_make_socket ();
  if (ripng->sock < 0)
    return ripng->sock;

  /* Threads. */
  ripng_event (RIPNG_READ, ripng->sock);
  ripng_event (RIPNG_FLUSH_EVENT, 0);

  return 0;
}

/* Sned RIPng request to the interface. */
int
ripng_request (struct interface *ifp)
{
  int ret;
  struct rte *rte;
  struct ripng_packet ripng_packet;

  if (IS_RIPNG_DEBUG_EVENT)
    zlog (NULL, LOG_INFO, "[Event] RIPng send request to %s", ifp->name);

  bzero (&ripng_packet, sizeof (ripng_packet));
  ripng_packet.command = RIPNG_REQUEST;
  ripng_packet.version = RIPNG_V1;
  rte = ripng_packet.rte;
  rte->metric = RIPNG_METRIC_INFINITY;

  ret = ripng_send_packet ((caddr_t) &ripng_packet, 
			   sizeof (ripng_packet), 
			   NULL,
			   ifp->index);

  return ret;
}

/* Make packet which send to zebra. */
int
ripng_zebra (struct thread *thread)
{
  struct route_node *node;

  /* First of all clear thread pointer. */
  ripng->t_zebra = NULL;

  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      
      slot = node->info;
      if (slot == NULL)
	continue;

      rinfo = RIPNG_SLOT_RTE(slot);
      if (rinfo == NULL)
	continue;

      ripng_zebra_ipv6_add ((struct prefix_ipv6 *)&node->p,
			    &rinfo->nexthop, rinfo->ifindex);
    }
  return 0;
}

/* Clean up installed RIPng routes. */
void
ripng_terminate ()
{
  struct route_node *node;

  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
  
      slot = node->info;

      if (slot == NULL)
	continue;

      if ((rinfo = RIPNG_SLOT_RTE (slot)) != NULL)
	ripng_zebra_ipv6_delete ((struct prefix_ipv6 *)&node->p,
				 &rinfo->nexthop, rinfo->ifindex);
    }
}

extern struct thread_master *master;

void
ripng_event (enum event event, int sock)
{
  int ripng_request_all (struct thread *);

  switch (event)
    {
    case RIPNG_READ:
      if (!ripng->t_read)
	ripng->t_read = thread_add_read (master, ripng_read, NULL, sock);
      break;
    case RIPNG_ZEBRA:
      if (!ripng->t_zebra)
	ripng->t_zebra = thread_add_event (master, ripng_zebra, NULL, 0);
      break;
    case RIPNG_REQUEST_EVENT:
      thread_add_event (master, ripng_request_all, NULL, 0);
      break;
    case RIPNG_FLUSH_EVENT:
      if (ripng->t_flush)
	thread_cancel (ripng->t_flush);
      ripng->t_flush = thread_add_timer (master, ripng_flush, NULL, 
					 ripng->flush_time);
      break;
    default:
      break;
    }
}

/* For messages. */
struct message
{
  int key;
  char *str;
} route_sort_msg[] =
{
  { RIPNG_ROUTE_RTE,       "R"},
  { RIPNG_ROUTE_STATIC,    "S"},
  { RIPNG_ROUTE_AGGREGATE, "A"}
};

/* Print out routes update time. */
static void
ripng_vty_out_uptime (struct vty *vty, struct ripng_info *rinfo)
{
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];

  time (&clock);
  clock -= rinfo->timer;
  tm = gmtime (&clock);
  strftime (timebuf, TIME_BUF, "%M:%S", tm);
  vty_out (vty, "%5s", timebuf);
}

DEFUN (show_ip_ripng,
       show_ip_ripng_cmd,
       "show ip ripng",
       SHOW_STR
       IP_STR
       "Show RIPng routes\n")
{
  struct route_node *node;

  /* Header of display. */ 
  vty_out (vty, "\r\nCodes: R - RIPng\r\n\r\n"
	   "  Network                             "
	   "Next Hop                Metric Tag Time\r\n");
  
  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      int i;
      int len;
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->info;

      if (slot == NULL)
	continue;

      for (i = 0; i < RIPNG_SLOT_MAX; i++)
	if ((rinfo = slot->rinfo[i]) != NULL)
	  {
	    len = vty_out (vty, "%s %s/%d ",
			   route_sort_msg[rinfo->type].str,
			   inet_ntop (AF_INET6, &node->p.u.prefix6, 
				      buf, BUFSIZ), 
			   node->p.prefixlen);
	    len = 38 - len;
	    
	    if (len > 0)
	      vty_out (vty, "%*s", len, " ");

	    len = vty_out (vty, "%s", 
			   inet_ntop (AF_INET6, &rinfo->nexthop, buf, BUFSIZ));
	    len = 26 - len;
	    
	    if (len > 0)
	      vty_out (vty, "%*s", len, " ");

	    vty_out (vty, "%4d %3d ", rinfo->metric, rinfo->rip_tag);
	    /* vty_out (vty, "%s", inet_ntoa (rinfo->gateway)); */
	    if (rinfo->type == RIPNG_ROUTE_RTE)
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
	zlog (NULL, LOG_WARNING, "can't create RIPng");
    }

  return CMD_SUCCESS;
}

DEFUN (route,
       route_cmd,
       "route IPV6ADDR",
       "Static route setup\n"
       "Set static RIPng route announcement\n")
{
  int ret;
  u_char metric;
  struct prefix p;
  struct route_node *node;

  metric = 0;
  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }

  if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6) && p.prefixlen == 0)
    {
      vty_out (vty, "Please use 'default' command for default route.\r\n");
      return CMD_WARNING;
    }

  node = route_node_get (ripng_table, &p);

  /* Metric should be configurable. */
  ret = ripng_static_add (node, metric, 1);
  if (ret < 0)
    {
      vty_out (vty, "There is already same static route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_route,
       no_route_cmd,
       "no route IPV6ADDR",
       NO_STR
       "Static route setup\n"
       "Delete static RIPng route announcement\n")
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

  node = route_node_get (ripng_table, &p);

  ret = ripng_static_delete (node);
  if (ret < 0)
    {
      vty_out (vty, "Can't find static route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }
  /* route_unlock_node (node); */
  return CMD_SUCCESS;
}

DEFUN (aggregate,
       aggregate_cmd,
       "aggregate IPV6ADDR",
       "Set aggregate RIPng route announcement\n"
       "IP address\n")
{
  int ret;
  u_char metric;
  struct prefix p;
  struct route_node *node;

  metric = 0;
  ret = str2prefix_ipv6 (argv[0], (struct prefix_ipv6 *)&p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }

  node = route_node_get (ripng_table, &p);

  /* Metric should be configurable. */
  ret = ripng_aggregate_add (node, metric);
  if (ret < 0)
    {
      vty_out (vty, "There is already same aggregate route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_aggregate,
       no_aggregate_cmd,
       "no aggregate IPV6ADDR",
       NO_STR
       "Delete aggregate RIPng route announcement\n"
       "IP address")
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

  node = route_node_get (ripng_table, &p);

  ret = ripng_aggregate_delete (node);
  if (ret < 0)
    {
      vty_out (vty, "Can't find aggregate route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }
  route_unlock_node (node);

  return CMD_SUCCESS;
}

/* RIPng flush timer setup. */
DEFUN (ripng_flush_timer,
       ripng_flush_timer_cmd,
       "flush-timer SECOND",
       "Set ripng flush timer in seconds\n"
       "Seconds\n")
{
  unsigned int newflush;

  newflush = atoi (argv[0]);
  if (!newflush)
    return CMD_WARNING;

  ripng->flush_time = newflush;

  ripng_event (RIPNG_FLUSH_EVENT, 0);
  return CMD_SUCCESS;
}

/* Dump static RIPng routing setup to the vty. */
void
ripng_static_dump (struct route_node *node, struct vty *vty)
{
  if (node->info)
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->info;
      rinfo = RIPNG_SLOT_STATIC(slot);

      if (rinfo && rinfo->sub_type)
	vty_out (vty, " route %s/%d%s",
		 inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ), 
		 node->p.prefixlen, VTY_NEWLINE);
    }
}

/* Dump aggregate RIPng routing setup to the vty. */
void
ripng_aggregate_dump (struct route_node *node, struct vty *vty)
{
  if (node->info)
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->info;
      rinfo = RIPNG_SLOT_AGGREGATE(slot);

      if (rinfo)
	vty_out (vty, " aggregate %s/%d%s",
		 inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ), 
		 node->p.prefixlen, VTY_NEWLINE);
    }
}


/* RIPng configuration write function. */
int
ripng_config_write (struct vty *vty)
{
  int ripng_network_write (struct vty *);
  void ripng_redistribute_write (struct vty *);
  int write = 0;

  if (ripng)
    {
      struct route_node *node;

      /* RIPng router. */
      vty_out (vty, "router ripng%s", VTY_NEWLINE);

      ripng_network_write (vty);

      ripng_redistribute_write (vty);
      
      /* RIPng aggregate routes. */
      for (node = route_top (ripng_table); node; node = route_next (node))
	ripng_aggregate_dump (node, vty);

      /* RIPng static routes. */
      for (node = route_top (ripng_table); node; node = route_next (node))
	ripng_static_dump (node, vty);

      /* Flush timer configuration print out. */
      if (ripng->flush_time != RIPNG_FLUSH_TIMER)
	vty_out (vty, " flush-timer %d%s", ripng->flush_time, VTY_NEWLINE);

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
  /* RIPng routig table. */
  ripng_table = route_table_init ();

  /* Install RIPNG_NODE. */
  install_node (&cmd_ripng_node, ripng_config_write);

  /* Install ripng commands. */
  install_element (VIEW_NODE, &show_ip_ripng_cmd);
  install_element (ENABLE_NODE, &show_ip_ripng_cmd);
  install_element (CONFIG_NODE, &router_ripng_cmd);
  install_element (RIPNG_NODE, &config_end_cmd);
  install_element (RIPNG_NODE, &config_exit_cmd);
  install_element (RIPNG_NODE, &config_help_cmd);
  install_element (RIPNG_NODE, &aggregate_cmd);
  install_element (RIPNG_NODE, &no_aggregate_cmd);
  install_element (RIPNG_NODE, &route_cmd);
  install_element (RIPNG_NODE, &no_route_cmd);
  install_element (RIPNG_NODE, &ripng_flush_timer_cmd);

  /* Interface related function init. */
  ripng_if_init ();
  ripng_debug_init ();

  /* Access list install. */
  access_list_init ();

  /* Distribute list install. */
  distribute_init ();
}
