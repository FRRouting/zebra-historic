/* RIPng daemon
   Copyright (C) 1998 Kunihiro Ishiguro

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
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <net/route.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <assert.h>

#include "thread.h"
#include "ripngd.h"
#include "zebra.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "host.h"
#include "route.h"
#include "memory.h"
#include "linklist.h"
#include "if.h"
#include "buffer.h"
#include "table.h"

/* RIPng structure which includes many parameters related to RIPng
   protocol. If ripng couldn't active or ripng doesn't configured,
   ripng->fd will be negative value. */

struct ripng *ripng = NULL;

/* RIPng routing table which hold routing table entry and static and
   aggregate network configuration. */

struct route_table *ripng_table;

/* For debug statement. */
unsigned long ripng_debug_option;
unsigned long ripng_debug_direction;
unsigned long ripng_debug_detail;

/* Debug sort enumeration. */
enum
{
  /* Debug option sort. */
  DEBUG_EVENT =  0x01,
  DEBUG_PACKET = 0x04,
  DEBUG_ACTION = 0x08,

  /* Debug direction. */
  DEBUG_BOTH = 0x01,
  DEBUG_IN =   0x02,
  DEBUG_OUT =  0x04,

  /* Debug detail. */
  DEBUG_NORMAL = 0x01,
  DEBUG_DETAIL = 0x02,
};

void
debug_set (unsigned int option)
{
  ripng_debug_option |= option;
}

void
debug_unset (unsigned int option)
{
  ripng_debug_option &= ~option;
}

int
debug (unsigned int option)
{
  return ripng_debug_option & option;
}

/* Set multicast hops 255 to the socket. */
static int
setsockopt_ipv6_multicast_hops (int sock)
{
  int ret;
  int val = 255;

  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));
  if (ret < 0)
    log ("can't setsockopt IPV6_MULTICAST_HOPS\n");
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
      log ("can't setsockopt IPV6_MULTICAST_LOOP\n");
  return ret;
}

static int
setsockopt_so_recvbuf (int sock, int size)
{
  int ret;

  ret = setsockopt (sock, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof (int));
  if (ret < 0)
    log ("can't setsockopt SO_RCVBUF\n");
  return ret;
}

/* Set IPv6 packet info to the socket. */
static int
setsockopt_ipv6_pktinfo (int sock)
{
  int ret;
  int val = 1;
    
  ret = setsockopt(sock, IPPROTO_IPV6, IPV6_PKTINFO, &val, sizeof(val));
  if (ret < 0)
      log ("can't setsockopt IPV6_PKTINFO : %s\n", strerror (errno));
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
      log ("Can't make ripng socket\n");
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
      log ("Can't bind ripng socket: %s.\n", strerror (errno));
      return ret;
    }
  return sock;
}

/* Send UDP RIPng packet to the socket. If under Hydrangea index is
   already specified in the address. */
#ifdef HYDRANGEA
ripng_send_packet (caddr_t pnt, 
		   int size, 
		   struct in6_addr *to,
		   unsigned int ifindex)
{
  int ret;
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
    inet_pton (AF_INET6, RIPNG_GROUP, &addr.sin6_addr);

#ifdef HYDRANGEA
#ifdef 0 /***** Modified by seirios *****/
  SET_IN6_LINKLOCAL_IFINDEX (addr.sin6_addr, ifp->index);
#else /* 0 */
  SET_IN6_LINKLOCAL_IFINDEX (addr.sin6_addr, ifindex);
#endif /* 0 */ /* by seirios */
#endif /* HYDRANGEA*/

#ifdef 0 /***** Modified by seirios *****/
  if (debug_opt & DEBUG_EVENT)
#else /* 0 */
  if (debug (DEBUG_EVENT))
#endif /* 0 */ /* by seirios */
    log ("[Event] RIPng packet send\n");

  ret = sendto (ripng->sock, pnt, size, 0,
		(struct sockaddr *)&addr, sizeof (struct sockaddr_in6));
  if (ret < 0)
    log ("ripng packet send fail:%s\n", strerror (errno));

  return ret;
}
#else
ripng_send_packet (caddr_t buf,
		   int bufsize, 
		   struct in6_addr *to, 
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

#ifdef HYDRANGEA
#ifdef 0 /***** Modified by seirios *****/
  SET_IN6_LINKLOCAL_IFINDEX (addr.sin6_addr, ifp->index);
#else /* 0 */
  SET_IN6_LINKLOCAL_IFINDEX (addr.sin6_addr, ifindex);
#endif /* 0 */ /* by seirios */
#endif /* HYDRANGEA*/

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
    log ("ripng packet send fail:%s\n", strerror (errno));

  return ret;
}
#endif /* HYDRANGEA */

/* Receive UDP RIPng packet from socket.  This part highly depends on
   operating system. I'll merge Hydrangea part when it's supports
   Advanced API. */
#ifdef HYDRANGEA
ripng_recv_packet (int sock, u_char *buf, int bufsize, 
		   struct sockaddr_in6 *from, unsigned int *ifindex)
{
  int len;
  int fromlen;

  fromlen = sizeof (struct sockaddr_in6);
  len = recvfrom (sock, (void *)buf, sizeof(buf), 0,
		  (struct sockaddr *) from, &fromlen);

  *ifindex = IN6_LINKLOCAL_IFINDEX (from->sin6_addr);

  return len;
}
#else 
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
	  if (debug (DEBUG_PACKET))
	    log ("[Packet] IPV6_PKTINFO ifindex %d\n", *ifindex);
        }
    }
  return ret;
}
#endif /* HYDRANGEA */

/* Dump rip packet */
ripng_packet_dump (struct ripng_packet *rp, 
		   int size, 
		   struct sockaddr_in6 *from)
{
  caddr_t lim;
  struct rte *rte;
  char pbuf[BUFSIZ];
  char *ripng_str[] = {"NULL", "RIP_REQUEST", "RIP_RESPONSE"};

  /* Dump packet header. */
  log ("RIPng version %d packet command [%s] size [%d] ",
       rp->version, ripng_str[rp->command], size);
  if (from != NULL)
    log2 ("host [%s] port [%d]",
	  inet_ntop (AF_INET6, &from->sin6_addr, pbuf, BUFSIZ), 
	  ntohs (from->sin6_port));
  log2("\n");

  rte = rp->rte;
  lim = ((caddr_t) rp) + size;
  
  log ("RIPng received\n");
  while ((caddr_t) rte < lim) 
    {
      if (rte->metric == 0xff)
	log ("nexthop [%s/%d]\n",
	     inet_ntop (AF_INET6, &rte->addr, pbuf, BUFSIZ), 
	     rte->masklen);
      else
	log ("prefix [%s/%d] tag [%d] metric [%d]\n",
	     inet_ntop (AF_INET6, &rte->addr, pbuf, BUFSIZ), 
	     rte->masklen, ntohs (rte->tag), rte->metric);
      rte ++;
    }
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

  /* OK I'm called so if debug option is set tell it to the user. */
  if (debug (DEBUG_EVENT))
    log ("[Event] RIPng packet read\n");

  /* Check ripng is active and alive. */
  assert (ripng != NULL);
  assert (ripng->sock >= 0);

  /* Fetch thread data and set read pointer to empty for event
     managing.  `sock' sould be same as ripng->sock. */
  sock = thread_fd (thread);
  ripng->t_read = NULL;

  len = ripng_recv_packet (sock, 
			   stream_data (ripng->ibuf),
			   stream_size (ripng->ibuf), 
			   &from, &ifindex);

  /* If we can't read RIPng packet, logging it and cancel to add new
     read thread. */
  if (len < 0) 
    {
      warning ("recvfrom failed by %s.\n", strerror (errno));
      return len;
    }

  packet = (struct ripng_packet *) stream_data (ripng->ibuf);

  /* Dump packet rte. */
  if (debug (DEBUG_PACKET))
    ripng_packet_dump (packet, len, &from);

  /* Is this packet is valid for this router. */
  ret = ripng_check_packet (packet, &from);
  if (ret < 0)
    return ret;

  switch (packet->command)
    {
    case RIPNG_REQUEST:
      ripng_request_process (packet, len, &from);
      break;
    case RIPNG_RESPONSE:
      ripng_response_process (packet, len, &from, ifindex);
      break;
    default:
      warning ("Invalid RIPng command %d\n", packet->command);
      break;
    }
  
  /* Add itself to the next event. */
  ripng_event (RIPNG_READ, sock);
}

ripng_expire ()
{
  ;
}

/* Age ripng routes. */
ripng_age ()
{
  struct route_node *node;
  struct ripng_slot *slot;
  struct ripng_info *rinfo;
  time_t current_time;

  time (&current_time);

  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      slot = node->route;

      if (!slot)
	continue;

      rinfo = RIPNG_SLOT_RTE (slot);
      /* If rte routes exist age it! */
      if (rinfo)
	{
	  if (rinfo->timer < (current_time - ripng->timeout_time))
	    ripng_expire ();
	}
    }
}

/* Supply route to the interface. */
ripng_supply (struct interface *ifp)
{
  struct route_node *node;
  struct ripng_slot *slot;
  struct ripng_info *rinfo;
  int nrte;
  int maxrte;
  u_char metric;
  struct stream *s;
  
  nrte = 0;
  s = ripng->obuf;
  maxrte = (STREAM_SIZE(s) - 4) / 20;

  if (debug (DEBUG_EVENT))
    log ("[Event] RIPng supply to ifindex %d\n", ifp->index);


  /* RIPns packet header. */
  stream_putc (s, RIPNG_RESPONSE);
  stream_putc (s, RIPNG_V1);
  stream_putw (s, 0);

  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      slot = node->route;

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
	  stream_write (s, 
			(u_char *)&node->p.u.prefix6, 
			sizeof (struct in6_addr));
	  stream_putw (s, 0);
	  stream_putc (s, node->p.prefixlen);
	  metric = rinfo->metric + ifp->metric;
	  if (metric > RIPNG_METRIC_INFINITY)
	    metric = RIPNG_METRIC_INFINITY;
	  stream_putc (s, metric);
	  nrte++;
	  if (nrte == maxrte)
	    {
	      nrte = 0;
	      ripng_send_packet (s->data, s->ep, NULL, ifp->index);
	      ripng_packet_dump ((struct ripng_packet *)s->data, s->ep, NULL);
	      stream_reset (s);
	    }
	  
	}

      rinfo = RIPNG_SLOT_RTE(slot);
      if (rinfo)
	{
	  /* Split horizon. */
	  if (rinfo->ifindex != ifp->index)
	    {
	      stream_write (s, 
			    (u_char *)&node->p.u.prefix6, 
			    sizeof (struct in6_addr));
	      stream_putw (s, 0);
	      stream_putc (s, node->p.prefixlen);
	      metric = rinfo->metric + ifp->metric;
	      if (metric > RIPNG_METRIC_INFINITY)
		metric = RIPNG_METRIC_INFINITY;
	      stream_putc (s, metric);
	      nrte++;
	      if (nrte == maxrte)
		{
		  nrte = 0;
		  ripng_send_packet (s->data, s->ep, NULL, ifp->index);
		  ripng_packet_dump ((struct ripng_packet *)s->data, s->ep, NULL);
		  stream_reset (s);
		}
	    }
	  
	}
    }
  ripng_send_packet (s->data, s->ep, NULL, ifp->index);
  ripng_packet_dump ((struct ripng_packet *)s->data, s->ep, NULL);
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

  if (debug (DEBUG_EVENT))
    log ("[Event] Flush timer fire\n");

  /* Age of rte routes. */
  ripng_age ();

  /* Supply routes to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp) || !if_is_up (ifp) || !if_is_multicast (ifp))
	continue;

      ri = ifp->if_data;
      if (ri->ri_send == RIPNG_SEND_OFF)
	{
	  if (debug (DEBUG_EVENT))
	    log ("[Event] RIPng send to if %d is suppressed by config\n",
		 ifp->index);
	}
      else
	ripng_supply (ifp);
    }

  /* Reset flush event. */
  ripng_event (RIPNG_FLUSH_EVENT, 0);
}

/* Create new RIP instance and set it to global variable rip. */
int
ripng_create ()
{
  /* ripng should be NULL. */
  assert (ripng == NULL);

  /* Allocaste RIP instance. */
  ripng = (struct ripng *) malloc (sizeof (struct ripng));
  bzero (ripng, sizeof (struct ripng));
  ripng->version = RIPNG_V1;

  /* Default timer values. */
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


/* Check packet's validity. */
int
ripng_check_packet (struct ripng_packet *rp, struct sockaddr_in6 *sin6)
{
  int ret;

  /* Check version number of incoming packet. */
  if (rp->version != ripng->version) 
    {
      log ("This packet's version[%d] doesn't fit to my version.\n", 
	   rp->version);
      return -1;
    }

  /* Check port number of incoming packet. */
  if (ntohs (sin6->sin6_port) != RIPNG_PORT_DEFAULT) 
    {
      log ("This packet doesn't come from ripng port : %d\n", 
	   ntohs (sin6->sin6_port));
      return -1;
    }
  
  /* Check packet comes from linklocal address. */
  ret = IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr);
  if (!ret)
    {
      log ("This packet is coming from not link local address\n");
      return -1;
    }
  
  /* Is this packet coming from myself? */

  /* Does this packet's hop counts set to 255? */

  return 1;
}

/* Response to request. */
ripng_request_process (struct ripng_packet *packet, 
		       int size, 
		       struct sockaddr_in6 *sin6)
{
  ;
}

unsigned long ripng_route_alloc = 0;

struct ripng_info *
ripng_info_new ()
{
  struct ripng_info *new;

  new = XMALLOC (MTYPE_RIPNG_ROUTE, sizeof (struct ripng_info));
  bzero (new, sizeof (struct ripng_info));
  ripng_route_alloc++;
  return new;
}

ripng_info_free (struct ripng_info *rinfo)
{
  ripng_route_alloc--;
  XFREE (MTYPE_RIPNG_ROUTE, rinfo);
}

/* Set nexthop address. */
ripng_nexthop_route (struct rte *rte, 
		     struct sockaddr_in6 *from,
		     struct in6_addr *nexthop)
{
  assert (rte->tag == 0);
  assert (rte->masklen == 0);

  /* If nexthop address is not link local address ignore it. */
  if (!IN6_IS_ADDR_LINKLOCAL (&rte->addr))
    return;
  IN6_COPY_ADDR (nexthop, &rte->addr);
}

/* RIP routing information. */
ripng_response_process (struct ripng_packet *rp, 
			int size, 
			struct sockaddr_in6 *from,
			unsigned int ifindex)
{
  struct rte *rte;
  time_t gettime;
  u_char *lim;
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

/* RIP packet adding routine. */
ripng_add_route (struct rte *rte,
		 struct sockaddr_in6 *from,
		 struct in6_addr *nexthop,
		 unsigned int ifindex,
		 time_t gettime)
{
  int ret;
  struct ripng_info *rinfo;
  struct ripng_slot *slot;
  struct route_node *node;
  char buf[INET6_ADDRSTRLEN];
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = if_lookup_by_index (ifindex);
  if (ifp == NULL)
    {
      log_warn ("Can't lookup interface by index [%d]\n", ifindex);
      return;
    }
  ri = ifp->if_data;

  /* Multicast address check. */
  if (IN6_IS_ADDR_MULTICAST (&rte->addr))
    {
      log_warn ("Destination prefix is a multicast address %s/%d. "
		"Ignore this routing entry.\n",
		inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
		rte->masklen);
      return;
    }

  /* Link local address check. */
  if (IN6_IS_ADDR_LINKLOCAL (&rte->addr))
    {
      log_warn ("Destination prefix is a link-local address %s/%d. "
		"Ignore this routing entry.\n",
		inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
		rte->masklen);
      return;
    }

  /* Prefix length check. We don't need negative check for masklen
     because masklen is define as u_char. */
  if (rte->masklen > 128)
    {
      log_warn ("Invalid prefix length %s/%d. Ignore this routing entry.\n",
		inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
		rte->masklen);
      return;
    }

  /* Default route check. */
  if (IN6_IS_ADDR_UNSPECIFIED (&rte->addr))
    {
      if (ri->ri_default_receive != RIPNG_DEFAULT_ACCEPT)
	{
	  if (debug (DEBUG_PACKET))
	    log ("Filtered default route\n");
	  return;
	}
    }

  if (ri->ri_receive == RIPNG_RECEIVE_OFF)
    {
      if (debug (DEBUG_EVENT))
	log ("[Event] RIPng route is filtered by configuration.\n");
      return;
    }

  /* Lookup routing table of RIPng, if there is no prefix in the table
     this function create it.  The node is locked by
     route_node_lokup function. */
  node = route_node_lookup (ripng_table, &rte->addr, rte->masklen);

  if (!node->route)
    ripng_slot_add (node);

  slot = node->route;
  
  rinfo = RIPNG_SLOT_RTE(slot);
  if (rinfo)
    {
      /* If route already exist in routing table then update timer of
         the route. */
      if (debug (DEBUG_PACKET))
	log ("ripng update route %s/%d\n",
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
    IN6_COPY_ADDR (&rinfo->nexthop, nexthop);
  else
    IN6_COPY_ADDR (&rinfo->nexthop, &from->sin6_addr);

  /* We preserve incoming hosts address. */
  IN6_COPY_ADDR (&rinfo->gateway, &from->sin6_addr);
  rinfo->type = RIPNG_ROUTE_RTE;
  rinfo->metric = rte->metric;
  rinfo->rip_tag = ntohs (rte->tag);
  rinfo->ifindex = ifindex;
  rinfo->timer = gettime;
  rinfo->fib = 1;
  RIPNG_SLOT_RTE(slot) = rinfo;
  
  if (debug (DEBUG_PACKET))
    log ("ripng add route %s/%d\n", 
	 inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN),
	 rte->masklen);

  /* Add zebra event. */
  ripng_event (RIPNG_ZEBRA, 0);
}

/* Sned RIPng request to the interface. */
ripng_request (struct interface *ifp)
{
  int ret;
  struct rte *rte;
  char pbuf [BUFSIZ];
  struct ripng_packet ripng_packet;

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

/* Process delete of route. */
ripng_delete_route (struct rte *rte,
		    struct sockaddr_in6 *from)
{
  char buf[INET6_ADDRSTRLEN];
  struct route_node *find;

  /* If route is alread exist update timer. */
  log ("rip delete route %s/%d\n", 
       inet_ntop (AF_INET6, &rte->addr, buf, INET6_ADDRSTRLEN), 
       rte->masklen);

  
  find = route_node_lookup (ripng_table, &rte->addr, rte->masklen);

  if (find->route == NULL)
    {
      log_warn ("route is already deleted\n");
      return -1;
    }

  ripng_info_free (find->route);
  find->route = NULL;
  route_unlock_node (find);
  ripng_event (RIPNG_ZEBRA, 0);
}

/* Make packet which send to zebra. */
ripng_zebra (struct thread *thread)
{
  struct stream *s;
  struct route_node *node;

  /* First of all clear thread pointer. */
  ripng->t_zebra = NULL;

  s = stream_new (ZEBRA_MAX_PACKET_SIZ);

  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      int size;
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      
      slot = node->route;
      if (slot == NULL)
	continue;

      rinfo = RIPNG_SLOT_RTE(slot);
      if (rinfo == NULL)
	continue;

      /* If there is no zebra header or nexthop is different. */
      if (stream_empty (s))
	{
	  /* Zebra packet length. */
	  stream_putc (s, 0);
	  stream_putc (s, 0);
	  stream_putc (s, ZEBRA_IPV6_ROUTE_ADD);
	  stream_putc (s, ZEBRA_ROUTE_RIPNG);
	  stream_write (s, &rinfo->nexthop, 16);
	}
      stream_putc (s, rinfo->ifindex);
      size = PSIZE (node->p.prefixlen);
      stream_putc (s, node->p.prefixlen);
      stream_write (s, &node->p.u.prefix, size);
      rinfo->fib = 0;

      if (s->ep >= ZEBRA_MAX_PACKET_SIZ - 20)
	{
	  u_short size;
	  size = htons (s->ep);
	  stream_set_cursor (s, 0);
	  stream_write (s, &size, 2);
	  zebra_write (s);
	  stream_reset (s);
	}
    }

  if (!stream_empty (s))
    {
      u_short size;
      size = htons (s->ep);
      stream_set_cursor (s, 0);
      stream_write (s, &size, 2);
      zebra_write (s);
    }
};


extern struct thread_master *master;

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

struct message route_sort_msg[] =
{
  { RIPNG_ROUTE_RTE,    "R"},
  { RIPNG_ROUTE_STATIC,    "S"},
  { RIPNG_ROUTE_AGGREGATE, "A"}
};

/* Dump ripng route to vty. This is callback funtion. */
show_ip_ripng_callback (struct vty *vty)
{
  struct route_node *node;
  
  for (node = route_top (ripng_table); node; node = route_next (node))
    {
      int len;
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->route;

      if (slot == NULL)
	continue;

      rinfo = RIPNG_SLOT_RTE (slot);
      if (rinfo)
	{
	  
	  len = vty_out (vty, "%s %s/%d ",
			 route_sort_msg[rinfo->type].str,
			 inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ), 
			 node->p.prefixlen);
	  len = 38 - len;

	  if (len > 0)
	    vty_out (vty, "%*s", len, " ");

	  len = vty_out (vty, "%s", 
			 inet_ntop (AF_INET6, &rinfo->nexthop, buf, BUFSIZ));
	  len = 27 - len;
      
	  if (len > 0)
	    vty_out (vty, "%*s", len, " ");

	  vty_out (vty, "%4d %4d ", rinfo->metric, rinfo->rip_tag);
	  /* vty_out (vty, "%s", inet_ntoa (rinfo->gateway)); */
	  vty_out (vty, "\r\n");
	}
    }
  return;
}

DEFUN (show_debug_ripng,
       show_debug_ripng_cmd,
       "show debug ripng",
       "Show debug option for ripng.")
{
  vty_out (vty, "Debug option\r\n");
  vty_out (vty, "============\r\n");

  vty_out (vty, "debug ripng event  : ");
  if (debug (DEBUG_EVENT))
    vty_out (vty, "set\r\n");
  else
    vty_out (vty, "unset\r\n");
  vty_out (vty, "debug ripng packet : ");
  if (debug (DEBUG_PACKET))
    vty_out (vty, "set\r\n");
  else
    vty_out (vty, "unset\r\n");
  return CMD_SUCCESS;
}

/* Debug options. */
DEFUN (debug_ripng,
       debug_ripng_cmd,
       "debug ripng [DEBUG_OPT]",
       "Debug option set for ripng.")
{
  if (argc == 0)
    {
      vty_out (vty, "Debug option for ripng\r\n");
      vty_out (vty, "------------------------\r\n");
      vty_out (vty, "debug ripng event -- Event of ripng.\r\n");
      vty_out (vty, "debug ripng packet -- Packet dump.\r\n");
      vty_out (vty, "------------------------\r\n");
      return;
     }

  if (strcmp (argv[0], "event") == 0)
    debug_set (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_set (DEBUG_PACKET);

  return CMD_SUCCESS;
}

DEFUN (no_debug_ripng,
       no_debug_ripng_cmd,
       "no debug ripng [DEBUG_OPT]",
       "Debug option unset for ripng.")
{
  if (argc == 0)
    {
      vty_out (vty, "Debug option unset ripng\r\n");
      vty_out (vty, "------------------------\r\n");
      vty_out (vty, "no debug ripng event -- Debug event for ripngd off.\r\n");
      vty_out (vty, "------------------------\r\n");
      return;
     }
  if (strcmp (argv[0], "event") == 0)
    debug_unset (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_unset (DEBUG_PACKET);

  return CMD_SUCCESS;
}

DEFUN (show_ip_ripng,
       show_ip_ripng_cmd,
       "show ip ripng",
       "Show RIPng routes.")
{
  /* Header of display. */ 
  vty_out (vty, "\r\nCodes: R - RIPng"
	   "\r\n  Network                             "
	   "Next Hop                Metric Tag Time\r\n");

  show_ip_ripng_callback (vty);

  return CMD_SUCCESS;
}

DEFUN (router_ripng,
       router_ripng_cmd,
       "router ripng",
       "Make RIPng instance command.")
{
  int ret;

  vty->node = RIPNG_NODE;

  if (!ripng)
    {
      ret = ripng_create ();
      if (ret < 0)
	{
	  /* Print out NOTICE of we couldn't make ripng. */
	  log_warn ("can't create ripng\n");
	}
    }
  return CMD_SUCCESS;
}

DEFUN (network,
       network_cmd,
       "network IPV6ADDR",
       "Set static RIPng route announcement.")
{
  int ret;
  u_char metric;
  struct newprefix p;
  struct route_node *node;

  metric = 0;
  ret = str2pref_in6 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return;
    }

  if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6) && p.prefixlen == 0)
    {
      vty_out (vty, "Please use 'default' command for default route.\r\n");
      return;
    }

  node = route_node_get (ripng_table, &p);

  /* Metric should be configurable. */
  ret = ripng_static_add (node, metric);
  if (ret < 0)
    {
      vty_out (vty, "There is already same static route.\r\n");
      route_unlock_node (node);
      return;
    }
  return CMD_SUCCESS;
}

DEFUN (no_network,
       no_network_cmd,
       "no network IPV6ADDR",
       "Delete static RIPng route announcement.")
{
  int ret;
  struct newprefix p;
  struct route_node *node;

  ret = str2pref_in6 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return;
    }

  node = route_node_get (ripng_table, &p);

  ret = ripng_static_delete (node);
  if (ret < 0)
    {
      vty_out (vty, "Can't find static route.\r\n");
      route_unlock_node (node);
      return;
    }
  route_unlock_node (node);
  return CMD_SUCCESS;
}

DEFUN (aggregate,
       aggregate_cmd,
       "aggregate IPV6ADDR",
       "Set aggregate RIPng route announcement.")
{
  int ret;
  u_char metric;
  struct newprefix p;
  struct route_node *node;

  metric = 0;
  ret = str2pref_in6 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return;
    }

  node = route_node_get (ripng_table, &p);

  /* Metric should be configurable. */
  ret = ripng_aggregate_add (node, metric);
  if (ret < 0)
    {
      vty_out (vty, "There is already same aggregate route.\r\n");
      route_unlock_node (node);
      return;
    }
  return CMD_SUCCESS;
}

DEFUN (no_aggregate,
       no_aggregate_cmd,
       "no aggregate IPV6ADDR",
       "Delete aggregate RIPng route announcement.")
{
  int ret;
  struct newprefix p;
  struct route_node *node;

  ret = str2pref_in6 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return;
    }

  node = route_node_get (ripng_table, &p);

  ret = ripng_aggregate_delete (node);
  if (ret < 0)
    {
      vty_out (vty, "Can't find aggregate route.\r\n");
      route_unlock_node (node);
      return;
    }
  route_unlock_node (node);
  return CMD_SUCCESS;
}

/* RIPng flush timer setup. */
DEFUN (ripng_flush_timer,
       ripng_flush_timer_cmd,
       "flush-timer SECOND",
       "Set ripng flush timer in seconds")
{
  unsigned int newflush;

  newflush = atoi (argv[0]);
  if (!newflush)
    return;

  ripng->flush_time = newflush;

  ripng_event (RIPNG_FLUSH_EVENT, 0);
  return CMD_SUCCESS;
}

/* Dump static ripng route to vty. */
ripng_static_dump (struct route_node *node, struct vty *vty)
{
  if (node->route)
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->route;
      rinfo = RIPNG_SLOT_STATIC(slot);

      if (rinfo)
	vty_out (vty, " network %s/%d%s",
		 inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ), 
		 node->p.prefixlen, VTY_NEWLINE);
    }
}

/* Dump static ripng route to vty. */
ripng_aggregate_dump (struct route_node *node, struct vty *vty)
{
  if (node->route)
    {
      struct ripng_slot *slot;
      struct ripng_info *rinfo;
      char buf[INET6_ADDRSTRLEN];

      slot = node->route;
      rinfo = RIPNG_SLOT_AGGREGATE(slot);

      if (rinfo)
	vty_out (vty, " aggregate %s/%d%s",
		 inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ), 
		 node->p.prefixlen, VTY_NEWLINE);
    }
}

/* RIPng configuration write function. */
ripng_config_write (struct vty *vty, vector v)
{
  if (ripng)
    {
      struct route_node *node;

      /* RIPng router. */
      vty_out (vty, "router ripng%s", VTY_NEWLINE);

      /* RIPng static routes. */
      for (node = route_top (ripng_table); node; node = route_next (node))
	ripng_aggregate_dump (node, vty);

      for (node = route_top (ripng_table); node; node = route_next (node))
	ripng_static_dump (node, vty);

      /* Flush timer print out. */
      if (ripng->flush_time != RIPNG_FLUSH_TIMER)
	vty_out (vty, " flush-timer %d%s", ripng->flush_time, VTY_NEWLINE);
    }
}

/* RIPng node structure. */
struct cmd_node cmd_ripng_node =
{
  RIPNG_NODE,
  "%s(config-router)# ",
};

/* Initialize ripng structure and set commands. */
ripng_init ()
{
  /* RIPng routig table. */
  ripng_table = route_table_init ();

  /* Install RIPNG_NODE. */
  install_node (&cmd_ripng_node, ripng_config_write);

  /* Install ripng commands. */
  install_element (VIEW_NODE, &show_ip_ripng_cmd);
  install_element (VIEW_NODE, &show_debug_ripng_cmd);
  install_element (ENABLE_NODE, &show_ip_ripng_cmd);
  install_element (ENABLE_NODE, &show_debug_ripng_cmd);
  install_element (ENABLE_NODE, &debug_ripng_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_cmd);
  install_element (CONFIG_NODE, &router_ripng_cmd);
  install_element (CONFIG_NODE, &debug_ripng_cmd);
  install_element (RIPNG_NODE, &config_end_cmd);
  install_element (RIPNG_NODE, &config_exit_cmd);
  install_element (RIPNG_NODE, &config_help_cmd);
  install_element (RIPNG_NODE, &aggregate_cmd);
  install_element (RIPNG_NODE, &no_aggregate_cmd);
  install_element (RIPNG_NODE, &network_cmd);
  install_element (RIPNG_NODE, &no_network_cmd);
  install_element (RIPNG_NODE, &ripng_flush_timer_cmd);
}
