/*
 * RIP version 1 and 2.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#include "if.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "roken.h"
#include "log.h"
#include "filter.h"

#include "zebra/zebra.h"
#include "ripd/ripd.h"
#include "ripd/rip_debug.h"

/* RIP Structure. */
struct rip rip;

/* RIP routing table radix tree. */
struct route_table *rip_table;

/* RIP's static routes table */
struct route_table *rip_static_table;

/* RIP event. */
enum rip_event {RIP_READ, RIP_WRITE};

/* RIP events. */
void rip_event (enum rip_event event, int sock);

/* This struct carries information of type of response and which
   interface this buffer is send to. */
struct rip_send_buf
{
  int type;
  u_char version;
  struct sockaddr_in dest;
  struct interface *ifp;
  struct rte *rte;
  struct rte *rtelim;
  union rip_buf rip_buf;
} rip_send_buf;

/* RIP command strings. */
struct message rip_msg[] = 
{
  { 0,             "NULL"},
  {RIP_REQUEST,    "request"},
  {RIP_RESPONSE,   "response"},
  {RIP_TRACEON,    "traceon"},
  {RIP_TRACEOFF,   "traceoff"},
  {RIP_POLL,       "poll"},
  {RIP_POLL_ENTRY, "poll entry"},
};

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

void
rip_info_free (struct rip_info *rinfo)
{
  XFREE (MTYPE_RIP_INFO, rinfo);
}

/* Add rip information to rip list. */
void
rip_add_rinfo (struct rip_info **rp, struct rip_info *rinfo)
{
  struct rip_info *cp;
  struct rip_info *pp;

  for (cp = pp = *rp; cp; pp = cp, cp = cp->next)
    if (rinfo->pref <= cp->pref)
      break;

  if (cp == pp)
    {
      *rp = rinfo;

      if (cp)
	cp->prev = rinfo;
      rinfo->next = cp;
    }
  else
    {
      if (pp)
	pp->next = rinfo;
      rinfo->prev = pp;

      if (cp)
	cp->prev = rinfo;
      rinfo->next = cp;
    }
  
}

/* Delete rib from rib list. */
void
rip_delete_rinfo (struct rip_info **rp, struct rip_info *rinfo)
{
  if (rinfo->next)
    rinfo->next->prev = rinfo->prev;
  if (rinfo->prev)
    rinfo->prev->next = rinfo->next;
  else
    *rp = rinfo->next;
}

/* RIP add route to routing table. */
int
rip_add_route (struct prefix_ipv4 *p, struct rip_info *rinfo, 
	       struct sockaddr_in *from, struct interface *ifp)
{
  int distance;
  int update;
  struct route_node *np;
  struct rip_info *rp;
  struct rip_info *fib;
  struct rip_info *same;

  /* Get index for the prefix. */
  np = route_node_get (rip_table, (struct prefix *) p);
  distance = route_info[rinfo->type].distance;

  /* Check same type route and FIB route. */
  fib = NULL;
  same = NULL;

  /* Lookup each rip information. */
  for (rp = np->info; rp; rp = rp->next)
    {
      if (rp->fib)
	fib = rp;
      if (rp->type == rinfo->type)
	same = rp;
    }

  /* If given route is redistributed route. */
  if (rinfo->type != ZEBRA_ROUTE_RIP)
    {
      if (fib)
	{
	  if (distance <= route_info[fib->type].distance)
	    {
	      fib->fib = 0;
	      rinfo->fib = 1;
	    }
	}
      else
	rinfo->fib = 1;

      if (IS_RIP_DEBUG_ZEBRA)
	zlog_info ("rip %s add %s/%d", 
		   route_info[rinfo->type].str_long, 
		   inet_ntoa (p->prefix), p->prefixlen);

      rip_add_rinfo ((struct rip_info **) &np->info, rinfo);

      if (same)
	{
	  rip_delete_rinfo ((struct rip_info **)&np->info, same);
	  rip_info_free (same);
	  route_unlock_node (np);
	}

      return 0;
    }

  /* There are three cases of add|replace|update. */
  if (same)
    {
      /* Does this RIP info come from same neighbor? */
      update = IPV4_ADDR_SAME (&same->from, &from->sin_addr);

      /* Logging. */
      if (IS_RIP_DEBUG_PACKET)
	zlog (NULL, LOG_INFO, "rip %s route %s/%d", 
	      update ? "update" : "replace",
	      inet_ntoa (p->prefix), p->prefixlen);

      /* If this datagram is from the same router as the existing
	 route, reinitialize the timeout... RFC2453 */
      if (update)
	same->timer = rinfo->timer;

      /* If the datagram is from the same router as the existing
         route, and the new metric is different than the old one; or,
         if the new metric is lower than the old one; do the following
         actions... RFC2453 */
      if ((update && rinfo->metric != same->metric) ||
	  (rinfo->metric < same->metric))
	{
	  /* - Adopt the route from the datagram (i.e., put the new
	     metric in and adjust the next hop address, if
	     necessary). */
	  same->tag = rinfo->tag;
	  same->metric = rinfo->metric;
	  same->from = rinfo->from;
	  same->timer = rinfo->timer;
	  
	  if (IPV4_ADDR_CMP (&same->nexthop, &rinfo->nexthop) != 0)
	    {
	      same->nexthop = rinfo->nexthop;
	      rip_zebra (ZEBRA_IPV4_ROUTE_ADD, p, &rinfo->nexthop);
	    }

	  /* - Set the route change flag and signal the output process
             to trigger an update */
	  /* rip_event (RIP_OUTPUT, 0); */

	  /* - If the new metric is infinity, start the deletion
	      process (described above); otherwise, re-initialize the
	      timeout */

	  /* Comment: Infinity route is handled in
             rip_delete_route(). */
	}

      /* rinfo information is applied, free used rinfo now.*/
      rip_info_free (rinfo);
      route_unlock_node (np);
    }
  else
    {
      /* This is new rip route. */
      if (IS_RIP_DEBUG_PACKET)
	zlog_info ("rip add route %s/%d", 
		   inet_ntoa (p->prefix), p->prefixlen);

      if (fib)
	{
	  /* There is already fib route. */
	  rip_info_free (rinfo);
	  route_unlock_node (np);
	}
      else
	{
	  rinfo->fib = 1;
	  rip_add_rinfo ((struct rip_info **) &np->info, rinfo);

	  if (rinfo->sub_type != RIP_ROUTE_STATIC)
	    rip_zebra (ZEBRA_IPV4_ROUTE_ADD, p, &rinfo->nexthop);
	}
    }
  return 0;
}

/* Process delete of route. */
int
rip_delete_route (struct prefix_ipv4 *p, struct rip_info *rinfo,
		  struct sockaddr_in *from, struct interface *ifp)
{
  struct route_node *np;
  struct rip_info *rp;

  /* If route is alread exist update timer. */
  if (IS_RIP_DEBUG_PACKET)
    zlog_info ("rip delete route %s/%d", inet_ntoa (p->prefix), p->prefixlen);

  /* Get index for the prefix. */
  np = route_node_get (rip_table, (struct prefix *) p);

  for (rp = np->info; rp; rp = rp->next)
    {
      if (IPV4_ADDR_SAME (&rp->from, &from->sin_addr))
	{
	  rip_delete_rinfo ((struct rip_info **) &np->info, rp);

	  if (rp->fib)
	    rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, p, &rp->nexthop);

	  route_unlock_node (np);
	  break;
	}
    }

  route_unlock_node (np);

  return 0;
}

/* Utility function to set boradcast option to the socket. */
int
sockopt_broadcast (int sock)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (char *) &on, sizeof on);
  if (ret < 0)
    {
      zlog_warn ("can't set sockopt SO_BROADCAST to socket %d", sock);
      return -1;
    }
  return 0;
}

/* Dump RIP packet */
void
rip_packet_dump (struct rip_packet *packet, int len,
		 struct sockaddr_in *from, struct interface *ifp)
{
  caddr_t end;
  struct rte *rte;
  struct in_addr addr;
  char pbuf[BUFSIZ], hbuf[BUFSIZ];

  zlog_info ("RIP recieved v%d %s from %s:%d %d on %s",
	     packet->version, LOOKUP (rip_msg, packet->command),
	     inet_ntoa(from->sin_addr), ntohs (from->sin_port),
	     len, ifp ? ifp->name : "unknown");

  rte = packet->route;
  end = ((caddr_t) packet) + len;
  
  while ((caddr_t) rte < end) 
    {
      u_char netmask = 0;

      addr.s_addr = rte->prefix;
      strncpy (pbuf, inet_ntoa (addr), BUFSIZ);

      if (packet->version == RIPv2)
	{
	  addr.s_addr = rte->netmask;
	  netmask = ip_masklen (addr);
	}

      addr.s_addr = rte->nexthop;
      strncpy (hbuf, inet_ntoa (addr), BUFSIZ);

      if (packet->version == RIPv2)
	zlog_info ("  %s/%d -> %s family %d tag %d metric %d",
		   pbuf, netmask, hbuf, 
		   ntohs (rte->family), ntohs (rte->tag), ntohl (rte->metric));
      else
	zlog_info ("  %s family %d tag %d metric %d", 
		   pbuf,
		   ntohs (rte->family), ntohs (rte->tag), ntohl (rte->metric));
      rte++;
    }
}

struct rip_info *
rip_info_new ()
{
  struct rip_info *new;

  new = XMALLOC (MTYPE_RIP_INFO, sizeof (struct rip_info));
  bzero (new, sizeof (struct rip_info));
  return new;
}

/* Check if the destination address is valid (unicast; not net 0
   or 127) (RFC2453 Section 3.9.2 - Page 26).  But we don't
   check net 0 because we accept default route. */
int
rip_check_address (u_int32_t addr)
{
  addr = ntohl (addr);

  if (IPV4_NET127 (addr))
    return 0;

  /* Net 0 may match to the default route.
  if (IPV4_NET0 (addr))
    return 0;
  */

  if (IN_CLASSA (addr))
    return 1;
  if (IN_CLASSB (addr))
    return 1;
  if (IN_CLASSC (addr))
    return 1;

  return 0;
}

/* RIP routing information. */
void
rip_response_recv (struct rip_packet *packet, int size, 
		   struct sockaddr_in *from, struct interface *ifp)
{
  int ret;
  caddr_t end;
  struct rte *rte;
  struct rip_info *rinfo;
  time_t gettime;

  /* Check port number of incoming packet. */
  if (ntohs (from->sin_port) != RIP_PORT_DEFAULT) 
    {
      zlog_info ("This packet doesn't come from rip port : %d", 
		 from->sin_port);
      return;
    }

  /* "The datagram's IPv4 source address should be checked to see
     whether the datagram is from a valid neighbor; the source of the
     datagram must be on a directly connected network" (RFC2453 -
     Sec. 3.9.2) */
  if (! if_valid_neighbor(from->sin_addr)) 
    {
      zlog_info ("This datagram doesn't came from a valid neighbor: %s",
		 inet_ntoa(from->sin_addr));
      return;
    }

  /* Set current time.  This time value is common to all routes which
     included in this packet. */
  time (&gettime);

  rte = packet->route;
  end = ((caddr_t) packet) + size;

  while ((caddr_t) rte < end) 
    {
      struct prefix_ipv4 p;
      struct in_addr mask;
      
      /* Address family check.  RIP only supports AF_INET. */
      if (ntohs (rte->family) != AF_INET)
	{
	  zlog_info ("Unsupported family %d from %s.",
		     ntohs (rte->family), inet_ntoa (from->sin_addr));
	  rte++;
	  continue;
	}

      /* Network 127 and Class A, B, C check. */
      if (! rip_check_address (rte->prefix))
        {
	  zlog_info ("Network is net 127 or it is not unicast network");
	  rte++;
	  continue;
	} 

      /* Check if the metric is valid  (STD-56 Section 3.9.2 - Page 27) */
      if (ntohl (rte->metric) > RIP_METRIC_INFINITY)
        {
	  zlog_info ("Route's metric is not in the 1-16 range.");
          rte++;
          continue;
        }

      /* Allocate new rt_in. */
      p.family = AF_INET;
      p.prefix.s_addr = rte->prefix;
      mask.s_addr = rte->netmask;
      p.prefixlen = ip_masklen (mask);

     /* For rip v1, there won't be a valid netmask.
      *
      * This is a best guess at the masks.  If everyone was using old Ciscos
      * before the 'ip subnet zero' option, it would be almost right too :-)
      *
      * Ciscos summarize ripv1 advertisments to the classful boundary (/16 for
      * class B's) except when the RIP packet does to inside the classful
      * network in question.
      */
      if (packet->version == RIPv1 &&
	  p.prefixlen == 0 &&
	  (u_int32_t) (p.prefix.s_addr))
	{
	  if(ntohl ((u_int32_t) (p.prefix.s_addr)) & 0xff) 
	    {
	      mask.s_addr = 0xffffffff;
	      p.prefixlen = 32;
	    }
	  else if((ntohl ((u_int32_t) (p.prefix.s_addr)) & 0xff00) ||
		  IN_CLASSC(p.prefix.s_addr)) 
	    {
	      mask.s_addr = 0xffffff00;
	      p.prefixlen = 24;
	    }
	  else if((ntohl ((u_int32_t) (p.prefix.s_addr)) & 0xff0000) ||
		  IN_CLASSB(p.prefix.s_addr)) 
	    {
	      mask.s_addr = 0xffff0000;
	      p.prefixlen = 16;
	    }
	  else 
	    {
	      mask.s_addr = 0xff000000;
	      p.prefixlen = 8;
	    }
	}

      /* Input distribute-list filtering. */
      if (distribute_apply_in (ifp, (struct prefix *) &p) == FILTER_DENY)
	{
	  if (IS_RIP_DEBUG_PACKET)
	    zlog_info ("RIP %s/%d filtered by distribute in",
		       inet_ntoa (p.prefix), p.prefixlen);
	  continue;
	}

      /* Fetch information into rip_info structure */
      rinfo = rip_info_new ();
      rinfo->type = ZEBRA_ROUTE_RIP;
      rinfo->pref = 10;
      rinfo->from = from->sin_addr;
      rinfo->tag = ntohl (rte->tag);
      rinfo->timer = gettime;
      rinfo->ifp = ifp;

      /* Once the entry has been validated, update the metric by
         adding the cost of the network on wich the message
         arrived. If the result is greater than infinity, use infinity
         (RFC2453 Sec. 3.9.2) */
      rinfo->metric = ntohl (rte->metric);
      rinfo->metric += ifp->metric;
      if (rinfo->metric > RIP_METRIC_INFINITY)
	rinfo->metric = RIP_METRIC_INFINITY;

      /* Next Hop: The inmmediate next hop IP address wo which the
	 packets to the destination specified by this route should be
	 forwarded.  Specifying a value of 0.0.0.0 in this field
	 indicates that routing should be via the originator of the
	 RIP advertisement (RFC2453 Sec. 4.4)*/
      if (ntohl (rte->nexthop) == 0)
	rinfo->nexthop.s_addr = from->sin_addr.s_addr;
      else 
	{
	  /* An address specified as next hop must be directly
	     reachable on the logical subnet which the advertisement
	     is made (NOT CHECKED!!! MUST BE CHECKED) */
	  rinfo->nexthop.s_addr = rte->nexthop;
	}

      /* Check nexthop address. */
      ret = if_check_address (rinfo->nexthop);
      if (ret)
	{
	  zlog (NULL, LOG_INFO, 
		"Route's nexthop set to myself! So ignore this route.");
	  rte++;
	  rip_info_free (rinfo);
	  continue;
	}

      /* Check metric is INFINITY or not. */
      if (rinfo->metric == RIP_METRIC_INFINITY) 
	rip_delete_route (&p, rinfo, from, ifp);
      else 
	rip_add_route (&p, rinfo, from, ifp);

      rte++;
    }
}

/* Set up initial send buffer. */
void
rip_send_init (u_char version)
{
  struct rip_packet *rip_packet;

  rip_packet = &rip_send_buf.rip_buf.rip_packet;
  rip_packet->command = RIP_RESPONSE;
  rip_packet->version = version;
  rip_packet->pad1 = 0;
  rip_packet->pad2 = 0;

  rip_send_buf.version = version;
  rip_send_buf.rte = rip_packet->route;
  rip_send_buf.rtelim = rip_packet->route + RIP_MAX_RTE;
  rip_send_buf.ifp = NULL;
  bzero (&rip_send_buf.dest, sizeof (struct sockaddr_in));
  rip_send_buf.dest.sin_family = AF_INET;
  rip_send_buf.dest.sin_port = htons (RIP_PORT_DEFAULT);
}

/* RIP packet send to destination address. */
int
rip_udp_send (int sock, u_char *pnt, int size, struct sockaddr_in *dest)
{
  int ret;
  struct sockaddr_in sin;

  if (dest == NULL)
    return 0;

#ifdef HAVE_SIN_LEN
  sin.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  sin.sin_family = AF_INET;
  if (dest->sin_port == 0)
    sin.sin_port = htons (RIP_PORT_DEFAULT);
  else
    sin.sin_port = dest->sin_port;
  sin.sin_addr.s_addr = dest->sin_addr.s_addr;

  ret = sendto (sock, pnt, size, 0, (struct sockaddr *)&sin,
		sizeof(struct sockaddr_in));

  if (ret < 0)
    zlog (NULL, LOG_INFO, "can't send packet : %s", strerror (errno));

  return ret;
}

/* Utility function to announce rip route. */
void
rip_send_announce ()
{
  int size;
  caddr_t end = (caddr_t)rip_send_buf.rte;
  caddr_t start = (caddr_t)&rip_send_buf.rip_buf;
  struct sockaddr_in *sin = &rip_send_buf.dest;
  struct rip_packet *rip_packet;

  /* Reset pointer. */
  rip_packet = &rip_send_buf.rip_buf.rip_packet;

  size = end - start;

  rip_udp_send (rip.sock, start, size, sin);
  
  rip_send_buf.rte = rip_packet->route;
}

/* Walkdown function of rip's radix tree. */
void
rip_announce_func (struct prefix *p, struct rip_info *rinfo,
		   struct interface *ifp)
{
  struct rte *rte;
  struct in_addr mask;
  struct rip_interface *ri;

  if (! rinfo->fib)
    return;

  /* Distribute-list out. */
  if (distribute_apply_out (ifp, p) == FILTER_DENY)
    {
      if (IS_RIP_DEBUG_PACKET)
	zlog_info ("RIP %s/%d filtered distribute out",
		   inet_ntoa (p->u.prefix4), p->prefixlen);
      return;
    }

  /* In case of RIP_POLL, do not perform split horizon/poisoned reverse. */
  if (rip_send_buf.type != RIP_POLL &&
      rip_send_buf.type != RIP_REQUEST)
    {
      ri = ifp->if_data;

      /* Split horizon. */
      if (ri->ri_split_horizon == RI_RIP_SPLIT_HORIZON_UNSPEC
	  || ri->ri_split_horizon == RI_RIP_SPLIT_HORIZON)
	if (rinfo->ifp == ifp)
	  return;

      /* Poisoned reverse. */
      ;
    }

  /* Write routing information. */
  ri = ifp->if_data;
  rte = rip_send_buf.rte;
  rte->family = htons (AF_INET);
  rte->tag = 0;
  masklen2ip (p->prefixlen, &mask);
  rte->metric = htonl (rinfo->metric);
  rip_send_buf.rte++;

  if (rip_send_buf.version == RIPv1)
    {
      rte->prefix = (p->u.prefix4.s_addr) & mask.s_addr;
      rte->netmask = 0;
    }	
  else
    {
      rte->prefix = p->u.prefix4.s_addr;
      rte->netmask = mask.s_addr;
    }

  /* If buffer is full of routes, send it to neighbor. */
  if (rip_send_buf.rte == rip_send_buf.rtelim)
    rip_send_announce ();
}

/* Walkdown RIP routing table then call RIP announcement function for
   each routes. */
void
rip_walkdown_send (struct interface *ifp)
{
  struct route_node *rp;
  struct rip_info *rinfo;

  for (rp = route_top (rip_table); rp; rp = route_next (rp))
    for (rinfo = rp->info; rinfo; rinfo = rinfo->next)
      if (rinfo->fib)
	rip_announce_func (&rp->p, rinfo, ifp);
  rip_send_announce ();
}

/* Response to request called from rip_read ().*/
void
rip_request_recv (struct rip_packet *packet, int size, 
		  struct sockaddr_in *from, struct interface *ifp)
{
  struct rte *rte;

  /* Set routing table entry pointer to incoming packet. */
  rte = packet->route;

  /* Check address family. */
  if (ntohs (rte->family) != AF_UNSPEC)
    {
      zlog (NULL, LOG_INFO, "rip query packet with non AF_UNSPEC family");
      return;
    }
  /* Check tag command. */
  if (rte->tag != 0)
    {
      zlog (NULL, LOG_INFO, "rip query packet with non zero tag value");
      return;
    }
  /* If metric is not inifinity, it's error. */
  if (ntohl (rte->metric) != RIP_METRIC_INFINITY)
    {
      zlog (NULL, LOG_INFO, "RIP query packet with non metric 16");
      return;
    }

  /* Make response packet header. */
  rip_send_init (packet->version);
  rip_send_buf.dest = *from;
  rip_send_buf.ifp = ifp;
  rip_send_buf.type = packet->command;
  
  rip_walkdown_send (ifp);
}

#if RIP_RECVMSG
/* Set IPv6 packet info to the socket. */
static int
setsockopt_pktinfo (int sock)
{
  int ret;
  int val = 1;
    
  ret = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
  if (ret < 0)
    zlog_warn ("Can't setsockopt IP_PKTINFO : %s", strerror (errno));
  return ret;
}

/* Read RIP packet by recvmsg function. */
int
rip_recvmsg (int sock, u_char *buf, int size, struct sockaddr_in *from,
	     int *ifindex)
{
  int ret;
  struct msghdr msg;
  struct iovec iov;
  struct cmsghdr *ptr;
  char adata[1024];

  msg.msg_name = (void *) from;
  msg.msg_namelen = sizeof (struct sockaddr_in);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = (void *) adata;
  msg.msg_controllen = sizeof adata;
  iov.iov_base = buf;
  iov.iov_len = size;

  ret = recvmsg (sock, &msg, 0);
  if (ret < 0)
    return ret;

  for (ptr = CMSG_FIRSTHDR(&msg); ptr != NULL; ptr = CMSG_NXTHDR(&msg, ptr))
    if (ptr->cmsg_level == IPPROTO_IP && ptr->cmsg_type == IP_PKTINFO) 
      {
	struct in_pktinfo *pktinfo;
	int i;

	pktinfo = (struct in_pktinfo *) CMSG_DATA (ptr);
	i = pktinfo->ipi_ifindex;
      }
  return ret;
}

/* RIP packet read function. */
int
rip_read_new (struct thread *t)
{
  int ret;
  int sock;
  char buf[RIP_PACKET_MAXSIZ];
  struct sockaddr_in from;
  unsigned int ifindex;
  
  /* Fetch socket then register myself. */
  sock = THREAD_FD (t);
  rip_event (RIP_READ, sock);

  /* Read RIP packet. */
  ret = rip_recvmsg (sock, buf, RIP_PACKET_MAXSIZ, &from, (int *)&ifindex);
  if (ret < 0)
    {
      log_warn ("Can't read RIP packet: %s", strerror (errno));
      return ret;
    }

  return ret;
}
#endif /* RIP_RECVMSG */

/* First entry point of RIP packet. */
int
rip_read (struct thread *t)
{
  int sock;
  union rip_buf rip_buf;
  struct rip_packet *packet;
  struct sockaddr_in from;
  int fromlen, len;
  struct interface *ifp;
  struct rip_interface *ri;

  /* Fetch socket then register myself. */
  sock = THREAD_FD (t);
  rip_event (RIP_READ, sock);

  /* RIPd manages only IPv4. */
  memset (&from, 0, sizeof (struct sockaddr_in));
  fromlen = sizeof (struct sockaddr_in);

  len = recvfrom (sock, (char *)&rip_buf.buf, sizeof (rip_buf.buf), 0, 
		  (struct sockaddr *) &from, &fromlen);
  if (len < 0) 
    {
      zlog_info ("recvfrom failed: %s", strerror (errno));
      return len;
    }

  /* For easy to handle. */
  packet = &rip_buf.rip_packet;

  /* Which interface is this packet comes from. */
  ifp = if_lookup_address (from.sin_addr);

  /* Check is this packet comming from myself? */
  if (if_check_address (from.sin_addr)) 
    {
      if (IS_RIP_DEBUG_PACKET)
	zlog_warn ("RIP packet comes from myself");
      return -1;
    }

  /* Dump RIP packet. */
  if (IS_RIP_DEBUG_PACKET)
    rip_packet_dump (packet, len, &from, ifp);

  /* If this packet come from unknown inteface, ignore it. */
  if (ifp == NULL)
    {
      zlog_info ("RIP packet comes from unknown inteface");
      return -1;
    }

  /* RIP version check. */
  if (packet->version == 0)
    {
      zlog_info ("RIP version 0 which has command %d received.", 
		 packet->command);
      return -1;
    }

  /* RIP version adjust. */
  if (packet->version > RIPv2)
    packet->version = RIPv2;

  /* We accept RIP_POLL. */
  if (packet->command != RIP_POLL && packet->command != RIP_REQUEST)
    {
      ri = ifp->if_data;

      if (ri->ri_receive == RI_RIP_UNSPEC)
	{
	  if (packet->version != rip.version) 
	    {
	      if (IS_RIP_DEBUG_PACKET)
		zlog_warn ("  packet's v%d doesn't fit to my version %d", 
			   packet->version, rip.version);
	      return -1;
	    }
	}
      else
	{
	  if (packet->version == RIPv1)
	    if (! (ri->ri_receive & RIPv1))
	      {
		if (IS_RIP_DEBUG_PACKET)
		  zlog_warn ("  packet's v%d doesn't fit to if version spec", 
			     packet->version);
		return -1;
	      }
	  if (packet->version == RIPv2)
	    if (! (ri->ri_receive & RIPv2))
	      {
		if (IS_RIP_DEBUG_PACKET)
		  zlog_warn ("  packet's v%d doesn't fit to if version spec", 
			     packet->version);
		return -1;
	      }
	}
    }
  
  /* Process each command. */
  switch (packet->command)
    {
    case RIP_RESPONSE:
      rip_response_recv (packet, len, &from, ifp);
      break;
    case RIP_REQUEST:
    case RIP_POLL:
      rip_request_recv (packet, len, &from, ifp);
      break;
    case RIP_TRACEON:
    case RIP_TRACEOFF:
      zlog_info ("Obsolete command %s received, please sent it to routed", 
		 LOOKUP (rip_msg, packet->command));
      break;
    case RIP_POLL_ENTRY:
      zlog_info ("Obsolete command %s received", 
		 LOOKUP (rip_msg, packet->command));
      break;
    default:
      zlog_info ("Unknown RIP command %d received", packet->command);
      break;
    }

  return len;
}

/* Make socket for RIP protocol. */
int 
rip_create_socket ()
{
  int ret;
  int sock;
  struct sockaddr_in addr;
  struct servent *sp;

  bzero (&addr, sizeof (struct sockaddr_in));

  /* Set RIP port. */
  sp = getservbyname ("router", "udp");
  if (sp) 
    addr.sin_port = sp->s_port;
  else 
    addr.sin_port = htons (RIP_PORT_DEFAULT);

  /* Address shoud be any address. */
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;

  /* Make datagram socket. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) 
    {
      perror ("socket");
      exit (1);
    }
  sockopt_broadcast (sock);
#ifdef RIP_RECVMSG
  setsockopt_pktinfo (sock);
#endif /* RIP_RECVMSG */

  ret = bind (sock, (struct sockaddr *) & addr, sizeof (addr));
  if (ret < 0)
    {
      perror ("bind");
      return ret;
    }
  
  return sock;
}

void
ripv2_make_auth ()
{
  /* family = 0xffff, route tag = 2 */
  ;
}

/* Update rip routes and if it expire, delete route from routing table. */
void
rip_invalid_route (unsigned long invalid)
{
  struct route_node *np;
  struct rip_info *rinfo;
  struct rip_info *next;
  time_t current_time;

  /* Set current time. */
  time (&current_time);

  /* Walk down routing table and update timer. */
  for (np = route_top (rip_table); np; np = route_next (np))
    for (rinfo = np->info; rinfo; rinfo = next)
      {
	struct prefix_ipv4 *p;

	/* Pre fetch next pointer. */
	next = rinfo->next;
	p = (struct prefix_ipv4 *)&np->p;

	if (rinfo->type != ZEBRA_ROUTE_RIP)
	  continue;
	if (rinfo->sub_type == RIP_ROUTE_STATIC)
	  continue;

	if (rinfo->timer < (current_time - invalid))
	  {
	    zlog_info ("route expired %s/%d", 
		       inet_ntoa (p->prefix), p->prefixlen);

	    rip_delete_rinfo ((struct rip_info **) &np->info, rinfo);

	    if (rinfo->fib)
	      rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, p, &rinfo->nexthop);
	  }
      }
}

void
rip_update_interface_version (struct interface *ifp, u_char version)
{
  struct prefix_ipv4 *p;
  struct connected *connected;
  listnode cnode;

  if (version == RIPv2 && if_is_multicast (ifp)) 
    {
      rip_send_init (version);
      rip_send_buf.dest.sin_addr.s_addr = htonl (INADDR_RIP_GROUP);
      rip_send_buf.type = RIP_RESPONSE;
      rip_send_buf.ifp = ifp;

      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("RIP multicast announce on %s ", ifp->name);

      rip_walkdown_send (ifp);
      return;
    }

  if (if_is_broadcast (ifp) || if_is_pointopoint (ifp))
    {
      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{	    
	  connected = getdata (cnode);

	  p = (struct prefix_ipv4 *) connected->destination;
 
	  rip_send_init (version);
	  rip_send_buf.dest.sin_addr = p->prefix;
	  rip_send_buf.type = RIP_RESPONSE;
	  rip_send_buf.ifp = ifp;

	  if (IS_RIP_DEBUG_EVENT)
	    zlog_info ("RIP unicast announce on %s ", ifp->name);

	  rip_walkdown_send (ifp);
	}
    }
}

void
rip_update_interface_send (struct interface *ifp)
{
  struct rip_interface *ri;

  ri = ifp->if_data;

  if (ri->ri_send == RI_RIP_UNSPEC)
    {
      if (rip.version == RIPv1)
	rip_update_interface_version (ifp, RIPv1);
      else
	rip_update_interface_version (ifp, RIPv2);
    }
  else
    {
      if (ri->ri_send & RIPv1)
	rip_update_interface_version (ifp, RIPv1);
      if (ri->ri_send & RIPv2)
	rip_update_interface_version (ifp, RIPv2);
    }
}

/* Update routes of the interfaces. */
void
rip_update_interface ()
{
  listnode node;
  extern list iflist;
  struct interface *ifp;

  /* We need interface loop here. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (! if_is_up (ifp))
	continue;

      if (if_is_loopback (ifp))
	continue;

      if (rip_interface_enable (ifp))
	rip_update_interface_send (ifp);
    }
}

/* RIP announce route to neighbor. */
void
rip_update_neighbor ()
{
  struct route_node *node;
  extern struct route_table *rip_neighbor_table;
  struct interface *ifp = NULL;

  for (node = route_top (rip_neighbor_table); node; node = route_next (node))
    if (node->info)
      {
	ifp = if_lookup_address (node->p.u.prefix4);
	if (! ifp)
	  {
	    if (IS_RIP_DEBUG_EVENT)
	      zlog_info ("neighbor %s doesn't exist direct connected network",
			 inet_ntoa (node->p.u.prefix4));
	    continue;
	  }
	rip_send_init (rip.version);
	rip_send_buf.type = RIP_RESPONSE;
	rip_send_buf.ifp = ifp;
	rip_send_buf.dest.sin_addr = node->p.u.prefix4;

	rip_walkdown_send (ifp);
      }
}

/* This function is called both rip_update_timer and RIP's output
   process tigger. */
void
rip_update ()
{
  rip_update_interface ();
  rip_update_neighbor ();
}

/* RIP's periodical timer. */
int
rip_update_timer (struct thread *thread)
{
  /* Clear timer pointer. */
  rip.t_update = NULL;

  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("RIP update timer fire!");

  rip_update ();

  /* Register myself. */
  RIP_TIMER_ON (rip.t_update, rip_update_timer, rip.v_update);

  return 0;
}

/* RIP's invalid timer. */
int
rip_invalid_timer (struct thread *t)
{
  rip.t_invalid = NULL;
  RIP_TIMER_ON (rip.t_invalid, rip_invalid_timer, rip.v_invalid);

  rip_invalid_route (rip.v_invalid);

  /* Register myself. */
  RIP_TIMER_ON (rip.t_invalid, rip_invalid_timer, rip.v_invalid);

  return 0;
}

/* RIP's holddown timer. */
int
rip_holddown (struct thread *t)
{
  rip.t_holddown = NULL;
  RIP_TIMER_ON (rip.t_holddown, rip_holddown, rip.v_holddown);
  return 0;
}

int
rip_flush (struct thread *t)
{
  rip.t_flush = NULL;
  RIP_TIMER_ON (rip.t_flush, rip_flush, rip.v_flush);
  return 0;
}

/* Set each RIP timer. */
int
rip_timer_set (int update, int invalid, int holddown, int flush)
{
  if (rip.v_update != update)
    {
      rip.v_update = update;
      RIP_TIMER_OFF (rip.t_update);
      RIP_TIMER_ON (rip.t_update, rip_update_timer, rip.v_update);
    }

  if (rip.v_invalid != invalid)
    {
      rip.v_invalid = invalid;
      RIP_TIMER_OFF (rip.t_invalid);
      RIP_TIMER_ON (rip.t_invalid, rip_invalid_timer, rip.v_invalid);
    }

  if (rip.v_holddown != holddown)
    {
      rip.v_holddown = holddown;
      RIP_TIMER_OFF (rip.t_holddown);
      RIP_TIMER_ON (rip.t_holddown, rip_holddown, rip.v_holddown);
    }

  if (rip.v_flush != flush)
    {
      rip.v_flush = flush;
      RIP_TIMER_OFF (rip.t_flush);
      RIP_TIMER_ON (rip.t_flush, rip_flush, rip.v_flush);
    }

  return 0;
}

/* Delete all added rip route. */
void
rip_rib_close ()
{
  struct route_node *np;
  struct rip_info *rinfo;

  for (np = route_top (rip_table); np; np = route_next (np))
    for (rinfo = np->info; rinfo; rinfo = rinfo->next)
      {
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *) &np->p;
	if (rinfo->type == ZEBRA_ROUTE_RIP && rinfo->fib)
	  rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, p, &rinfo->nexthop);
      }
}

void
rip_event (enum rip_event event, int sock)
{
  switch (event)
    {
    case RIP_READ:
      thread_add_read (master, rip_read, NULL, sock);
      break;
    case RIP_WRITE:
      break;
    }
}

DEFUN (router_rip,
       router_rip_cmd,
       "router rip",
       "Enable a routing process\n"
       "Start RIP configuration\n")
{
  vty->node = RIP_NODE;

  if (!rip.enable)
    {
      rip.enable = 1;
      rip.sock = rip_create_socket ();

      if (rip.sock < 0)
	{
	  zlog_info ("Can't make RIP socket");
	  return CMD_WARNING;
	}

      /* Create read and timer thread. */
      rip_event (RIP_READ, rip.sock);

      /* RIP timer on. */
      rip_timer_set (RIP_DEFAULT_UPDATE_TIMER, RIP_DEFAULT_INVALID_TIMER,
		     RIP_DEFAULT_HOLDDOWN_TIMER, RIP_DEFAULT_FLUSH_TIMER);
    }

  return CMD_SUCCESS;
}

DEFUN (rip_version, rip_version_cmd,
       "version VERSION",
       "Set default rip version\n"
       "Version\n")
{
  int version;

  version = atoi (argv[0]);
  if (version != RIPv1 && version != RIPv2)
    {
      vty_out (vty, "invalid rip version %d\r\n", version);
      return CMD_WARNING;
    }
  rip.version = version;

  return CMD_SUCCESS;
} 

DEFUN (rip_route,
       rip_route_cmd,
       "route A.B.C.D/M",
       "RIP static route configuration\n"
       "RIP static route\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *node;
  struct rip_info *rinfo;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address\r\n");
      return CMD_WARNING;
    }

  /* For router rip configuration. */
  node = route_node_get (rip_static_table, (struct prefix *) &p);

  if (node->info)
    {
      vty_out (vty, "There is already same static route.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }

  node->info = "static";

  /* Add this route to RIP routing information base. */
  rinfo = (struct rip_info *) rip_info_new ();
  rinfo->pref = -10;
  rinfo->fib = 1;
  rinfo->type = ZEBRA_ROUTE_RIP;
  rinfo->sub_type = RIP_ROUTE_STATIC;
  rinfo->ifp = NULL;
  rinfo->metric = 1;
  
  /* Register route to rip table. */
  rip_add_route (&p, rinfo, NULL, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_rip_route,
       no_rip_route_cmd,
       "no rip route A.B.C.D/M",
       NO_STR
       "RIP configuration\n"
       "RIP static route\n"
       "RIP static route\n")
{
  return CMD_SUCCESS;
}

DEFUN (rip_timers,
       rip_timers_cmd,
       "timers basic <update> <invalid> <holddown> <flush>",
       "RIP timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information becomes invalid timer. Default is 180.\n"
       "Holddown timer for routing information. Default is 180.\n"
       "Flush timer for routing information. Default is 240.\n")
{
  unsigned long update;
  unsigned long invalid;
  unsigned long holddown;
  unsigned long flush;
  char *endptr = NULL;

  update = strtoul (argv[0], &endptr, 10);
  if (update == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "update timer value error\r\n");
      return CMD_WARNING;
    }
  
  invalid = strtoul (argv[1], &endptr, 10);
  if (invalid == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "invalid timer value error\r\n");
      return CMD_WARNING;
    }
  
  holddown = strtoul (argv[2], &endptr, 10);
  if (holddown == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "holddown timer value error\r\n");
      return CMD_WARNING;
    }
  
  flush = strtoul (argv[3], &endptr, 10);
  if (flush == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "flush timer value error\r\n");
      return CMD_WARNING;
    }

  rip_timer_set (update, invalid, holddown, flush);

  return CMD_SUCCESS;
}

DEFUN (no_rip_timers,
       no_rip_timers_cmd,
       "no timers basic",
       NO_STR
       "RIP timers setup\n"
       "Basic timer\n")
{
  rip_timer_set (RIP_DEFAULT_UPDATE_TIMER, RIP_DEFAULT_INVALID_TIMER,
		 RIP_DEFAULT_HOLDDOWN_TIMER, RIP_DEFAULT_FLUSH_TIMER);
  return CMD_SUCCESS;
}

/* Print out routes update time. */
void
rip_vty_out_uptime (struct vty *vty, struct rip_info *rinfo)
{
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];

  time (&clock);
  clock -= rinfo->timer;
  tm = gmtime (&clock);
  strftime (timebuf, TIME_BUF, "%H:%M:%S", tm);
  vty_out (vty, "%7s", timebuf);
}

DEFUN (show_ip_rip,
       show_ip_rip_cmd,
       "show ip rip",
       SHOW_STR
       "Show RIP routes\n"
       "Show RIP routes\n")
{
  struct route_node *np;
  struct rip_info *rinfo;

  vty_out (vty, "\r\nCodes: R - RIP C - connected\r\n"
	   "   Network            Next Hop    Metric From            Time\r\n");
  
  for (np = route_top (rip_table); np; np = route_next (np))
    for (rinfo = np->info; rinfo; rinfo = rinfo->next)
      {
	int len;

	len = vty_out (vty, "%s%c %s/%d",
		       /* np->lock, For debugging. */
		       route_info[rinfo->type].str,
		       rinfo->fib ? '*' : ' ',
		       inet_ntoa (np->p.u.prefix4), np->p.prefixlen);
	
	len = 22 - len;

	if (len > 0)
	  vty_out (vty, "%*s", len, " ");

	/* Route which exist in kernel routing table. */
	switch (rinfo->type)
	  {
	  case ZEBRA_ROUTE_RIP:
	    {
	      vty_out (vty, "%-15s %2d ", 
		       inet_ntoa (rinfo->nexthop), rinfo->metric);
	      if (rinfo->sub_type == RIP_ROUTE_NORMAL)
		{
		  vty_out (vty, "%-15s ", inet_ntoa (rinfo->from));
		  rip_vty_out_uptime (vty, rinfo);
		}

	    }
	    break;
	  default:
	    vty_out (vty, "                %2d ", rinfo->metric);
	    break;
	  }
	vty_out (vty, "\r\n");
      }
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
config_write_rip (struct vty *vty)
{
  int write = 0;
  struct route_node *node;
  int config_write_rip_network (struct vty *);
  int config_write_rip_redistribute (struct vty *);

  if (rip.enable)
    {
      /* Router RIP statement. */
      vty_out (vty, "router rip%s", VTY_NEWLINE);
      write++;
  
      /* RIP version statement.  Default is RIP version 2. */
      if (rip.version != RIPv2)
	vty_out (vty, " version %d%s", rip.version, VTY_NEWLINE);

      /* RIP enabled network and interface configuration. */
      config_write_rip_network (vty);

      /* Redistribute configuration. */
      config_write_rip_redistribute (vty);

      /* RIP timer configuration. */
      if (rip.v_update != RIP_DEFAULT_UPDATE_TIMER ||
	  rip.v_invalid != RIP_DEFAULT_INVALID_TIMER ||
	  rip.v_holddown != RIP_DEFAULT_HOLDDOWN_TIMER ||
	  rip.v_flush != RIP_DEFAULT_FLUSH_TIMER)
	vty_out (vty, " timers basic %lu %lu %lu %lu%s",
		 rip.v_update, rip.v_invalid, rip.v_holddown, rip.v_flush,
		 VTY_NEWLINE);

      /* RIP static route configuration. */
      for (node = route_top (rip_static_table); node; node = route_next (node))
	if (node->info)
	  vty_out (vty, " route %s%s", 
		   inet_ntoa (node->p.u.prefix4), VTY_NEWLINE);
    }
  return write;
}

/* RIP node structure. */
struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

/* Allocate new rip structure and set default value. */
void
rip_init ()
{
  /* Make rip instance and set default value.*/
  bzero (&rip, sizeof (struct rip));

  /* Set initial value. */
  rip.sock = -1;
  rip.version = RIPv2;

  /* RIP routig table. */
  rip_table = route_table_init ();
  rip_static_table = route_table_init ();

  /* Debug related init. */
  rip_debug_init ();

  /* Filter related init. */
  access_list_init ();
  distribute_init ();

  /* Install top nodes. */
  install_node (&rip_node, config_write_rip);

  /* Install rip commands. */
  install_element (VIEW_NODE, &show_ip_rip_cmd);
  install_element (ENABLE_NODE, &show_ip_rip_cmd);
  install_element (CONFIG_NODE, &router_rip_cmd);

  install_default (RIP_NODE);
  install_element (RIP_NODE, &rip_version_cmd);
  install_element (RIP_NODE, &rip_timers_cmd);
  install_element (RIP_NODE, &no_rip_timers_cmd);
  install_element (RIP_NODE, &rip_route_cmd);
}
