/*
 * $Id: ripd.c,v 1.123 1999/02/22 12:15:39 developer Exp $
 *
 * RIP version 1 and 2.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "if.h"
#include "thread.h"
#include "memory.h"
#include "buffer.h"
#include "roken.h"
#include "log.h"

#include "zebra/zebra.h"
#include "ripd/ripd.h"

extern struct thread_master *master;

/* RIP Structure. */
struct rip rip_master;

/* Pointer to RIP structure. */
struct rip *rip;

/* RIP routing table radix tree. */
struct route_table *rip_table;

/* Extern function. */
void rip_zebra (int, struct prefix_ipv4 *, struct in_addr *);

/* This struct carries information of type of response and which
   interface this buffer is send to. */
struct rip_send_buf
{
  int type;
  struct interface *ifp;
  struct rte *rte;
  struct rte *rtelim;
  union rip_buf rip_buf;
  struct sockaddr_in *dest;
} rip_send_buf;

/* RIP command strings. */
struct message rip_msg[] = 
{
  { 0,             "NULL"},
  {RIP_REQUEST,    "RIP_REQUEST"},
  {RIP_RESPONSE,   "RIP_RESPONSE"},
  {RIP_TRACEON,    "RIP_TRACEON"},
  {RIP_TRACEOFF,  "RIP_TRACEOFF"},
  {RIP_POLL,       "RIP_POLL"},
  {RIP_POLL_ENTRY, "RIP_POLL_ENTRY"},
};

struct message route_sort_msg[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X"},
  { ZEBRA_ROUTE_KERNEL,  "K"},
  { ZEBRA_ROUTE_CONNECT, "C"},
  { ZEBRA_ROUTE_STATIC,  "S"},
  { ZEBRA_ROUTE_RIP,     "R"},
  { ZEBRA_ROUTE_RIPNG,   "R"},
  { ZEBRA_ROUTE_BGP,     "B"},
};


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

/* Interface filter check. */
int
ri_check (struct prefix_ipv4 *p, struct interface *ifp)
{
  struct rip_interface *ri;

  ri = ifp->if_data;

  if (prefix_ipv4_any (p))
    if (ri->ri_default_receive == RIP_DEFAULT_ACCEPT_NONE)
      return 0;
  return 1;
}

/* RIP add route to routing table. */
int
rip_add_route (struct prefix_ipv4 *p, struct rip_info *rinfo, 
	       struct sockaddr_in *from, struct interface *ifp)
{
  int ret;
  struct route_node *np;

  struct rip_info *rp;
  struct rip_info *rip;
  struct rip_info *connected;

  /* Add interface's metric. */
  rinfo->metric += ifp->metric;

  /* Get index for the prefix. */
  np = route_node_get (rip_table, (struct prefix *) p);

  /* Check rip route filtering. */
  ret = ri_check (p, ifp);
  if (!ret)
    {
      zlog (NULL, LOG_INFO, "rip filtered route %s/%d",
	      inet_ntoa (p->prefix), p->prefixlen);
      return ret;
    }

  /* Check same prefix rip route exists. */
  rip = NULL;
  connected = NULL;
  for (rp = np->info; rp; rp = rp->next)
    {
      if (rp->type == ZEBRA_ROUTE_RIP)
	rip = rp;
      if (rp->type == ZEBRA_ROUTE_CONNECT)
	connected = rp;
    }

  /* If given route is connected route. */
  if (rinfo->type == ZEBRA_ROUTE_CONNECT)
    {
      zlog (NULL, LOG_INFO, "rip connected add %s/%d", inet_ntoa (p->prefix),
	      p->prefixlen);

      if (connected)
	{
	  rip_delete_rinfo ((struct rip_info **)&np->info, connected);
	  route_unlock_node (np);
	}
      rip_add_rinfo ((struct rip_info **) &np->info, rinfo);

      return 0;
    }

  /* There are three cases of add|replace|update. */
  if (rip)
    {
      if (IPV4_ADDR_CMP (&rip->from, &from->sin_addr) == 0)
	{
	  /* This is update of existing rip route. */
	  zlog (NULL, LOG_INFO, "rip update route %s/%d", inet_ntoa (p->prefix), 
		  p->prefixlen);
	}
      else
	{
	  /* This is replacement of rip route. */
	  zlog (NULL, LOG_INFO, "rip replace route %s/%d", inet_ntoa (p->prefix), 
		  p->prefixlen);
	}
      rip->tag = rinfo->tag;
      rip->metric = rinfo->metric;
      rip->from = rinfo->from;
      rip->timer = rinfo->timer;

      /* Change nexthop address. */
      if (IPV4_ADDR_CMP (&rip->nexthop, &rinfo->nexthop) != 0)
	{
	  rip->nexthop = rinfo->nexthop;
	  rip_zebra (ZEBRA_IPV4_ROUTE_ADD, p, &rinfo->nexthop);
	}
      route_unlock_node (np);
    }
  else
    {
      /* This is new rip route. */
      zlog (NULL, LOG_INFO, "rip add route %s/%d", inet_ntoa (p->prefix), p->prefixlen);
      rip_add_rinfo ((struct rip_info **) &np->info, rinfo);
      if (!connected)
	{
	  rinfo->fib = 1;
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
  zlog (NULL, LOG_INFO, "rip delete route %s/%d", inet_ntoa (p->prefix),
	  p->prefixlen);

  /* Get index for the prefix. */
  np = route_node_get (rip_table, (struct prefix *) p);

  for (rp = np->info; rp; rp = rp->next)
    {
      ;
    }

  /* rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, pin, 0); */

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
      zlog (NULL, LOG_WARNING, "can't set sockopt SO_BROADCAST to socket %d",
	      sock);
      return -1;
    }
  return 0;
}

/* Dump rip packet */
void
rip_packet_dump (struct rip_packet *packet, int size)
{
  caddr_t end;
  struct rte *rte;
  struct in_addr addr;
  char pbuf[BUFSIZ], nbuf[BUFSIZ], hbuf[BUFSIZ];

  rte = packet->route;
  end = ((caddr_t) packet) + size;
  
  zlog (NULL, LOG_INFO, "------------- Routing information -----------");
  while ((caddr_t) rte < end) 
    {
      zlog (NULL, LOG_INFO, "family [%d] tag [%d] metric [%d]",
	      ntohs (rte->family), ntohs (rte->tag), ntohl (rte->metric));

      addr.s_addr = rte->prefix;
      strncpy (pbuf, inet_ntoa (addr), BUFSIZ);
      addr.s_addr = rte->netmask;
      strncpy (nbuf, inet_ntoa (addr), BUFSIZ);
      addr.s_addr = rte->nexthop;
      strncpy (hbuf, inet_ntoa (addr), BUFSIZ);

      zlog (NULL, LOG_INFO, "prefix  [%s] netmask [%s] nexthop [%s]",
	      pbuf, nbuf, hbuf);

      rte ++;
    }
  zlog (NULL, LOG_INFO, "------------- Routing information -----------");
}

struct rip_info *
rip_info_new ()
{
  struct rip_info *new;

  new = XMALLOC (MTYPE_RIP_INFO, sizeof (struct rip_info));
  bzero (new, sizeof (struct rip_info));
  return new;
}

/* RIP routing information. */
void
rip_process_route (struct rip_packet *packet, int size, 
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
      zlog (NULL, LOG_INFO, "This packet doesn't come from rip port : %d",
	      from->sin_port);
      return;
    }

  time (&gettime);

  rte = packet->route;
  end = ((caddr_t) packet) + size;

  while ((caddr_t) rte < end) 
    {
      struct prefix_ipv4 p;
      struct in_addr mask;

      /* Address family check. ripd only supports AF_INET. */
      if (ntohs (rte->family) != AF_INET)
	{
	  zlog (NULL, LOG_INFO, "unsupported family %d from %s.",
		  ntohs (rte->family), inet_ntoa (from->sin_addr));
	  rte++;
	  continue;
	}

      /* Allocate new rt_in. */
      p.family = AF_INET;
      p.prefix.s_addr = rte->prefix;
      mask.s_addr = rte->netmask;
      p.prefixlen = ip_masklen (mask);

      /* Fetch information into rip_info structure */
      rinfo = rip_info_new ();
      rinfo->type = ZEBRA_ROUTE_RIP;
      rinfo->pref = 10;
      rinfo->metric = ntohl (rte->metric);
      rinfo->from.s_addr = from->sin_addr.s_addr;
      rinfo->tag = ntohl (rte->tag);
      if (ntohl (rte->nexthop) == 0)
	rinfo->nexthop.s_addr = from->sin_addr.s_addr;
      else
	rinfo->nexthop.s_addr = rte->nexthop;
      rinfo->timer = gettime;

      /* Check nexthop address. */
      ret = if_check_address (rinfo->nexthop);
      if (ret)
	{
	  zlog (NULL, LOG_INFO, "route's nexthop set to myself! So ignore this route.");
	  rte++;
	  continue;
	}

      /* Check metric is INFINITY or not. */
      if (rinfo->metric != RIP_METRIC_INFINITY) 
	rip_add_route (&p, rinfo, from, ifp);
      else 
	rip_delete_route (&p, rinfo, from, ifp);

      rte++;
    }
}

/* Set up initial send buffer. */
void
rip_send_init ()
{
  struct rip_packet *rip_packet;
  extern struct rip *rip;

  rip_packet = &rip_send_buf.rip_buf.rip_packet;
  rip_packet->command = RIP_RESPONSE;
  rip_packet->version = rip->version;
  rip_packet->pad1 = 0;
  rip_packet->pad2 = 0;

  rip_send_buf.rte = rip_packet->route;
  rip_send_buf.rtelim = rip_packet->route + RIP_MAX_RTE;
  rip_send_buf.dest = NULL;
  rip_send_buf.ifp = NULL;
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
    zlog (NULL, LOG_INFO, "can't send packet : %m");

  return ret;
}

/* Utility function to announce rip route. */
void
rip_send_announce ()
{
  int size;
  caddr_t end = (caddr_t)rip_send_buf.rte;
  caddr_t start = (caddr_t)&rip_send_buf.rip_buf;
  struct sockaddr_in *sin = rip_send_buf.dest;
  struct rip_packet *rip_packet;

  extern struct rip *rip;

  /* Reset pointer. */
  rip_packet = &rip_send_buf.rip_buf.rip_packet;

  size = end - start;

  if (rip_send_buf.type == RIP_REQUEST || rip_send_buf.type == RIP_POLL)
    rip_udp_send (rip->sock, start, size, sin);
  
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
  unsigned long metric;

  metric = 0;

  /* Do not send loopback route. */
  if (rinfo->type == ZEBRA_ROUTE_CONNECT)
    {
      if (if_is_loopback (rinfo->ifp))
	return;
      metric = ifp->metric;
    }

  /* If tag value is zero then this route isn't take into account. */
  if (rinfo->type == ZEBRA_ROUTE_RIP)
    {
      if (!rinfo->fib)
	return;
      metric = rinfo->ifp->metric + rinfo->metric;
    }

  /* Check metric overflow. */
  if (metric >= RIP_METRIC_INFINITY)
    metric = RIP_METRIC_INFINITY;

  /* In case of RIP_POLL, do not perform split horizon/poisoned reverse. */
  if (rip_send_buf.type != RIP_POLL)
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
  rte = rip_send_buf.rte;
  rte->family = htons (AF_INET);
  rte->tag = 0;
  rte->prefix = p->u.prefix4.s_addr;
  masklen2ip (p->prefixlen, &mask);
  rte->netmask = mask.s_addr;
  rte->metric = htonl (metric);
  rip_send_buf.rte++;

  /* If buffer is full of routes, send it to neighbor. */
  if (rip_send_buf.rte == rip_send_buf.rtelim)
    rip_send_announce ();
}

/* Response to request called from rip_read ().*/
void
rip_process_query (struct rip_packet *packet, int size, 
		   struct sockaddr_in *sin, struct interface *ifp)
{
  struct rte *rte;
  struct route_node *node;
  struct rip_info *rinfo;

  rte = packet->route;

  /* Check address family. */
  if (ntohs (rte->family) != AF_UNSPEC)
    {
      zlog (NULL, LOG_INFO, "rip query packet with not AF_UNSPEC family");
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
      zlog (NULL, LOG_INFO, "RIP query packet with not metric 16");
      return;
    }

  /* Make response packet header. */
  rip_send_init ();
  rip_send_buf.dest = sin;
  rip_send_buf.ifp = ifp;

  /* In case of invoked by RIP_POLL packet, it does not perform Split
     Horizon and/or Poisoned Reverse. */
  rip_send_buf.type = packet->command;
  
  for (node = route_top (rip_table); node; node = route_next (node))
    for (rinfo = node->info; rinfo; rinfo = rinfo->next)
      rip_announce_func (&node->p, rinfo, ifp);

  rip_send_announce ();
}

/* First entry point of RIP packet. */
int
rip_read (struct thread *thread)
{
  union rip_buf rip_buf;
  struct rip_packet *packet;
  struct sockaddr_in from;
  int fromlen, len;
  struct interface *ifp;
  int sock;

  /* Fetch thread argument. */
  sock = THREAD_FD (thread);

  /* Register myself to thread. */
  thread_add_read (master, rip_read, NULL, sock);

  /* RIPd manages only IPv4. */
  fromlen = sizeof (struct sockaddr_in);
  len = recvfrom (sock, (char *)&rip_buf.buf, sizeof (rip_buf.buf), 0, 
		  (struct sockaddr *) &from, &fromlen);
  if (len < 0) 
    {
      zlog (NULL, LOG_INFO, "recvfrom failed : %m");
      return len;
    }

  /* For easy to handle. */
  packet = &rip_buf.rip_packet;
  ifp = (struct interface *) if_lookup_address (from.sin_addr);

  /* Dump packet header. */
  zlog (NULL, LOG_INFO, "RIP version %d packet size [%d] command [%s] "
	  "host [%s] port [%d] if [%s]\n",
	  packet->version, len, LOOKUP (rip_msg, packet->command),
	  inet_ntoa(from.sin_addr), ntohs (from.sin_port),
	  ifp ? ifp->name : "unknown");

  /* Dump packet rte. */
  rip_packet_dump (packet, len);

  /* If this packet come from unknown inteface, ignore it. */
  if (ifp == NULL)
    {
      zlog (NULL, LOG_INFO, "RIP packet come from unknown inteface.");
      return 0;
    }

  /* RIP version check. */
  if (packet->version == 0)
    {
      zlog (NULL, LOG_INFO, "RIP version 0 which has command %d received.",
	      packet->command);
      return 0;
    }

  if (packet->version > RIPv2)
    packet->version = RIPv2;

  if (packet->version != rip->version) 
    {
      zlog (NULL, LOG_INFO, "This packet's version[%d] doesn't fit to my version.", 
	   packet->version);
      return 0;
    }

  /* check is this packet comming from myself? */
  if (if_check_address (from.sin_addr) && packet->command != RIP_POLL) 
    {
      zlog (NULL, LOG_INFO, "This packet comes from myself");
      return 0;
    }
  
  switch (packet->command)
    {
    case RIP_RESPONSE:
      rip_process_route (packet, len, &from, ifp);
      break;
    case RIP_REQUEST:
    case RIP_POLL:
      rip_process_query (packet, len, &from, ifp);
      break;
    case RIP_TRACEON:
    case RIP_TRACEOFF:
      zlog (NULL, LOG_INFO, "Obsolete command %s received, please sent it to routed", 
	   LOOKUP (rip_msg, packet->command));
      break;
    case RIP_POLL_ENTRY:
      break;
    default:
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

  ret = bind (sock, (struct sockaddr *) & addr, sizeof (addr));
  if (ret < 0)
    {
      perror ("bind");
      return ret;
    }
  
  return sock;
}

/* Make RIP request packet. */
int
rip_make_request (u_char *pnt, int version)
{
  u_char *start = pnt;
  
  /*
   * RIP first Initializetaion query is
   *  command = RIP_REQUEST
   *  address family = AF_UNSPEC
   *  metric = 16 (RIP_METRIC_INFINITY)
   */
  PUTC (RIP_REQUEST, pnt);	/* command */
  PUTC (version, pnt);		/* version */
  PUTW (0, pnt);		/* domain */
  PUTW (AF_UNSPEC, pnt);	/* family */
  PUTW (0, pnt);		/* tag */
  PUTL (0, pnt);		/* prefix */
  PUTL (0, pnt);		/* netmask */
  PUTL (0, pnt);		/* nexthop */
  PUTL (RIP_METRIC_INFINITY, pnt); /* metric */

  /* Return size of the packet. */
  return pnt - start;
}

void
ripv2_make_auth ()
{
  /* family = 0xffff, route tag = 2 */
  ;
}

/* Update rip routes and if it expire, delete route from routing table. */
void
rip_age_route ()
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

	if (rinfo->timer < (current_time - RIP_TIMEOUT))
	  {
	    zlog (NULL, LOG_INFO, "route expired %s/%d", inet_ntoa (p->prefix), 
		 p->prefixlen);

	    rip_delete_rinfo ((struct rip_info **) &np->info, rinfo);
	    if (rinfo->fib)
	      rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, p, &rinfo->nexthop);
	  }
      }
}

/* Flash out routes to the intefaces. */
int
rip_announce ()
{
  listnode node;
  struct interface *ifp;
  extern list iflist;
  /*  extern vector ifvec; */

  rip_send_init ();

  /* This means periodical update of routes. */
  rip_send_buf.type = RIP_RESPONSE;

  /* We need interface loop here. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      /* Skip loopback interface. */
      if (if_is_loopback (ifp))
	continue;

      rip_send_buf.ifp = ifp;
      /* radix_apply_func (rip_radix, rip_announce_func, &rip_send_buf); */
    }

  rip_send_announce ();
  return 0;
}

/* RIP periodical timer. */
int
rip_timer (struct thread *thread)
{
  rip_age_route ();
  rip_announce ();

  rip->timer = thread_add_timer (master, rip_timer, NULL, RIP_FLASH_TIMER);
  return 0;
}

/* Interface initialize and send request to each interface. */
void
rip_start ()
{
  /* Make rip socket. */
  rip->sock = rip_create_socket ();
  if (rip->sock < 0)
    {
      zlog (NULL, LOG_INFO, "Can't make RIP socket");
      return;
    }

  /* Set multicast if it needs. */
  if (rip->multicast == RIP_MULTICAST)
    rip_multicast_enable (rip->sock);

  /* Create read and timer thread. */
  rip->read = thread_add_read (master, rip_read, NULL, rip->sock);
  rip->timer = thread_add_timer (master, rip_timer, NULL, RIP_FLASH_TIMER);

  rip_request_all ();
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

/* RIP is started at bootstrap of RIPd.  First of all rip_init()
   initialize rip structure.  Second rip_start() make rip socket,
   timer, interface init and request.  So `router rip' command only
   change current user node. */
DEFUN (router_rip,
       router_rip_cmd,
       "router rip",
       "Enable a routing process\n"
       "Start RIP configuration\n")
{
  vty->node = RIP_NODE;
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
  rip->version = version;
  return CMD_SUCCESS;
} 

DEFUN (rip_multicast,
       rip_multicast_cmd,
       "multicast",
       "RIP send multicast packet.")
{
  rip->multicast = RIP_MULTICAST;
  return CMD_SUCCESS;
}

DEFUN (rip_broadcast,
       rip_broadcast_cmd,
       "broadcast",
       "RIP send broadcast packet.")
{
  rip->multicast = RIP_BROADCAST;
  return CMD_SUCCESS;
}

DEFUN (rip_network,
       rip_network_cmd,
       "network IPV4_ADDR",
       "Set announced network for RIP\n"
       "IP Address\n")
{
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
	   "      Network            Next Hop    Metric From            Time\r\n");
  
  for (np = route_top (rip_table); np; np = route_next (np))
    for (rinfo = np->info; rinfo; rinfo = rinfo->next)
      {
	int len;

	len = vty_out (vty, "[%d]%s%c %s/%d",
		       np->lock, /* For debugging. */
		       route_sort_msg[rinfo->type].str,
		       rinfo->fib ? '*' : ' ',
		       inet_ntoa (np->p.u.prefix4), np->p.prefixlen);
	
	len = 25 - len;

	if (len > 0)
	  vty_out (vty, "%*s", len, " ");

	/* Route which exist in kernel routing table. */
	switch (rinfo->type)
	  {
	  case ZEBRA_ROUTE_RIP:
	    {
	      vty_out (vty, "%-15s %2d ", 
		       inet_ntoa (rinfo->nexthop), rinfo->metric);
	      vty_out (vty, "%-15s ", inet_ntoa (rinfo->from));
	      rip_vty_out_uptime (vty, rinfo);
	      vty_out (vty, "\r\n");
	    }
	    break;
	  case ZEBRA_ROUTE_CONNECT:
	    {
	      struct interface *ifp;
	      ifp = rinfo->ifp;
	      
	      vty_out (vty, "%-15s %2d\r\n", ifp->name, ifp->metric);
	    }
	    break;
	  }
      }
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
config_write_rip (struct vty *vty)
{
  vty_out (vty, "router rip%s", VTY_NEWLINE);
  
  if (rip->version != RIPv2)
    vty_out (vty, " version %d%s", rip->version, VTY_NEWLINE);
  if (rip->multicast == RIP_BROADCAST)
    vty_out (vty, " broadcast%s", VTY_NEWLINE);
  return 0;
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
  rip = &rip_master;
  rip->sock = -1;
  rip->version = RIPv2;
  rip->multicast = RIP_MULTICAST;

  /* RIP routig table. */
  rip_table = route_table_init ();

  /* Install top nodes. */
  install_node (&rip_node, config_write_rip);

  /* Install rip commands. */
  install_element (VIEW_NODE, &show_ip_rip_cmd);
  install_element (ENABLE_NODE, &show_ip_rip_cmd);
  install_element (RIP_NODE, &config_end_cmd);
  install_element (RIP_NODE, &config_exit_cmd);
  install_element (RIP_NODE, &config_help_cmd);
  install_element (RIP_NODE, &rip_version_cmd);
  install_element (RIP_NODE, &rip_multicast_cmd);
  install_element (RIP_NODE, &rip_broadcast_cmd);
  install_element (CONFIG_NODE, &router_rip_cmd);
}
