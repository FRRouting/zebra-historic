/* RIP announce treatment.
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

#ifdef HAVE_IPV6
#ifdef HYDRANGEA
#ifdef INET6
#undef INET6
#undef HYDRANGEA
#undef HAVE_IPV6
#endif /* INET6 */
#endif /* HYDRANGEA */
#endif /* HAVE_IPV6 */

#include <config.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <time.h>

#include "ripd.h"
#include "route.h"
#include "radix.h"
#include "zebra.h"
#include "vector.h"
#include "linklist.h"
#include "if.h"

/* RIP routing table radix tree. */
extern struct radix_top *rip_radix;

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

/* RIP aging routes. */
rip_age_func (struct prefix_in *pin, time_t time)
{
  struct rip_info *rinfo;

  if (pin->type != ZEBRA_ROUTE_RIP)
    return;

  rinfo = pin->gate.info;

  /* Expired route. */
  if (rinfo->timer < (time - RIP_TIMEOUT))
    {
      log ("route expired %s/%d\n", inet_ntoa (pin->prefix), pin->mask);
      radix_delete (rip_radix, (struct prefix *) pin);
    }
}

/* Update rip routes and if it expire, delete route from routing table. */
rip_age ()
{
  time_t current_time;

  /* Set current time. */
  time (&current_time);

  /* Walk down radix tree and update timer. */
  radix_apply_func (rip_radix, rip_age_func, current_time);
}

/**/
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
    {
      rip_udp_send (rip->sock, start, size, sin);
    }
  
  rip_send_buf.rte = rip_packet->route;
}


if_lookup_pin ()
{

}

/* Walkdown function of rip's radix tree. */
rip_announce_func (struct prefix_in *pin, void *arg)
{
  struct rip_send_buf *rsb;
  struct rte *rte;
  struct in_addr mask;
  struct rip_interface *ri;
  struct interface *ifp;
  struct rip_info *rinfo;
  unsigned long metric;

  rsb = arg;
  rte = rsb->rte;

  rinfo = pin->gate.info;
  
  /* Do not send loopback route. */
  if (pin->type == ZEBRA_ROUTE_CONNECT)
    {
      ifp = pin->gate.info;
      if (if_is_loopback (ifp))
	return;
      metric = ifp->metric;
    }
  else if (pin->type == ZEBRA_ROUTE_RIP)
    {
      /* If tag value is zero then this route isn't take into account. */
      if (!pin->fib)
	return;

      ifp = rsb->ifp;
      metric = ifp->metric + rinfo->metric;
      if (metric >= RIP_METRIC_INFINITY)
	metric = RIP_METRIC_INFINITY;
    }

  /* In case of RIP_POLL, do not perform split horizon/poisoned reverse. */
  if (rsb->type != RIP_POLL)
    {
      ri = ifp->if_data;

      /* Split horizon. */
      if (ri->ri_split_horizon == RI_RIP_SPLIT_HORIZON_UNSPEC
	  || ri->ri_split_horizon == RI_RIP_SPLIT_HORIZON)
	if (if_lookup_pin (pin))
	  return;

      /* Poisoned reverse. */
      ;
    }

  /* Write routing information. */
  rte->family = htons (AF_INET);
  rte->tag = 0;
  rte->prefix = pin->prefix.s_addr;
  masklen2ip (pin->mask, &mask);
  rte->netmask = mask.s_addr;
  rte->metric = htonl (metric);
  rip_send_buf.rte++;

  /* If buffer is full of routes, send it to neighbor. */
  if (rip_send_buf.rte == rip_send_buf.rtelim)
    rip_send_announce ();
}

/* Set up initial send buffer. */
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

/* Flash out routes to the intefaces. */
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
      radix_apply_func (rip_radix, rip_announce_func, &rip_send_buf);
    }

  rip_send_announce ();
}

/* Response to request called from rip_read ().*/
rip_process_query (struct rip_packet *packet, 
		   int size, 
		   struct sockaddr_in *sin,
		   struct interface *ifp)
{
  struct rte *rte;
  
  rte = packet->route;

  /* Check address family. */
  if (ntohs (rte->family) != AF_UNSPEC)
    {
      log ("rip query packet with not AF_UNSPEC family\n");
      return;
    }
  /* Check tag command. */
  if (rte->tag != 0)
    {
      log ("rip query packet with non zero tag value\n");
      return;
    }

  /* If metric is not inifinity, it's error. */
  if (ntohl (rte->metric) != RIP_METRIC_INFINITY)
    {
      log ("RIP query packet with not metric 16.\n");
      return;
    }

  /* Make response packet header. */
  rip_send_init ();
  rip_send_buf.dest = sin;
  rip_send_buf.ifp = ifp;

  /* In case of invoked by RIP_POLL packet, it does not perform Split
     Horizon and/or Poisoned Reverse. */
  rip_send_buf.type = packet->command;
  
  radix_apply_func (rip_radix, rip_announce_func, &rip_send_buf);
  rip_send_announce ();
}
