/* zebra client
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA. 
 */

#include <zebra.h>

#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "roken.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_attr.h"

int bgp_interface_add (int, struct zebra *, zebra_size_t);
int bgp_interface_delete (int, struct zebra *, zebra_size_t);
int bgp_interface_address_add (int, struct zebra *, zebra_size_t);
int bgp_interface_address_delete (int, struct zebra *, zebra_size_t);

/* Virtual peer for myself. */
extern struct peer *peer_self;

/* All information about zebra. */
struct zebra *zclient = NULL;

/* Update default router id. */
int
bgp_if_update (struct interface *ifp)
{
  struct bgp *bgp;
  listnode node;
  extern list bgp_list;
  listnode cn;

  for (cn = listhead (ifp->connected); cn; nextnode (cn))
    {
      struct connected *co;
      struct in_addr *addr;

      co = getdata (cn);

      if (co->address->family == AF_INET)
	{
	  addr = &co->address->u.prefix4;

	  for (node = listhead (bgp_list); node; nextnode (node))
	    {
	      bgp = getdata (node);

	      if (! (bgp->config & BGP_CONFIG_ROUTER_ID))
		if (ntohl (bgp->ident) < ntohl (addr->s_addr))
		  bgp->ident = addr->s_addr;
	    }
	}
    }

  return 0;
}

/* Inteface addition message from zebra. */
int
bgp_interface_add (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

#if 0
  if (IS_BGP_DEBUG_ZEBRA)
    zlog_info ("BGP interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);
#endif /* 0 */  

  bgp_if_update (ifp);

  return 0;
}

int
bgp_interface_delete (int command, struct zebra *zebra, zebra_size_t length)
{
  return 0;
}

int
bgp_interface_address_add (int command, struct zebra *zebra,
			     zebra_size_t length)
{
  struct connected *c;

  c = zebra_interface_address_add_read (zclient->ibuf);

  if (c == NULL)
    return 0;

#if 0
  if (IS_BGP_DEBUG_ZEBRA)
    {
      struct prefix *p;
      char buf[INET6_ADDRSTRLEN];

      p = c->address;
      if (p->family == AF_INET6)
	zlog_info ("BGP connected address %s/%d", 
		   inet_ntop (AF_INET6, &p->u.prefix6, buf, INET6_ADDRSTRLEN),
		   p->prefixlen);
    }
#endif /* 0 */

  bgp_if_update (c->ifp);

  return 0;
}

int
bgp_interface_address_delete (int command, struct zebra *zebra,
				zebra_size_t length)
{
  return 0;
}

/* At this moment, this is very ugly implementation. */
int
bgp_redist_type_match (int family, int type)
{
  struct bgp *bgp;
  listnode node;
  extern list bgp_list;

  node = listhead (bgp_list);
  if (! node)
    return 0;

  bgp = node->data;

  if (! bgp)
    return 0;

  if (bgp->redist[family][type])
    return 1;
  else
    return 0;
}

/* Zebra route add and delete treatment. */
int
zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *lim;
  struct stream *s;
  unsigned int ifindex;

  s = zclient->ibuf;
  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in_addr));

  /* Then fetch IPv4 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv4 p;
      struct bgp_info *bgp_info;

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (bgp_redist_type_match (ZEBRA_FAMILY_IPV4, type))
	{
	  bgp_info = bgp_info_new ();
	  bgp_info->type = type;
	  bgp_info->peer = peer_self;
	  bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);
	  bgp_info->uptime = time (NULL);

	  if (command == ZEBRA_IPV4_ROUTE_ADD)
	    nlri_process ((struct prefix *)&p, bgp_info);
	  else
	    nlri_delete (peer_self, (struct prefix *)&p);
	}
    }
  return 0;
}

#ifdef HAVE_IPV6
/* Zebra route add and delete treatment. */
int
zebra_read_ipv6 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in6_addr nexthop;
  u_char *lim;
  struct stream *s;

  s = zclient->ibuf;
  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  stream_get (&nexthop, s, sizeof (struct in6_addr));

  /* Then fetch IPv6 prefixes. */
  while (stream_pnt (s) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      struct bgp_info *bgp_info;
      unsigned int ifindex;

      ifindex = stream_getl (s);

      bzero (&p, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (s);
      size = PSIZE (p.prefixlen);
      stream_get (&p.prefix, s, size);

      if (bgp_redist_type_match (ZEBRA_FAMILY_IPV6, type))
	{
	  bgp_info = bgp_info_new ();
	  bgp_info->type = type;
	  bgp_info->peer = peer_self;
	  bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);
	  bgp_info->uptime = time (NULL);

	  if (command == ZEBRA_IPV6_ROUTE_ADD)
	    nlri_process ((struct prefix *)&p, bgp_info);
	  else
	    nlri_delete (peer_self, (struct prefix *)&p);
	}
    }
  return 0;
}
#endif /* HAVE_IPV6 */

/* Other routes redistribution into BGP. */
void
bgp_redistribute_set (struct bgp *bgp, int family, int route_type)
{
  /* Set flag to BGP instance. */
  bgp->redist[family][route_type] = 1;

  /* Return if already redistribute flag is set. */
  if (zclient->redist[route_type])
    return;

  zclient->redist[route_type] = 1;

  /* Return if zebra connection is not established. */
  if (zclient->sock < 0)
    return;
    
  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, route_type);
}

/* Unset redistribution. */
void
bgp_redistribute_unset (struct bgp *bgp, int family, int route_type)
{
  /* Unset flag from BGP instance. */
  bgp->redist[family][route_type] = 0;

  /* Return if zebra connection is disabled. */
  if (! zclient->redist[route_type])
    return;

  if (bgp->redist[ZEBRA_FAMILY_IPV4][route_type] == 0 &&
      bgp->redist[ZEBRA_FAMILY_IPV6][route_type] == 0 &&
      zclient->sock >= 0)
    /* Send distribute delete message to zebra. */
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock,
			     route_type);
  
  /* Withdraw redistributed routes from current BGP's routing table. */
  bgp_redistribute_withdraw (bgp, family, route_type);
}

DEFUN (bgp_redistribute_kernel,
       bgp_redistribute_kernel_cmd,
       "redistribute kernel",
       "Redistribute\n"
       "Kernel route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4, 
			ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_kernel,
       no_bgp_redistribute_kernel_cmd,
       "no redistribute kernel",
       NO_STR
       "Redistribute\n"
       "Kernel route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			  ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (bgp_redistribute_static,
       bgp_redistribute_static_cmd,
       "redistribute static",
       "Redistribute\n"
       "Static route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4, 
			ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_static,
       no_bgp_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute\n"
       "Static route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			  ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (bgp_redistribute_connected,
       bgp_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute\n"
       "Connected route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_connected,
       no_bgp_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute\n"
       "Connected route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			  ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (bgp_redistribute_rip,
       bgp_redistribute_rip_cmd,
       "redistribute rip",
       "Redistribute\n"
       "RIP route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			ZEBRA_ROUTE_RIP);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_rip,
       no_bgp_redistribute_rip_cmd,
       "no redistribute rip",
       NO_STR
       "Redistribute\n"
       "RIP route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4, 
			  ZEBRA_ROUTE_RIP);
  return CMD_SUCCESS;
}

DEFUN (bgp_redistribute_ospf,
       bgp_redistribute_ospf_cmd,
       "redistribute ospf",
       "Redistribute\n"
       "OSPF route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			ZEBRA_ROUTE_OSPF);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_ospf,
       no_bgp_redistribute_ospf_cmd,
       "no redistribute ospf",
       NO_STR
       "Redistribute\n"
       "OSPF route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV4,
			  ZEBRA_ROUTE_OSPF);
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_redistribute_kernel,
       ipv6_bgp_redistribute_kernel_cmd,
       "ipv6 bgp redistribute kernel",
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Kernel route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6, 
			ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_redistribute_kernel,
       no_ipv6_bgp_redistribute_kernel_cmd,
       "no ipv6 bgp redistribute kernel",
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Kernel route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			  ZEBRA_ROUTE_KERNEL);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_redistribute_static,
       ipv6_bgp_redistribute_static_cmd,
       "ipv6 bgp redistribute static",
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Static route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6, 
			ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_redistribute_static,
       no_ipv6_bgp_redistribute_static_cmd,
       "no ipv6 bgp redistribute static",
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Static route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			  ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_redistribute_connected,
       ipv6_bgp_redistribute_connected_cmd,
       "ipv6 bgp redistribute connected",
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Connected route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_redistribute_connected,
       no_ipv6_bgp_redistribute_connected_cmd,
       "no ipv6 bgp redistribute connected",
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "Connected route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			  ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_redistribute_ripng,
       ipv6_bgp_redistribute_ripng_cmd,
       "ipv6 bgp redistribute ripng",
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "RIPng route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_redistribute_ripng,
       no_ipv6_bgp_redistribute_ripng_cmd,
       "no ipv6 bgp redistribute ripng",
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "RIPng route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6, 
			  ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_redistribute_ospf6,
       ipv6_bgp_redistribute_ospf6_cmd,
       "ipv6 bgp redistribute ospf6",
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "OSPF for IPv6 route\n")
{
  bgp_redistribute_set ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			ZEBRA_ROUTE_OSPF6);
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_redistribute_ospf6,
       no_ipv6_bgp_redistribute_ospf6_cmd,
       "no ipv6 bgp redistribute ospf6",
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute\n"
       "OSPF for IPv6 route\n")
{
  bgp_redistribute_unset ((struct bgp *) vty->index, ZEBRA_FAMILY_IPV6,
			  ZEBRA_ROUTE_OSPF6);
  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

struct interface *
if_lookup_by_ipv4 (struct in_addr *addr)
{
  listnode ifnode;
  listnode cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv4 p;
  struct prefix *cp; 
  
  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  connected = getdata (cnode);
	  cp = connected->address;
	    
	  if (cp->family == AF_INET)
	    if (prefix_match (cp, (struct prefix *)&p))
	      return ifp;
	}
    }
  return NULL;
}

#ifdef HAVE_IPV6
struct interface *
if_lookup_by_ipv6 (struct in6_addr *addr)
{
  listnode ifnode;
  listnode cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv6 p;
  struct prefix *cp; 
  
  p.family = AF_INET6;
  p.prefix = *addr;
  p.prefixlen = IPV6_MAX_BITLEN;

  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  connected = getdata (cnode);
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    if (prefix_match (cp, (struct prefix *)&p))
	      return ifp;
	}
    }
  return NULL;
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_IPV6
int
if_get_ipv6_global (struct interface *ifp, struct in6_addr *addr)
{
  listnode cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
    {
      connected = getdata (cnode);
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (! IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}

int
if_get_ipv6_local (struct interface *ifp, struct in6_addr *addr)
{
  listnode cnode;
  struct connected *connected;
  struct prefix *cp; 
  
  for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
    {
      connected = getdata (cnode);
      cp = connected->address;
	    
      if (cp->family == AF_INET6)
	if (IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
	  {
	    memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
	    return 1;
	  }
    }
  return 0;
}
#endif /* HAVE_IPV6 */

int
bgp_nexthop_set (union sockunion *local, union sockunion *remote, 
		 struct bgp_nexthop *nexthop, struct peer *peer)
{
  int ret = 0;
  struct interface *ifp = NULL;

  memset (nexthop, 0, sizeof (struct bgp_nexthop));

  if (!local)
    return -1;
  if (!remote)
    return -1;

  if (local->sa.sa_family == AF_INET)
    {
      nexthop->v4 = local->sin.sin_addr;
      ifp = if_lookup_by_ipv4 (&local->sin.sin_addr);
    }
#ifdef HAVE_IPV6
  if (local->sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  if (peer->ifname)
	    ifp = if_lookup_by_index (if_nametoindex (peer->ifname));
	}
      else
	ifp = if_lookup_by_ipv6 (&local->sin6.sin6_addr);
    }
#endif /* HAVE_IPV6 */

  if (!ifp)
    return -1;

  nexthop->ifp = ifp;

  /* IPv4 connection. */
  if (local->sa.sa_family == AF_INET)
    {
#ifdef HAVE_IPV6
      /* IPv6 nexthop*/
      ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

      /* There is no global nexthop. */
      if (!ret)
	if_get_ipv6_local (ifp, &nexthop->v6_global);
      else
	if_get_ipv6_local (ifp, &nexthop->v6_local);
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* IPv6 connection. */
  if (local->sa.sa_family == AF_INET6)
    {
      struct interface *direct = NULL;

      /* IPv4 nexthop.  I don't care about it. */
      if (peer->bgp->ident)
	nexthop->v4.s_addr = peer->bgp->ident;

      /* Global address*/
      if (! IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
	{
	  memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		  IPV6_MAX_BYTELEN);

	  /* If directory connected set link-local address. */
	  direct = if_lookup_by_ipv6 (&remote->sin6.sin6_addr);
	  if (direct)
	    if_get_ipv6_local (ifp, &nexthop->v6_local);
	}
      else
	/* Link-local address. */
	{
	  ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

	  /* If there is no global address.  Set link-local address as
             global.  I know this break RFC specification... */
	  if (!ret)
	    memcpy (&nexthop->v6_global, &local->sin6.sin6_addr, 
		    IPV6_MAX_BYTELEN);
	  else
	    memcpy (&nexthop->v6_local, &local->sin6.sin6_addr, 
		    IPV6_MAX_BYTELEN);
	}
    }

  if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr) ||
      if_lookup_by_ipv6 (&remote->sin6.sin6_addr))
    peer->shared_network = 1;
  else
    peer->shared_network = 0;
#endif /* HAVE_IPV6 */

  return ret;
}

#ifdef HAVE_IPV6
unsigned int
bgp_ifindex_by_nexthop (struct in6_addr *addr)
{
  listnode ifnode;
  listnode cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv6 p;
  
  p.family = AF_INET6;
  p.prefix = *addr;
  p.prefixlen = IPV6_MAX_BITLEN;

  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix *cp; 

	  connected = getdata (cnode);
	  cp = connected->address;
	    
	  if (cp->family == AF_INET6)
	    {
	      if (prefix_match (cp, (struct prefix *)&p))
		return ifp->ifindex;
	    }
	}
    }
  return 0;
}
#endif /* HAVE_IPV6 */

void
bgp_zebra_announce (struct prefix *p, struct bgp_info *info)
{
  int flags = 0;

  if (zclient->sock < 0)
    return;

  if (! zclient->redist[ZEBRA_ROUTE_BGP])
    return;

  if (bgp_peer_sort (info->peer) == BGP_PEER_IBGP)
    flags |= ZEBRA_FLAG_INTERNAL;

  if (p->family == AF_INET)
    {
      zebra_ipv4_add (zclient->sock, ZEBRA_ROUTE_BGP, flags,
		      (struct prefix_ipv4 *)p, &info->attr->nexthop, 0);
      return;
    }
#ifdef HAVE_IPV6
  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6)
    {
      unsigned int ifindex;
      struct in6_addr *nexthop;

      ifindex = 0;
      nexthop = NULL;

      /* Only global address nexthop exists. */
      if (info->attr->mp_nexthop_len == 16)
	nexthop = &info->attr->mp_nexthop_global;
      
      /* If both global and link-local address present. */
      if (info->attr->mp_nexthop_len == 32)
	{
	  nexthop = &info->attr->mp_nexthop_local;
	  if (info->peer->nexthop.ifp)
	    ifindex = info->peer->nexthop.ifp->ifindex;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	if (info->peer->ifname)
	  ifindex = if_nametoindex (info->peer->ifname);

      zebra_ipv6_add (zclient->sock, ZEBRA_ROUTE_BGP, flags,
		      (struct prefix_ipv6 *)p, nexthop, ifindex);
    }
#endif /* HAVE_IPV6 */
}

void
bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info)
{
  int flags = 0;

  if (zclient->sock < 0)
    return;

  if (! zclient->redist[ZEBRA_ROUTE_BGP])
    return;

  if (bgp_peer_sort (info->peer) == BGP_PEER_IBGP)
    flags |= ZEBRA_FLAG_INTERNAL;

  if (p->family == AF_INET)
    zebra_ipv4_delete (zclient->sock, ZEBRA_ROUTE_BGP, flags,
		       (struct prefix_ipv4 *)p, &info->attr->nexthop, 0);
#ifdef HAVE_IPV6
  /* We have to think about a IPv6 link-local address curse. */
  if (p->family == AF_INET6)
    {
      unsigned int ifindex;
      struct in6_addr *nexthop;

      ifindex = 0;
      nexthop = NULL;

      /* Only global address nexthop exists. */
      if (info->attr->mp_nexthop_len == 16)
	nexthop = &info->attr->mp_nexthop_global;

      /* If both global and link-local address present. */
      if (info->attr->mp_nexthop_len == 32)
	{
	  nexthop = &info->attr->mp_nexthop_local;
	  if (info->peer->nexthop.ifp)
	    ifindex = info->peer->nexthop.ifp->ifindex;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	if (info->peer->ifname)
	  ifindex = if_nametoindex (info->peer->ifname);

      zebra_ipv6_delete (zclient->sock, ZEBRA_ROUTE_BGP, flags,
			 (struct prefix_ipv6 *)p, nexthop, ifindex);
    }
#endif /* HAVE_IPV6 */
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")
{
  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

DEFUN (redistribute_bgp,
       redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  zclient->redist[ZEBRA_ROUTE_BGP] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_redistribute_bgp,
       no_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  zclient->redist[ZEBRA_ROUTE_BGP] = 0;
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_BGP])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute bgp%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

void
bgp_zclient_reset ()
{
  zclient_reset (zclient);
}

void
zebra_init (int enable)
{
  /* Set default values. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_BGP);
  zclient->interface_add = bgp_interface_add;
  zclient->interface_delete = bgp_interface_delete;
  zclient->interface_address_add = bgp_interface_address_add;
  zclient->interface_address_delete = bgp_interface_address_delete;
  zclient->ipv4_route_add = zebra_read_ipv4;
  zclient->ipv4_route_delete = zebra_read_ipv4;
#ifdef HAVE_IPV6
  zclient->ipv6_route_add = zebra_read_ipv6;
  zclient->ipv6_route_delete = zebra_read_ipv6;
#endif /* HAVE_IPV6 */

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &redistribute_bgp_cmd);
  install_element (ZEBRA_NODE, &no_redistribute_bgp_cmd);
  install_element (BGP_NODE, &bgp_redistribute_kernel_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_kernel_cmd);
  install_element (BGP_NODE, &bgp_redistribute_static_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_static_cmd);
  install_element (BGP_NODE, &bgp_redistribute_connected_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_connected_cmd);
  install_element (BGP_NODE, &bgp_redistribute_rip_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_rip_cmd);
  install_element (BGP_NODE, &bgp_redistribute_ospf_cmd);
  install_element (BGP_NODE, &no_bgp_redistribute_ospf_cmd);
#ifdef HAVE_IPV6
  install_element (BGP_NODE, &ipv6_bgp_redistribute_kernel_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_redistribute_kernel_cmd);
  install_element (BGP_NODE, &ipv6_bgp_redistribute_static_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_redistribute_static_cmd);
  install_element (BGP_NODE, &ipv6_bgp_redistribute_connected_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_redistribute_connected_cmd);
  install_element (BGP_NODE, &ipv6_bgp_redistribute_ripng_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ripng_cmd);
  install_element (BGP_NODE, &ipv6_bgp_redistribute_ospf6_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ospf6_cmd);
#endif /* HAVE_IPV6 */

  /* Interface related init. */
  if_init ();
}
