/*
 * zebra connect library 
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

#include "zebra/zebra.h"
#include "command.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "client.h"
#include "roken.h"
#include "log.h"
#include "thread.h"
#include "sockunion.h"
#include "if.h"
#include "zclient.h"

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_attr.h"

/* All information about zebra. */
struct zebra *zebra = NULL;

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

/* Get all interface information. */
int
bgp_get_all_interface (int command, struct zebra *zebra, zebra_size_t length)
{
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;
  unsigned long endp;
  struct stream *s;

  s = zebra->ibuf;
  endp = stream_get_endp (s);

  while (stream_get_getp(s) < endp)
    {
      u_char tmpnam[INTERFACE_NAMSIZ + 1];

      bzero (tmpnam, sizeof (tmpnam));

      /* Get interface's name */
      stream_strncpy (tmpnam, s, INTERFACE_NAMSIZ);

      /* create interface structure */
      ifp = if_get_by_name (tmpnam);

      /* Get interface's index and values. */
      ifp->index = stream_getc (s);
      ifp->flags = stream_getl (s);
      ifp->metric = stream_getl (s);
      ifp->mtu = stream_getl (s);

      /* Get interface's address. */
      connected_count = stream_getl (s);

      while (connected_count--)
	{
	  struct prefix *p;
	  int plen;

	  connected = connected_new ();

	  p = prefix_new ();
	  p->family = stream_getc (s);

	  plen = prefix_blen (p);
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);
	  p->prefixlen = stream_getc (s);
	  connected->address = p;

	  p = prefix_new ();
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);

	  connected->destination = p;

	  connected_add (ifp, connected);
	}
      bgp_if_update (ifp);
    }
  return 0;
}

extern struct peer *peer_self;

/* Zebra route add and delete treatment. */
int
zebra_read_ipv4 (int command, struct zebra *zebra, zebra_size_t length)
{
  u_char type;
  u_char flags;
  struct in_addr nexthop;
  u_char *pnt;
  u_char *lim;
  struct stream *s;

  s = zebra->ibuf;

  pnt = stream_pnt (s);
  lim = pnt + length;

  /* Fetch type and nexthop first. */
  type = *pnt++;
  flags = *pnt++;
  memcpy(&nexthop, pnt, 4);
  pnt += 4;

  /* Then fetch IPv4 prefixes. */
  while (pnt < lim)
    {
      int size;
      struct prefix_ipv4 p;
      struct bgp_info *bgp_info;

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      size = PSIZE (p.prefixlen);
      memcpy (&p.prefix, pnt, size);
      pnt += size;

      bgp_info = bgp_info_new ();
      bgp_info->type = type;
      bgp_info->peer = peer_self;
      bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	nlri_process ((struct prefix *)&p, bgp_info);
      else
	nlri_delete (peer_self, (struct prefix *)&p);
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

  s = zebra->ibuf;

  lim = stream_pnt (s) + length;

  /* Fetch type and nexthop first. */
  type = stream_getc (s);
  flags = stream_getc (s);
  memcpy (&nexthop, stream_pnt (s), sizeof (struct in6_addr));
  stream_forward (s, sizeof (struct in6_addr));

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
      memcpy (&p.prefix, stream_pnt (s), size);
      stream_forward (s, size);

      bgp_info = bgp_info_new ();
      bgp_info->type = type;
      bgp_info->peer = peer_self;
      bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	nlri_process ((struct prefix *)&p, bgp_info);
      else
	nlri_delete (peer_self, (struct prefix *)&p);
    }
  return 0;
}
#endif /* HAVE_IPV6 */

/* Redistribute static */
void
bgp_zebra_redistribute (int type)
{
  if (zebra->redist[type])
    return;

  zebra->redist[type] = 1;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zebra->sock, type);
}

void
bgp_zebra_no_redistribute (int type)
{
  if (! zebra->redist[type])
    return;

  zebra->redist[type] = 0;

  if (zebra->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zebra->sock, type);
}

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
  int ret;
  struct interface *ifp = NULL;
  struct interface *direct = NULL;

  memset (nexthop, 0, sizeof (struct bgp_nexthop));

  if (!local)
    return -1;
  if (!remote)
    return -1;

  if (local->sa.sa_family == AF_INET)
    ifp = if_lookup_by_ipv4 (&local->sin.sin_addr);
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
      nexthop->v4 = local->sin.sin_addr;

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
#endif /* HAVE_IPV6 */

  return 0;
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
		return ifp->index;
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

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_BGP])
    return;

  if (bgp_peer_sort (info->peer) == BGP_PEER_IBGP)
    flags |= ZEBRA_FLAGS_INTERNAL;

  if (p->family == AF_INET)
    {
      zebra_ipv4_add (zebra->sock, ZEBRA_ROUTE_BGP, flags,
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
	    ifindex = info->peer->nexthop.ifp->index;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	if (info->peer->ifname)
	  ifindex = if_nametoindex (info->peer->ifname);

      zebra_ipv6_add (zebra->sock, ZEBRA_ROUTE_BGP, flags,
		      (struct prefix_ipv6 *)p, nexthop, ifindex);
    }
#endif /* HAVE_IPV6 */
}

void
bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info)
{
  int flags = 0;

  if (zebra->sock < 0)
    return;

  if (! zebra->redist[ZEBRA_ROUTE_BGP])
    return;

  if (bgp_peer_sort (info->peer) == BGP_PEER_IBGP)
    flags |= ZEBRA_FLAGS_INTERNAL;

  if (p->family == AF_INET)
    zebra_ipv4_delete (zebra->sock, ZEBRA_ROUTE_BGP, flags,
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
	    ifindex = info->peer->nexthop.ifp->index;
	}

      if (nexthop == NULL)
	return;

      if (IN6_IS_ADDR_LINKLOCAL (nexthop) && ! ifindex)
	if (info->peer->ifname)
	  ifindex = if_nametoindex (info->peer->ifname);

      zebra_ipv6_delete (zebra->sock, ZEBRA_ROUTE_BGP, flags,
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
  int ret;

  vty->node = ZEBRA_NODE;

  /* Set router zebra is enabled. */
  zebra->enable = 1;

  /* If already has socket then return. */
  if (zebra->sock >= 0)
    {
      vty_out (vty, "already connected to zebra\r\n");
      return CMD_WARNING;
    }

  /* Connect to zebra. */
  ret = zebra_create (zebra);

  if (ret < 0)
    {
      vty_out (vty, "Can't connect to zebra\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")
{
  zebra->enable = 0;
  return CMD_SUCCESS;
}

DEFUN (redistribute_bgp,
       redistribute_bgp_cmd,
       "redistribute bgp",
       "Redistribute control\n"
       "BGP route\n")
{
  zebra->redist[ZEBRA_ROUTE_BGP] = 1;
  return CMD_SUCCESS;
}

DEFUN (no_redistribute_bgp,
       no_redistribute_bgp_cmd,
       "no redistribute bgp",
       NO_STR
       "Redistribute control\n"
       "BGP route\n")
{
  zebra->redist[ZEBRA_ROUTE_BGP] = 0;
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
int
zebra_config_write (struct vty *vty)
{
  if (! zebra->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zebra->redist[ZEBRA_ROUTE_BGP])
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

/* Start related zebra thread. */
void
zebra_start ()
{
  zebra_create (zebra);
}

void
zebra_init (int enable)
{
  /* Allocate zebra structure. */
  zebra = zebra_new ();

  /* Set default values. */
  zebra->enable = 1;
  zebra->sock = -1;
  zebra->redist_default = ZEBRA_ROUTE_BGP;
  zebra->redist[ZEBRA_ROUTE_BGP] = 1;

  /* Set call back functions. */
  zebra->ipv4_route_add = zebra_read_ipv4;
  zebra->ipv4_route_delete = zebra_read_ipv4;
#ifdef HAVE_IPV6
  zebra->ipv6_route_add = zebra_read_ipv6;
  zebra->ipv6_route_delete = zebra_read_ipv6;
#endif /* HAVE_IPV6 */
  zebra->get_all_interface = bgp_get_all_interface;

  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);

  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &redistribute_bgp_cmd);
  install_element (ZEBRA_NODE, &no_redistribute_bgp_cmd);

  /* Interface related init. */
  if_init ();
}
