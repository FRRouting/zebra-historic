/*
 * Interface related function for RIP.
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

#include "zebra/zebra.h"
#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "network.h"
#include "table.h"
#include "roken.h"
#include "log.h"
#include "stream.h"
#include "thread.h"
#include "zclient.h"
#include "filter.h"

#include "zebra/connected.h"
#include "ripd/ripd.h"
#include "ripd/rip_debug.h"

/* RIP enabled network vector. */
vector rip_enable_vector;

/* RIP enabled interface table. */
struct route_table *rip_enable_table;

/* RIP neighbor address table. */
struct route_table *rip_neighbor_table;

int rip_enable_apply_all ();

static struct message ri_version_msg[] = 
{
  {RI_RIP_UNSPEC,          NULL},
  {RI_RIP_VERSION_1,       "version 1"},
  {RI_RIP_VERSION_2,       "version 2"},
  {RI_RIP_VERSION_1_AND_2, "version 1 2"},
  {RI_RIP_NONE,            "none"},
};

static struct message ri_split_horizon_msg[] = 
{
  {RI_RIP_SPLIT_HORIZON_UNSPEC,   NULL},
  {RI_RIP_SPLIT_HORIZON_NONE,     "none"},
  {RI_RIP_SPLIT_HORIZON,          ""},
  {RI_RIP_SPLIT_HORIZON_POISONED, "poisoned"},
};

/* Allocate new RIP's interface configuration. */
struct rip_interface *
rip_interface_new ()
{
  struct rip_interface *ri;

  ri = XMALLOC (MTYPE_IF, sizeof (struct rip_interface));
  bzero (ri, sizeof (struct rip_interface));
  ri->ri_split_horizon = RI_RIP_SPLIT_HORIZON_UNSPEC;
  ri->enable = 0;

#ifdef RIP_ADVANCED
  ri->ri_send = RI_RIP_UNSPEC;
  ri->ri_receive = RI_RIP_UNSPEC;
  ri->ri_default_send = RIP_DEFAULT_ADVERTISE_UNSPEC;
  ri->ri_default_receive = RIP_DEFAULT_ACCEPT_UNSPEC;
#endif /* RIP_ADVANCED */

  return ri;
}

/* Make RIP request packet. */
int
rip_make_request (struct stream *s, int version)
{
  /*
   * RIP's query packet is made from
   *  command = RIP_REQUEST
   *  family  = AF_UNSPEC
   *  metric  = 16 (RIP_METRIC_INFINITY)
   */
  stream_putc (s, RIP_REQUEST);	/* command */
  stream_putc (s, version);		/* version */
  stream_putw (s, 0);		/* domain */
  stream_putw (s, AF_UNSPEC);	/* family */
  stream_putw (s, 0);		/* tag */
  stream_putl (s, 0);		/* prefix */
  stream_putl (s, 0);		/* netmask */
  stream_putl (s, 0);		/* nexthop */
  stream_putl (s, RIP_METRIC_INFINITY); /* metric */

  /* Return size of the packet. */
  return s->endp;
}

/* Ask routes at specific interface.  This will be executed when
 interface goes up. */
void
rip_request_interface (struct interface *ifp, int sock)
{
  int size;
#define REQUEST_BUF 256
  struct sockaddr_in sin;
  struct stream *s;

  if (!if_is_up (ifp))
    return;

  /* In default ripd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  s = stream_new (RIP_REQUEST_PACKET_SIZE);

  size = rip_make_request (s, rip.version);

  if (size > RIP_REQUEST_PACKET_SIZE)
    {
      zlog (NULL, LOG_WARNING, "RIP request packet size overflow");
      exit (1);
    }

  if ((rip.multicast == RIP_MULTICAST) && if_is_multicast (ifp)) 
    {
      listnode node;
      
      if (IS_RIP_DEBUG_EVENT)
	zlog (NULL, LOG_INFO, "multicast RIP request at %s", ifp->name);

      for (node = listhead (ifp->connected); node; nextnode (node))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;
	  struct in_addr addr;

	  connected = getdata (node);
	  p = (struct prefix_ipv4 *) connected->address;

	  if (p->family != AF_INET)
	    continue;

	  addr = p->prefix;

	  if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF,
			  &addr, sizeof(addr)) < 0) 
	    {
	      perror ("setsockopt");
	      return;
	    }
	}
    
      bzero (&sin, sizeof (struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_port = htons (RIP_PORT_DEFAULT);
      sin.sin_addr.s_addr = htonl (INADDR_RIP_GROUP);

      if (IS_RIP_DEBUG_EVENT)
	zlog_info ("send RIP request to %s", inet_ntoa (sin.sin_addr));

      rip_udp_send (sock, STREAM_DATA (s), size, &sin);
    }

  if (if_is_pointopoint (ifp) || 
      (! if_is_multicast (ifp) && if_is_broadcast (ifp)))
    {
      listnode cnode;

      if (IS_RIP_DEBUG_EVENT)
	zlog (NULL, LOG_INFO, "broadcast RIP request at %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;

	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->destination;

	  bzero (&sin, sizeof (struct sockaddr_in));
	  sin.sin_port = htons (RIP_PORT_DEFAULT);
	  sin.sin_addr = p->prefix;

	  if (IS_RIP_DEBUG_EVENT)
	    zlog_info ("send RIP request to %s", inet_ntoa (sin.sin_addr));
	  
	  rip_udp_send (sock, STREAM_DATA (s), size, &sin);
	}
    }
  stream_free (s);
}

void
rip_request_neighbor (struct in_addr addr)
{
  int size;
  struct sockaddr_in sin;
  struct stream *s;

  s = stream_new (RIP_REQUEST_PACKET_SIZE);

  size = rip_make_request (s, rip.version);

  if (size > RIP_REQUEST_PACKET_SIZE)
    {
      zlog (NULL, LOG_WARNING, "RIP request packet size overflow");
      exit (1);
    }
  
  bzero (&sin, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (RIP_PORT_DEFAULT);
  sin.sin_addr = addr;

  rip_udp_send (rip.sock, STREAM_DATA (s), size, &sin);

  stream_free (s);
}

/* Request routes at all interfaces. */
void
rip_request_neighbor_all ()
{
  struct route_node *rp;

  if (IS_RIP_DEBUG_EVENT)
    zlog_info ("RIP request to the all neighbor");

  /* Send request to all neighbor. */
  for (rp = route_top (rip_neighbor_table); rp; rp = route_next (rp))
    if (rp->info)
      rip_request_neighbor (rp->p.u.prefix4);
}

/* Join to the rip version 2 multicast group. */
int
ipv4_multicast_join (int sock, struct in_addr group, struct in_addr ifa)
{
  int ret;
  struct ip_mreq mreq;

  mreq.imr_multiaddr.s_addr = group.s_addr;
  mreq.imr_interface.s_addr = ifa.s_addr;

  ret = setsockopt (sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
		    (char *)&mreq, sizeof (mreq));

  if (ret < 0) 
    zlog (NULL, LOG_INFO, "can't setsockopt IP_ADD_MEMBERSHIP");

  return ret;
}

/* Multicast packet receive socket. */
void
rip_multicast_interface (struct interface *ifp, int sock)
{
  listnode cnode;

  if (if_is_up (ifp) && if_is_multicast (ifp))
    {
      if (IS_RIP_DEBUG_EVENT)
	zlog (NULL, LOG_INFO, "multicast enabled at %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;
	  struct in_addr any;
	      
	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->address;
      
	  if (p->family != AF_INET)
	    continue;
      
	  any.s_addr = htonl (INADDR_RIP_GROUP);
	  ipv4_multicast_join (sock, any, p->prefix);
	}
    }
}

/* Does this address belong to me ? */
int
if_check_address (struct in_addr addr)
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct connected *connected;
	  struct prefix_ipv4 *p;

	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) connected->address;

	  if (p->family != AF_INET)
	    continue;
	  if (IPV4_ADDR_CMP (&p->prefix, &addr) == 0)
	    return 1;
	}
    }
  return 0;
}

/* is this address from a valid neighbor? (RFC2453 - Sec. 3.9.2) */
int
if_valid_neighbor (struct in_addr addr)
{
  listnode node;
  struct connected *connected = NULL;
  struct prefix_ipv4 *p;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix *pxn = NULL; /* Prefix of the neighbor */
	  struct prefix *pxc = NULL; /* Prefix of the connected network */

	  connected = getdata (cnode);

	  if (if_is_pointopoint (ifp))
	    {
	      p = (struct prefix_ipv4 *) connected->address;

	      if (p && p->family == AF_INET)
		{
		  if (IPV4_ADDR_SAME (&p->prefix, &addr))
		    return 1;

		  p = (struct prefix_ipv4 *) connected->destination;
		  if (p && IPV4_ADDR_SAME (&p->prefix, &addr))
		    return 1;
		}
	    }
	  else
	    {
	      p = (struct prefix_ipv4 *) connected->address;

	      if (p->family != AF_INET)
		continue;

	      pxn = prefix_new();
	      pxn->family = AF_INET;
	      pxn->prefixlen = 32;
	      pxn->u.prefix4 = addr;
	      
	      pxc = prefix_new();
	      prefix_copy(pxc, (struct prefix *) p);
	      apply_mask( (struct prefix_ipv4 *) pxc);
	  
	      if (prefix_match (pxc, pxn)) 
		{
		  prefix_free (pxn);
		  prefix_free (pxc);
		  return 1;
		}
	      prefix_free(pxc);
	      prefix_free(pxn);
	    }
	}
    }
  return 0;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_address (struct in_addr src)
{
  listnode node;
  struct prefix_ipv4 addr;
  
  addr.family = AF_INET;
  addr.prefix = src;
  addr.prefixlen = IPV4_MAX_BITLEN;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead(ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix *p;
	  struct connected *connected;

	  connected = getdata (cnode);

	  if (if_is_pointopoint (ifp))
	    {
	      p = connected->address;

	      if (p && p->family == AF_INET)
		{
		  if (IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;

		  p = connected->destination;
		  if (p && IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;
		}
	    }
	  else
	    {
	      p = connected->address;

	      if (p->family == AF_INET)
		{
		  if (prefix_match (p, (struct prefix *) &addr))
		    return ifp;
		}
	    }
	}
    }
  return NULL;
}

/* Add prefix into rib. */
void
rip_connected_add (struct interface *ifp, 
		   struct connected *connected)
{
  struct prefix_ipv4 p;
  struct rip_info *rinfo;

  memcpy (&p, connected->address, sizeof (struct prefix_ipv4));
  apply_mask (&p);

  if (IS_RIP_DEBUG_ZEBRA)
    zlog_info ("connected route %s/%d directly connect to %s",
	       inet_ntoa (p.prefix), p.prefixlen, ifp->name);

  rinfo = rip_info_new ();
  rinfo->pref = -10;
  rinfo->fib = 1;
  rinfo->type = ZEBRA_ROUTE_CONNECT;
  rinfo->ifp = ifp;
  
  /* Register route to rip table. */
  rip_add_route (&p, rinfo, NULL, ifp);
}

/* Called when new interface is added. */
void
rip_enable_interface (struct interface *ifp)
{
  struct rip_interface *ri;

  /* Check is this interface rip enabled or not. */
  rip_enable_apply_all ();

  ri = ifp->if_data;

  if (ri->enable)
    {
      /* Join to multicast group. */
      rip_multicast_interface (ifp, rip.sock);

      /* Send RIP request to the interface. */
      rip_request_interface (ifp, rip.sock);
    }
}

/* Get all interface information. */
void
rip_zebra_get_interface (int command, struct zebra *zebra, u_int16_t length)
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
	  int family;
	  int plen;

	  connected = connected_new ();

	  p = prefix_new ();
	  family = p->family = stream_getc (s);

	  plen = prefix_blen (p);
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);
	  p->prefixlen = stream_getc (s);
	  connected->address = p;

	  p = prefix_new ();
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  p->family = family;
	  stream_forward (s, plen);

	  connected->destination = p;

	  connected_add (ifp, connected);

	  p = connected->address;
#if 0
	  if (p->family == AF_INET)
	    rip_connected_add (ifp, connected);
#endif /* 0 */
	}
      rip_enable_interface (ifp);
    }
  distribute_apply_all ();

  rip_request_neighbor_all ();
}

int
config_write_rip_network (struct vty *vty)
{
  int i;
  char *ifname;
  struct route_node *node;

  /* Network type RIP enable interface statement. */
  for (node = route_top (rip_enable_table); node; node = route_next (node))
    if (node->info)
      vty_out (vty, " network %s/%d%s", inet_ntoa (node->p.u.prefix4),
	       node->p.prefixlen, VTY_NEWLINE);

  /* Interface name RIP enable statement. */
  for (i = 0; i < vector_max (rip_enable_vector); i++)
    if ((ifname = vector_slot (rip_enable_vector, i)) != NULL)
      vty_out (vty, " network %s%s", ifname, VTY_NEWLINE);

  /* RIP neighbors listing. */
  for (node = route_top (rip_neighbor_table); node; node = route_next (node))
    if (node->info)
      vty_out (vty, " neighbor %s%s", 
	       inet_ntoa (node->p.u.prefix4), VTY_NEWLINE);

  return 0;
}

int
rip_enable_network_lookup (struct interface *ifp)
{
  listnode listnode;
  struct connected *connected;

  for (listnode = listhead (ifp->connected); listnode; nextnode (listnode))
    if ((connected = getdata (listnode)) != NULL)
      {
	struct prefix *p; 
	struct route_node *node;

	p = connected->address;

	if (p->family == AF_INET)
	  {
	    node = route_node_match (rip_enable_table, p);
	    if (node)
	      {
		route_unlock_node (node);
		return 1;
	      }
	  }
      }
  return -1;
}

/* Lookup function. */
int
rip_enable_vector_lookup (char *ifname)
{
  int i;
  char *str;

  for (i = 0; i < vector_max (rip_enable_vector); i++)
    if ((str = vector_slot (rip_enable_vector, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

int
rip_enable_apply_all ()
{
  int ret;
  struct interface *ifp;
  struct rip_interface *ri = NULL;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->if_data;

      ret = rip_enable_vector_lookup (ifp->name);
      if (ret >= 0)
	ri->enable = 1;
      else
	{
	  ret = rip_enable_network_lookup (ifp);
	  if (ret >= 0)
	    ri->enable = 1;
	  else
	    ri->enable = 0;
	}
    }
  return 0;
}

/* Add RIPng enable network. */
void
rip_enable_network_add (struct prefix_ipv4 *p)
{
  struct route_node *node;

  node = route_node_get (rip_enable_table, (struct prefix *) p);
  if (node->info)
    {
      route_unlock_node (node);
      return;
    }
  else
    node->info = "enabled";

  rip_enable_apply_all ();
}

/* Add inteface to rip_enable_vectro. */
void
rip_enable_vector_add (char *ifname)
{
  int ret;

  ret = rip_enable_vector_lookup (ifname);
  if (ret >= 0)
    return;

  vector_set (rip_enable_vector, strdup (ifname));

  rip_enable_apply_all ();
}

/* Add new RIP neighbor to the neighbor tree. */
int
rip_neighbor_add (struct prefix_ipv4 *p)
{
  struct route_node *node;

  node = route_node_get (rip_neighbor_table, (struct prefix *) p);

  if (node->info)
    return -1;

  node->info = rip_neighbor_table;

  return 0;
}

/* Delete RIP neighbor from the neighbor tree. */
int
rip_neighbor_delete (struct prefix_ipv4 *p)
{
  struct route_node *node;

  /* Lock for look up. */
  node = route_node_lookup (rip_neighbor_table, (struct prefix *) p);

  if (! node)
    return -1;
  
  node->info = NULL;

  /* Unlock lookup lock. */
  route_unlock_node (node);

  /* Unlock real neighbor information lock. */
  route_unlock_node (node);

  return 0;
}


/* RIP enable network or interface configuration. */
DEFUN (rip_network,
       rip_network_cmd,
       "network IPV4_ADDR",
       "Set announced network for RIP\n"
       "IP Address\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret)
    rip_enable_network_add (&p);
  else
    rip_enable_vector_add (argv[0]);

  return CMD_SUCCESS;
}


/* RIP neighbor configuration set. */
DEFUN (rip_neighbor,
       rip_neighbor_cmd,
       "neighbor A.B.C.D",
       "RIP neighbor router address specification\n"
       "Address of the neighbor router\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (! ret)
    {
      vty_out (vty, "Please specify address by A.B.C.D\r\n");
      return CMD_WARNING;
    }

  rip_neighbor_add (&p);
  
  return CMD_SUCCESS;
}

/* RIP neighbor configuration unset. */
DEFUN (no_rip_neighbor,
       no_rip_neighbor_cmd,
       "no neighbor A.B.C.D",
       NO_STR
       "RIP neighbor router address specification\n"
       "Address of the neighbor router\n")
{
  int ret;
  struct prefix_ipv4 p;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (! ret)
    {
      vty_out (vty, "Please specify address by A.B.C.D\r\n");
      return CMD_WARNING;
    }

  rip_neighbor_delete (&p);
  
  return CMD_SUCCESS;
}

DEFUN (ip_rip_receive_version,
       ip_rip_receive_version_cmd,
       "ip rip receive version (1|2)",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1. */
  if (atoi (argv[0]) == 1)
    {
      ri->ri_receive = RI_RIP_VERSION_1;
      return CMD_SUCCESS;
    }
  if (atoi (argv[0]) == 2)
    {
      ri->ri_receive = RI_RIP_VERSION_2;
      return CMD_SUCCESS;
    }
  return CMD_WARNING;
}

DEFUN (ip_rip_receive_version_1,
       ip_rip_receive_version_1_cmd,
       "ip rip receive version 1 2",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1 and 2. */
  ri->ri_receive = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_receive_version_2,
       ip_rip_receive_version_2_cmd,
       "ip rip receive version 2 1",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1 and 2. */
  ri->ri_receive = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_receive_version,
       no_ip_rip_receive_version_cmd,
       "no ip rip receive version",
       NO_STR
       IP_STR
       "RIP configuration\n"
       "Set interface's receive RIP version control\n"
       "RIP version\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_receive = RI_RIP_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_send_version,
       ip_rip_send_version_cmd,
       "ip rip send version (1|2)",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1. */
  if (atoi (argv[0]) == 1)
    {
      ri->ri_send = RI_RIP_VERSION_1;
      return CMD_SUCCESS;
    }
  if (atoi (argv[0]) == 2)
    {
      ri->ri_send = RI_RIP_VERSION_2;
      return CMD_SUCCESS;
    }
  return CMD_WARNING;
}

DEFUN (ip_rip_send_version_1,
       ip_rip_send_version_1_cmd,
       "ip rip send version 1 2",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 1\n"
       "RIP version 2\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1 and 2. */
  ri->ri_send = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (ip_rip_send_version_2,
       ip_rip_send_version_2_cmd,
       "ip rip send version 2 1",
       "IP Information\n"
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n"
       "RIP version 2\n"
       "RIP version 1\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  /* Version 1 and 2. */
  ri->ri_send = RI_RIP_VERSION_1_AND_2;
  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_send_version,
       no_ip_rip_send_version_cmd,
       "no ip rip send version",
       NO_STR
       IP_STR
       "RIP configuration\n"
       "Set interface's send RIP version control\n"
       "RIP version\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_send = RI_RIP_UNSPEC;
  return CMD_SUCCESS;
}

/* Write rip configuration of each interface. */
int
interface_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct rip_interface *ri;

      ifp = getdata (node);
      ri = ifp->if_data;

      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);

      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc, VTY_NEWLINE);

      if (ri->ri_send != RI_RIP_UNSPEC)
	vty_out (vty, " ip rip send %s%s",
		 LOOKUP (ri_version_msg, ri->ri_send), VTY_NEWLINE);

      if (ri->ri_receive != RI_RIP_UNSPEC)
	vty_out (vty, " ip rip receive %s%s",
		 LOOKUP (ri_version_msg, ri->ri_receive), VTY_NEWLINE);

#ifdef RIP_ADVANCD
      if (ri->ri_default_send != RIP_DEFAULT_ADVERTISE_UNSPEC)
	vty_out (vty, " advertize default%s", VTY_NEWLINE);

      if (ri->ri_default_receive != RIP_DEFAULT_ACCEPT_UNSPEC)
	vty_out (vty, " accept default%s", VTY_NEWLINE);
#endif /* RIP_ADVANCED */

      if (ri->ri_split_horizon != RI_RIP_SPLIT_HORIZON_UNSPEC)
	vty_out (vty, " split horizon %s%s", 
		 LOOKUP (ri_split_horizon_msg, ri->ri_split_horizon),
		 VTY_NEWLINE);

      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Called when interface structure allocated. */
int
rip_interface_new_hook (struct interface *ifp)
{
  ifp->if_data = rip_interface_new ();
  return 0;
}

/* Allocate and initialize interface vector. */
void
rip_if_init ()
{
  /* Default initial size of interface vector. */
  if_init();
  if_add_hook (IF_NEW_HOOK, rip_interface_new_hook);

  /* RIP network init. */
  rip_enable_vector = vector_init (1);
  rip_enable_table = route_table_init ();

  rip_neighbor_table = route_table_init ();

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  /* Install interface's commands. */
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

  install_element (RIP_NODE, &rip_neighbor_cmd);
  install_element (RIP_NODE, &no_rip_neighbor_cmd);

  install_element (INTERFACE_NODE, &ip_rip_send_version_cmd);
  install_element (INTERFACE_NODE, &ip_rip_send_version_1_cmd);
  install_element (INTERFACE_NODE, &ip_rip_send_version_2_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_send_version_cmd);

  install_element (INTERFACE_NODE, &ip_rip_receive_version_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_version_1_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_version_2_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_receive_version_cmd);

  install_element (RIP_NODE, &rip_network_cmd);
}
