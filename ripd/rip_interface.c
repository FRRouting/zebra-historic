/*
 * $Id: rip_interface.c,v 1.85 1999/02/22 12:15:39 developer Exp $
 *
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

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "memory.h"
#include "buffer.h"
#include "network.h"
#include "table.h"
#include "roken.h"
#include "log.h"

#include "zebra/zebra.h"
#include "zebra/connected.h"
#include "ripd/ripd.h"

/* Global rip structure. */
extern struct rip *rip;

static struct message ri_version_msg[] = 
{
  {RI_RIP_UNSPEC,          NULL},
  {RI_RIP_VERSION_1,       "version 1"},
  {RI_RIP_VERSION_2,       "version 2"},
  {RI_RIP_VERSION_1_AND_2, "version 1_and_2"},
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
ri_new ()
{
  struct rip_interface *ri;

  ri = XMALLOC (MTYPE_IF, sizeof (struct rip_interface));
  bzero (ri, sizeof (struct rip_interface));
  ri->ri_send = RI_RIP_UNSPEC;
  ri->ri_receive = RI_RIP_UNSPEC;
  ri->ri_split_horizon = RI_RIP_SPLIT_HORIZON_UNSPEC;
  ri->ri_default_send = RIP_DEFAULT_ADVERTISE_UNSPEC;
  ri->ri_default_receive = RIP_DEFAULT_ACCEPT_UNSPEC;
  return ri;
}

/* Ask routes at specific interface.  This will be executed when
 interface goes up. */
void
rip_request (struct interface *ifp, int sock)
{
  int size;
#define REQUEST_BUF 256
  char buf[REQUEST_BUF];
  struct sockaddr_in sin;

  size = rip_make_request (buf, rip->version);
  if (size > REQUEST_BUF)
    {
      zlog (NULL, LOG_WARNING, "RIP request packet size overflow");
      exit (1);
    }

  if (!if_is_up (ifp))
    return;

  /* In default ripd doesn't send RIP_REQUEST to the loopback interface. */
  if (if_is_loopback (ifp))
    return;

  if ((rip->multicast == RIP_MULTICAST) && if_is_multicast (ifp)) 
    {
      listnode node;
      
      zlog (NULL, LOG_INFO, "multicast RIP request at %s", ifp->name);

      for (node = listhead (ifp->connected); node; nextnode (node))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;
	  struct in_addr addr;

	  connected = getdata (node);
	  p = (struct prefix_ipv4 *) &connected->address;

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

      rip_udp_send (sock, buf, size, &sin);
    }
  else if (if_is_broadcast (ifp) || if_is_pointopoint (ifp)) 
    {
      listnode cnode;

      zlog (NULL, LOG_INFO, "broadcast RIP request at %s", ifp->name);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix_ipv4 *p;
	  struct connected *connected;

	  connected = getdata (cnode);
	  p = (struct prefix_ipv4 *) &connected->destination;

	  bzero (&sin, sizeof (struct sockaddr_in));
	  sin.sin_port = htons (RIP_PORT_DEFAULT);
	  sin.sin_addr = p->prefix;

	  rip_udp_send (sock, buf, size, &sin);
	}
    }
}

/* Request routes at all interfaces. */
void
rip_request_all ()
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    rip_request (getdata (node), rip->sock);
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

/* Multicast packet recieve socket. */
void
rip_multicast_enable (int sock)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      
      if (if_is_up (ifp) && if_is_multicast (ifp))
	{
	  listnode cnode;

	  zlog (NULL, LOG_INFO, "Multicast enabled at %s", ifp->name);

	  for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	    {
	      struct prefix_ipv4 *p;
	      struct connected *connected;
	      struct in_addr any;
	      
	      connected = getdata (cnode);
	      p = (struct prefix_ipv4 *) &connected->address;
      
	      if (p->family != AF_INET)
		continue;
      
	      any.s_addr = htonl (INADDR_RIP_GROUP);
	      ipv4_multicast_join (sock, any, p->prefix);
	    }
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
	  p = (struct prefix_ipv4 *) &connected->address;

	  if (p->family != AF_INET)
	    continue;
	  if (IPV4_ADDR_CMP (&p->prefix, &addr) == 0)
	    return 1;
	}
    }
  return 0;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_address (struct in_addr addr)
{
  listnode node;
  struct prefix_ipv4 p;
  
  p.family = AF_INET;
  p.prefix = addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  for (node = listhead (iflist); node; nextnode (node))
    {
      listnode cnode;
      struct interface *ifp;

      ifp = getdata (node);

      for (cnode = listhead(ifp->connected); cnode; nextnode (cnode))
	{
	  struct prefix *n;
	  struct connected *connected;

	  connected = getdata (cnode);
	  n = connected->address;

	  if (n->family != AF_INET)
	    continue;

	  if (prefix_match (n, (struct prefix *) &p))
	    return ifp;
	}
    }
  return NULL;
}

/* Add prefix into rib. */
void
rip_connected_add (struct interface *ifp, 
		   struct connected *connected)
{
  struct prefix_ipv4 *p;
  struct rip_info *rinfo;

  p = (struct prefix_ipv4 *) connected->address;

  zlog (NULL, LOG_INFO, "connected route %s/%d directly connect to %s",
	  inet_ntoa (p->prefix), p->prefixlen, ifp->name);

  rinfo = (struct rip_info *) rip_info_new ();
  rinfo->pref = -10;
  rinfo->fib = 1;
  rinfo->type = ZEBRA_ROUTE_CONNECT;
  rinfo->ifp = ifp;
  
  /* Register route to rip table. */
  rip_add_route (p, rinfo, NULL, ifp);
}

/* Get interface information from zebra daemon. */
int
zebra_get_interface (int sock, u_int16_t length)
{
  u_char *pnt;
  u_char *start;
  u_char *lim;
  int nbytes;
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;

  /* Allocate read buffer. */
  pnt = start = XMALLOC (0, length + 1);
  nbytes = readn (sock, pnt, length - 3);

  if (nbytes <= 0) 
    return nbytes;

  lim = (caddr_t)pnt + length - 3;
  while (pnt < lim) 
    {
      char tmpnam[INTERFACE_NAMSIZ];

      /* Get interface's name. */
      strncpy (tmpnam, pnt, INTERFACE_NAMSIZ);
      pnt += INTERFACE_NAMSIZ;

      ifp = if_get_by_name (tmpnam);

      /* Get interface's index. */
      GETC (ifp->index, pnt);
      GETL (ifp->flags, pnt);
      GETL (ifp->metric, pnt);
      GETL (ifp->mtu, pnt);

      /* Get interface's address count. */
      GETL (connected_count, pnt);
      while (connected_count--) 
	{
	  struct prefix *p;
	  int plen;

	  connected = connected_new ();

	  p = prefix_new ();
	  GETC (p->family, pnt);
	  plen = prefix_blen (p);
	  memcpy (&p->u.prefix, pnt, plen);
	  pnt += plen;
	  p->prefixlen = *pnt++;
	  connected->address = p;

	  p = prefix_new ();
	  memcpy (&p->u.prefix, pnt, plen);
	  pnt += plen;
	  connected->destination = p;

	  p = connected->address;
	  connected_add (ifp, connected);
	  
	  if (p->family == AF_INET)
	    rip_connected_add (ifp, connected);
	}
    }
  XFREE (0, start);

  /* Return read packet size. */
  return pnt - start;
}

DEFUN (ip_rip_receive,
       ip_rip_receive_cmd,
       "ip rip receive version NUMBER",
       "IP Information\n"
       "Set interface's specific RIP version control\n"
       "\n"
       "\n"
       "\n")
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

DEFUN (ip_rip_receive_none,
       ip_rip_receive_none_cmd,
       "ip rip receive none",
       "IP Information\n"
       "Don't recieve RIP packet from this interface\n"
       "\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_receive = RI_RIP_NONE;
  return CMD_SUCCESS;
}

DEFUN (no_ip_rip_receive,
       no_ip_rip_receive_cmd,
       "no ip rip receive",
       NO_STR
       "IP Information\n"
       "Set default to RIP packet receive method\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_receive = RI_RIP_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (advertize_default,
       advertize_default_cmd,
       "advertize default",
       "Don't advertize default route\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_default_send = RIP_DEFAULT_ADVERTISE;
  return CMD_SUCCESS;
}

DEFUN (no_advertize_default,
       no_advertize_default_cmd,
       "no advertize default",
       NO_STR
       "Don't advertize default route\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;
  
  ri->ri_default_send = RIP_DEFAULT_ADVERTISE_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (accept_default,
       accept_default_cmd,
       "accept default",
       "Accept default route\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_default_receive = RIP_DEFAULT_ACCEPT;
  return CMD_SUCCESS;
}

DEFUN (no_accept_default,
       no_accept_default_cmd,
       "no accept default",
       NO_STR
       "Don't accept default route\n"
       "\n")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_default_receive = RIP_DEFAULT_ACCEPT_UNSPEC;
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

      if (ri->ri_default_send != RIP_DEFAULT_ADVERTISE_UNSPEC)
	vty_out (vty, " advertize default%s", VTY_NEWLINE);

      if (ri->ri_default_receive != RIP_DEFAULT_ACCEPT_UNSPEC)
	vty_out (vty, " accept default%s", VTY_NEWLINE);

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
rip_if_new_hook (struct interface *ifp)
{
  ifp->if_data = ri_new ();
  return 0;
}

/* Allocate and initialize interface vector. */
void
rip_if_init ()
{
  /* Default initial size of interface vector. */
  if_init();
  if_add_hook (IF_NEW_HOOK, rip_if_new_hook);

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  /* Install interface's commands. */
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_cmd);
  install_element (INTERFACE_NODE, &ip_rip_receive_none_cmd);
  install_element (INTERFACE_NODE, &no_ip_rip_receive_cmd);
  install_element (INTERFACE_NODE, &accept_default_cmd);
  install_element (INTERFACE_NODE, &no_accept_default_cmd);
  install_element (INTERFACE_NODE, &advertize_default_cmd);
  install_element (INTERFACE_NODE, &no_advertize_default_cmd);
}
