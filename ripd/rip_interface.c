/* Interface related function for RIP.
   Copyright (C) 1997 Kunihiro Ishiguro

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
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "ripd.h"
#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"
#include "if.h"
#include "ifa.h"
#include "zebra.h"
#include "route.h"
#include "memory.h"

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

/* Request routes at all interfaces. */
rip_request_all ()
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    rip_request (getdata (node), rip->sock);
}

/* Ask routes at specific interface.  This will be executed when
 interface goes up. */
rip_request (struct interface *ifp, int sock)
{
  int size;
#define REQUEST_BUF 256
  char buf[REQUEST_BUF];
  struct sockaddr_in sin;

  size = rip_make_request (buf, rip->version);
  if (size > REQUEST_BUF)
    {
      log_warn ("rip request packet size overflow\n");
      exit (1);
    }

  if (! if_is_up (ifp))
    return;

  /* In default ripd doesn't send RIP_REQUEST into LOOPBACK interface. */
  if (if_is_loopback (ifp))
    return;

  if (rip->multicast && if_is_multicast (ifp)) 
    {
      listnode node;
      
      log ("multicast RIP request at %s\n", ifp->name);

      for (node = listhead (ifp->addr); node; nextnode (node))
	{
	  struct if_addr *ifa;
	  struct in_addr addr;

	  ifa = getdata (node);

	  if (ifa->ifa_addr.sa.sa_family != AF_INET)
	    continue;

	  addr = sockunion_get_in_addr (&ifa->ifa_addr);

	  if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF,
			  &addr, sizeof(addr)) < 0) 
	    {
	      perror ("setsockopt");
	      return;
	    }
	}
    
      bzero (&sin, sizeof (struct sockaddr_in));
      sin.sin_addr.s_addr = htonl (INADDR_RIP_GROUP);
      rip_udp_send (sock, buf, size, &sin);
    }
  else if (ifp->flags & IFF_BROADCAST || ifp->flags & IFF_POINTOPOINT) 
    {
      log ("broadcast or pointopoing RIP request at %s\n", ifp->name);

      /* sin.sin_addr = sockunion_get_in_addr (&ifa->ifa_addr); */
      rip_udp_send (sock, buf, size, &sin);
    }
}

/* Join the interface to multicast group. */
rip_multicast_if (int sock, struct interface *ifp)
{
  listnode node;

  for (node = ifp->addr->head; node; nextnode (node))
    {
      struct if_addr *ifa;
      struct in_addr addr;

      ifa = getdata (node);

      if (ifa->ifa_addr.sa.sa_family != AF_INET)
	continue;
      
      addr = sockunion_get_in_addr (&ifa->ifa_addr);

      ipv4_multicast_join (sock, htonl (INADDR_RIP_GROUP), addr);
    }
}

/* multicast packet recieve socket */
int
rip_multicast_socket (int sock)
{
  listnode node;
  struct interface *ifp;


  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      
      if (if_is_up (ifp) && if_is_multicast (ifp))
	{
	  log ("Multicast enabled at %s\n", ifp->name);
	  rip_multicast_if (sock, ifp);
	}
    }
}

/* Is this address belong to me ? */
if_check_address (struct in_addr addr)
{
  listnode node;
  struct interface *ifp;
  struct if_addr *ifa;

  for (node = listhead (iflist); node; nextnode (node))
    {
      int ret;

      ifp = getdata (node);

      ret = ifa_same_address (ifp, addr);
      if (ret)
	return ret;
    }
  return 0;
}

struct interface *
if_lookup_address (struct in_addr addr)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      int ret;

      ifp = getdata (node);

      ret = ifa_lookup_address (ifp, addr);
      if (ret)
	return ifp;
    }
  return NULL;
}

check_hit (struct in_addr net, struct in_addr mask, struct in_addr addr)
{
  return  (ntohl (addr.s_addr) & ntohl (mask.s_addr)) == 
    (ntohl (net.s_addr) & ntohl (mask.s_addr));
}

ifa_lookup_address (struct interface *ifp, struct in_addr addr)
{
  int ret;
  listnode node;
  struct if_addr *ifa;
  struct sockaddr_in *sin;

  for (node = ifp->addr->head; node; nextnode (node))
    {
      ifa = getdata (node);

      sin = &ifa->ifa_addr.sin;

      if (sin->sin_family != AF_INET)
	continue;

      ret = check_hit (sin->sin_addr, ifa->ifa_mask.sin.sin_addr, addr);
      if (ret)
	return 1;
    }

  return 0;
}

ifa_same_address (struct interface *ifp, struct in_addr addr)
{
  int ret;
  listnode node;
  struct if_addr *ifa;
  struct sockaddr_in *sin;

  for (node = ifp->addr->head; node; nextnode (node))
    {
      ifa = getdata (node);

      sin = &ifa->ifa_addr.sin;

      if (sin->sin_family != AF_INET)
	continue;

      ret = memcmp (&sin->sin_addr, &addr, sizeof (struct in_addr));
      if (ret == 0)
	return 1;
    }

  return 0;
}

/* Allocate new address structure. */
struct if_addr *
ifa_new ()
{
  struct if_addr *new = XMALLOC (MTYPE_IF_ADDR, sizeof (struct if_addr));
  bzero (new, sizeof (struct if_addr));
  return new;
}

/* Print if_addr structure. */
void
ifa_print (unsigned long flags, struct if_addr *ifa)
{
  switch (ifa->ifa_addr.sa.sa_family) {
  case AF_INET:
    log ("  inet ");
    sockunion_log (&ifa->ifa_addr);
    log2 (" ");
    sockunion_log (&ifa->ifa_mask);
    log2 (" ");
    if (flags & IFF_BROADCAST)
      sockunion_log (&ifa->ifa_dest);
    log2 ("\n");
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    log ("  inet6 ");
    sockunion_log (&ifa->ifa_addr);
    log2 ("/%d\n", ip6_masklen (ifa->ifa_mask.sin6.sin6_addr));
    break;
#endif /* HAVE_IPV6 */
  default:
    break;
  }
}

ifa_lookup_by_prefix (struct interface *ifp, struct prefix_in *pin)
{
  struct if_addr *ifa;
  listnode node;

  for (node = ifp->addr->head; node; nextnode (node))
    {
      struct prefix_in dummy;
      ifa = getdata (node);

      if (ifa->ifa_addr.sa.sa_family != AF_INET)
	continue;

      dummy.prefix = ifa->ifa_addr.sin.sin_addr;
      dummy.mask = ip_masklen (ifa->ifa_mask.sin.sin_addr);
      masked_route_in (&dummy);
      if (dummy.prefix.s_addr == pin->prefix.s_addr &&
	  dummy.mask == pin->mask)
	return 1;
    }
  return 0;
}

struct interface *
if_lookup_by_prefix (struct prefix_in *pin)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifa_lookup_by_prefix (ifp, pin))
	return ifp;
    }
  return NULL;
}

/* Get interface information from zebra daemon. */
zebra_get_interface (int sock, u_int32_t length)
{
  u_char *pnt;
  u_char *start;
  u_char *lim;
  int nbyte;
  struct interface *ifp;
  struct if_addr *ifa;
  u_int32_t ifa_count;

  /* Allocate read buffer. */
  pnt = start = (u_char *) malloc (length + 1);
  nbyte = readn (sock, pnt, length - 8);

  if (nbyte == 0) 
    {
      fprintf (stderr, "connection closed\n");
      return;
    }

  lim = (caddr_t)pnt + length - 8;
  while (pnt < lim) 
    {
      char tmpnam [INTERFACE_NAMSIZ];

      /* Get interface's name. */
      strncpy (tmpnam, pnt, INTERFACE_NAMSIZ);
      pnt += INTERFACE_NAMSIZ;

      ifp = if_lookup_by_name (tmpnam);
      if (ifp == NULL)
	{
	  ifp = (struct interface *) if_new ();
	  strncpy (ifp->name, tmpnam, INTERFACE_NAMSIZ);
	}

      /* Get interface's index. */
      ld_1byte (ifp->index, pnt);
      ld_4byte (ifp->flags, pnt);
      ld_4byte (ifp->metric, pnt);
      ld_4byte (ifp->mtu, pnt);

      /* Get interface's address count. */
      ld_4byte (ifa_count, pnt);
      while (ifa_count--) 
	{
	  ifa = (struct if_addr *) ifa_new (ifp);

	  list_add_node (ifp->addr, ifa);

	  memcpy (&ifa->ifa_addr, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (&ifa->ifa_mask, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (&ifa->ifa_dest, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  
	  ifa_rip_insert (ifa, ifp);
	}
    }
  free (start);
  if_dump_all ();
}

/* Insert interface address route into rip's routing table. */
ifa_rip_insert (struct if_addr *ifa, struct interface *ifp)
{
  if (ifa->ifa_addr.sa.sa_family == AF_INET)
    {
      struct prefix_in *pin;

      pin = prefix_in_new ();
      pin->type = ZEBRA_ROUTE_CONNECT;
      pin->prefix = ifa->ifa_addr.sin.sin_addr;
      pin->mask = ip_masklen (ifa->ifa_mask.sin.sin_addr);
      pin->gate.info = ifp;
      pin->fib = 1;

      /* We need which interface is this route belongs to. */
      rip_add_ifa (pin);
    }
}

/* Add prefix into rib. */
rip_add_ifa (struct prefix_in *pin)
{
  extern struct radix_top *rip_radix;

  /* Make sure route masked. */
  masked_route_in (pin);

  /* Make gateway structure. */
  if (pin->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;

      ifp = (struct interface *) pin->gate.info;
      log ("connected route %s/%d", inet_ntoa (pin->prefix), pin->mask);
      log2 (" directly conncted to %s\n", ifp->name);
    }

  radix_add (rip_radix, (struct prefix *) pin);
}

/* Called when interface structure allocated. */
rip_if_new_hook (struct interface *ifp)
{
  ifp->if_data = ri_new ();
}


DEFUN (ip_rip_receive,
       ip_rip_receive_cmd,
       "ip rip receive version NUMBER",
       "Set interface's specific RIP version control.")
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
       "Don't recieve RIP packet from this interface.")
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
       "Set default to RIP packet receive method.")
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
       "Don't advertize default route.")
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
       "Don't advertize default route.")
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
       "Accept default route.")
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
       "Don't accept default route.")
{
  struct interface *ifp;
  struct rip_interface *ri;

  ifp = (struct interface *)vty->index;
  ri = ifp->if_data;

  ri->ri_default_receive = RIP_DEFAULT_ACCEPT_UNSPEC;
  return CMD_SUCCESS;
}

/* Write rip configuration of each interface. */
interface_config_write (struct vty *vty, vector v)
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
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

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
