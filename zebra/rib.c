/* Routing Information Base.
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "rib.h"
#include "route.h"
#include "radix.h"
#include "sockunion.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "if.h"
#include "table.h"
#include "zebra.h"

/* Radix treee for IP version 4 RIB */
struct radix_top *ipv4_rib_radix;

/* Radix treee for IP version 6 RIB */
struct radix_top *ipv6_rib_radix;
struct route_table *ipv6_rib_table;

struct message
{
  int key;
  char *str;
};

/* Route sort characters. */
struct message route_sort_msg[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X"},
  { ZEBRA_ROUTE_KERNEL,  "K"},
  { ZEBRA_ROUTE_CONNECT, "C"},
  { ZEBRA_ROUTE_STATIC,  "S"},
  { ZEBRA_ROUTE_RIP,     "R"},
  { ZEBRA_ROUTE_RIPNG,   "R"},
  { ZEBRA_ROUTE_BGP,     "B"},
  { ZEBRA_ROUTE_RADIX,   "D"},
};

/* Route sort string. */
struct message route_log_msg[] = 
{
  { ZEBRA_ROUTE_SYSTEM,  "system"},
  { ZEBRA_ROUTE_KERNEL,  "kernel"},
  { ZEBRA_ROUTE_CONNECT, "connected"},
  { ZEBRA_ROUTE_STATIC,  "static"},
  { ZEBRA_ROUTE_RIP,     "rip"},
  { ZEBRA_ROUTE_RIPNG,   "ripng"},
  { ZEBRA_ROUTE_BGP,     "bgp"},
  { ZEBRA_ROUTE_RADIX,   "radix"},
};

struct prefix *
rib_delete_in (struct prefix_in *pin)
{
  /* Make sure route masked. */
  apply_mask (pin);
  
  /* Make gateway structure. */
  if (pin->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;

      ifp = (struct interface *) pin->gate.info;
      log ("connected route delete %s/%d", inet_ntoa (pin->prefix), pin->mask);
      log2 (" directly conncted to %s\n", ifp->name);
    }
  else
    {
      log ("%s route delete %s/%d", route_log_msg[pin->type].str,
	   inet_ntoa (pin->prefix), pin->mask);
      log2 (" via %s\n", inet_ntoa (pin->gate.addr));
    }

  return radix_delete (ipv4_rib_radix, (struct prefix *) pin);
}

/* IPv4 route add to rib.  This function convert sockaddr_in structure
   to prefix_in structure. */
rib_add_ipv4 (int type,
	      struct sockaddr_in *dest,
	      struct sockaddr_in *mask,
	      struct sockaddr_in *gate)
{
  struct prefix_in *pin;

  /* Allocate new prefix. */
  pin = prefix_in_new ();

  /* Convert sockaddr_in mask into mask length. */
  if (mask->sin_family == 0)
    pin->mask = 32;
  else
    pin->mask = ip_masklen (mask->sin_addr);

  /* Fetch each value into prefix structure. */
  pin->type = type;
  pin->prefix = dest->sin_addr;
  pin->gate.addr = gate->sin_addr;
  pin->fib = 1;

  /* Push into rib. */
  rib_add_in (pin);
}

/* Add prefix into rib. */
rib_add_in (struct prefix_in *pin)
{
  /* Make sure route masked. */
  apply_mask (pin);

  /* Make gateway structure. */
  if (pin->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;

      ifp = (struct interface *) pin->gate.info;
      log ("connected route add %s/%d", inet_ntoa (pin->prefix), pin->mask);
      log2 (" directly conncted to %s\n", ifp->name);
    }
  else
    {
      log ("%s route add %s/%d", route_log_msg[pin->type].str,
	   inet_ntoa (pin->prefix), pin->mask);
      log2 (" via %s\n", inet_ntoa (pin->gate.addr));
    }

  radix_add (ipv4_rib_radix, (struct prefix *) pin);
}

#ifdef HAVE_IPV6
/* IPv6 route treatment. */
rib_add_ipv6 (int type,
	     struct sockaddr_in6 *dest,
	     struct sockaddr_in6 *mask,
	     struct sockaddr_in6 *gate)
{
  int masklen;
  char buf[BUFSIZ];
  struct prefix_in6 *pin6;

  pin6 = prefix_in6_new ();

  /* Convert sockaddr_in mask into masklen. */
  if (mask->sin6_family == 0)
    pin6->mask = 128;
  else
    pin6->mask = ip6_masklen (mask->sin6_addr);

  pin6->type = type;
  memcpy (&pin6->prefix, &dest->sin6_addr, sizeof (struct in6_addr));
  memcpy (&pin6->gate.addr, &gate->sin6_addr, sizeof (struct in6_addr));
  pin6->fib = 1;

  rib_add_in6 (pin6);
}

/* IPv6 route treatment. */
rib_delete_in6 (struct prefix_in6 *pin6)
{
  int masklen;
  char buf[BUFSIZ];

  masked_route_in6 (&pin6->prefix, pin6->mask);

  /* Make gateway structure. */
  if (pin6->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;

      ifp = (struct interface *) pin6->gate.info;
      log ("connected route delete %s/%d", 
	   inet_ntop (AF_INET6, &pin6->prefix, buf, BUFSIZ), pin6->mask);
      log2 (" directly conncted to %s\n", ifp->name);
    }
  else
    {
      log ("%s route delete %s/%d", route_log_msg[pin6->type].str,
	   inet_ntop (AF_INET6, &pin6->prefix, buf, BUFSIZ), pin6->mask);
      log2 (" via %s\n", inet_ntop (AF_INET6, &pin6->gate.addr, buf, BUFSIZ));
    }

  radix_delete (ipv6_rib_radix, (struct prefix *)pin6);
}

/* IPv6 route treatment. */
rib_add_in6 (struct prefix_in6 *pin6, unsigned int ifindex)
{
  int masklen;
  char buf[INET6_ADDRSTRLEN];

  masked_route_in6 (&pin6->prefix, pin6->mask);

  /* Make gateway structure. */
  if (pin6->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;

      ifp = (struct interface *) pin6->gate.info;
      log ("connected route %s/%d", 
	   inet_ntop (AF_INET6, &pin6->prefix, buf, BUFSIZ), pin6->mask);
      log2 (" directly conncted to %s\n", ifp->name);
    }
  else
    {
      log ("%s route %s/%d", route_log_msg[pin6->type].str,
	   inet_ntop (AF_INET6, &pin6->prefix, buf, BUFSIZ), pin6->mask);
      log2 (" via %s\n", inet_ntop (AF_INET6, &pin6->gate.addr, buf, 
				    INET6_ADDRSTRLEN));
    }
  rtable_add_in6 (pin6->type, &pin6->prefix, pin6->mask, &pin6->gate.info, 0);

  /* radix_add (ipv6_rib_radix, (struct prefix *)pin6); */
}

struct prefix_in6 *
rib_search_prefix_in6 (int type, struct prefix_in6 *pin)
{
  return (struct prefix_in6 *) radix_lookup_prefix (ipv6_rib_radix, type, pin);
}
#endif /* HAVE_IPV6 */

struct prefix_in *
rib_search_prefix (int type, struct prefix_in *pin)
{
  return (struct prefix_in *) radix_lookup_prefix (ipv4_rib_radix, type, pin);
}

vty_rt_dump (struct prefix *rt, struct vty *vty)
{
  struct prefix_in *pin = (struct prefix_in *) rt;

  vty_out (vty, "%s%s %s/%d ",
	   route_sort_msg[pin->type].str, pin->fib ? "*" : " ",
	   inet_ntoa (pin->prefix), pin->mask);

  /* Route which exist in kernel routing table. */
  switch (pin->type)
    {
    case ZEBRA_ROUTE_CONNECT:
      {
	struct interface *ifp;
      
	ifp = pin->gate.info;
	vty_out (vty, "is directly connected %s\r\n", ifp->name);
      }
      break;
    case ZEBRA_ROUTE_KERNEL:
    case ZEBRA_ROUTE_STATIC:
    default:
      {
	struct in_addr addr = pin->gate.addr;
	vty_out (vty, "via %s\r\n", inet_ntoa (addr));
	break;
      }
    }
}

/* Command function calling from vty. */
DEFUN (show_ip, show_ip_cmd,
       "show ip route [IPV4_ADDRESS] [IPV4_MASK]",
       "show IP address information.")
{
  vty_out (vty, "\r\n");
  vty_out (vty, "Codes: K - kernel route, C - connected, S - static, R - RIP, B - BGP\r\n");
  vty_out (vty, "       * - fib route.\r\n");
  vty_out (vty, "\r\n");

  radix_apply_func (ipv4_rib_radix, vty_rt_dump, vty);
  return CMD_SUCCESS;
}

delete_all_static (struct prefix *rt, struct vty *vty)
{
  radix_delete (ipv4_rib_radix, rt);
}

DEFUN (ip_route_delete, ip_route_delete_cmd,
       "ip route delete [IPV4_ADDRESS] [IPV4_MASK]",
       "show IP address information.")
{
  radix_apply_func (ipv4_rib_radix, delete_all_static, vty);
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* show ip6 command*/
DEFUN (show_ipv6, show_ipv6_cmd,
       "show ipv6 route [IPV6_ADDRESS]",
       "show IPv6 address information.")
{
  char buf[BUFSIZ];
  struct route_node *node;
  list rlist;

  vty_out (vty, "\r\n");
  vty_out (vty, "Codes: K - kernel route, C - connected, S - static, R - RIP, B - BGP\r\n");
  vty_out (vty, "\r\n");

  for (node = route_top (ipv6_rib_table); node; node = route_next (node))
    {
      rlist = node->route;

      if (rlist == NULL)
	continue;
      
      vty_out (vty, "    %s/%d ",
	       /* route_sort_msg[pin6->type].str, */
	       /* pin6->fib ? "*" : " ", */
	       inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ),
	       node->p.prefixlen);

#if 0
      switch (type)
	{
	case ZEBRA_ROUTE_CONNECT:
	  {
	    struct interface *ifp;
      
	    ifp = pin6->gate.info;
	    vty_out (vty, "is directly connected %s\r\n", ifp->name);
	  }
	  break;
	case ZEBRA_ROUTE_KERNEL:
	case ZEBRA_ROUTE_STATIC:
	default:
	  {
	    vty_out (vty, "via %s\r\n", 
		     inet_ntop (AF_INET6, &pin6->gate.addr, buf, BUFSIZ));
	    break;
	  }

	  return CMD_SUCCESS;
	}
#endif /* 0 */
    }
}
#endif /* HAVE_IPV6 */

/* Routing information base initialize. */
rib_init ()
{
  ipv4_rib_radix = radix_make_rib (AF_INET);
  ipv4_rib_radix->sameprefix = rt_ip_sameprefix;
  /* ipv4_rib_radix->samecontents = rt_ip_samecontents; */
#ifdef HAVE_IPV6
  ipv6_rib_radix = radix_make_rib (AF_INET6);
  ipv6_rib_radix->sameprefix = rt_ipv6_sameprefix;
  /* ipv6_rib_radix->samecontents = rt_ipv6_samecontents; */

  ipv6_rib_table = route_table_init ();
#endif /* HAVE_IPV6 */

  install_element (VIEW_NODE, &show_ip_cmd);
  install_element (ENABLE_NODE, &show_ip_cmd);

  /* Only for radix test.*/
  install_element (ENABLE_NODE, &ip_route_delete_cmd);
#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ipv6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_cmd);
#endif /* HAVE_IPV6 */
}
