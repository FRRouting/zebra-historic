/*
 * $Id: rib.c,v 1.106 1999/02/22 12:15:40 developer Exp $
 *
 * Routing Information Base.
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

#include "prefix.h"
#include "table.h"
#include "zebra/zebra.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "str.h"
#include "command.h"
#include "linklist.h"
#include "if.h"
#include "rib.h"
#include "rt.h"
#include "log.h"

/* Routing table for IP version 4 RIB */
struct route_table *ipv4_rib_table;

/* Routing table for IP version 6 RIB */
#ifdef HAVE_IPV6
struct route_table *ipv6_rib_table;
#endif /* HAVE_IPV6 */

/* Each route type's strings and default preference. */
struct
{  
  int key;  
  char *str; 
  char *str_long;
  int pref;
} route_info[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X", "system",    -30},
  { ZEBRA_ROUTE_KERNEL,  "K", "kernel",    -20},
  { ZEBRA_ROUTE_CONNECT, "C", "connected", -10},
  { ZEBRA_ROUTE_STATIC,  "S", "static",     10},
  { ZEBRA_ROUTE_RIP,     "R", "rip",        20},
  { ZEBRA_ROUTE_RIPNG,   "R", "ripng",      30},
  { ZEBRA_ROUTE_BGP,     "B", "bgp",        40},
};

/* New routing information base. */
struct rib *
rib_create (int type, int pref, int ifindex)
{
  struct rib *new;

  new = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  bzero (new, sizeof (struct rib));
  new->type = type;
  new->pref = pref;
  new->ifindex = ifindex;

  return new;
}

/* Free routing information base. */
void
rib_free (struct rib *rib)
{
  XFREE (MTYPE_RIB, rib);
}

/* Loggin of rib function. */
void
rib_log (char *message, int type, struct prefix *p,
	 void *gate, unsigned int ifindex)
{
  char buf[BUFSIZ];
  char logbuf[BUFSIZ];

  /* If the route is connected route print interface name. */
  if (type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;
      ifp = if_lookup_by_index (ifindex);
      snprintf (logbuf, BUFSIZ, " directly connected to %s\n", ifp->name);
    }
  else
    {
      snprintf (logbuf, BUFSIZ, " via %s\n",
		inet_ntop (p->family, gate, buf, BUFSIZ));
    }

  zlog (NULL, LOG_INFO, "%s route %s %s/%d %s", 
	  route_info[type].str_long, message,
	  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen,
	  logbuf);


}

/* If type is system route's type then return 1. */
int
rib_system_route (type)
{
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    return 1;
  else
    return 0;
}

/* Add rib to the rib list. */
void
rib_add_rib (struct rib **rp, struct rib *rib)
{
  struct rib *cp;
  struct rib *pp;


  for (cp = pp = *rp; cp; pp = cp, cp = cp->next)
    if (rib->pref <= cp->pref)
      break;

  if (cp == pp)
    {
      *rp = rib;

      if (cp)
	cp->prev = rib;
      rib->next = cp;
    }
  else
    {
      if (pp)
	pp->next = rib;
      rib->prev = pp;

      if (cp)
	cp->prev = rib;
      rib->next = cp;
    }
}

/* Delete rib from rib list. */
void
rib_delete_rib (struct rib **rp, struct rib *rib)
{
  if (rib->next)
    rib->next->prev = rib->prev;
  if (rib->prev)
    rib->prev->next = rib->next;
  else
    *rp = rib->next;
}

/* Add prefix into rib. If there is a same type prefix, then we assume
   it as implicit replacement of the route. */
int
rib_add_ipv4 (int type, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex)
{
  int pref;
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;

  p->family = AF_INET;
  apply_mask (p);

  pref = route_info[type].pref;

  rib_log ("add", type, (struct prefix *)p, gate, ifindex);

  /* Make new rib. */
  rib = rib_create (type, pref, ifindex);
  if (gate)
    rib->u.gate4 = *gate;

  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Check fib and same type route. */
  fib = same = NULL;
  for (rp = np->info; rp; rp = rp->next) 
    {
      if (rp->fib)
	fib = rp;
      if (rp->type == type)
	same = rp;
    }

  /* Same static route existance check. */
  if (type == ZEBRA_ROUTE_STATIC && same)
    {
      route_unlock_node (np);
      return ZEBRA_ERR_RTEXIST;
    }

  /* Then next add new route to rib. */
  rib_add_rib ((struct rib **) &np->info, rib);

  /* If there is FIB route and it's preference is higher than self
     replace FIB route.*/
  if (fib)
    {
      if (pref <= fib->pref)
	{
	  fib->fib = 0;
	  rib->fib = 1;

	  if (IPV4_ADDR_CMP(&fib->u.gate4, &rib->u.gate4) != 0 &&
	      !rib_system_route (rib->type))
	    {
	      /* Route change. */
	      kernel_delete_ipv4 (p, &fib->u.gate4, ifindex, 0);
	      kernel_add_ipv4 (p, &rib->u.gate4, ifindex, 0);
	    }
	}
    }
  else
    {
      rib->fib = 1;

      if (!rib_system_route (rib->type))
	kernel_add_ipv4 (p, gate, ifindex, 0);
    }

  /* If same type of route exists, replace it with new one. */
  if (same)
    {
      rib_delete_rib ((struct rib **)&np->info, same);
      rib_free (same);
      route_unlock_node (np);
    }

  return 0;
}

/* Delete prefix from the rib. */
int
rib_delete_ipv4 (int type, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex)
{
  int ret;
  struct route_node *np;
  struct rib *rib;
  struct rib *fib;
  
  ret = 0;
  apply_mask (p);

  rib_log ("delete", type, (struct prefix *)p, gate, ifindex);

  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type &&
	  IPV4_ADDR_CMP(&rib->u.gate4, gate) == 0 &&
	  rib->ifindex == ifindex)
	break;
    }

  if (!rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      zlog (NULL, LOG_INFO, "route %s/%d via %s doesn't exist in rib",
	   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
	   inet_ntop (AF_INET, gate, buf2, BUFSIZ));
      route_unlock_node (np);
      return ZEBRA_ERR_RTNOEXIST;
    }

  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  if (rib->fib)
    {
      ret = kernel_delete_ipv4 (p, gate, ifindex, 0);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  fib->fib = 1;
	  if (IPV4_ADDR_CMP(&fib->u.gate4, &rib->u.gate4) != 0 &&
	      !rib_system_route (fib->type))
	    kernel_add_ipv4 (p, &fib->u.gate4, ifindex, 0);
	}
    }

  rib_free (rib);
  route_unlock_node (np);

  return ret;
}

/* Vty list of static route configuration. */
void
rib_static_list (struct vty *vty, struct route_table *top)
{
  struct route_node *np;
  struct rib *rib;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];

  for (np = route_top (top); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (rib->type == ZEBRA_ROUTE_STATIC)
	vty_out (vty, "ip%s route %s/%d %s\r\n",
		 np->p.family == AF_INET ? "" : "v6",
		 inet_ntop (np->p.family, &np->p.u.prefix, buf1, BUFSIZ),
		 np->p.prefixlen,
		 inet_ntop (np->p.family, &rib->u.gate4, buf2, BUFSIZ));
}

/* Delete all added route and close rib. */
void
rib_close_ipv4 ()
{
  struct route_node *np;
  struct rib *rib;

  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (!rib_system_route (rib->type) && rib->fib)
	kernel_delete_ipv4 ((struct prefix_ipv4 *)&np->p, 
			    &rib->u.gate4, rib->ifindex, 0);
}


/* Command function calling from vty. */
DEFUN (show_ip, show_ip_cmd,
       "show ip route [IPV4_ADDRESS] [IPV4_MASK]",
       SHOW_STR
       "IP information\n"
       "IP routing table\n"
       "IP Address\n"
       "IP Netmask\n")
{
  char buf[BUFSIZ];
  struct route_node *np;
  struct rib *rib;

  /* Show matched route. */
  ;

  /* Print header. */
  vty_out (vty, "\r\nCodes: K - kernel route, C - connected, S - static,"
	   " R - RIP, B - BGP\r\n       * - FIB route.\r\n\r\n");

  /* Show all IPv4 routes. */
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      {
	int len;

	/* For DEBUG purpose. 
	len = vty_out (vty, "[%d]%s%c %s/%d", 
		       np->lock, 
	*/

	len = vty_out (vty, "%s%c %s/%d", 
		       route_info[rib->type].str,
		       rib->fib ? '*' : ' ',
		       inet_ntop (AF_INET, &np->p.u.prefix, buf, BUFSIZ),
		       np->p.prefixlen);

	len = 25 - len;
	if (len < 0)
	  len = 0;

	if (rib->type == ZEBRA_ROUTE_CONNECT)
	  {
	    struct interface *ifp;
	    ifp = if_lookup_by_index (rib->ifindex);
	    vty_out (vty, "%*s %s\r\n", len, " ", ifp->name);
	  }
	else
	  vty_out (vty, "%*s %s\r\n", len, " ",
		   inet_ntop (np->p.family, &rib->u.gate4, buf, BUFSIZ));
      }

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Add route to the routing table. */
int
rib_add_ipv6 (int type, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex)
{
  int pref;
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;

  /* Make sure mask is applied. */
  p->family = AF_INET6;
  apply_mask_ipv6 (p);

  pref = route_info[type].pref;

  rib_log ("add", type, (struct prefix *)p, gate, ifindex);

  /* Make new rib. */
  rib = rib_create (type, pref, ifindex);
  if (gate)
    rib->u.gate6 = *gate;

  /* This lock the node. */
  np = route_node_get (ipv6_rib_table, (struct prefix *)p);

  /* Check fib and same type route. */
  fib = same = NULL;
  for (rp = np->info; rp; rp = rp->next) 
    {
      if (rp->fib)
	fib = rp;
      if (rp->type == type)
	same = rp;
    }

  /* Same static route existance check. */
  if (type == ZEBRA_ROUTE_STATIC && same)
    {
      route_unlock_node (np);
      return ZEBRA_ERR_RTEXIST;
    }

  /* Then next add new route to rib. */
  rib_add_rib ((struct rib **) &np->info, rib);

    /* If there is FIB route and it's preference is higher than self
     replace FIB route.*/
  if (fib)
    {
      if (pref <= fib->pref)
	{
	  fib->fib = 0;
	  rib->fib = 1;

	  if (IPV6_ADDR_CMP(&fib->u.gate6, &rib->u.gate6) != 0 &&
	      !rib_system_route (rib->type))
	    {
	      /* Route change. */
	      kernel_delete_ipv6 (p, &fib->u.gate6, ifindex, 0);
	      kernel_add_ipv6 (p, &rib->u.gate6, ifindex, 0);
	    }
	}
    }
  else
    {
      rib->fib = 1;

      if (!rib_system_route (rib->type))
	kernel_add_ipv6 (p, gate, ifindex, 0);
    }

  /* If same type of route exists, replace it with new one. */
  if (same)
    {
      rib_delete_rib ((struct rib **)&np->info, same);
      rib_free (same);
      route_unlock_node (np);
    }
  return 0;
}

/* IPv6 route treatment. */
int
rib_delete_ipv6 (int type, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex)
{
  int ret;
  struct route_node *np;
  struct rib *rib;
  struct rib *fib;
  
  ret = 0;
  apply_mask_ipv6 (p);

  rib_log ("delete", type, (struct prefix *)p, gate, ifindex);

  np = route_node_get (ipv6_rib_table, (struct prefix *) p);

  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type &&
	  IPV6_ADDR_CMP(&rib->u.gate6, gate) == 0 &&
	  rib->ifindex == ifindex)
	break;
    }

  if (!rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      zlog (NULL, LOG_INFO, "route %s/%d via %s doesn't exist in rib",
	   inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ), p->prefixlen,
	   inet_ntop (AF_INET6, gate, buf2, BUFSIZ));
      route_unlock_node (np);
      return ZEBRA_ERR_RTNOEXIST;
    }

  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  if (rib->fib)
    {
      ret = kernel_delete_ipv6 (p, gate, ifindex, 0);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  fib->fib = 1;
	  if (IPV6_ADDR_CMP(&fib->u.gate6, &rib->u.gate6) != 0 &&
	      !rib_system_route (fib->type))
	    kernel_add_ipv6 (p, &fib->u.gate6, ifindex, 0);
	}
    }

  rib_free (rib);
  route_unlock_node (np);

  return ret;
}

/* Delete non system routes. */
void
rib_close_ipv6 ()
{
  struct route_node *np;
  struct rib *rib;

  for (np = route_top (ipv6_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (! rib_system_route (rib->type) && rib->fib)
	kernel_delete_ipv6 ((struct prefix_ipv6 *)&np->p, &rib->u.gate6, 
			    rib->ifindex, 0);
}

/* show ip6 command*/
DEFUN (show_ipv6, show_ipv6_cmd,
       "show ipv6 route [IPV6_ADDRESS]",
       SHOW_STR
       "IP information\n"
       "IP routing table\n"
       "IP Address\n"
       "IP Netmask\n")
{
  char buf[BUFSIZ];
  struct route_node *np;
  struct rib *rib;

  /* Show matched command. */

  /* Print out header. */
  vty_out (vty, "\r\nCodes: K - kernel route, C - connected, S - static,"
	   " R - RIPng, B - BGP\r\n       * - FIB route.\r\n\r\n");

  for (np = route_top (ipv6_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      {
	int len;

	len = vty_out (vty, "%s%c %s/%d",
		       route_info[rib->type].str,
		       rib->fib ? '*' : ' ',
		       inet_ntop (AF_INET6, &np->p.u.prefix6, buf, BUFSIZ),
		       np->p.prefixlen);
	len = 25 - len;
	if (len < 0)
	  len = 0;

	if (rib->type == ZEBRA_ROUTE_CONNECT)
	  {
	    struct interface *ifp;
	    ifp = if_lookup_by_index (rib->ifindex);
	    vty_out (vty, "%*s %s\r\n", len, " ", ifp->name);
	  }
	else
	  vty_out (vty, "%*s %s\r\n", len, " ",
		   inet_ntop (np->p.family, &rib->u.gate6, buf, BUFSIZ));
      }

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* Close rib when zebra terminates. */
void
rib_close ()
{
  rib_close_ipv4 ();
#ifdef HAVE_IPV6
  rib_close_ipv6 ();
#endif /* HAVE_IPV6 */
}

/* Routing information base initialize. */
void
rib_init ()
{
  ipv4_rib_table = route_table_init ();
  install_element (VIEW_NODE, &show_ip_cmd);
  install_element (ENABLE_NODE, &show_ip_cmd);

#ifdef HAVE_IPV6
  ipv6_rib_table = route_table_init ();
  install_element (VIEW_NODE, &show_ipv6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_cmd);
#endif /* HAVE_IPV6 */
}
