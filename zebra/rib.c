/*
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

#include "zebra/zebra.h"
#include "zebra/redistribute.h"

/* Routing information base. */
struct route_table *ipv4_rib_table;
struct route_table *ipv4_rib_static;
#ifdef HAVE_IPV6
struct route_table *ipv6_rib_table;
struct route_table *ipv6_rib_static;
#endif /* HAVE_IPV6 */

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

struct nexthop
{
  union
  {
    struct in_addr nexthop4;
#ifdef HAVE_IPV6
    struct in6_addr nexthop6;
#endif /* HAVE_IPV6 */
  } u;
  char *ifname;
};

struct nexthop *
nexthop_new ()
{
  struct nexthop *new;
  new = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  bzero (new, sizeof (struct nexthop));
  return new;
}

void
nexthop_free (struct nexthop *nexthop)
{
  if (nexthop->ifname)
    free (nexthop->ifname);
  XFREE (MTYPE_NEXTHOP, nexthop);
}

/* New routing information base. */
struct rib *
rib_create (int type, int distance, int ifindex, int table)
{
  struct rib *new;

  new = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  bzero (new, sizeof (struct rib));
  new->type = type;
  new->distance = distance;
  new->ifindex = ifindex;
  new->table = table;

  return new;
}

/* Free routing information base. */
void
rib_free (struct rib *rib)
{
  if (IS_RIB_LINK (rib))
    XFREE (0, rib->u.ifname);
  XFREE (MTYPE_RIB, rib);
}

/* Loggin of rib function. */
void
rib_log (char *message, struct prefix *p, struct rib *rib)
{
  char buf[BUFSIZ];
  char logbuf[BUFSIZ];

  /* If the route is connected route print interface name. */
  if (rib->type == ZEBRA_ROUTE_CONNECT)
    {
      struct interface *ifp;
      ifp = if_lookup_by_index (rib->ifindex);
      snprintf (logbuf, BUFSIZ, "directly connected to %s", ifp->name);
    }
  else
    {
      if (IS_RIB_LINK (rib))
	snprintf (logbuf, BUFSIZ, "via %s", rib->u.ifname);
      else
	snprintf (logbuf, BUFSIZ, "via %s",
		  inet_ntop (p->family, &rib->u, buf, BUFSIZ));
    }

  zlog (NULL, LOG_INFO, "%s route %s %s/%d %s",
	route_info[rib->type].str_long, message,
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
    if (rib->distance <= cp->distance)
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

void
rib_if_set (struct rib *rib, unsigned int ifindex)
{
  struct interface *ifp;

  ifp = if_lookup_by_index (ifindex);
  if (ifp)
    {
      RIB_LINK_SET (rib);
      rib->u.ifname = XSTRDUP (0, ifp->name);
    }
  else
    rib->u.ifname = "unknown";
}

int
rib_add_ipv4_internal (struct prefix_ipv4 *p, struct rib *rib, int table)
{
  int ret;
  struct route_node *np;
  struct prefix_ipv4 tmp;
  struct rib *fib;

  /* Lookup rib */
  tmp.family = AF_INET;
  tmp.prefixlen = 32;
  tmp.prefix = rib->u.gate4;

  np = route_node_match (ipv4_rib_table, (struct prefix *)&tmp);

  if (!np)
    return ZEBRA_ERR_RTUNREACH;

  for (fib = np->info; fib; fib = fib->next)
    if (IS_RIB_FIB (fib))
      break;

  if (! fib)
    {
      route_unlock_node (np);
      return ZEBRA_ERR_RTUNREACH;
    }

  if (fib && ! IS_RIB_LINK (fib))
    {
      ret = kernel_add_ipv4 (p, &fib->u.gate4, fib->ifindex, 0, table);
      if (ret != 0)
	{
	  route_unlock_node (np);
	  return ret;
	}
      
      rib->i.gate4 = fib->u.gate4;
      RIB_INTERNAL_SET (rib);
    }
  route_unlock_node (np);
  return 0;
}

/* Add prefix into rib. If there is a same type prefix, then we assume
   it as implicit replacement of the route. */
int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table)
{
  int ret;
  int distance;
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;

  /* Make it sure prefixlen is applied to the prefix. */
  p->family = AF_INET;
  apply_mask (p);

  /* Set default protocol distance. */
  distance = route_info[type].distance;

  /* Make new rib. */
  if (! table)
    table = RT_TABLE_MAIN;

  /* Create new rib. */
  rib = rib_create (type, distance, ifindex, table);

  /* Set gateway address or gateway interface name. */
  if (gate)
    rib->u.gate4 = *gate;
  else
    rib_if_set (rib, ifindex);

  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* From here real work is started. */

  /* Check fib and same type route. */
  fib = same = NULL;
  for (rp = np->info; rp; rp = rp->next) 
    {
      if (IS_RIB_FIB (rp))
	fib = rp;
      if (rp->type == type)
	same = rp;
    }

  /* Same static route existance check. */
  if (type == ZEBRA_ROUTE_STATIC && same)
    {
      rib_free (rib);
      route_unlock_node (np);
      return ZEBRA_ERR_RTEXIST;
    }

  /* If there is FIB route and it's preference is higher than self
     replace FIB route.*/
  if (fib)
    {
      if (distance <= fib->distance)
	{
	  /* Redistribute the informaion. */
	  if (rib_system_route (rib->type))
	    {
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv4 (np, fib);
	      redistribute_add_ipv4 (np, rib);
	    }
	  else if (IPV4_ADDR_CMP(&fib->u.gate4, &rib->u.gate4) != 0)
	    {
	      /* Route change. */
	      kernel_delete_ipv4 (p, &fib->u.gate4, ifindex, 0, fib->table);
	      ret = kernel_add_ipv4 (p, &rib->u.gate4, ifindex, 0, table);
	      if (ret != 0)
		{
		  /* Internal route... */

		  /* Restore old route. */
		  kernel_add_ipv4 (p, &fib->u.gate4, ifindex, 0, fib->table);

		  route_unlock_node (np);
		  rib_free (rib);
		  return ZEBRA_ERR_RTUNREACH;
		}
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv4 (np, fib);
	      redistribute_add_ipv4 (np, rib);
	    }
	  else
	    {
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv4 (np, fib);
	      redistribute_add_ipv4 (np, rib);
	    }
	}
    }
  else
    {
      if (rib_system_route (rib->type))
	{
	  RIB_FIB_SET (rib);
	  redistribute_add_ipv4 (np, rib);
	}
      else
	{
	  /* Redistribute the information. */
	  ret = kernel_add_ipv4 (p, gate, ifindex, 0, table);
	  if (ret != 0)
	    {
	      /* If internal route... */
	      if (gate && flags == ZEBRA_ROUTE_INTERNAL)
		{
		  ret = rib_add_ipv4_internal (p, rib, table);
		  if (ret != 0)
		    {
		      route_unlock_node (np);
		      rib_free (rib);
		      return ZEBRA_ERR_RTUNREACH;
		    }
		}
	      else
		{
		  route_unlock_node (np);
		  rib_free (rib);
		  return ZEBRA_ERR_RTUNREACH;
		}
	    }
	  RIB_FIB_SET (rib);
	  redistribute_add_ipv4 (np, rib);
	}
    }

  /* OK rib is setup.  Now logging it. */
  rib_log ("add", (struct prefix *)p, rib);

  /* Then next add new route to rib. */
  rib_add_rib ((struct rib **) &np->info, rib);

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
rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table)
{
  int ret = 0;
  struct route_node *np;
  struct rib *rib;
  struct rib *fib = NULL;

  /* Make it sure prefixlen is applied to the prefix. */
  p->family = AF_INET;
  apply_mask (p);

  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Search delete rib. */
  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type &&
	  rib->ifindex == ifindex &&
	  (!table || rib->table == table))
	if (! gate || (IPV4_ADDR_CMP(&rib->u.gate4, gate) == 0))
	  break;
    }
  
  /* If rib can't find. */
  if (! rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      if (gate)
	zlog (NULL, LOG_INFO, "route %s/%d via %s doesn't exist in rib",
	      inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
	      inet_ntop (AF_INET, gate, buf2, BUFSIZ));
      else
	zlog (NULL, LOG_INFO, "route %s/%d ifindex %d doesn't exist in rib",
	      inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
	      ifindex);
      route_unlock_node (np);
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Logging. */
  rib_log ("delete", (struct prefix *)p, rib);

  /* Deletion complete. */
  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  /* Kernel updates. */
  if (IS_RIB_FIB (rib))
    {
      if (! rib_system_route (type))
	{
	  if (IS_RIB_INTERNAL (rib))
	    ret = kernel_delete_ipv4 (p, &rib->i.gate4, ifindex, 0, rib->table);
	  else
	    ret = kernel_delete_ipv4 (p, gate, ifindex, 0, rib->table);
	}

      /* Redistribute it. */
      redistribute_delete_ipv4 (np, rib);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  if (IPV4_ADDR_CMP(&fib->u.gate4, &rib->u.gate4) != 0 &&
	      ! rib_system_route (fib->type))
	    {
	      ret = kernel_add_ipv4 (p, &fib->u.gate4, ifindex, 0, fib->table);

	      if (ret == 0)
		{
		  RIB_FIB_SET (fib);
		  redistribute_add_ipv4 (np, fib);
		}
	    }
	}
    }

  rib_free (rib);
  route_unlock_node (np);

  return ret;
}

/* Vty list of static route configuration. */
int
rib_static_list (struct vty *vty, struct route_table *top)
{
  struct route_node *np;
  struct rib *rib;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  int write = 0;

  for (np = route_top (top); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (rib->type == ZEBRA_ROUTE_STATIC)
	{
	  if (IS_RIB_LINK (rib))
	    vty_out (vty, "ip%s route %s/%d %s%s",
		     np->p.family == AF_INET ? "" : "v6",
		     inet_ntop (np->p.family, &np->p.u.prefix, buf1, BUFSIZ),
		     np->p.prefixlen,
		     rib->u.ifname,
		     VTY_NEWLINE);
	  else
	    vty_out (vty, "ip%s route %s/%d %s%s",
		     np->p.family == AF_INET ? "" : "v6",
		     inet_ntop (np->p.family, &np->p.u.prefix, buf1, BUFSIZ),
		     np->p.prefixlen,
		     inet_ntop (np->p.family, &rib->u.gate4, buf2, BUFSIZ),
		     VTY_NEWLINE);
	  write++;
	}
  return write;
}

/* Delete all added route and close rib. */
void
rib_close_ipv4 ()
{
  struct route_node *np;
  struct rib *rib;

  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (!rib_system_route (rib->type) && IS_RIB_FIB (rib))
	{
	  if (IS_RIB_LINK (rib))
	    kernel_delete_ipv4 ((struct prefix_ipv4 *)&np->p, 
				NULL, rib->ifindex, 0, rib->table);
	  else
	    kernel_delete_ipv4 ((struct prefix_ipv4 *)&np->p, 
				&rib->u.gate4, rib->ifindex, 0, rib->table);
	}
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

	len = vty_out (vty, "%s%c %s/%d", 
		       route_info[rib->type].str,
		       IS_RIB_FIB (rib) ? '*' : ' ',
#if 0
		       rib->table,
#endif /* 0 */
		       inet_ntop (AF_INET, &np->p.u.prefix, buf, BUFSIZ),
		       np->p.prefixlen);

	len = 26 - len;
	if (len < 0)
	  len = 0;

	if (rib->type == ZEBRA_ROUTE_CONNECT)
	  {
	    struct interface *ifp;
	    ifp = if_lookup_by_index (rib->ifindex);
	    vty_out (vty, "%*s %s\r\n", len, " ", ifp->name);
	  }
	else
	  {
	    if (IS_RIB_LINK (rib))
	      vty_out (vty, "%*s %s\r\n", len, " ", rib->u.ifname);
	    else
	      vty_out (vty, "%*s %s\r\n", len, " ",
		       inet_ntop (np->p.family, &rib->u.gate4, buf, BUFSIZ));
	  }
      }

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
int
rib_bogus_ipv6 (int type, struct prefix_ipv6 *p,
		struct in6_addr *gate, unsigned int ifindex, int table)
{
  if (type == ZEBRA_ROUTE_CONNECT && IN6_IS_ADDR_UNSPECIFIED (&p->prefix))
    return 1;
  if (type == ZEBRA_ROUTE_KERNEL && IN6_IS_ADDR_UNSPECIFIED (&p->prefix)
      && p->prefixlen == 96 && gate && IN6_IS_ADDR_UNSPECIFIED (gate))
    {
      kernel_delete_ipv6 (p, gate, ifindex, 0, table);
      return 1;
    }
  return 0;
}

/* Add route to the routing table. */
int
rib_add_ipv6 (int type, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table)
{
  int distance;
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;
  int ret;

  /* Make sure mask is applied. */
  p->family = AF_INET6;
  apply_mask_ipv6 (p);

  distance = route_info[type].distance;

  /* Make new rib. */
  if (!table)
    table = RT_TABLE_MAIN;

  /* Filter bogus route. */
  if (rib_bogus_ipv6 (type, p, gate, ifindex, table))
    return 0;

  rib = rib_create (type, distance, ifindex, table);

  if (gate)
    rib->u.gate6 = *gate;
  else
    rib_if_set (rib, ifindex);

  /* This lock the node. */
  np = route_node_get (ipv6_rib_table, (struct prefix *)p);

  /* Check fib and same type route. */
  fib = same = NULL;
  for (rp = np->info; rp; rp = rp->next) 
    {
      if (IS_RIB_FIB (rp))
	fib = rp;
      if (rp->type == type)
	same = rp;
    }

  /* Same static route existance check. */
  if (type == ZEBRA_ROUTE_STATIC && same)
    {
      rib_free (rib);
      route_unlock_node (np);
      return ZEBRA_ERR_RTEXIST;
    }

  rib_log ("add", (struct prefix *)p, rib);

  /* If there is FIB route and it's preference is higher than self
     replace FIB route.*/
  if (fib)
    {
      if (distance <= fib->distance)
	{
	  if (rib_system_route (rib->type))
	    {
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv6 (np, fib);
	      redistribute_add_ipv6 (np, rib);
	    }
	  else if (IPV6_ADDR_CMP(&fib->u.gate6, &rib->u.gate6) != 0)
	    {
	      /* Route change. */
	      kernel_delete_ipv6 (p, &fib->u.gate6, ifindex, 0, fib->table);
	      ret = kernel_add_ipv6 (p, &rib->u.gate6, ifindex, 0, table);
	      if (ret != 0)
		{
		  kernel_add_ipv6 (p, &fib->u.gate6, ifindex, 0, fib->table);
		  route_unlock_node (np);
		  rib_free (rib);
		  return ZEBRA_ERR_RTUNREACH;
		}
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv6 (np, fib);
	      redistribute_add_ipv6 (np, rib);
	    }
	  else
	    {
	      RIB_FIB_UNSET (fib);
	      RIB_FIB_SET (rib);
	      redistribute_delete_ipv6 (np, fib);
	      redistribute_add_ipv6 (np, rib);
	    }
	}
    }
  else
    {
      if (rib_system_route (rib->type))
	{
	  RIB_FIB_SET (rib);
	  redistribute_add_ipv6 (np, rib);
	}
      else
	{
	  ret = kernel_add_ipv6 (p, gate, ifindex, 0, table);
	  if (ret != 0)
	    {
	      route_unlock_node (np);
	      rib_free (rib);
	      return ZEBRA_ERR_RTUNREACH;
	    }
	  RIB_FIB_SET (rib);
	  redistribute_add_ipv6 (np, rib);
	}
    }

  /* Then next add new route to rib. */
  rib_add_rib ((struct rib **) &np->info, rib);

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
		 struct in6_addr *gate, unsigned int ifindex, int table)
{
  int ret = 0;
  struct route_node *np;
  struct rib *rib;
  struct rib *fib;
  
  p->family = AF_INET6;
  apply_mask_ipv6 (p);

  np = route_node_get (ipv6_rib_table, (struct prefix *) p);

  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type &&
	  IPV6_ADDR_CMP(&rib->u.gate6, gate) == 0 &&
	  rib->ifindex == ifindex &&
	  (!table || rib->table == table))
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

  rib_log ("delete", (struct prefix *)p, rib);

  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  if (IS_RIB_FIB (rib))
    {
      if (! rib_system_route (type))
	ret = kernel_delete_ipv6 (p, gate, ifindex, 0, rib->table);

      /* Redistribute it. */
      redistribute_delete_ipv6 (np, rib);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  RIB_FIB_SET (fib);

	  if (IPV6_ADDR_CMP(&fib->u.gate6, &rib->u.gate6) != 0 &&
	      !rib_system_route (fib->type))
	    {
	      ret = kernel_add_ipv6 (p, &fib->u.gate6, ifindex, 0, fib->table);

	      if (ret == 0)
		{
		  RIB_FIB_SET (fib);
		  redistribute_add_ipv6 (np, fib);
		}
	    }
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
      if (! rib_system_route (rib->type) && IS_RIB_FIB (rib))
	kernel_delete_ipv6 ((struct prefix_ipv6 *)&np->p, &rib->u.gate6, 
			    rib->ifindex, 0, rib->table);
}

/* IPv6 static route add. */
int
ipv6_static_add (struct prefix_ipv6 *p, struct in6_addr *gate, char *ifname)
{
  struct nexthop *nexthop;
  struct route_node *node;

  node = route_node_get (ipv6_rib_static, (struct prefix *) p);

  /* If same static route exists. */
  if (node->info)
    {
      route_unlock_node (node);
      return -1;
    }

  /* Allocate new nexthop structure. */
  nexthop = nexthop_new ();

  if (gate)
    nexthop->u.nexthop6 = *gate;

  if (ifname)
    nexthop->ifname = strdup (ifname);

  node->info = nexthop;

  return 0;
}

/* IPv6 static route delete. */
int
ipv6_static_delete (struct prefix_ipv6 *p, struct in6_addr *gate, char *ifname)
{
  struct route_node *node;
  struct nexthop *nexthop;

  node = route_node_lookup (ipv6_rib_static, (struct prefix *) p);
  if (! node)
    return -1;

  nexthop = node->info;
  if (gate)
    {
      if (IPV6_ADDR_CMP (gate, &nexthop->u.nexthop6))
	{
	  route_unlock_node (node);
	  return -1;
	}
    }
  if (ifname)
    {
      if (!nexthop->ifname)
	{
	  route_unlock_node (node);
	  return -1;
	}
      if (strcmp (ifname, nexthop->ifname))
	{
	  route_unlock_node (node);
	  return -1;
	}
    }

  nexthop_free (nexthop);
  node->info = NULL;

  route_unlock_node (node);
  route_unlock_node (node);

  return 0;
}

int
ipv6_static_list (struct vty *vty)
{
  struct route_node *np;
  struct nexthop *nexthop;
  char b1[BUFSIZ];
  char b2[BUFSIZ];
  int write = 0;

  for (np = route_top (ipv6_rib_static); np; np = route_next (np))
    if ((nexthop = np->info) != NULL)
      {
	if (nexthop->ifname)
	  vty_out (vty, "ipv6 route %s/%d %s %s%s",
		   inet_ntop (np->p.family, &np->p.u.prefix, b1, BUFSIZ),
		   np->p.prefixlen,
		   inet_ntop (np->p.family, &nexthop->u.nexthop6, b2, BUFSIZ),
		   nexthop->ifname,
		   VTY_NEWLINE);
	else
	  vty_out (vty, "ipv6 route %s/%d %s%s",
		   inet_ntop (np->p.family, &np->p.u.prefix, b1, BUFSIZ),
		   np->p.prefixlen,
		   inet_ntop (np->p.family, &nexthop->u.nexthop6, b2, BUFSIZ),
		   VTY_NEWLINE);
	write++;
      }
  return write;
}

DEFUN (ipv6_route, ipv6_route_cmd,
       "ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "Destination IP Address\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gate;

  /* Route prefix/prefixlength format check. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Gateway format check. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  /* We need rib error treatment here. */
  ret = rib_add_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, 0);
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist\r\n");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable\r\n");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied\r\n");
	  break;
	default:
	  break;
	}
      return CMD_WARNING;
    }

  ipv6_static_add (&p, &gate, NULL);

  return CMD_SUCCESS;
}

DEFUN (ipv6_route_ifname, ipv6_route_ifname_cmd,
       "ipv6 route IPV6_ADDRESS IPV6_ADDRESS IFNAME",
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "Destination IP Address\n"
       "Destination interface name\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gate;
  struct interface *ifp;

  /* Route prefix/prefixlength format check. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Gateway format check. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Interface name check. */
  ifp = if_lookup_by_name (argv[2]);
  if (!ifp)
    {
      vty_out (vty, "Can't find interface\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  /* We need rib error treatment here. */
  ret = rib_add_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gate, ifp->index, 0);
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist\r\n");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable\r\n");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied\r\n");
	  break;
	default:
	  break;
	}
    }

  ipv6_static_add (&p, &gate, argv[2]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "IP Netmask\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gate;
  
  /* Check ipv6 prefix. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Check gateway. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  ret = rib_delete_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, 0);

  switch (ret)
    {
    default:
      /* Success */
      break;
    }

  ipv6_static_delete (&p, &gate, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS IFNAME",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "Interface name\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gate;
  struct interface *ifp;
  
  /* Check ipv6 prefix. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Check gateway. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Interface name check. */
  ifp = if_lookup_by_name (argv[2]);
  if (!ifp)
    {
      vty_out (vty, "Can't find interface\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  ret = rib_delete_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gate, ifp->index, 0);

  switch (ret)
    {
    default:
      /* Success */
      break;
    }

  /* Check static configuration. */
  ret = ipv6_static_delete (&p, &gate, argv[2]);

  return CMD_SUCCESS;
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
		       IS_RIB_FIB (rib) ? '*' : ' ',
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

static void
rib_weed_table (struct route_table *rib_table)
{
  struct route_node *np;
  struct rib *rib;
  extern int rtm_table_default;

  for (np = route_top (rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      {
        if (rib->table != rtm_table_default &&
	    rib->table != RT_TABLE_MAIN)
          {
            rib_delete_rib ((struct rib **)&np->info, rib);
            rib_free (rib);
          }
      }
}

/* Delete all routes from unmanaged tables. */
void
rib_weed_tables ()
{
  rib_weed_table (ipv4_rib_table);
#ifdef HAVE_IPV6
  rib_weed_table (ipv6_rib_table);
#endif /* HAVE_IPV6 */
}

/* Close rib when zebra terminates. */
void
rib_close ()
{
  rib_close_ipv4 ();
#ifdef HAVE_IPV6
  rib_close_ipv6 ();
#endif /* HAVE_IPV6 */
}

/* Static ip route configuration write function. */
int
config_write_ip (struct vty *vty)
{
  int write = 0;

  write += rib_static_list (vty, ipv4_rib_table);
#ifdef HAVE_IPV6
  write += ipv6_static_list (vty);
#endif /* HAVE_IPV6 */

  return write;
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
  ipv6_rib_static = route_table_init ();
  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);

  install_element (VIEW_NODE, &show_ipv6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_cmd);
#endif /* HAVE_IPV6 */
}
