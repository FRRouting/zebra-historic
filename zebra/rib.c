/* Routing Information Base.
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
#include "sockunion.h"

#include "zebra/zserv.h"
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
  { ZEBRA_ROUTE_SYSTEM,  "X", "system",    0},
  { ZEBRA_ROUTE_KERNEL,  "K", "kernel",    0},
  { ZEBRA_ROUTE_CONNECT, "C", "connected", 0},
  { ZEBRA_ROUTE_STATIC,  "S", "static",    1},
  { ZEBRA_ROUTE_RIP,     "R", "rip",       120},
  { ZEBRA_ROUTE_RIPNG,   "R", "ripng",     120},
  { ZEBRA_ROUTE_OSPF,    "O", "ospf",      110},
  { ZEBRA_ROUTE_OSPF6,   "O", "ospf6",     110},
  /* iBGP 200 */
  { ZEBRA_ROUTE_BGP,     "B", "bgp",        20},
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


#ifdef HAVE_IF_PSEUDO
/* New routing information base. */
struct rib *
rib_create (int type, u_char flags, int distance, int ifindex, char *ifname, int table)
{
  struct rib *new;

  new = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  bzero (new, sizeof (struct rib));
  new->type = type;
  new->flags = flags;
  new->distance = distance;
  new->u.ifindex = ifindex;
  new->table = table;
  if (ifname){
    strncpy(new->u.ifname,ifname,INTERFACE_NAMSIZ);
  }

  return new;
}
#else
/* New routing information base. */
struct rib *
rib_create (int type, u_char flags, int distance, int ifindex, int table,
	    u_int32_t metric)
{
  struct rib *new;

  new = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  bzero (new, sizeof (struct rib));
  new->type = type;
  new->flags = flags;
  new->distance = distance;
  new->u.ifindex = ifindex;
  new->table = table;
  new->metric = metric;

  return new;
}
#endif /* HAVE_IF_PSEUDO */

/* Free routing information base. */
void
rib_free (struct rib *rib)
{
  XFREE (MTYPE_RIB, rib);
}

/* Loggin of rib function. */
void
rib_log (char *message, struct prefix *p, struct rib *rib)
{
  char buf[BUFSIZ];
  char logbuf[BUFSIZ];
  void *addrp;
  struct interface *ifp;

  switch (p->family)
    {
    case AF_INET:
      addrp = &rib->u.gate4;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      addrp = &rib->u.gate6;
      break;
#endif /* HAVE_IPV6 */
    default:
      addrp = NULL;
      break;
    }

  /* If the route is connected route print interface name. */
  if (rib->type == ZEBRA_ROUTE_CONNECT)
    {
      ifp = if_lookup_by_index (rib->u.ifindex);
      snprintf (logbuf, BUFSIZ, "directly connected to %s", ifp->name);
    }
  else
    {
      if (IS_RIB_LINK (rib))
	snprintf (logbuf, BUFSIZ, "via %s", ifindex2ifname (rib->u.ifindex));
      else
	snprintf (logbuf, BUFSIZ, "via %s ifindex %d",
		  inet_ntop (p->family, addrp, buf, BUFSIZ),
		  rib->u.ifindex);
    }

  zlog_info ("%s route %s %s/%d %s",
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
      rib->u.ifindex = ifindex;
    }
}

void
rib_if_check (struct rib *rib, unsigned int ifindex, struct in_addr *gate)
{
  struct interface *ifp;

  if (ifindex)
    ifp = if_lookup_by_index (ifindex);
  else
    ifp = if_lookup_address(*gate);

#ifdef HAVE_IF_PSEUDO  
  if (ifp){
    rib->u.ifindex = ifp->ifindex;
    if_indextoname(rib->u.ifindex,rib->u.ifname);
  }
  else
    rib->u.ifindex = INTERFACE_UNKNOWN;
#else
  if (ifp)
    rib->u.ifindex = ifp->ifindex;
  else
    rib->u.ifindex = 0;
#endif /* HAVE_IF_PSEUDO */
}

void
rib_fib_set (struct route_node *np, struct rib *rib)
{
  RIB_FIB_SET (rib);
  redistribute_add (np, rib);
}

void
rib_fib_unset (struct route_node *np, struct rib *rib)
{
  RIB_FIB_UNSET (rib);
  redistribute_delete (np, rib);
}

int
rib_add_ipv4_internal (struct prefix_ipv4 *p, struct rib *rib, int table)
{
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

  if (fib->type == ZEBRA_ROUTE_CONNECT)
    {
      route_unlock_node (np);
      return kernel_add_ipv4 (p, &rib->u.gate4, rib->u.ifindex, rib->flags,
			      table);
    }

  /* Save original nexthop. */
  rib->i.gate4 = rib->u.gate4;
  rib->i.ifindex = rib->u.ifindex;

  rib->u.gate4 = fib->u.gate4;
  rib->u.ifindex = fib->u.ifindex;
  RIB_INTERNAL_SET (rib);

  route_unlock_node (np);
  
  return kernel_add_ipv4 (p, &rib->u.gate4, rib->u.ifindex, rib->flags, table);
}

#ifdef HAVE_IF_PSEUDO
int
rib_add_ipv4_pseudo (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, char *ifname , int table)
{

  int distance;
  struct route_node *np;
  struct rib *rib;

  /* currently no way to add pseudo route with gateway */
  if (gate) return 1;
  /* Make it sure prefixlen is applied to the prefix. */
  p->family = AF_INET;
  apply_mask_ipv4 (p);

  /* Set default protocol distance. */
  distance = route_info[type].distance;

  if (! table)
    table = RT_TABLE_MAIN;

  /* Create new rib. */
  rib = rib_create (type, flags, distance, 0, ifname, table);

  RIB_LINK_SET (rib);
  
  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Logging. */
  rib_log ("add pseudo", (struct prefix *)p, rib);
#if 0  
  if ((ret = rib_add_ipv4_internal (p, rib, table)) != 0){	    
    rib_log ("rib non-existent interface: couldn't add route", (struct prefix *)p, rib);
  }
#endif 

  rib_fib_unset (np,rib);
  rib_add_rib ((struct rib **) &np->info, rib);

  return 0;
  
}
#endif /* HAVE_IF_PSEUDO */
/* Add prefix into rib. If there is a same type prefix, then we assume
   it as implicit replacement of the route. */
int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table,
	      u_int32_t metric, u_char distance)
{
  int ret;
  /* int distance; */
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;
#ifdef HAVE_IF_PSEUDO
  struct in_addr zero_gate;
  char ifname[INTERFACE_NAMSIZ];

  memset (&zero_gate,0, sizeof (struct in_addr)); 
#endif /* HAVE_IF_PSEUDO */
  
  /* Make it sure prefixlen is applied to the prefix. */
  p->family = AF_INET;
  apply_mask_ipv4 (p);

  /* Set default protocol distance. */
  if (distance == 255)
    return 0;

  if (distance == 0)
    {
      distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

  /* Make new rib. */
  if (! table)
    table = RT_TABLE_MAIN;

#ifdef HAVE_IF_PSEUDO
  /* Create new rib. */
  if (ifindex != INTERFACE_PSEUDO && ifindex != INTERFACE_UNKNOWN
      && if_indextoname(ifindex,ifname))
    rib = rib_create (type, flags, distance, ifindex, ifname, table);
  else
    rib = rib_create (type, flags, distance, ifindex, NULL, table);
  
  /* Set gateway address or gateway interface name. */
  if (gate && !IPV4_ADDR_SAME(gate,&zero_gate)) 
    {
      rib->u.gate4 = *gate;
      rib_if_check (rib, ifindex, gate);
    }
  else
    rib_if_set (rib, ifindex);
#else
  /* Create new rib. */
  rib = rib_create (type, flags, distance, ifindex, table, metric);
  
  if (gate) 
    {
      rib->u.gate4 = *gate;
      rib_if_check (rib, ifindex, gate);
    }
  else
    rib_if_set (rib, ifindex);
#endif /* HAVE_IF_PSEUDO */
  
  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Check fib and same type route. */
  fib = same = NULL;
  for (rp = np->info; rp; rp = rp->next) 
    {
      if (IS_RIB_FIB (rp))
	fib = rp;
      if ((rp->type == type) &&
	  (IPV4_ADDR_SAME (&rp->u.gate4, &rib->u.gate4)))
	same = rp;
    }

  /* Same static route existance check. */
  if (type == ZEBRA_ROUTE_STATIC && same)
    {
      rib_free (rib);
      route_unlock_node (np);
      return ZEBRA_ERR_RTEXIST;
    }

  /* Now logging it. */
  rib_log ("add", (struct prefix *)p, rib);

  /* If there is FIB route and it's preference is higher than self
     replace FIB route.*/
  if (fib)
    {
      if (distance <= fib->distance)
	{
	  /* Kernel route or if nexthop is same as current one. */
	  if ((IPV4_ADDR_SAME (&fib->u.gate4, &rib->u.gate4) && 
	       (fib->u.ifindex == rib->u.ifindex)))
	    {
	      rib_fib_unset (np, fib);
	      rib_fib_set (np, rib);
	    }
	  else
	    {
	      kernel_delete_ipv4 (p, &fib->u.gate4, fib->u.ifindex, 0, 
				  fib->table);

	      /* If the new route is received from kernel,
		 do not install it into kernel */
	      if (!rib_system_route (rib->type))
		{
		  if (gate && (flags & ZEBRA_FLAG_INTERNAL))
		    ret = rib_add_ipv4_internal (p, rib, table);
		  else
		    ret = kernel_add_ipv4 (p, &rib->u.gate4, ifindex, flags,
				       table);
		  
		  if (ret != 0)
		    {
		      /* Restore old route. */
		      kernel_add_ipv4 (p, &fib->u.gate4,
				       fib->u.ifindex, fib->flags, fib->table);
		      goto finish;
		    }
		}
	      rib_fib_unset (np, fib);
	      rib_fib_set (np, rib);
	    }
	}
    }
  else
    {
      if (! rib_system_route (rib->type))
	{
#ifndef HAVE_IF_PSEUDO
	  if (gate && (flags & ZEBRA_FLAG_INTERNAL))
	    ret = rib_add_ipv4_internal (p, rib, table);
	  else
	    ret = kernel_add_ipv4 (p, gate, ifindex, flags, table);
#else	  
	  if (gate && (flags & ZEBRA_FLAG_INTERNAL)){
	    if ((ret = rib_add_ipv4_internal (p, rib, table)) != 0){	    
	      rib_log ("internal rib: route unreachable", (struct prefix *)p, rib);
	    }
	  }
	  else {
	    if ((ret = kernel_add_ipv4 (p, gate, ifindex, flags, table)) != 0){
	      rib_log ("kernel rib: couldn't add route", (struct prefix *)p, rib);
	    }
	  }
#endif /* HAVE_IF_PSEUDO */

	  if (ret != 0)
	    goto finish;
	}
      rib_fib_set (np, rib);
    }

 finish:

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

#ifdef HAVE_IF_PSEUDO
int
rib_delete_ipv4_pseudo (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, char *ifname, int table)
{
  struct route_node *np;
  struct rib *rib;

  /* Make it sure prefixlen is applied to the prefix. */
  p->family = AF_INET;
  apply_mask_ipv4 (p);

  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Search delete rib. */
  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type && !strncmp(rib->u.ifname,ifname,INTERFACE_NAMSIZ) &&
	  (!table || rib->table == table))
	{
	  if (! gate)
	      break;

	  if (IS_RIB_INTERNAL (rib))
	    {
	      if (IPV4_ADDR_SAME (&rib->i.gate4, gate))
		break;
	    }
	  else
	    {
	      if (IPV4_ADDR_SAME (&rib->u.gate4, gate))
		break;
	    }
	}
    }
  
  /* If rib can't find. */
  if (! rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      if (gate)
	zlog_info ("route %s/%d via %s ifname %s doesn't exist in rib",
		   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
		   inet_ntop (AF_INET, gate, buf2, BUFSIZ),
		   ifname);
      else
	zlog_info ("route %s/%d ifname %s doesn't exist in rib",
		   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
		   ifname);
      route_unlock_node (np);
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Logging. */
  rib_log ("delete pseudo", (struct prefix *)p, rib);

  /* Deletion complete. */
  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  rib_free (rib);
  route_unlock_node (np);

  return 0;
}
#endif /* HAVE_IF_PSEUDO */

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
  apply_mask_ipv4 (p);

  /* Lookup route node. */
  np = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* Search delete rib. */
  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type && 
	  (!table || rib->table == table))
	{
	  if (! gate)
	    break;

	  if (IS_RIB_INTERNAL (rib))
	    {
	      if (IPV4_ADDR_SAME (&rib->i.gate4, gate))
		break;
	    }
	  else
	    {
	      if (IPV4_ADDR_SAME (&rib->u.gate4, gate))
		break;
	    }
	}
    }
  
  /* If rib can't find. */
  if (! rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      if (gate)
	zlog_info ("route %s/%d via %s ifindex %d doesn't exist in rib",
		   inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ), p->prefixlen,
		   inet_ntop (AF_INET, gate, buf2, BUFSIZ),
		   ifindex);
      else
	zlog_info ("route %s/%d ifindex %d doesn't exist in rib",
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
	ret = kernel_delete_ipv4 (p, &rib->u.gate4, ifindex, 0, rib->table);

      /* Redistribute it. */
      redistribute_delete (np, rib);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  if (! rib_system_route (fib->type))
	    {
	      ret = kernel_add_ipv4 (p, &fib->u.gate4, fib->u.ifindex,
				     fib->flags, fib->table);

	      if (ret == 0)
		rib_fib_set (np, fib);
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
#ifdef HAVE_IF_PSEUDO
		     rib->u.ifname,
#else
		     ifindex2ifname(rib->u.ifindex),
#endif
		     VTY_NEWLINE);
#ifndef HAVE_IF_PSEUDO
	  else
#else
	  else{
	    if (rib->u.ifindex == INTERFACE_PSEUDO){
#endif /* HAVE_IF_PSEUDO */
	    vty_out (vty, "ip%s route %s/%d %s%s",
		     np->p.family == AF_INET ? "" : "v6",
		     inet_ntop (np->p.family, &np->p.u.prefix, buf1, BUFSIZ),
		     np->p.prefixlen,
#ifdef HAVE_IF_PSEUDO
		     rib->u.ifname,
		     VTY_NEWLINE);
	    }
	    else {
	      vty_out (vty, "ip%s route %s/%d %s%s",
		     np->p.family == AF_INET ? "" : "v6",
		     inet_ntop (np->p.family, &np->p.u.prefix, buf1, BUFSIZ),
		     np->p.prefixlen,
#endif /* HAVE_IF_PSEUDO */
		     inet_ntop (np->p.family, &rib->u.gate4, buf2, BUFSIZ),
		     VTY_NEWLINE);
#ifdef HAVE_IF_PSEUDO
	    }
	  }
#endif /* HAVE_IF_PSEUDO */
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
				NULL, rib->u.ifindex, 0, rib->table);
	  else
	    kernel_delete_ipv4 ((struct prefix_ipv4 *)&np->p, 
				&rib->u.gate4, rib->u.ifindex, 0, rib->table);
	}
}

u_int32_t
rib_lookup_ipv4_nexthop (struct in_addr addr)
{
  struct prefix p;
  struct route_node *rn;
  struct rib *fib;

  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = addr;

  rn = route_node_match (ipv4_rib_table, (struct prefix *) &p);

  if (!rn)
    return 0;

  while (rn)
    {
      for (fib = rn->info; fib; fib = fib->next)
	if (IS_RIB_FIB (fib))
	  break;

      if (fib && fib->type != ZEBRA_ROUTE_BGP)
	{
	  route_unlock_node (rn);
	  return 1;
	}

      route_unlock_node (rn);

      rn = rn->parent;
      if (rn)
	route_lock_node (rn);
    }
  return 0;
}


void
print_ip_route_vty (struct vty *vty, struct rib *rib, struct prefix *p)
{
  int len;
  char buf[BUFSIZ];

  if (rib->type != ZEBRA_ROUTE_KERNEL && rib->type != ZEBRA_ROUTE_CONNECT)
    len = vty_out (vty, "%s%c %s/%d [%d/%d]",
		   route_info[rib->type].str,
		   IS_RIB_FIB (rib) ? '*' : ' ',
		   inet_ntop (AF_INET, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen,
		   rib->distance, rib->metric);
  else
    len = vty_out (vty, "%s%c %s/%d",
		   route_info[rib->type].str,
		   IS_RIB_FIB (rib) ? '*' : ' ',
		   inet_ntop (AF_INET, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen);
  
  len = 26 - len;
  if (len < 0)
    len = 0;
  
  if (len)
    vty_out(vty, "%*s", len, " ");
  
  vty_out(vty, "%8s (%d) ",
	  ifindex2ifname (rib->u.ifindex), rib->u.ifindex);
  
  if (rib->type == ZEBRA_ROUTE_CONNECT)
    vty_out (vty, "direct");
  else if (IS_RIB_LINK (rib)) 
    vty_out (vty, "link");
  else
    vty_out (vty, "%s", inet_ntop (p->family, &rib->u.gate4,
				   buf, BUFSIZ));
  vty_out (vty, "%s", VTY_NEWLINE);
}

void
show_ip_route_vty (struct vty *vty, struct route_node *np)
{
#ifdef HAVE_IF_PSEUDO
  int len;
#endif /* HAVE_IF_PSEUDO */
  struct rib *rib;
  for (rib = np->info; rib; rib = rib->next)
    {
      print_ip_route_vty (vty, rib, &np->p);
    }
}

void
show_ip_route_type_vty (struct vty *vty, struct route_node *np, int type)
{
  struct rib *rib;
  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type)
	print_ip_route_vty (vty, rib, &np->p);
    }
}

void
show_ip_route_vty_detail (struct vty *vty, struct route_node *np)
{
  struct rib *rib;
  char buf[BUFSIZ];

  for (rib = np->info; rib; rib = rib->next)
    {
      vty_out (vty, "%c %s/%d%s", 
	       IS_RIB_FIB (rib) ? '*' : ' ',
	       inet_ntop (AF_INET, &np->p.u.prefix, buf, BUFSIZ),
	       np->p.prefixlen,
	       VTY_NEWLINE);
      vty_out (vty, "  Route type \"%s\"", route_info[rib->type].str_long,
	       VTY_NEWLINE);
      vty_out (vty, ", distance %d, metric %d%s", rib->distance, rib->metric,
	       VTY_NEWLINE);

      if (rib->type == ZEBRA_ROUTE_CONNECT)
	{
	  struct interface *ifp;
	  ifp = if_lookup_by_index (rib->u.ifindex);
	  vty_out (vty, "  Nexthop: %s%s", ifp->name,
		   VTY_NEWLINE);
	}
      else
	{
	  if (IS_RIB_LINK (rib))
	    vty_out (vty, "  Nexthop: %s%s", ifindex2ifname (rib->u.ifindex),
		     VTY_NEWLINE);
	  else
	    vty_out (vty, "  Nexthop: %s%s",
		     inet_ntop (np->p.family, &rib->u.gate4, buf, BUFSIZ),
		     VTY_NEWLINE);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

/* Command function calling from vty. */
DEFUN (show_ip_route, show_ip_route_cmd,
       "show ip route",
       SHOW_STR
       IP_STR
       "IP routing table\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *np;

  /* Show matched route. */
  if (argc == 1)
    {
      ret = str2prefix_ipv4 (argv[0], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      np = route_node_match (ipv4_rib_table, (struct prefix *) &p);
      if (np == NULL)
	{
	  vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      
      show_ip_route_vty_detail (vty, np);
      route_unlock_node (np);
      
      return CMD_SUCCESS;
    }

  /* Print header. */
  vty_out (vty, "Codes: K - kernel route, C - connected, S - static,"
	  " R - RIP, O - OSPF,%s        B - BGP, * - FIB route.%s%s",
	  VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  /* Show all IPv4 routes. */
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    show_ip_route_vty (vty, np);

  return CMD_SUCCESS;
}

ALIAS (show_ip_route, show_ip_route_addr_cmd,
       "show ip route A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")

DEFUN (show_ip_route_prefix, show_ip_route_prefix_cmd,
       "show ip route A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix match;
  struct prefix *p;
  struct route_node *rn;
  
  ret = str2prefix (argv[0], &match);
  if (! ret)
    {
      vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (ipv4_rib_table, &match);
  p = &rn->p;
  if (rn == NULL || p->prefixlen != match.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
      
  show_ip_route_vty_detail (vty, rn);
  route_unlock_node (rn);
      
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_protocol,
       show_ip_route_protocol_cmd,
       "show ip route (bgp|connected|kernel|ospf|rip|static)",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Border Gateway Protocol (BGP)\n"
       "Connected\n"
       "Kernel\n"
       "Open Shortest Path First (OSPF)\n"
       "Routing Information Protocol (RIP)\n"
       "Static routes\n")
{
  int route_type;
  struct route_node *np;

  if (strncmp (argv[0], "b", 1) == 0)
    route_type = ZEBRA_ROUTE_BGP;
  else if (strncmp (argv[0], "c", 1) == 0)
    route_type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "k", 1) ==0)
    route_type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "o", 1) == 0)
    route_type = ZEBRA_ROUTE_OSPF;
  else if (strncmp (argv[0], "r", 1) == 0)
    route_type = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "s", 1) == 0)
    route_type = ZEBRA_ROUTE_STATIC;
  else 
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Show all IPv4 routes. */
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    show_ip_route_type_vty (vty, np, route_type);  
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

void
rib_ipv6_nexthop_set (struct prefix_ipv6 *p, struct rib *rib)
{
  struct route_node *np;
  struct prefix_ipv6 tmp;
  struct rib *fib;

  /* Lookup rib */
  tmp.family = AF_INET6;
  tmp.prefixlen = 128;
  tmp.prefix = rib->u.gate6;

  np = route_node_match (ipv6_rib_table, (struct prefix *) &tmp);

  if (!np)
    return;

  for (fib = np->info; fib; fib = fib->next)
    if (IS_RIB_FIB (fib))
      break;

  if (! fib)
    {
      route_unlock_node (np);
      return;
    }

  if (fib->type == ZEBRA_ROUTE_CONNECT)
    {
      route_unlock_node (np);
      return;
    }

  /* Save original nexthop. */
  memcpy (&rib->i.gate6, &rib->u.gate6, sizeof (struct in6_addr));
  rib->i.ifindex = rib->u.ifindex;

  /* Copy new nexthop. */
  memcpy (&rib->u.gate6, &fib->u.gate6, sizeof (struct in6_addr));
  rib->u.ifindex = fib->u.ifindex;
  RIB_INTERNAL_SET (rib);

  route_unlock_node (np);
  
  return;
}

/* Compare two routing information base.  If same gateway and same
   interface index then return 1. */
int
rib_same_ipv6 (struct rib *rib, struct rib *fib)
{
  /* FIB may internal route. */
  if (IS_RIB_INTERNAL (fib))
    {
      if (IPV6_ADDR_SAME (&rib->u.gate6, &fib->i.gate6) &&
	  rib->u.ifindex == fib->i.ifindex)
	return 1;
    }
  else
    {
      if (IPV6_ADDR_SAME (&rib->u.gate6, &fib->u.gate6) &&
	  rib->u.ifindex == fib->u.ifindex)
	return 1;
    }
  return 0;
}

/* Add route to the routing table. */
int
rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p,
	      struct in6_addr *gate, unsigned int ifindex, int table)
{
  int distance;
  struct route_node *np;
  struct rib *rp;
  struct rib *rib;
  struct rib *fib;
  struct rib *same;
  int ret;
  u_int32_t metric = 0;

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

  rib = rib_create (type, flags, distance, ifindex, table, metric);

  if (gate)
    memcpy (&rib->u.gate6, gate, sizeof (struct in6_addr));
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
	  /* System route or same gateway route. */
	  if (rib_system_route (rib->type) || rib_same_ipv6 (rib, fib))
	    {
	      rib_fib_unset (np, fib);
	      rib_fib_set (np, rib);
	    }
	  else
	    {
	      /* Route change. */
	      kernel_delete_ipv6 (p, &fib->u.gate6, fib->u.ifindex, 
				  0, fib->table);
	      rib_fib_unset (np, fib);
	      
	      /* Internal route have to check nexthop. */
	      if (gate 
		  && ! IN6_IS_ADDR_LINKLOCAL (gate)
		  && (flags & ZEBRA_FLAG_INTERNAL))
		rib_ipv6_nexthop_set (p, rib);

	      /* OK install into the kernel. */
	      ret = kernel_add_ipv6 (p, gate ? &rib->u.gate6 : NULL,
                                     rib->u.ifindex, 0, rib->table);

	      /* If we can't install the route into the kernel. Old
                 route comes back.*/
	      if (ret != 0)
		{
#if 0
		  kernel_add_ipv6 (p, &fib->u.gate6, fib->u.ifindex, 
				   0, fib->table);
#endif /* 0 */
		  goto end;
		}
	      rib_fib_set (np, rib);
	    }
	}
    }
  else
    {
      if (! rib_system_route (rib->type))
	{
	  if (gate 
	      && ! IN6_IS_ADDR_LINKLOCAL (gate)
	      && (flags & ZEBRA_FLAG_INTERNAL))
	    rib_ipv6_nexthop_set (p, rib);

	  ret = kernel_add_ipv6 (p, gate ? &rib->u.gate6 : NULL,
                                 rib->u.ifindex, 0, rib->table);

	  /* If we can't install the route into the kernel. */
	  if (ret != 0)
            {
	      zlog_warn ("kernel add route failed: %s (%d)",
			 strerror (errno), errno);
	      goto end;
            }
	}
      rib_fib_set (np, rib);
    }

 end:

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
rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p,
		 struct in6_addr *gate, unsigned int ifindex, int table)
{
  int ret = 0;
  struct route_node *np;
  struct rib *rib;
  struct rib *fib;
  struct in6_addr nullgate;
  
  memset (&nullgate, 0, sizeof (struct in6_addr));
  p->family = AF_INET6;
  apply_mask_ipv6 (p);

  np = route_node_get (ipv6_rib_table, (struct prefix *) p);

  for (rib = np->info; rib; rib = rib->next)
    {
      if (rib->type == type &&
	  (!table || rib->table == table))
	{
#if 0
	  if (! gate)
            break;
#endif
	  if (IS_RIB_INTERNAL (rib))
	    {
	      if (rib->i.ifindex == ifindex && 
		  IPV6_ADDR_SAME (&rib->i.gate6, gate ? gate : &nullgate))
		break;
	    }
	  else
	    {
	      if (rib->u.ifindex == ifindex && 
		  IPV6_ADDR_SAME (&rib->u.gate6, gate ? gate : &nullgate))
		break;
	    }
	}
    }
      
  if (!rib)
    {
      char buf1[BUFSIZ];
      char buf2[BUFSIZ];

      if (gate)
	zlog_info ("route %s/%d via %s ifindex %d doesn't exist in rib",
		   inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ),
		   p->prefixlen,
		   inet_ntop (AF_INET6, gate, buf2, BUFSIZ),
		   ifindex);
      else
	zlog_info ("route %s/%d ifindex %d doesn't exist in rib",
		   inet_ntop (AF_INET6, &p->prefix, buf1, BUFSIZ), 
		   p->prefixlen,
		   ifindex);
      route_unlock_node (np);
      return ZEBRA_ERR_RTNOEXIST;
    }

  rib_log ("delete", (struct prefix *)p, rib);

  rib_delete_rib ((struct rib **)&np->info, rib);
  route_unlock_node (np);

  if (IS_RIB_FIB (rib))
    {
      if (! rib_system_route (type))
	{
	  ret = kernel_delete_ipv6 (p, gate ? &rib->u.gate6 : NULL,
                                    rib->u.ifindex, 0, rib->table);
	}

      /* Redistribute it. */
      redistribute_delete (np, rib);

      /* We should reparse rib and check if new fib appear or not. */
      fib = np->info;
      if (fib)
	{
	  if (! rib_system_route (fib->type))
	    {
	      ret = kernel_add_ipv6 (p, &fib->u.gate6, fib->u.ifindex, 
				     0, fib->table);

	      if (ret == 0)
		rib_fib_set (np, fib);
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
			    rib->u.ifindex, 0, rib->table);
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
       "ipv6 route X:X::X:X/M X:X::X:X",
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
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Gateway format check. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  /* We need rib error treatment here. */
  ret = rib_add_ipv6 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, 0);
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist%s", VTY_NEWLINE);
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable%s", VTY_NEWLINE);
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied%s", VTY_NEWLINE);
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
       "ipv6 route X:X::X:X/M X:X::X:X IFNAME",
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
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Gateway format check. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Interface name check. */
  ifp = if_lookup_by_name (argv[2]);
  if (!ifp)
    {
      vty_out (vty, "Can't find interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  /* We need rib error treatment here. */
  ret = rib_add_ipv6 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, ifp->ifindex, 0);
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist%s", VTY_NEWLINE);
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable%s", VTY_NEWLINE);
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied%s", VTY_NEWLINE);
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
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check gateway. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  ret = rib_delete_ipv6 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, 0);

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
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check gateway. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Interface name check. */
  ifp = if_lookup_by_name (argv[2]);
  if (!ifp)
    {
      vty_out (vty, "Can't find interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  ret = rib_delete_ipv6 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, ifp->ifindex, 0);

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
DEFUN (show_ipv6,
       show_ipv6_cmd,
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
  vty_out (vty, "Codes: K - kernel route, C - connected, S - static,"
	   " R - RIPng, O - OSPFv3,%s       B - BGP, * - FIB route.%s%s",
           VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

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

        if (IS_RIB_LINK (rib))
	  {
	    struct interface *ifp;
	    ifp = if_lookup_by_index (rib->u.ifindex);
	    vty_out (vty, "%*s %s%s", len,
		     " ",
		     ifp->name,
		     VTY_NEWLINE);
	  }
	else
	  vty_out (vty, "%*s %s%s", len,
		   " ",
		   inet_ntop (np->p.family, &rib->u.gate6, buf, BUFSIZ),
		   VTY_NEWLINE);
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

void
zebra_sweep_table (struct route_table *rib_table)
{
  struct route_node *np;
  struct rib *rib;
  struct rib *next;
  int ret = 0;

  for (np = route_top (rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = next)
      {
	next = rib->next;

        if ((rib->type == ZEBRA_ROUTE_KERNEL) && 
	    (rib->flags & ZEBRA_FLAG_SELFROUTE))
          {
	    if (np->p.family == AF_INET)
	      ret = kernel_delete_ipv4 ((struct prefix_ipv4 *)&np->p,
					&rib->u.gate4, rib->u.ifindex, 
					0, rib->table);
#ifdef HAVE_IPV6
	    else
	      ret = kernel_delete_ipv6 ((struct prefix_ipv6 *)&np->p,
					&rib->u.gate6, rib->u.ifindex, 
					0, rib->table);
#endif /* HAVE_IPV6 */
	    if (!ret)
	      {
		rib_delete_rib ((struct rib **)&np->info, rib);
		rib_free (rib);
		route_unlock_node (np);
	      }
          }
      }
}

void
zebra_sweep_route ()
{
  zebra_sweep_table (ipv4_rib_table);
#ifdef HAVE_IPV6  
  zebra_sweep_table (ipv6_rib_table);
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

/* IP node for static routes. */
struct cmd_node ip_node =
{
  IP_NODE,
  "",				/* This node has no interface. */
  1
};

/* Routing information base initialize. */
void
rib_init ()
{
  install_node (&ip_node, config_write_ip);

  ipv4_rib_table = route_table_init ();
  ipv4_rib_static = route_table_init ();
  install_element (VIEW_NODE, &show_ip_route_cmd);
  install_element (VIEW_NODE, &show_ip_route_addr_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_route_cmd);
  install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);
  

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

/* Interface change related functions. */

/* Check all static routes then install it into the kernel. */
void
rib_if_up (struct interface *ifp)
{
  int ret;
  struct route_node *rn;
  struct rib *rib;
  struct rib *best;
  struct interface *ifp_gate;

  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    {
      best = rn->info;

      /* Check most prefered route. */
      for (rib = rn->info; rib; rib = rib->next)
	{
	  if (rib->distance < best->distance)
	    best = rib;
	}

      if (best && ! IS_RIB_FIB (best))
	{
	  /* Check interface. */
	  if (IS_RIB_LINK (best))
	    {
#ifdef HAVE_IF_PSEUDO
	      /* route with unknown interface */
	      if (best->u.ifindex == INTERFACE_UNKNOWN &&
		  !strncmp(best->u.ifname,ifp->name,INTERFACE_NAMSIZ)){
		    best->u.ifindex=ifp->ifindex;
	      }
#endif /* HAVE_IF_PSEUDO */
	      if (best->u.ifindex == ifp->ifindex)
		{
		  ret = kernel_add_ipv4 ((struct prefix_ipv4 *)&rn->p,
					 NULL,
					 best->u.ifindex, best->flags, 0);
		  if (ret == 0)
		    RIB_FIB_SET (best);
		}
	    }
	  else
	    {
	      ifp_gate = if_lookup_address (best->u.gate4);
	      if (ifp_gate){
		if (ifp_gate->ifindex == ifp->ifindex)
		  {
		    /* route with unknown interface */
		    if (best->u.ifindex == INTERFACE_UNKNOWN){
		      best->u.ifindex=ifp->ifindex;
#ifdef HAVE_IF_PSEUDO
		      strncpy (best->u.ifname,ifp->name,INTERFACE_NAMSIZ);
#endif /* HAVE_IF_PSEUDO */
		    }

		    ret = kernel_add_ipv4 ((struct prefix_ipv4 *)&rn->p,
					   &best->u.gate4,
					   best->u.ifindex, best->flags, 0);
		    if (ret == 0)
		      RIB_FIB_SET (best);
		  }
	      }		
	    }
	}
    }
}

void
rib_if_down (struct interface *ifp)
{
  struct route_node *rn;
  struct rib *rib;

  /* Walk down all routes. */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    {
      for (rib = rn->info; rib; rib = rib->next)
	{
	  if (ifp->ifindex == rib->u.ifindex)
	    {
	      if (rib->type == ZEBRA_ROUTE_STATIC && IS_RIB_FIB (rib))
		{
		  RIB_FIB_UNSET (rib);
		}
	    }
	}
    }
}

void
rib_if_delete (struct interface *ifp)
{
  struct route_node *rn;
  struct rib *rib;

  /* Walk down all routes and remove them from FIB making ifindex UNKNOWN */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    {
      for (rib = rn->info; rib; rib = rib->next)
	{
	  if (ifp->ifindex == rib->u.ifindex)
	    {
#ifdef HAVE_IF_PSEUDO
	      if (IS_IF_PSEUDO(ifp)){
		rib->u.ifindex=INTERFACE_PSEUDO;
	      }
	      else
		rib->u.ifindex=INTERFACE_UNKNOWN;
#else
	      rib->u.ifindex=INTERFACE_UNKNOWN;
#endif /* HAVE_IF_PSEUDO */
	      if (IS_RIB_FIB (rib))
		{
		  RIB_FIB_UNSET (rib);
		}
	    }
	}
    }
}

#ifdef HAVE_IF_PSEUDO	    
void rib_ifindex_update_name(char *name,int ifindex_new)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib tmp_rib;
  struct prefix_ipv4 p;

  /* Walk down all routes and update ifindex */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    {
      for (rib = rn->info; rib; rib = rib->next)
	{
	  if (rib->u.ifname){
	    if (!strncmp(rib->u.ifname,name,INTERFACE_NAMSIZ)){
	      memset(&tmp_rib,0,sizeof (struct rib));
	      memcpy(&tmp_rib,rib,sizeof (struct rib));
	      memcpy(&p,(struct prefix_ipv4 *)&rn->p,sizeof (struct prefix_ipv4));

	      rib_delete_ipv4_pseudo(rib->type,rib->flags,
				     (struct prefix_ipv4 *)&rn->p,
				     &rib->u.gate4,rib->u.ifname,rib->table);
	      
	      tmp_rib.u.ifindex=ifindex_new;
#ifdef DEBUG
	      printf ("rib ifname %s ifindex %d will be added",
		      tmp_rib.u.ifname , tmp_rib.u.ifindex);
#endif /* DEBUG */	      
	      rib_add_ipv4(tmp_rib.type,tmp_rib.flags,&p,
			   NULL,tmp_rib.u.ifindex,tmp_rib.table,0 ,0);
	    }	    
	  }
	}
    }  
}
#endif /* HAVE_IF_PSEUDO */     
