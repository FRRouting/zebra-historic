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
#include "vty.h"
#include "str.h"
#include "command.h"
#include "linklist.h"
#include "if.h"
#include "rib.h"
#include "rt.h"
#include "log.h"
#include "sockunion.h"
#include "thread.h"

#include "zebra/zserv.h"
#include "zebra/redistribute.h"

/* Routing information base. */
struct route_table *ipv4_rib_table;
struct route_table *static_ipv4_table;
#ifdef HAVE_IPV6
struct route_table *ipv6_rib_table;
struct route_table *ipv6_rib_static;
#endif /* HAVE_IPV6 */

/* Default rtm_table for all clients */
extern int rtm_table_default;

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

struct static_ipv6
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

struct static_ipv6 *
static_ipv6_new ()
{
  struct static_ipv6 *new;
  new = XMALLOC (MTYPE_NEXTHOP, sizeof (struct static_ipv6));
  bzero (new, sizeof (struct static_ipv6));
  return new;
}

void
static_ipv6_free (struct static_ipv6 *nexthop)
{
  if (nexthop->ifname)
    free (nexthop->ifname);
  XFREE (MTYPE_NEXTHOP, nexthop);
}

#ifdef HAVE_IF_PSEUDO
/* New routing information base. */
struct rib *
rib_create (int type, u_char flags, int distance, int ifindex,
	    char *ifname, int table)
{
  struct rib *new;

  new = XMALLOC (MTYPE_RIB, sizeof (struct rib));
  bzero (new, sizeof (struct rib));
  new->type = type;
  new->flags = flags;
  new->distance = distance;
  new->u.ifindex = ifindex;
  new->table = table;

  if (ifname)
    strncpy(new->u.ifname, ifname, INTERFACE_NAMSIZ);

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

/* If type is system route's type then return 1. */
int
rib_system_route (type)
{
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    return 1;
  else
    return 0;
}

#ifndef OLD_RIB

/* Add nexthop to the end of the list.  */
void
nexthop_add (struct new_rib *rib, struct nexthop *nexthop)
{
  struct nexthop *last;

  for (last = rib->nexthop; last && last->next; last = last->next)
    ;
  if (last)
    last->next = nexthop;
  else
    rib->nexthop = nexthop;
  nexthop->prev = last;

  rib->nexthop_num++;
}

/* Delete specified nexthop from the list. */
void
nexthop_delete (struct new_rib *rib, struct nexthop *nexthop)
{
  if (nexthop->next)
    nexthop->next->prev = nexthop->prev;
  if (nexthop->prev)
    nexthop->prev->next = nexthop->next;
  else
    rib->nexthop = nexthop->next;
  rib->nexthop_num--;
}

/* Free nexthop. */
void
nexthop_free (struct nexthop *nexthop)
{
  if (nexthop->type == NEXTHOP_TYPE_IFNAME && nexthop->gate.ifname)
    free (nexthop->gate.ifname);
  XFREE (MTYPE_NEXTHOP, nexthop);
}

struct nexthop *
nexthop_ifindex_add (struct new_rib *rib, unsigned int ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IFINDEX;
  nexthop->ifindex = ifindex;

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ifname_add (struct new_rib *rib, char *ifname)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->type = NEXTHOP_TYPE_IFNAME;
  nexthop->gate.ifname = strdup (ifname);

  nexthop_add (rib, nexthop);

  return nexthop;
}

struct nexthop *
nexthop_ipv4_add (struct new_rib *rib, 
		  struct in_addr *ipv4, 
		  unsigned int krnl_ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->krnl_ifindex = krnl_ifindex;
  nexthop->type = NEXTHOP_TYPE_IPV4;
  nexthop->gate.ipv4 = *ipv4;

  nexthop_add (rib, nexthop);

  return nexthop;
}

#ifdef HAVE_IPV6
struct nexthop *
nexthop_ipv6_add (struct new_rib *rib, 
		  struct in6_addr *ipv6,
		  unsigned int krnl_ifindex)
{
  struct nexthop *nexthop;

  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
  memset (nexthop, 0, sizeof (struct nexthop));
  nexthop->krnl_ifindex = krnl_ifindex;
  nexthop->type = NEXTHOP_TYPE_IPV6;
  nexthop->gate.ipv6 = *ipv6;

  nexthop_add (rib, nexthop);

  return nexthop;
}
#endif /* HAVE_IPV6 */

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
int
nexthop_active_ipv4 (struct new_rib *rib, struct nexthop *nexthop, int set,
		     struct route_node *top)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct new_rib *match;
  struct nexthop *newhop;

  nexthop->ifindex = 0;

  if (set)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

  /* Make lookup prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = nexthop->gate.ipv4;

  rn = route_node_match (ipv4_rib_table, (struct prefix *) &p);
  while (rn)
    {
      route_unlock_node (rn);
      
      /* If lookup self prefix return immidiately. */
      if (rn == top)
	return 0;

      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, RIB_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    {
	      /* Directly point connected route. */
	      newhop = match->nexthop;
	      if (newhop)
		nexthop->ifindex = newhop->ifindex;
	      
	      return 1;
	    }
	  else if (CHECK_FLAG (rib->flags, RIB_FLAG_INTERNAL))
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB)
		    && ! CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
		  {
		    if (set)
		      {
			SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
			nexthop->rtype = newhop->type;
			if (newhop->type == NEXTHOP_TYPE_IPV4)
			  nexthop->rgate.ipv4 = newhop->gate.ipv4;
			if (newhop->type == NEXTHOP_TYPE_IFINDEX
			    || newhop->type == NEXTHOP_TYPE_IFNAME)
			  nexthop->rifindex = newhop->ifindex;
		      }
		    return 1;
		  }
	      return 0;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

int
nexthop_active_check (struct route_node *rn, struct new_rib *rib,
		      struct nexthop *nexthop, int set)
{
  struct interface *ifp;

  switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IFINDEX:
      ifp = if_lookup_by_index (nexthop->ifindex);
      if (ifp && if_is_up (ifp))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    case NEXTHOP_TYPE_IFNAME:
      ifp = if_lookup_by_name (nexthop->gate.ifname);
      if (ifp && if_is_up (ifp))
	{
	  if (set)
	    nexthop->ifindex = ifp->ifindex;
	  SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      else
	{
	  if (set)
	    nexthop->ifindex = 0;
	  UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
	}
      break;
    case NEXTHOP_TYPE_IPV4:
      if (nexthop_active_ipv4 (rib, nexthop, set, rn))
	SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      else
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      break;
    }
  return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

int
nexthop_active_update (struct route_node *rn, struct new_rib *rib, int set)
{
  struct nexthop *nexthop;
  int active;

  rib->nexthop_active_num = 0;
  UNSET_FLAG (rib->flags, RIB_FLAG_CHANGED);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
      rib->nexthop_active_num += nexthop_active_check (rn, rib, nexthop, set);
      if (active != CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	SET_FLAG (rib->flags, RIB_FLAG_CHANGED);
    }
  return rib->nexthop_active_num;
}

#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

void
newrib_free (struct new_rib *rib)
{
  struct nexthop *nexthop;
  struct nexthop *next;

  for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      nexthop_free (nexthop);
    }
  XFREE (MTYPE_RIB, rib);
}

void
rib_install_kernel (struct route_node *rn, struct new_rib *rib)
{
  int ret;
  struct nexthop *nexthop;

  ret = kernel_add_ipv4_multipath (&rn->p, rib);

  if (ret < 0)
    {
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}

/* Uninstall the route from kernel. */
int
rib_uninstall_kernel (struct route_node *rn, struct new_rib *rib)
{
  int ret;
  struct nexthop *nexthop;

  ret = kernel_delete_ipv4_multipath (&rn->p, rib);

  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  return ret;
}

/* Uninstall the route from kernel. */
void
rib_uninstall (struct route_node *rn, struct new_rib *rib)
{
  if (CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED))
    {
      redistribute_delete_multipath (rn, rib);
      if (! RIB_SYSTEM_ROUTE (rib))
	rib_uninstall_kernel (rn, rib);
      UNSET_FLAG (rib->flags, RIB_FLAG_SELECTED);
    }
}

/* Core function for processing routing information base. */
void
rib_process (struct route_node *rn, struct new_rib *del)
{
  struct new_rib *rib;
  struct new_rib *fib = NULL;
  struct new_rib *select = NULL;

  for (rib = rn->info; rib; rib = rib->next)
    {
      /* Currently installed rib. */
      if (CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED))
	fib = rib;

      /* Skip unreachable nexthop. */
      if (! nexthop_active_update (rn, rib, 0))
	continue;

      /* Infinit distance. */
      if (rib->distance == DISTANCE_INFINITY)
	continue;

      /* Newly selected rib. */
      if (! select || rib->distance < select->distance)
	select = rib;
    }

  /* Deleted route check. */
  if (del && CHECK_FLAG (del->flags, RIB_FLAG_SELECTED))
    fib = del;

  /* Same route is selected. */
  if (select && select == fib)
    {
      if (CHECK_FLAG (select->flags, RIB_FLAG_CHANGED))
	{
	  redistribute_delete_multipath (rn, select);
	  if (! RIB_SYSTEM_ROUTE (select))
	    rib_uninstall_kernel (rn, select);

	  /* Set real nexthop. */
	  nexthop_active_update (rn, select, 1);
  
	  if (! RIB_SYSTEM_ROUTE (select))
	    rib_install_kernel (rn, select);
	  redistribute_add_multipath (rn, select);
	}
      return;
    }

  /* Uninstall old rib from forwarding table. */
  if (fib)
    {
      redistribute_delete_multipath (rn, fib);
      if (! RIB_SYSTEM_ROUTE (fib))
	rib_uninstall_kernel (rn, fib);
      UNSET_FLAG (fib->flags, RIB_FLAG_SELECTED);

      /* Set real nexthop. */
      nexthop_active_update (rn, fib, 1);
    }

  /* Install new rib into forwarding table. */
  if (select)
    {
      /* Set real nexthop. */
      nexthop_active_update (rn, select, 1);

      if (! RIB_SYSTEM_ROUTE (select))
	rib_install_kernel (rn, select);
      SET_FLAG (select->flags, RIB_FLAG_SELECTED);
      redistribute_add_multipath (rn, select);
    }
}

/* Add RIB to head of the route node. */
void
rib_addnode (struct route_node *rn, struct new_rib *rib)
{
  struct new_rib *head;

  head = rn->info;
  if (head)
    head->prev = rib;
  rib->next = head;
  rn->info = rib;
}

void
rib_delnode (struct route_node *rn, struct new_rib *rib)
{
  if (rib->next)
    rib->next->prev = rib->prev;
  if (rib->prev)
    rib->prev->next = rib->next;
  else
    rn->info = rib->next;
}

int
rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, 
	      struct in_addr *gate, unsigned int ifindex, int table,
	      u_int32_t metric, u_char distance)
{
  struct new_rib *rib;
  struct new_rib *same = NULL;
  struct route_node *rn;
  struct nexthop *nexthop;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask_ipv4 (p);

  /* Set default distance by route type. */
  if (distance == 0)
    {
      distance = route_info[type].distance;

      /* iBGP distance is 200. */
      if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
	distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == type)
      {
	same = rib;
	rib_delnode (rn, same);
	route_unlock_node (rn);
	break;
      }

  /* Allocate new rib structure. */
  rib = XMALLOC (MTYPE_RIB, sizeof (struct new_rib));
  memset (rib, 0, sizeof (struct new_rib));
  rib->type = type;
  rib->distance = distance;
  rib->flags = flags;
  rib->metric = metric;
  rib->table = table;
  rib->nexthop_num = 0;

  if (CHECK_FLAG (flags, ZEBRA_FLAG_INTERNAL))
    SET_FLAG (rib->flags, RIB_FLAG_INTERNAL);
  
  /* Nexthop settings. */
  if (gate)
    /* Pass through ifindex so that we can keep track of kernel routes */
    nexthop_ipv4_add (rib, gate, ifindex);
  else
    nexthop_ifindex_add (rib, ifindex);

  /* If this route is kernel route, set FIB flag to the route. */
  if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);

  /* Process this route node. */
  rib_process (rn, same);

  /* Free implicit route.*/
  if (same)
    newrib_free (same);

  return 0;
}

int
rib_add_ipv4_multipath (struct prefix_ipv4 *p, struct new_rib *rib)
{
  struct route_node *rn;
  struct new_rib *same;
  struct nexthop *nexthop;

  /* Make it sure prefixlen is applied to the prefix. */
  apply_mask_ipv4 (p);

  /* Set default distance by route type. */
  if (rib->distance == 0)
    {
      rib->distance = route_info[rib->type].distance;

      /* iBGP distance is 200. */
      if (rib->type == ZEBRA_ROUTE_BGP 
	  && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
	rib->distance = 200;
    }

  /* Lookup route node.*/
  rn = route_node_get (ipv4_rib_table, (struct prefix *) p);

  /* If same type of route are installed, treat it as a implicit
     withdraw. */
  for (same = rn->info; same; same = same->next)
    if (same->type == rib->type)
      {
	rib_delnode (rn, same);
	route_unlock_node (rn);
	break;
      }

  /* Allocate new rib structure. */
  if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
    SET_FLAG (rib->flags, RIB_FLAG_INTERNAL);
  
  /* If this route is kernel route, set FIB flag to the route. */
  if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
      SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

  /* Link new rib to node.*/
  rib_addnode (rn, rib);

  /* Process this route node. */
  rib_process (rn, same);

  /* Free implicit route.*/
  if (same)
    newrib_free (same);

  return 0;
}

int
rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p,
		 struct in_addr *gate, unsigned int ifindex, int table)
{
  struct route_node *rn;
  struct new_rib *rib;
  struct new_rib *fib = NULL;
  struct new_rib *same = NULL;
  struct nexthop *nexthop;

  /* Apply mask. */
  apply_mask_ipv4 (p);

  /* Lookup route node. */
  rn = route_node_lookup (ipv4_rib_table, (struct prefix *) p);
  if (! rn)
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
      return ZEBRA_ERR_RTNOEXIST;
    }

  /* Lookup same type route. */
  for (rib = rn->info; rib; rib = rib->next)
    {
      if (CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED))
	fib = rib;

      if (rib->type == type && rib->table == table)
	same = rib;
    }

  /* If same type of route can't be found and this message is from
     kernel. */
  if (! same)
    {
      if (fib && type == ZEBRA_ROUTE_KERNEL)
	{
	  /* Unset flags. */
	  for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
	    UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

	  UNSET_FLAG (fib->flags, RIB_FLAG_SELECTED);
	}
      else
	{
	  char buf1[BUFSIZ];
	  char buf2[BUFSIZ];

	  if (gate)
	    zlog_info ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
		       inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       inet_ntop (AF_INET, gate, buf2, BUFSIZ),
		       ifindex,
		       type);
	  else
	    zlog_info ("route %s/%d ifindex %d type %d doesn't exist in rib",
		       inet_ntop (AF_INET, &p->prefix, buf1, BUFSIZ),
		       p->prefixlen,
		       ifindex,
		       type);
	  return ZEBRA_ERR_RTNOEXIST;
	}
    }

  if (same)
    rib_delnode (rn, same);

  rib_process (rn, same);

  if (same)
    {
      newrib_free (same);
      route_unlock_node (rn);
    }

  route_unlock_node (rn);

  return 0;
}

/* Checks whether a route is in the RIB or not */
int
rib_check_for_connected_ipv4(struct prefix_ipv4 *p, unsigned int ifindex ) 
{
  struct route_node *rn;
  struct new_rib *rib;
  struct nexthop *nexthop;

  rn = route_node_lookup (ipv4_rib_table, (struct prefix *)p);
  if (!rn)
    return 0;

  for (rib = rn->info; rib; rib = rib->next)
    {
      if (rib->type != ZEBRA_ROUTE_CONNECT 
	  || rib->table != 0)
	continue;

      
      if (!ifindex)
	{
	  route_unlock_node (rn);
	  return 1;
	}

      /* Scan nexthops to check ifindex */
      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	{
	  if (nexthop->type != NEXTHOP_TYPE_IFINDEX)
	    continue;
	  
	  if (nexthop->ifindex != ifindex)
	    continue;

	  route_unlock_node (rn);
	  return 1;
	}
    }

  route_unlock_node (rn);
  return 0;
}


/* Install static route into rib. */
void
rib_static_install (struct prefix_ipv4 *p, struct static_ipv4 *si)
{
  struct new_rib *rib;
  struct route_node *rn;

  /* Lookup existing route */
  rn = route_node_get (ipv4_rib_table, (struct prefix *) p);
  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;

  if (rib)
    {
      /* Same distance static route is there.  Update it with new
         nexthop. */
      rib_uninstall (rn, rib);
      route_unlock_node (rn);

      if (CHECK_FLAG (si->flags, STATIC_IPV4_GATEWAY))
	nexthop_ipv4_add (rib, &si->gate.ipv4, 0);
      if (CHECK_FLAG (si->flags, STATIC_IPV4_IFNAME))
	nexthop_ifname_add (rib, si->gate.ifname);

      rib_process (rn, NULL);
    }
  else
    {
      /* This is new static route. */
      rib = XMALLOC (MTYPE_RIB, sizeof (struct new_rib));
      memset (rib, 0, sizeof (struct new_rib));

      rib->type = ZEBRA_ROUTE_STATIC;
      rib->distance = si->distance;
      rib->metric = 0;
      rib->nexthop_num = 0;

      if (CHECK_FLAG (si->flags, STATIC_IPV4_GATEWAY))
	nexthop_ipv4_add (rib, &si->gate.ipv4, 0);
      if (CHECK_FLAG (si->flags, STATIC_IPV4_IFNAME))
	nexthop_ifname_add (rib, si->gate.ifname);

      /* Link this rib to the tree. */
      rib_addnode (rn, rib);

      /* Process this prefix. */
      rib_process (rn, NULL);
    }
}

int
rib_static_nexthop_same (struct nexthop *nexthop, struct static_ipv4 *si)
{
  if (nexthop->type == NEXTHOP_TYPE_IPV4
      && CHECK_FLAG (si->flags, STATIC_IPV4_GATEWAY)
      && IPV4_ADDR_SAME (&nexthop->gate.ipv4, &si->gate.ipv4))
    return 1;
  if (nexthop->type == NEXTHOP_TYPE_IFNAME
      && CHECK_FLAG (si->flags, STATIC_IPV4_IFNAME)
      && strcmp (nexthop->gate.ifname, si->gate.ifname) == 0)
    return 1;
  return 0;;
}

/* Update all static route status to check nexthop. */
void
static_ipv4_update ()
{
  struct route_node *rn;
  struct route_node *ribrn;

  for (rn = route_top (static_ipv4_table); rn; rn = route_next (rn))
    if (rn->info)
      {
	ribrn = route_node_get (ipv4_rib_table, &rn->p);
	rib_process (ribrn, NULL);
	route_unlock_node (ribrn);
      }
}

/* Uninstall static route from RIB. */
void
rib_static_uninstall (struct prefix_ipv4 *p, struct static_ipv4 *si)
{
  struct route_node *rn;
  struct new_rib *rib;
  struct nexthop *nexthop;

  /* Lookup existing route with type and distance. */
  rn = route_node_lookup (ipv4_rib_table, (struct prefix *) p);
  if (! rn)
    return;

  for (rib = rn->info; rib; rib = rib->next)
    if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
      break;
  if (! rib)
    {
      route_unlock_node (rn);
      return;
    }

  /* Lookup nexthop. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    if (rib_static_nexthop_same (nexthop, si))
      break;

  /* Can't find nexthop. */
  if (! nexthop)
    {
      route_unlock_node (rn);
      return;
    }
  
  /* Check nexthop. */
  if (rib->nexthop_num == 1)
    {
      rib_delnode (rn, rib);
      rib_process (rn, rib);
      newrib_free (rib);
      route_unlock_node (rn);
    }
  else
    {
      rib_uninstall (rn, rib);
      nexthop_delete (rib, nexthop);
      nexthop_free (nexthop);
      rib_process (rn, rib);
    }

  /* Unlock node. */
  route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int
static_ipv4_add (struct prefix_ipv4 *p, struct in_addr *gate, char *ifname,
		 u_char distance, int table)
{
  u_char flags = 0;
  struct route_node *rn;
  struct static_ipv4 *si;
  struct static_ipv4 *pp;
  struct static_ipv4 *cp;
  
  /* Lookup static route prefix. */
  rn = route_node_get (static_ipv4_table, (struct prefix *) p);

  /* Make flags. */
  if (gate)
    SET_FLAG (flags, STATIC_IPV4_GATEWAY);
  if (ifname)
    SET_FLAG (flags, STATIC_IPV4_IFNAME);

  /* Do nothing if there is a same static route.  */
  for (si = rn->info; si; si = si->next)
    {
      if (distance == si->distance 
	  && flags == si->flags
	  && (! gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4))
	  && (! ifname || strcmp (ifname, si->gate.ifname) == 0))
	{
	  route_unlock_node (rn);
	  return 0;
	}
    }

  /* Make new static route structure. */
  si = XMALLOC (MTYPE_STATIC_IPV4, sizeof (struct static_ipv4));
  memset (si, 0, sizeof (struct static_ipv4));

  si->flags = flags;
  si->distance = distance;

  if (gate)
    si->gate.ipv4 = *gate;
  if (ifname)
    si->gate.ifname = XSTRDUP (0, ifname);

  /* Add new static route information to the tree with sort by
     distance value and gateway address. */
  for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
      if (si->distance < cp->distance)
	break;
      if (si->distance > cp->distance)
	continue;
      if (CHECK_FLAG (si->flags, STATIC_IPV4_GATEWAY) 
	  && CHECK_FLAG (cp->flags, STATIC_IPV4_GATEWAY))
	{
	  if (ntohl (si->gate.ipv4.s_addr) < ntohl (cp->gate.ipv4.s_addr))
	    break;
	  if (ntohl (si->gate.ipv4.s_addr) > ntohl (cp->gate.ipv4.s_addr))
	    continue;
	}
    }

  /* Make linked list. */
  if (pp)
    pp->next = si;
  else
    rn->info = si;
  if (cp)
    cp->prev = si;
  si->prev = pp;
  si->next = cp;

  /* Install into rib. */
  rib_static_install (p, si);

  return 1;
}

/* Delete static route from static route configuration. */
int
static_ipv4_delete (struct prefix_ipv4 *p, struct in_addr *gate, char *ifname,
		    u_char distance, int table)
{
  u_char flags = 0;
  struct route_node *rn;
  struct static_ipv4 *si;

  /* Lookup static route prefix. */
  rn = route_node_lookup (static_ipv4_table, (struct prefix *) p);
  if (! rn)
    return 0;

  /* Make flags. */
  if (gate)
    SET_FLAG (flags, STATIC_IPV4_GATEWAY);
  if (ifname)
    SET_FLAG (flags, STATIC_IPV4_IFNAME);

  /* Find same static route is the tree */
  for (si = rn->info; si; si = si->next)
    if (distance == si->distance 
	&& flags == si->flags
	&& (! gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4))
	&& (! ifname || strcmp (ifname, si->gate.ifname) == 0))
      break;

  /* Can't find static route. */
  if (! si)
    {
      route_unlock_node (rn);
      return 0;
    }

  /* Install into rib. */
  rib_static_uninstall (p, si);

  /* Unlink static route from linked list. */
  if (si->prev)
    si->prev->next = si->next;
  else
    rn->info = si->next;
  if (si->next)
    si->next->prev = si->prev;
  
  /* Free static route configuration. */
  XFREE (MTYPE_STATIC_IPV4, si);

  return 1;
}

/* Write IPv4 static route configuration. */
int
static_ipv4_write (struct vty *vty)
{
  struct route_node *rn;
  struct static_ipv4 *si;  

  for (rn = route_top (static_ipv4_table); rn; rn = route_next (rn))
    for (si = rn->info; si; si = si->next)
      {
	vty_out (vty, "ip route %s/%d", inet_ntoa (rn->p.u.prefix4),
		 rn->p.prefixlen);
	if (CHECK_FLAG (si->flags, STATIC_IPV4_GATEWAY))
	  vty_out (vty, " %s", inet_ntoa (si->gate.ipv4));
	if (CHECK_FLAG (si->flags, STATIC_IPV4_IFNAME))
	  vty_out (vty, " %s", si->gate.ifname);
	if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
	  vty_out (vty, " %d", si->distance);
	vty_out (vty, "%s", VTY_NEWLINE);
      }
  return 0;
}

/* General fucntion for static route. */
int
static_ipv4_func (struct vty *vty, int add_cmd,
		  char *dest_str, char *mask_str, char *gate_str,
		  char *distance_str)
{
  int ret;
  u_char distance;
  struct prefix_ipv4 p;
  struct in_addr gate;
  struct in_addr mask;
  char *ifname;
  int table = rtm_table_default;
  
  ret = str2prefix_ipv4 (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Cisco like mask notation. */
  if (mask_str)
    {
      ret = inet_aton (mask_str, &mask);
      if (ret == 0)
	{
	  vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      p.prefixlen = ip_masklen (mask);
    }

  /* Apply mask for given prefix. */
  apply_mask_ipv4 (&p);

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* When gateway is A.B.C.D format, gate is treated as nexthop
     address other case gate is treated as interface name. */
  ret = inet_aton (gate_str, &gate);
  if (ret)
    ifname = NULL;
  else
    ifname = gate_str;

  if (add_cmd)
    static_ipv4_add (&p, ifname ? NULL : &gate, ifname, distance, table);
  else
    static_ipv4_delete (&p, ifname ? NULL : &gate, ifname, distance, table);

  /* static_ipv4_update (); */

  return CMD_SUCCESS;
}

/* Static route configuration. */
DEFUN (ip_route, 
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 1, argv[0], NULL, argv[1], NULL);
}

DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 1, argv[0], argv[1], argv[2], NULL);
}

DEFUN (ip_route_pref,
       ip_route_pref_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 1, argv[0], NULL, argv[1], argv[2]);
}

DEFUN (ip_route_mask_pref,
       ip_route_mask_pref_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 1, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 0, argv[0], NULL, argv[1], NULL);
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")
{
  return static_ipv4_func (vty, 0, argv[0], argv[1], argv[2], NULL);
}

DEFUN (no_ip_route_pref,
       no_ip_route_pref_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 0, argv[0], NULL, argv[1], argv[2]);
}

DEFUN (no_ip_route_mask_pref,
       no_ip_route_mask_pref_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")
{
  return static_ipv4_func (vty, 0, argv[0], argv[1], argv[2], argv[3]);
}
#else
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
	      if (! rib_system_route (rib->type))
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
#endif /* ! OLD_RIB */

#ifdef OLD_RIB
#ifndef HAVE_IF_PSEUDO
DEFUN (ip_route, 
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;

  /* a.b.c.d/mask gateway format. */
  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Gateway. */
  ret = inet_aton (argv[1], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", 
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ifindex = ifp->ifindex;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv4 (&p);

  /* We need rib error treatment here. */
  if (ifindex)
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table, 0, 0);
  else
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table, 0, 0);

  /* Error checking and display message. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix), p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix\n"
       "IP destination netmask\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;
  struct in_addr tmpmask;

  /* A.B.C.D */
  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* X.X.X.X */
  ret = inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  p.prefixlen = ip_masklen (tmpmask);

  /* Gateway. */
  ret = inet_aton (argv[2], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[2]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ifindex = ifp->ifindex;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv4 (&p);

  /* We need rib error treatment here. */
  if (ifindex)
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table, 0, 0);
  else
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table, 0, 0);

  /* Error checking and display meesage. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "Same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix),
	       p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|unknown)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n"
       "unknown interface\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask_ipv4 (&p);

  /* Gateway. */
  ret = inet_aton (argv[1], &gate);

  /* direct route */
  if (!ret)	
    {
      /* route on "unknown" interface */
      if (!strcmp(argv[1],"unknown")){
	ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, INTERFACE_UNKNOWN, table);
      }

      /* route on known interface */
      else{
	ifp = if_lookup_by_name (argv[1]);
	if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ifindex = ifp->ifindex;
      ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table);
      }
    }
  /* route with gateway */
  else {
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table);
  }
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix),
	       p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix\n"
       "IP destination netmask\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  struct in_addr tmpmask;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING; 
    }
  inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING; 
    }
  p.prefixlen = ip_masklen (tmpmask);
      
  ret = inet_aton (argv[2], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ifindex = ifp->ifindex;
    }

  /* Make sure mask is applied. */
  apply_mask_ipv4 (&p);

  if (ifindex)
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table);
  else
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table);

  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix),
	       p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}
#else
DEFUN (ip_route, 
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  struct interface *ifp;

  /* a.b.c.d/mask gateway format. */
  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv4 (&p);

  /* Gateway. */
  ret = inet_aton (argv[1], &gate);

  /* direct route */
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", 
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (IS_IF_PSEUDO(ifp)){
	ret = rib_add_ipv4_pseudo (ZEBRA_ROUTE_STATIC, 0 , &p, NULL, ifp->name, table);
      }
      else {
	ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifp->ifindex, table, 0, 0);
      }
    }
  /* route with gateway */
  else {
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table, 0, 0);
  }
    

  /* Error checking and display message. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix), p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}
DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix\n"
       "IP destination netmask\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  struct interface *ifp;
  struct in_addr tmpmask;

  /* A.B.C.D */
  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* X.X.X.X */
  ret = inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  p.prefixlen = ip_masklen (tmpmask);

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv4 (&p);

  /* Gateway. */
  ret = inet_aton (argv[2], &gate);

  /* direct route */
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[2]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid%s", 
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (IS_IF_PSEUDO(ifp)){
	ret = rib_add_ipv4_pseudo (ZEBRA_ROUTE_STATIC, 0 , &p, NULL, ifp->name, table);
      }
      else {
	ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifp->ifindex, table, 0 ,0);
      }
    }
  /* route with gateway */
  else {
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table, 0, 0);
  }
    

  /* Error checking and display message. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix), p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}
DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask_ipv4 (&p);

  /* Gateway. */
  ret = inet_aton (argv[1], &gate);

  /* direct route */
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  /* route on deleted interface */
	  if (rib_delete_ipv4_pseudo(ZEBRA_ROUTE_STATIC, 0, &p, NULL,
				     argv[1], table) == ZEBRA_ERR_RTNOEXIST){
	    vty_out (vty, "Gateway address or device name is invalid%s", VTY_NEWLINE);
	    return CMD_WARNING;
	  }
	}
      ifindex = ifp->ifindex;
      if (IS_IF_PSEUDO(ifp)){
	ret = rib_delete_ipv4_pseudo (ZEBRA_ROUTE_STATIC, 0, &p, NULL,
				      ifp->name, table);
      }
      else{
	ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table);
      }
    }
  /* route with gateway */
  else {
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table);
  }
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix),
	       p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP destination prefix\n"
       "IP destination netmask\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  struct in_addr tmpmask;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING; 
    }
  inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING; 
    }
  p.prefixlen = ip_masklen (tmpmask);
      
  /* Make sure mask is applied. */
  apply_mask_ipv4 (&p);

  /* Gateway. */
  ret = inet_aton (argv[2], &gate);

  /* direct route */
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[2]);
      if (! ifp)
	{
	  /* route on deleted interface */
	  if (rib_delete_ipv4_pseudo(ZEBRA_ROUTE_STATIC, 0, &p, NULL,
				     argv[2], table) == ZEBRA_ERR_RTNOEXIST){
	    vty_out (vty, "Gateway address or device name is invalid%s", VTY_NEWLINE);
	    return CMD_WARNING;
	  }
	}
      ifindex = ifp->ifindex;
      if (IS_IF_PSEUDO(ifp)){
	ret = rib_delete_ipv4_pseudo (ZEBRA_ROUTE_STATIC, 0, &p, NULL,
				      ifp->name, table);
      }
      else{
	ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, NULL, ifindex, table);
      }
    }
  /* route with gateway */
  else {
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, 0, &p, &gate, 0, table);
  }
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.%s", inet_ntoa (p.prefix),
	       p.prefixlen,
	       VTY_NEWLINE);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

#endif /* HAVE_IF_PSEUDO */
#endif /* OLD_RIB */

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

#ifdef OLD_RIB
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
#endif /* OLD_RIB */

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
#ifdef OLD_RIB
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
#else
void
rib_close_ipv4 ()
{
  struct route_node *rn;
  struct new_rib *rib;

  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (! RIB_SYSTEM_ROUTE (rib)
	  && CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED))
	rib_uninstall_kernel (rn, rib);
}
#endif /* OLD_RIB */

#ifdef OLD_RIB
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
#else
struct new_rib *
rib_lookup_ipv4_nexthop (struct in_addr addr)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct new_rib *match;
  struct nexthop *newhop;

  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = addr;

  rn = route_node_match (ipv4_rib_table, (struct prefix *) &p);

  while (rn)
    {
      route_unlock_node (rn);
      
      /* Pick up selected route. */
      for (match = rn->info; match; match = match->next)
	if (CHECK_FLAG (match->flags, RIB_FLAG_SELECTED))
	  break;

      /* If there is no selected route or matched route is EGP, go up
         tree. */
      if (! match || match->type == ZEBRA_ROUTE_BGP)
	{
	  do {
	    rn = rn->parent;
	  } while (rn && rn->info == NULL);
	  if (rn)
	    route_lock_node (rn);
	}
      else
	{
	  if (match->type == ZEBRA_ROUTE_CONNECT)
	    /* Directly point connected route. */
	    return match;
	  else
	    {
	      for (newhop = match->nexthop; newhop; newhop = newhop->next)
		if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
		  return match;
	      return NULL;
	    }
	}
    }
  return NULL;
}
#endif /* OLD_RIB */

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

#ifdef OLD_RIB
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
#else
/* Each route type's strings and default preference. */
struct
{  
  int key;
  char c;
} route_char[] =
{
  { ZEBRA_ROUTE_SYSTEM,  'X'},
  { ZEBRA_ROUTE_KERNEL,  'K'},
  { ZEBRA_ROUTE_CONNECT, 'C'},
  { ZEBRA_ROUTE_STATIC,  'S'},
  { ZEBRA_ROUTE_RIP,     'R'},
  { ZEBRA_ROUTE_RIPNG,   'R'},
  { ZEBRA_ROUTE_OSPF,    'O'},
  { ZEBRA_ROUTE_OSPF6,   'O'},
  { ZEBRA_ROUTE_BGP,     'B'},
};

/* New RIB.  Detailed information for IPv4 route. */
void
vty_show_ip_route_detail (struct vty *vty, struct route_node *rn)
{
  struct new_rib *rib;
  struct nexthop *nexthop;

  for (rib = rn->info; rib; rib = rib->next)
    {
      vty_out (vty, "Routing entry for %s/%d%s", 
	       inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
	       VTY_NEWLINE);
      vty_out (vty, "  Known via \"%s\"", route_info[rib->type].str_long);
      vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
      if (CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED))
	vty_out (vty, ", best");
      vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

	  vty_out (vty, "  Last update ");

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  "%02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, "%dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, "%02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	  vty_out (vty, " ago%s", VTY_NEWLINE);
	}

      for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
	{
	  vty_out (vty, "  %c",
		   CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

	  switch (nexthop->type)
	    {
	    case NEXTHOP_TYPE_IPV4:
	      vty_out (vty, " %s", inet_ntoa (nexthop->gate.ipv4));
	      if (nexthop->ifindex)
		vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	      vty_out (vty, " directly connected, %s",
		       ifindex2ifname (nexthop->ifindex));
	      break;
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " directly connected, %s",
		       nexthop->gate.ifname);
	      break;
	    default:
	      break;
	    }
	  if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	    vty_out (vty, " inactive");

	  if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	    {
	      vty_out (vty, " (recursive");
		
	      switch (nexthop->rtype)
		{
		case NEXTHOP_TYPE_IPV4:
		  vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
		  break;
		case NEXTHOP_TYPE_IFINDEX:
		case NEXTHOP_TYPE_IFNAME:
		  vty_out (vty, " is directly connected, %s)",
			   ifindex2ifname (nexthop->rifindex));
		  break;
		default:
		  break;
		}
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

void
vty_show_ip_route (struct vty *vty, struct route_node *rn, struct new_rib *rib)
{
  struct nexthop *nexthop;
  int len = 0;
  char buf[BUFSIZ];

  /* Nexthop information. */
  for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
      if (nexthop == rib->nexthop)
	{
	  /* Prefix information. */
	  len = vty_out (vty, "%c%c%c %s/%d",
			 route_char[rib->type].c,
			 CHECK_FLAG (rib->flags, RIB_FLAG_SELECTED)
			 ? '>' : ' ',
			 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
			 ? '*' : ' ',
			 inet_ntop (AF_INET, &rn->p.u.prefix, buf,
				    BUFSIZ),
			 rn->p.prefixlen);
		
	  /* Distance and metric display. */
	  if (rib->type != ZEBRA_ROUTE_CONNECT 
	      && rib->type != ZEBRA_ROUTE_KERNEL)
	    len += vty_out (vty, " [%d/%d]", rib->distance,
			    rib->metric);
	}
      else
	vty_out (vty, "  %c%*c",
		 CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB)
		 ? '*' : ' ',
		 len - 3, ' ');

      switch (nexthop->type)
	{
	case NEXTHOP_TYPE_IPV4:
	  vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
	  if (nexthop->ifindex)
	    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFINDEX:
	  vty_out (vty, " is directly connected, %s",
		   ifindex2ifname (nexthop->ifindex));
	  break;
	case NEXTHOP_TYPE_IFNAME:
	  vty_out (vty, " is directly connected, %s",
		   nexthop->gate.ifname);
	  break;
	default:
	  break;
	}
      if (! CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
	vty_out (vty, " inactive");

      if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
	{
	  vty_out (vty, " (recursive");
		
	  switch (nexthop->rtype)
	    {
	    case NEXTHOP_TYPE_IPV4:
	      vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
	      break;
	    case NEXTHOP_TYPE_IFINDEX:
	    case NEXTHOP_TYPE_IFNAME:
	      vty_out (vty, " is directly connected, %s)",
		       ifindex2ifname (nexthop->rifindex));
	      break;
	    default:
	      break;
	    }
	}

      if (rib->type == ZEBRA_ROUTE_RIP
	  || rib->type == ZEBRA_ROUTE_OSPF
	  || rib->type == ZEBRA_ROUTE_BGP)
	{
	  time_t uptime;
	  struct tm *tm;

	  uptime = time (NULL);
	  uptime -= rib->uptime;
	  tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

	  if (uptime < ONE_DAY_SECOND)
	    vty_out (vty,  ", %02d:%02d:%02d", 
		     tm->tm_hour, tm->tm_min, tm->tm_sec);
	  else if (uptime < ONE_WEEK_SECOND)
	    vty_out (vty, ", %dd%02dh%02dm", 
		     tm->tm_yday, tm->tm_hour, tm->tm_min);
	  else
	    vty_out (vty, ", %02dw%dd%02dh", 
		     tm->tm_yday/7,
		     tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

DEFUN (show_ip_route,
       show_ip_route_cmd,
       "show ip route",
       SHOW_STR
       IP_STR
       "IP routing table\n")
{
  struct route_node *rn;
  struct new_rib *rib;
  int first = 1;

  /* Show all IPv4 routes. */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      {
	if (first)
	  {
	    vty_out (vty, "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF,%s       B - BGP, > - selected route, * - FIB route%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	    first = 0;
	  }
	vty_show_ip_route (vty, rn, rib);
      }
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
  int type;
  struct route_node *rn;
  struct new_rib *rib;
  int first = 1;

  if (strncmp (argv[0], "b", 1) == 0)
    type = ZEBRA_ROUTE_BGP;
  else if (strncmp (argv[0], "c", 1) == 0)
    type = ZEBRA_ROUTE_CONNECT;
  else if (strncmp (argv[0], "k", 1) ==0)
    type = ZEBRA_ROUTE_KERNEL;
  else if (strncmp (argv[0], "o", 1) == 0)
    type = ZEBRA_ROUTE_OSPF;
  else if (strncmp (argv[0], "r", 1) == 0)
    type = ZEBRA_ROUTE_RIP;
  else if (strncmp (argv[0], "s", 1) == 0)
    type = ZEBRA_ROUTE_STATIC;
  else 
    {
      vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Show matched type IPv4 routes. */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = rib->next)
      if (rib->type == type)
	{
	  if (first)
	    {
	      vty_out (vty, "Codes: K - kernel route, C - connected, S - static, R - RIP, O - OSPF,%s       B - BGP, > - selected route, * - FIB route%s%s", VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);
	      first = 0;
	    }
	  vty_show_ip_route (vty, rn, rib);
	}
  return CMD_SUCCESS;
}

DEFUN (show_ip_route_addr,
       show_ip_route_addr_cmd,
       "show ip route A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *rn;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (ipv4_rib_table, (struct prefix *) &p);
  if (! rn)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix,
       show_ip_route_prefix_cmd,
       "show ip route A.B.C.D/M",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct route_node *rn;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv4 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_match (ipv4_rib_table, (struct prefix *) &p);
  if (! rn || rn->p.prefixlen != p.prefixlen)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_show_ip_route_detail (vty, rn);

  route_unlock_node (rn);

  return CMD_SUCCESS;
}
#endif /* OLD_RIB */

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

#ifdef HAVE_IF_PSEUDO
  rib = rib_create (type, flags, distance, ifindex, NULL, metric);
#else
  rib = rib_create (type, flags, distance, ifindex, table, metric);
#endif /* HAVE_IF_PSEUDO */

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
  struct static_ipv6 *nexthop;
  struct route_node *node;

  node = route_node_get (ipv6_rib_static, (struct prefix *) p);

  /* If same static route exists. */
  if (node->info)
    {
      route_unlock_node (node);
      return -1;
    }

  /* Allocate new nexthop structure. */
  nexthop = static_ipv6_new ();

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
  struct static_ipv6 *nexthop;

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

  static_ipv6_free (nexthop);
  node->info = NULL;

  route_unlock_node (node);
  route_unlock_node (node);

  return 0;
}

int
ipv6_static_list (struct vty *vty)
{
  struct route_node *np;
  struct static_ipv6 *nexthop;
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


DEFUN (ipv6_route,
       ipv6_route_cmd,
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

#if 0
void
static_ipv6_add ()
{
  ;
}

void
static_ipv6_delete ()
{
  ;
}

/* General fucntion for IPv6 static route. */
int
static_ipv6_func (struct vty *vty, int add_cmd, char *dest_str,
		  char *gate_str, char *ifname, char *distance_str)
{
  int ret;
  u_char distance;
  struct prefix_ipv6 p;
  struct in6_addr gate;
  int table = rtm_table_default;
  
  ret = str2prefix_ipv6 (dest_str, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Apply mask for given prefix. */
  apply_mask_ipv6 (&p);

  /* Administrative distance. */
  if (distance_str)
    distance = atoi (distance_str);
  else
    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

  /* When gateway is A.B.C.D format, gate is treated as nexthop
     address other case gate is treated as interface name. */
  ret = inet_pton (AF_INET6, gate_str, &gate);

  /* When ifname is specified. */
  if (ifname)
    {
      if (ret)
	vty_out (vty, "");
    }
  else
    {
      if (ret)
	ifname = NULL;
      else
	ifname = gate_str;
    }

  if (add_cmd)
    static_ipv6_add (&p, ifname ? NULL : &gate, ifname, distance, table);
  else
    static_ipv6_delete (&p, ifname ? NULL : &gate, ifname, distance, table);

  return CMD_SUCCESS;
}

DEFUN (ipv6_route,
       ipv6_route_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL);
}

DEFUN (ipv6_route_ifname,
       ipv6_route_ifname_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL);
}

DEFUN (ipv6_route_pref,
       ipv6_route_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2]);
}

DEFUN (ipv6_route_ifname_pref,
       ipv6_route_ifname_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL);
}

DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL);
}

DEFUN (no_ipv6_route_pref,
       no_ipv6_route_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, argv[2]);
}

DEFUN (no_ipv6_route_ifname_pref,
       no_ipv6_route_ifname_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
  return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], argv[3]);
}

#endif /* 0 */

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

#ifndef OLD_RIB
void
rib_weed_table_new (struct route_table *rib_table)
{
  struct route_node *rn;
  struct new_rib *rib;
  struct new_rib *next;

  for (rn = route_top (rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = next)
      {
	next = rib->next;

        if (rib->table != rtm_table_default &&
	    rib->table != RT_TABLE_MAIN)
	  {
	    rib_delnode (rn, rib);
	    newrib_free (rib);
	    route_unlock_node (rn);
	  }
      }
}
#endif /* OLD_RIB */

void
rib_weed_table (struct route_table *rib_table)
{
  struct route_node *np;
  struct rib *rib;

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
#ifdef OLD_RIB
  rib_weed_table (ipv4_rib_table);
#else
  rib_weed_table_new (ipv4_rib_table);
#endif /* OLD_RIB */

#ifdef HAVE_IPV6
  rib_weed_table (ipv6_rib_table);
#endif /* HAVE_IPV6 */
}

#ifndef OLD_RIB
void
zebra_sweep_table_new (struct route_table *rib_table)
{
  struct route_node *rn;
  struct new_rib *rib;
  struct new_rib *next;
  int ret = 0;

  for (rn = route_top (rib_table); rn; rn = route_next (rn))
    for (rib = rn->info; rib; rib = next)
      {
	next = rib->next;

        if ((rib->type == ZEBRA_ROUTE_KERNEL) && 
	    CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
          {
	    if (rn->p.family == AF_INET)
	      ret = rib_uninstall_kernel (rn, rib);
#if 0
#ifdef HAVE_IPV6
	    else
	      ret = kernel_delete_ipv6 ((struct prefix_ipv6 *)&rn->p,
					&rib->u.gate6, rib->u.ifindex, 
					0, rib->table);
#endif /* HAVE_IPV6 */
#endif /* 0 */
	    if (! ret)
	      {
		rib_delnode (rn, rib);
		newrib_free (rib);
		route_unlock_node (rn);
	      }
          }
      }
}
#endif /* OLD_RIB */

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
#ifdef OLD_RIB
  zebra_sweep_table (ipv4_rib_table);
#else
  zebra_sweep_table_new (ipv4_rib_table);
#endif /* OLD_RIB */
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

#ifdef OLD_RIB
  write += rib_static_list (vty, ipv4_rib_table);
#else
  static_ipv4_write (vty);
#endif /* OLD_RIB*/

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
  static_ipv4_table = route_table_init ();

  install_element (VIEW_NODE, &show_ip_route_cmd);
  install_element (VIEW_NODE, &show_ip_route_addr_cmd);
  install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
  install_element (ENABLE_NODE, &show_ip_route_cmd);
  install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
  install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);

  install_element (CONFIG_NODE, &ip_route_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_cmd);
  install_element (CONFIG_NODE, &no_ip_route_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_cmd);

#ifdef HAVE_IPV6
  ipv6_rib_table = route_table_init ();
  ipv6_rib_static = route_table_init ();

  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);
#if 0
  install_element (CONFIG_NODE, &ipv6_route_pref_cmd);
  install_element (CONFIG_NODE, &ipv6_route_ifname_pref_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_pref_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_cmd);
#endif /* 0 */

  install_element (VIEW_NODE, &show_ipv6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_cmd);
#endif /* HAVE_IPV6 */

#ifndef OLD_RIB
  install_element (CONFIG_NODE, &ip_route_pref_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_pref_cmd);
  install_element (CONFIG_NODE, &no_ip_route_pref_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_pref_cmd);
#endif /* OLD_RIB */
}

#ifdef OLD_RIB
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
		    rib_fib_set (rn, best);
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
		      rib_fib_set (rn, best);
		  }
	      }		
	    }
	}
    }
}

/* Interface is down. */
void
rib_if_down (struct interface *ifp)
{
  struct route_node *rn;
  struct rib *rib;
  struct rib *next;

  /* Walk down all routes. */
  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    {
      for (rib = rn->info; rib; rib = next)
	{
	  next = rib->next;

	  if (ifp->ifindex == rib->u.ifindex)
	    {
	      if (rib->type == ZEBRA_ROUTE_STATIC && IS_RIB_FIB (rib))
		{
		  rib_fib_unset (rn, rib);
		}
	      if (rib->type == ZEBRA_ROUTE_KERNEL && IS_RIB_FIB (rib))
		{
		  rib_delete_ipv4 (rib->type, rib->flags, 
				   (struct prefix_ipv4 *)&rn->p,
				   &rib->u.gate4, rib->u.ifindex, 0);
                  redistribute_delete (rn, rib);
		}
	    }
	}
    }
}
#else
void
rib_if_update_nexthop(struct route_node *rn, 
		      unsigned int ifindex, 
		      struct prefix *p,
		      int type)
{
  struct new_rib *rib;
  struct new_rib *nrib;
  struct nexthop *nexthop;
  struct nexthop *nnexthop;

  /* Lock node to prevent problems */
  route_lock_node(rn);

  /* Clean up node BEFORE the slaughter */
  rib_process(rn, NULL);

  /* This is where we should return if an interface is coming up */
  if (ifindex == 0)
    {
      route_unlock_node (rn);
      return;
    }

  for (rib = rn->info; rib; rib = nrib)
    {
      nrib = rib->next;

      if (type != 0 && rib->type != type)
	continue;
      
      /* Always skip static routes */
      if (rib->type == ZEBRA_ROUTE_STATIC)
	continue;

      /* Loop over nexthops and delete garbage */
      for (nexthop = rib->nexthop; nexthop; nexthop = nnexthop)
	{
	  nnexthop = nexthop->next;

	  /* Skip interfaces that don't match */
	  if (nexthop->krnl_ifindex != ifindex && nexthop->ifindex != ifindex)
	    continue;

	  if ( p != NULL )
	    {
	      struct prefix n;

	      /* turn nexthop into a prefix */
	      switch (nexthop->type)
		{
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		  n.family = AF_INET;
		  n.u.prefix4 = nexthop->gate.ipv4;
		  n.prefixlen = IPV4_MAX_PREFIXLEN;
		  break;

#ifdef HAVE_IPV6
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
		  n.family = AF_INET6;
		  /* Don't worry, this works! */
		  n.u.prefix6 = nexthop->gate.ipv6;
		  n.prefixlen = IPV6_MAX_PREFIXLEN;
		  break;
#endif
		default:
		  goto case_continue;
		  break;
		}
	      
	      /* Do comparision */
	      if( !prefix_match (p, &n) )
		continue;


	    }
	  /* Found something - do deezz business! */
	  if (rib->nexthop_num == 1)  
	    {
	      rib_delnode (rn, rib);
	      rib_process (rn, rib);
	      newrib_free (rib);
	      route_unlock_node (rn);
	      continue;
	    }
	  else
	    {
	      rib_uninstall (rn, rib);
	      nexthop_delete (rib, nexthop);
	      nexthop_free (nexthop);
	      rib_process (rn, rib);
	    }

	    case_continue:
	}
    }

  route_unlock_node (rn);
}

/* RIB update function. */
void
rib_update (unsigned int ifindex, struct prefix *p)
{
  struct route_node *rn;

  for (rn = route_top (ipv4_rib_table); rn; rn = route_next (rn))
    rib_if_update_nexthop(rn, ifindex, p, ZEBRA_ROUTE_KERNEL);
}

/* Interface goes up. */
void
rib_if_up (struct interface *ifp)
{
  rib_update (0, NULL);
}

/* Interface goes down. */
void
rib_if_down (struct interface *ifp)
{
  rib_update (ifp->ifindex, NULL);
}
#endif /* OLD_RIB */

#ifdef OLD_RIB
#ifdef HAVE_IF_PSEUDO
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
	      if (IS_IF_PSEUDO(ifp))
		rib->u.ifindex=INTERFACE_PSEUDO;
	      else
		rib->u.ifindex=INTERFACE_UNKNOWN;

	      if (IS_RIB_FIB (rib))
		{
		  rib_fib_unset (rn, rib);
		}
	    }
	}
    }
}
#endif /* HAVE_IF_PSEUDO */
#endif /* OLD_RIB */

#ifdef OLD_RIB
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
#endif /* OLD_RIB */
