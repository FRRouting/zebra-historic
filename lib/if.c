/* 
 * Interface functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "zebra/connected.h"
#include "memory.h"
#include "table.h"
#include "buffer.h"
#include "str.h"
#include "log.h"
#ifdef RIP_API
#include "ripd/ripd_api.h"
#endif /* RIP_API */

/* Master list of interfaces. */
struct list *iflist;

/* One for each program.  This structure is needed to store hooks. */
struct if_master
{
  int (*if_new_hook) (struct interface *);
  int (*if_delete_hook) (struct interface *);
} if_master;

/* Create new interface structure. */
struct interface *
if_new ()
{
  struct interface *ifp;

  ifp = XMALLOC (MTYPE_IF, sizeof (struct interface));
  memset (ifp, 0, sizeof (struct interface));
  return ifp;
}

struct interface *
if_create ()
{
  struct interface *ifp;

  ifp = if_new ();
  
  listnode_add (iflist, ifp);
  ifp->connected = list_new ();
  ifp->connected->del = (void (*) (void *)) connected_free;

  if (if_master.if_new_hook)
    (*if_master.if_new_hook) (ifp);

  return ifp;
}

/* Delete and free interface structure. */
void
if_delete (struct interface *ifp)
{
  listnode_delete (iflist, ifp);

  if (if_master.if_delete_hook)
    (*if_master.if_delete_hook) (ifp);

  /* Free connected address list */
  list_delete (ifp->connected);

  XFREE (MTYPE_IF, ifp);
}

/* Add hook to interface master. */
void
if_add_hook (int type, int (*func)(struct interface *ifp))
{
  switch (type) {
  case IF_NEW_HOOK:
    if_master.if_new_hook = func;
    break;
  case IF_DELETE_HOOK:
    if_master.if_delete_hook = func;
    break;
  default:
    break;
  }
}

/* Interface existance check by index. */
struct interface *
if_lookup_by_index (unsigned int index)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == index)
	return ifp;
    }
  return NULL;
}

char *
ifindex2ifname (unsigned int index)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == index)
	return ifp->name;
    }
  return "unknown";
}

/* Interface existance check by interface name. */
struct interface *
if_lookup_by_name (char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (strncmp (name, ifp->name, sizeof ifp->name) == 0)
	return ifp;
    }
  return NULL;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_exact_address (struct in_addr src)
{
  listnode node;
  listnode cnode;
  struct interface *ifp;
  struct prefix *p;
  struct connected *c;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  c = getdata (cnode);

	  p = c->address;

	  if (p && p->family == AF_INET)
	    {
	      if (IPV4_ADDR_SAME (&p->u.prefix4, &src))
		return ifp;
	    }	      
	}
    }
  return NULL;
}

/* Lookup interface by IPv4 address. */
struct interface *
if_lookup_address (struct in_addr src)
{
  listnode node;
  struct prefix_ipv4 addr;
  listnode cnode;
  struct interface *ifp;
  struct prefix *p;
  struct connected *c;
  struct interface *match;

  addr.family = AF_INET;
  addr.prefix = src;
  addr.prefixlen = IPV4_MAX_BITLEN;

  match = NULL;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
	{
	  c = getdata (cnode);

	  if (if_is_pointopoint (ifp))
	    {
	      p = c->address;

	      if (p && p->family == AF_INET)
		{
		  if (IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;

		  p = c->destination;
		  if (p && IPV4_ADDR_SAME (&p->u.prefix4, &src))
		    return ifp;
		}
	    }
	  else
	    {
	      p = c->address;

	      if (p->family == AF_INET)
		{
		  if (prefix_match (p, (struct prefix *) &addr))
		    match = ifp;
		}
	    }
	}
    }
  return match;
}

/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *
if_get_by_name (char *name)
{
  struct interface *ifp;

  ifp = if_lookup_by_name (name);
  if (ifp == NULL)
    {
      ifp = if_create ();
      strncpy (ifp->name, name, IFNAMSIZ);
    }
  return ifp;
}

/* Does interface up ? */
int
if_is_up (struct interface *ifp)
{
  return ifp->flags & IFF_UP;
}

/* Is this loopback interface ? */
int
if_is_loopback (struct interface *ifp)
{
  return ifp->flags & IFF_LOOPBACK;
}

/* Does this interface support broadcast ? */
int
if_is_broadcast (struct interface *ifp)
{
  return ifp->flags & IFF_BROADCAST;
}

/* Does this interface support broadcast ? */
int
if_is_pointopoint (struct interface *ifp)
{
  return ifp->flags & IFF_POINTOPOINT;
}

/* Does this interface support multicast ? */
int
if_is_multicast (struct interface *ifp)
{
  return ifp->flags & IFF_MULTICAST;
}

/* Printout flag information into log */
const char *
if_flag_dump (unsigned long flag)
{
  int separator = 0;
  static char logbuf[BUFSIZ];

#define IFF_OUT_LOG(X,STR) \
  if ((X) && (flag & (X))) \
    { \
      if (separator) \
	strlcat (logbuf, ",", BUFSIZ); \
      else \
	separator = 1; \
      strlcat (logbuf, STR, BUFSIZ); \
    }

  strlcpy (logbuf, "  <", BUFSIZ);
  IFF_OUT_LOG (IFF_UP, "UP");
  IFF_OUT_LOG (IFF_BROADCAST, "BROADCAST");
  IFF_OUT_LOG (IFF_DEBUG, "DEBUG");
  IFF_OUT_LOG (IFF_LOOPBACK, "LOOPBACK");
  IFF_OUT_LOG (IFF_POINTOPOINT, "POINTOPOINT");
  IFF_OUT_LOG (IFF_NOTRAILERS, "NOTRAILERS");
  IFF_OUT_LOG (IFF_RUNNING, "RUNNING");
  IFF_OUT_LOG (IFF_NOARP, "NOARP");
  IFF_OUT_LOG (IFF_PROMISC, "PROMISC");
  IFF_OUT_LOG (IFF_ALLMULTI, "ALLMULTI");
  IFF_OUT_LOG (IFF_OACTIVE, "OACTIVE");
  IFF_OUT_LOG (IFF_SIMPLEX, "SIMPLEX");
  IFF_OUT_LOG (IFF_LINK0, "LINK0");
  IFF_OUT_LOG (IFF_LINK1, "LINK1");
  IFF_OUT_LOG (IFF_LINK2, "LINK2");
  IFF_OUT_LOG (IFF_MULTICAST, "MULTICAST");

  strlcat (logbuf, ">", BUFSIZ);

  return logbuf;
}

/* For debugging */
void
if_dump (struct interface *ifp)
{
  listnode node;

  zlog_info ("Interface %s index %d metric %d mtu %d %s",
	     ifp->name, ifp->ifindex, ifp->metric, ifp->mtu, 
	     if_flag_dump (ifp->flags));
  
  for (node = listhead (ifp->connected); node; nextnode (node))
    ;
}

/* Interface printing for all interface. */
void
if_dump_all ()
{
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    if_dump (getdata (node));
}

#ifdef HAVE_IPV6
void
if_index_address (struct in6_addr *addr)
{
  ;
}
#endif /* HAVE_IPV6 */

DEFUN (interface_desc, 
       interface_desc_cmd,
       "description .LINE",
       "Interface specific description\n"
       "Characters describing this interface\n")
{
  int i;
  struct interface *ifp;
  struct buffer *b;

  if (argc == 0)
    return CMD_SUCCESS;

  ifp = vty->index;
  if (ifp->desc)
    XFREE (0, ifp->desc);

  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  ifp->desc = buffer_getstr (b);
  buffer_free (b);

  return CMD_SUCCESS;
}

DEFUN (no_interface_desc, 
       no_interface_desc_cmd,
       "no description",
       NO_STR
       "Interface specific description\n")
{
  struct interface *ifp;

  ifp = vty->index;
  if (ifp->desc)
    XFREE (0, ifp->desc);
  ifp->desc = NULL;

  return CMD_SUCCESS;
}


/* See also wrapper function zebra_interface() in zebra/interface.c */
DEFUN (interface,
       interface_cmd,
       "interface IFNAME",
       "Select an interface to configure\n"
       "Interface's name\n")
{
  struct interface *ifp;

  ifp = if_lookup_by_name (argv[0]);

  if (ifp == NULL)
    {
      ifp = if_create ();
      strncpy (ifp->name, argv[0], INTERFACE_NAMSIZ);
    }
  vty->index = ifp;
  vty->node = INTERFACE_NODE;

  return CMD_SUCCESS;
}

#ifdef HAVE_IF_PSEUDO
DEFUN (interface_pseudo,
       interface_pseudo_cmd,
       "pseudo",
       "Specify pseudo interface\n")
{
  struct interface *ifp;

  ifp = vty->index;

  /* real interface could become pseudo real */    
  if (!IS_IF_PSEUDO(ifp) && (ifp->ifindex != INTERFACE_PSEUDO)){
    IF_PSEUDO_SET(ifp);
  }

  /* new interface could become pseudo */
  if (!IS_IF_PSEUDO(ifp) && (ifp->ifindex == INTERFACE_PSEUDO)){
    IF_PSEUDO_SET(ifp);
  }
  
  return CMD_SUCCESS;
}

DEFUN (no_interface_pseudo,
       no_interface_pseudo_cmd,
       "no pseudo",
       NO_STR
       "Specify pseudo interface\n")
{
  struct interface *ifp;

  ifp = vty->index;

  /* pseudo real interface become real */
  if (IS_IF_PSEUDO(ifp) && (ifp->ifindex != INTERFACE_PSEUDO)){
     IF_PSEUDO_UNSET(ifp);
  }


  return CMD_SUCCESS;
}
#endif /* HAVE_IF_PSEUDO */

/* Allocate connected structure. */
struct connected *
connected_new ()
{
  struct connected *new = XMALLOC (MTYPE_CONNECTED, sizeof (struct connected));
  memset (new, 0, sizeof (struct connected));
  return new;
}

/* Free connected structure. */
void
connected_free (struct connected *connected)
{
  if (connected->address)
    prefix_free (connected->address);

  if (connected->destination)
    prefix_free (connected->destination);

  XFREE (MTYPE_CONNECTED, connected);
}

/* Print if_addr structure. */
void
connected_log (struct connected *connected, char *str)
{
  struct prefix *p;
  struct interface *ifp;
  char logbuf[BUFSIZ];
  char buf[BUFSIZ];
  
  ifp = connected->ifp;
  p = connected->address;

  snprintf (logbuf, BUFSIZ, "%s interface %s %s %s/%d ", 
	    str, ifp->name, prefix_family_str (p),
	    inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
	    p->prefixlen);

  p = connected->destination;
  if (p)
    {
      strncat (logbuf, inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
	       BUFSIZ - strlen(logbuf));
    }
  zlog (NULL, LOG_INFO, logbuf);
}

/* If two connected address has same prefix return 1. */
int
connected_same_prefix (struct prefix *p1, struct prefix *p2)
{
  if (p1->family == p2->family)
    {
      if (p1->family == AF_INET &&
	  IPV4_ADDR_SAME (&p1->u.prefix4, &p2->u.prefix4))
	return 1;
#ifdef HAVE_IPV6
      if (p1->family == AF_INET6 &&
	  IPV6_ADDR_SAME (&p1->u.prefix6, &p2->u.prefix6))
	return 1;
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/* Add interface's address information. */
void
connected_add (struct interface *ifp, struct connected *connected)
{
  struct listnode *node;
  struct listnode *next;
  struct listnode *prev;
  struct connected *ifc;
  int found;

#ifdef CONNECTED_DEBUG
  connected_log (connected, "add");
#endif /* CONNECTED_DEBUG */

  /* Check existing prefix information. 
     Keep list in order if old info found, essential for repeatable
     operation in some daemons */
  prev = NULL;
  found = 0;
  for (node = listhead (ifp->connected); node; node = next)
    {
      ifc = getdata (node);
      prev = node->prev;
      next = node->next;

      if (connected_same_prefix (ifc->address, connected->address))
	{
	  /* zlog_info ("same prefix %s", inet_ntoa (ifc->address->u.prefix4)); */
	  found = 1;
	  listnode_delete (ifp->connected, ifc);
	  connected_free (ifc);
	  break;
	}
    }

  /* Link connected address to interface. */
  connected->ifp = ifp;
  if (!found)
    listnode_add (ifp->connected, connected);
  else
    listnode_add_after (ifp->connected, prev, connected);
}

struct connected *
connected_delete_by_prefix (struct interface *ifp, struct prefix *p)
{
  struct listnode *node;
  struct listnode *next;
  struct connected *ifc;

  /* In case of same prefix come, replace it with new one. */
  for (node = listhead (ifp->connected); node; node = next)
    {
      ifc = getdata (node);
      next = node->next;

      if (connected_same_prefix (ifc->address, p))
	{
#ifdef CONNECTED_DEBUG
	  connected_log (ifc, "delete");
#endif /* CONNECTED_DEBUG */
	  listnode_delete (ifp->connected, ifc);
	  return ifc;
	}
    }
  return NULL;
}

#ifndef HAVE_IF_NAMETOINDEX
unsigned int
if_nametoindex (const char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (strcmp (ifp->name, name) == 0)
	return ifp->ifindex;
    }
  return 0;
}
#endif

#ifndef HAVE_IF_INDEXTONAME
char *
if_indextoname (unsigned int ifindex, char *name)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->ifindex == ifindex)
	{
	  memcpy (name, ifp->name, IFNAMSIZ);
	  return ifp->name;
	}
    }
  return NULL;
}
#endif

#ifdef RIP_API
/*************************
 Function:if_get_next_node
 PURPOSE: Get the node after the current one ('prev_node') in the
          'iflist' linked list.
          If the 'prev_node' is NULL, get the fist node.
          If "End of table" is a case, returns NULL
 PARAMETERS:
    IN    prev_node
**************************/
listnode
if_get_next_node (listnode prev_node)
{   
  if (prev_node)
    return nextnode(prev_node);
  else if (iflist)
    return listhead (iflist);
  else
    return NULL;
}

/*************************
 Function:if_get_next_connected
 PURPOSE: Lookup next interface/connected
 PARAMETERS:
    IN    listnode prev_connected_node
    IN    listnode prev_ifp_node
    OUT   listnode* next_ifp_node
    RETURNS: listnode 'next_connected_node' (of NULL in "End of table" case)
**************************/
listnode
if_get_next_connected (listnode prev_connected_node,
                       listnode prev_ifp_node,
                       listnode* next_ifp_node)
{
  interface_t*  ifp;
  listnode      node = NULL;

  if (prev_connected_node) {
    prev_connected_node = if_get_next_node (prev_connected_node);
    if (prev_connected_node) {
      *next_ifp_node = prev_ifp_node;
      return prev_connected_node;
    }
    node = prev_ifp_node;
  }

  for (node = if_get_next_node (node); node; node = if_get_next_node (node)) {
    ifp = getdata (node);
    prev_connected_node = listhead (ifp->connected);
    if (prev_connected_node) {
      *next_ifp_node = node;
      return prev_connected_node;
    }
  }

  return NULL;
}

/*************************
 Function:if_lookup_next (was rip_if_lookup_next in rip_snmp.c)
 PURPOSE: Lookup next interface by IPv4 address.
 PARAMETERS:
    INOUT    in_addr *src
    OUT      in_addr *dst (Point-to-point link)
    RETURNS: interface *ifp (of NULL in "End of table" case)
 NOTE: it was moved from rip_snmp.c, old name was rip_if_lookup_next
**************************/
interface_t *
if_lookup_next (struct in_addr *src, struct in_addr *dst)
{
  listnode node;
  listnode cnode;
  interface_t *ifp;
  struct prefix *p;
  connected_t *c;
  struct in_addr *min_addr;
  struct interface *min_ifp;
  
  min_addr=NULL;
  min_ifp=NULL;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      for (cnode = listhead (ifp->connected); cnode; nextnode (cnode))
        {
          c = getdata (cnode);

          p = c->address;

          if (p && p->family == AF_INET)
            {
 	      if (ntohl (p->u.prefix4.s_addr) > ntohl (src->s_addr))
		if ((min_addr && (ntohl(min_addr->s_addr) > ntohl (p->u.prefix4.s_addr)))
		    || (!min_addr))		   
		  {
		    min_addr = &(p->u.prefix4);
		    min_ifp = ifp;
		  }	       
	    	      
	    }
        }
    }
  if (min_addr){
    src->s_addr=min_addr->s_addr;
    return min_ifp;
  }
  else
    return NULL;    
  
}
#endif /* RIP_API */

/* Interface looking up by interface's address. */

/* Interface's IPv4 address reverse lookup table. */
struct route_table *ifaddr_ipv4_table;
/* struct route_table *ifaddr_ipv6_table; */

void
ifaddr_ipv4_add (struct in_addr *ifaddr, struct interface *ifp)
{
  struct route_node *rn;
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *ifaddr;

  rn = route_node_get (ifaddr_ipv4_table, (struct prefix *) &p);
  if (rn)
    {
      route_unlock_node (rn);
      zlog_info ("ifaddr_ipv4_add(): address %s is already added",
		 inet_ntoa (*ifaddr));
      return;
    }
  rn->info = ifp;
}

void
ifaddr_ipv4_delete (struct in_addr *ifaddr, struct interface *ifp)
{
  struct route_node *rn;
  struct prefix_ipv4 p;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *ifaddr;

  rn = route_node_lookup (ifaddr_ipv4_table, (struct prefix *) &p);
  if (! rn)
    {
      zlog_info ("ifaddr_ipv4_delete(): can't find address %s",
		 inet_ntoa (*ifaddr));
      return;
    }
  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);
}

/* Lookup interface by interface's IP address or interface index. */
struct interface *
ifaddr_ipv4_lookup (struct in_addr *addr, unsigned int ifindex)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct interface *ifp;
  listnode node;

  if (addr)
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_PREFIXLEN;
      p.prefix = *addr;

      rn = route_node_lookup (ifaddr_ipv4_table, (struct prefix *) &p);
      if (! rn)
	return NULL;
      
      ifp = rn->info;
      route_unlock_node (rn);
      return ifp;
    }
  else
    {
      for (node = listhead (iflist); node; nextnode (node))
	{
	  ifp = getdata (node);

	  ;

	  if (ifp->ifindex == ifindex)
	    return ifp;
	}
    }
  return NULL;
}

/* Initialize interface list. */
void
if_init ()
{
  iflist = list_new ();
  ifaddr_ipv4_table = route_table_init ();

  if (iflist)
    return;

  memset (&if_master, 0, sizeof if_master);
}
