/* 
 * $Id: if.c,v 1.41 1999/02/22 12:15:38 developer Exp $
 *
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
#include "buffer.h"
#include "str.h"
#include "log.h"
/* One for each program.  This structure is needed to store hooks. */
struct if_master
{
  int (*if_new_hook) (struct interface *);
  int (*if_delete_hook) (struct interface *);
} if_master;

/* Export to user function. */
list iflist;

/* Create new interface structure. */
struct interface *
if_new ()
{
  struct interface *ifp;

  ifp = XMALLOC (MTYPE_IF, sizeof (struct interface));
  bzero (ifp, sizeof (struct interface));
  ifp->connected = list_init ();
  list_add_node (iflist, ifp);

  if (if_master.if_new_hook)
    (*if_master.if_new_hook) (ifp);

  return ifp;
}

/* Delete and free interface structure. */
void
if_delete (struct interface *ifp)
{
  list_delete_by_val (iflist, ifp);
  if (if_master.if_delete_hook)
    (*if_master.if_delete_hook) (ifp);
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
if_lookup_by_index (int index)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (ifp->index == index)
	return ifp;
    }
  return NULL;
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

/* Get interface by name if given name interface doesn't exist create
   one. */
struct interface *
if_get_by_name (char *name)
{
  struct interface *ifp;

  ifp = if_lookup_by_name (name);
  if (ifp == NULL)
    {
      ifp = if_new ();
      strncpy (ifp->name, name, IFNAMSIZ);
    }
  return ifp;
}

void
if_up (struct interface *ifp)
{
  ;				/* not yet implemented. */
}

void
if_down (struct interface *ifp)
{
  ;				/* not yet implemented. */
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

  zlog (NULL, LOG_INFO, "Interface %s index %d metric %d mtu %d %s",
       ifp->name, ifp->index, ifp->metric, ifp->mtu, if_flag_dump (ifp->flags));
  
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
       "description ...",
       "Set interface description\n"
       "Description\n")
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
       "no description [description]",
       NO_STR
       "Delete interface description\n"
       "Description\n")
{
  struct interface *ifp;

  ifp = vty->index;
  if (ifp->desc)
    XFREE (0, ifp->desc);
  ifp->desc = NULL;

  return CMD_SUCCESS;
}

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
      ifp = if_new ();
      strncpy (ifp->name, argv[0], INTERFACE_NAMSIZ);
      ifp->index = -1;
    }
  vty->index = ifp;
  vty->node = INTERFACE_NODE;

  return CMD_SUCCESS;
}

/* Initialize interface list. */
void
if_init ()
{
  iflist = list_init ();

  if (iflist)
    return;

  bzero (&if_master, sizeof if_master);
}

/* Allocate connected structure. */
struct connected *
connected_new ()
{
  struct connected *new = XMALLOC (MTYPE_CONNECTED, sizeof (struct connected));
  bzero (new, sizeof (struct connected));
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
connected_log (struct connected *connected)
{
  struct prefix *p;
  struct interface *ifp;
  char logbuf[BUFSIZ];
  char buf[BUFSIZ];
  
  ifp = connected->ifp;
  p = connected->address;

  snprintf (logbuf, BUFSIZ, "interface %s %s %s/%d", 
       ifp->name, 
       prefix_family_str (p),
       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
       p->prefixlen);
  
  p = connected->destination;
  if (p)
    {
      if (p->family == AF_INET)
	strncat (logbuf, inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 BUFSIZ - strlen(logbuf));
    }
  zlog (NULL, LOG_INFO, logbuf);
}

void
connected_add (struct interface *ifp, struct connected *connected)
{
  /* Link connected address to interface. */
  list_add_node (ifp->connected, connected);
  connected->ifp = ifp;

  connected_log (connected);
}
