/* Routing Table
   Copyright (C) 1998 Kunihiro Ishiguro

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>		/* atoi */
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <assert.h>
#include <arpa/inet.h>		/* ient_pton, inet_ntop */

#include "table.h"
#include "memory.h"

void route_node_delete (struct route_node *);

/* Copy prefix from src to dst. */
void
prefix_copy (struct newprefix *dst, struct newprefix *src)
{
  dst->family = src->family;
  dst->prefixlen = src->prefixlen;

  switch (src->family)
    {
    case AF_INET:
      memcpy (&dst->u.prefix4, &src->u.prefix4, sizeof (struct in_addr));
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      memcpy (&dst->u.prefix6, &src->u.prefix6, sizeof (struct in6_addr));
      break;
#endif /* HAVE_IPV6 */
    default:
      assert (0);
      break;
    }
}

/* This mean only one table */
struct route_table *
route_table_init (void)
{
  struct route_table *rt;

  rt = XMALLOC (MTYPE_ROUTE_TABLE, sizeof (struct route_table));
  bzero (rt, sizeof (struct route_table));
  return rt;
}

/* Allocate new route node. */
struct route_node *
route_node_new ()
{
  struct route_node *node;
  
  node = XMALLOC (MTYPE_ROUTE_NODE, sizeof (struct route_node));
  bzero (node, sizeof (struct route_node));

  return node;
}

/* Allocate new route node with prefix set. */
struct route_node *
route_node_set (struct route_table *table, struct newprefix *prefix)
{
  struct route_node *node;
  
  node = XMALLOC (MTYPE_ROUTE_NODE, sizeof (struct route_node));
  bzero (node, sizeof (struct route_node));

  prefix_copy (&node->p, prefix);
  node->table = table;

  return node;
}

/* Free route node. */
void
route_node_free (struct route_node *node)
{
  XFREE (MTYPE_ROUTE_NODE, node);
}


/* Utility mask array. */
static u_char maskbit[] = 
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* If n includes p prefix then return 1. */
static int
route_match (struct newprefix *n, struct newprefix *p)
{
  int offset;
  int shift;

  u_char *np = (u_char *)&n->u.prefix;
  u_char *pp = (u_char *)&p->u.prefix;

  assert (n->prefixlen <= p->prefixlen);

  offset = n->prefixlen / 8;
  shift =  n->prefixlen % 8;

  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;
  
  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

/* Common prefix route genaration. */
static void
route_common (struct newprefix *n, struct newprefix *p, struct newprefix *new)
{
  int i;
  u_char diff;
  u_char mask;

  u_char *np = (u_char *)&n->u.prefix;
  u_char *pp = (u_char *)&p->u.prefix;
  u_char *newp = (u_char *)&new->u.prefix;

  for (i = 0; i < p->prefixlen / 8; i++)
    {
      if (np[i] == pp[i])
	newp[i] = np[i];
      else
	break;
    }

  new->prefixlen = i * 8;

  if (new->prefixlen != p->prefixlen)
    {
      diff = np[i] ^ pp[i];
      mask = 0x80;
      while (new->prefixlen < p->prefixlen && !(mask & diff))
	{
	  mask >>= 1;
	  new->prefixlen++;
	}
      newp[i] = np[i] & maskbit[new->prefixlen % 8];
    }
}

/* Macro version of check_bit (). */
#define CHECK_BIT(X,P) ((((u_char *)(X))[(P) / 8]) >> (7 - ((P) % 8)) & 1)

/* Check bit of the prefix. */
static int
check_bit (u_char *prefix, u_char prefixlen)
{
  int offset;
  int shift;
  u_char *p = (u_char *)prefix;

  assert (prefixlen <= 128);

  offset = prefixlen / 8;
  shift = 7 - (prefixlen % 8);
  
  return (p[offset] >> shift & 1);
}

/* Macro version of set_link (). */
#define SET_LINK(X,Y) (X)->link[CHECK_BIT(&(Y)->prefix,(X)->prefixlen)] = (Y);\
                      (Y)->parent = (X)

static void
set_link (struct route_node *node, struct route_node *new)
{
  int bit;
    
  bit = check_bit (&new->p.u.prefix, node->p.prefixlen);

  assert (bit == 0 || bit == 1);

  node->link[bit] = new;
  new->parent = node;
}

/* Lock node. */
void
route_lock_node (struct route_node *node)
{
  node->lock++;
}

/* Unlock node. */
void
route_unlock_node (struct route_node *node)
{
  node->lock--;

  if (node->lock == 0)
    route_node_delete (node);
}

/* Add node to routing table. */
struct route_node *
route_node_get (struct route_table *table, struct newprefix *p)
{
  struct route_node *new;
  struct route_node *node;
  struct route_node *match;

  match = NULL;
  node = table->top;
  while (node && node->p.prefixlen <= p->prefixlen && 
	 route_match (&node->p, p))
    {
      if (node->p.prefixlen == p->prefixlen)
	{
	  route_lock_node (node);
	  return node;
	}
      match = node;
      node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
    }

  if (node == NULL)
    {
      new = route_node_set (table, p);
      if (match)
	set_link (match, new);
      else
	table->top = new;
    }
  else
    {
      new = route_node_new ();
      route_common (&node->p, p, &new->p);
      new->p.family = p->family;
      new->table = table;
      set_link (new, node);

      if (match)
	set_link (match, new);
      else
	table->top = new;

      if (new->p.prefixlen != p->prefixlen)
	{
	  match = new;
	  new = route_node_set (table, p);
	  set_link (match, new);
	}
    }
  route_lock_node (new);
  return new;
}

#ifdef HAVE_IPV6
/* Utility function should be removed in the feature. */
struct route_node *
route_node_lookup (struct route_table *table, 
		   struct in6_addr *prefix,
		   int prefixlen)
{
  struct newprefix new;

  new.family = AF_INET6;
  memcpy (&new.u.prefix6, prefix, sizeof (struct in6_addr));
  new.prefixlen = prefixlen;

  return route_node_get (table, &new);
}
#endif /* HAVE_IPV6 */

/* Delete node from the routing table. */
void
route_node_delete (struct route_node *node)
{
  struct route_node *child;

  assert (node->lock == 0);
  assert (node->route == NULL);

  if (node->l_left && node->l_right)
    return;

  if (node->l_left)
    child = node->l_left;
  else
    child = node->l_right;

  if (child)
    child->parent = node->parent;

  if (node->parent)
    {
      if (node->parent->l_left == node)
	node->parent->l_left = child;
      else
	node->parent->l_right = child;
    }
  else
    node->table->top = child;

  route_node_free (node);
}

/* Get fist node and lock it.  This function is usefull when one want
   to lookup all the node exist in the routing table. */
struct route_node *
route_top (struct route_table *table)
{
  /* If there is no node in the routing table return NULL. */
  if (table->top == NULL)
    return NULL;

  /* Lock the top node and return it. */
  route_lock_node (table->top);
  return table->top;
}

/* Unlock current node and lock next node then return it. */
struct route_node *
route_next (struct route_node *node)
{
  /* Node may be deleted from route_unlock_node so we have to preserve
     next node's pointer. */
  struct route_node *next;
  struct route_node *start;

  if (node->l_left)
    {
      next = node->l_left;
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }
  if (node->l_right)
    {
      next = node->l_right;
      route_lock_node (next);
      route_unlock_node (node);
      return next;
    }

  start = node;
  while (node->parent)
    {
      if (node->parent->l_left == node && node->parent->l_right)
	{
	  next = node->parent->l_right;
	  route_lock_node (next);
	  route_unlock_node (start);
	  return next;
	}
      node = node->parent;
    }
  route_unlock_node (start);
  return NULL;
}

#ifdef HAVE_IPV6
int
str2pref_in6 (char *str, struct newprefix *prefix)
{
  u_char *p;
  int ret;

  p = strchr (str, '/');
  if (p == NULL)
    return -1;

  *p = '\0';
  ret = inet_pton (AF_INET6, str, &prefix->u.prefix6);
  if (ret <= 0)
    return -1;

  /* Should we use strtol and check ERANGE. */
  prefix->prefixlen = (u_char) atoi (++p);
  prefix->family = AF_INET6;

  return 0;
}

/* Dump routing table. */
void
route_dump_node (struct route_table *t)
{
  struct route_node *node;
  char buf[46];

  for (node = route_top (t); node != NULL; node = route_next (node))
    {
      printf ("%s/%d\n", inet_ntop (AF_INET6, &node->p.u.prefix6, buf, 46),
	      node->p.prefixlen);
    }
}
#endif /* HAVE_IPV6 */

#ifdef TEST2
main ()
{
  FILE *fp;
  char buf[BUFSIZ];
  struct newprefix prefix;
  struct route_node *node;
  struct route_table *table;

  fp = fopen ("file", "r");
  if (fp == NULL)
    {
      perror ("open");
      exit (1);
    }
  table = route_table_init ();

  while (fgets (buf, BUFSIZ, fp))
    {
      char *p;

      p = strrchr (buf, ' ');
      str2pref_in6 (++p, &prefix);
#if 0
      printf ("%s/%d\n", inet_ntop (AF_INET6, &prefix.prefix, buf, BUFSIZ),
	      prefix.prefixlen);

#endif
      node = route_node_get (table, &prefix);

      node->route = NULL;
    }

  for (node = route_top (table); node; node = route_next (node))
    {
      printf ("[%d] %s/%d\n", 
	      node->lock,
	      inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ),
	      node->p.prefixlen);
    }
#if 0
  for (node = route_top (table); node; node = route_next (node))
    {
      printf ("[%d] %s/%d\n", 
	      node->lock,
	      inet_ntop (AF_INET6, &node->prefix, buf, BUFSIZ),
	      node->prefixlen);
    }
#endif
}
#endif TEST2

#ifdef TEST
main ()
{
  struct newprefix a;
  struct newprefix b;
  struct newprefix c;
  struct newprefix d;
  struct route_table *top;
  struct route_node *node;

  inet_pton (AF_INET6, "::", &a.prefix);
  a.prefixlen = 0;

  inet_pton (AF_INET6, "F000::", &b.prefix);
  b.prefixlen = 4;

  inet_pton (AF_INET6, "0101::", &a.prefix);
  a.prefixlen = 16;
  inet_pton (AF_INET6, "200::", &b.prefix);
  b.prefixlen = 8;

  inet_pton (AF_INET6, "0100::", &d.prefix);
  d.prefixlen = 8;

  top = route_table_init ();

  route_node_get (top, &a);
  node = route_node_get (top, &b);
  route_node_get (top, &c);
  route_node_get (top, &d);

  route_dump_node (top);

  printf ("=======\n");
  route_node_delete (top, node);

  route_dump_node (top);
}
#endif /* TEST */
