/* Generic linked list routine.
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
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
#include "memory.h"

/* Initialize linked list : allocate memory and return list */
struct list *
list_init ()
{
  struct list *new;

  new = XMALLOC (MTYPE_LINK_LIST, sizeof (struct list));
  memset (new, 0, sizeof (struct list));
  return new;
}

/* Free given list and decrement allocation counter. */
void
list_free (struct list *list)
{
  XFREE (MTYPE_LINK_LIST, list);
}

/* Internal function to create new listnode structure. */
static listnode
listnode_new ()
{
  listnode node;

  node = XMALLOC (MTYPE_LINK_NODE, sizeof (struct listnode));
  memset (node, 0, sizeof (struct listnode));
  return node;
}

/* Free given listnode and decrement allocation counter. */
static
void
listnode_free (listnode n)
{
  XFREE (MTYPE_LINK_NODE, n);
}

/* Add new data to the list. */
void
list_add_node (struct list *list, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  /* node->next = NULL;  This is set in listnode_new(). */
  node->prev = list->tail;
  node->data = val;

  if (list_isempty (list))
    list->head = node;
  else
    list->tail->next = node;
  list->tail = node;

  list->count++;
}

void
list_add_sort_node (struct list *list, void *val)
{
  struct listnode *n;
  struct listnode *new;

  new = listnode_new ();
  new->data = val;

  if (list->cmp)
    {
      for (n = list->head; n; n = n->next)
	{
	  if ((*list->cmp) (val, n->data) < 0)
	    {	    
	      new->next = n;
	      new->prev = n->prev;

	      if (n->prev)
		n->prev->next = new;
	      else
		list->head = new;
	      n->prev = new;
	      list->count++;
	      return;
	    }
	}
    }
  new->prev = list->tail;
  if (list->tail)
    list->tail->next = new;
  else
    list->head = new;
  list->tail = new;
  list->count++;
}

/* Delete all listnode from the list. */
void
list_delete_all_node (list list)
{
  listnode n;

  for (n = listhead (list); n; n = listhead (list))
    {
      list_delete_node (list, n);
    }
}

/* Delete all node from the list. */
void
list_delete_all (list list)
{
  list_delete_all_node (list);
  list_free (list);
}

/* Delete the node which has the val argument from list. */
void
list_delete_by_val (list list, void *val)
{
  listnode n;

  for (n = list->head; n; n = n->next)
    if (n->data == val)
      {
	if (n->prev)
	  n->prev->next = n->next;
	else
	  list->head = n->next;

	if (n->next)
	  n->next->prev = n->prev;
	else
	  list->tail = n->prev;

	list->count--;
	listnode_free (n);

	return;
      }
}

void *
listnode_delete (struct list *list, void *val)
{
  struct listnode *node;

  for (node = list->head; node; node = node->next)
    {
      if (node->data == val)
	{
	  if (node->prev)
	    node->prev->next = node->next;
	  else
	    list->head = node->next;

	  if (node->next)
	    node->next->prev = node->prev;
	  else
	    list->tail = node->prev;

	  list->count--;
	  listnode_free (node);
	  return val;
	}
    }
  return NULL;
}

void
list_delete (struct list *list)
{
  struct listnode *node;
  struct listnode *next;

  for (node = list->head; node; node = next)
    {
      next = node->next;
      if (list->del)
	(list->del) (node->data);
      listnode_free (node);
    }
  list_free (list);
}

/* Below three functions are only used in ospfd. */
void
list_add_node_prev (list list, listnode current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  node->next = current;
  node->data = val;

  if (current->prev == NULL)
    list->head = node;
  else
    current->prev->next = node;

  node->prev = current->prev;
  current->prev = node;

  list->count++;
}

void
list_add_node_next (list list, listnode current, void *val)
{
  struct listnode *node;

  node = listnode_new ();
  node->prev = current;
  node->data = val;

  if (current->next == NULL)
    list->tail = node;
  else
    current->next->prev = node;

  node->next = current->next;
  current->next = node;

  list->count++;
}

void
list_add_list (struct list *l, struct list *m)
{
  struct listnode *n;

  for (n = listhead (m); n; nextnode (n))
    list_add_node (l, n->data);
}

/* Lookup the node which has given data.  For ospfd and ospf6d. */
listnode
list_lookup_node (list list, void *data)
{
  listnode n;

  for (n = list->head; n; nextnode (n))
    if (data == getdata (n))
      return n;
  return NULL;
}

/* Delete the node from list. */
void
list_delete_node (list list, listnode node)
{
  listnode n;

  for (n = list->head; n; n = n->next)
    if (n == node)
      {
	if (n->prev)
	  n->prev->next = n->next;
	else
	  list->head = n->next;
	if (n->next)
	  n->next->prev = n->prev;
	else
	  list->tail = n->prev;
	list->count--;
	listnode_free (n);
	return;
      }
}

#ifdef TEST
main ()
{
  ;
}
#endif /* TEST */
