/* Generic linked list
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

#ifndef _ZEBRA_LINKLIST_H
#define _ZEBRA_LINKLIST_H

typedef struct list *list;
typedef struct listnode *listnode;

struct listnode 
{
  struct listnode *next;
  struct listnode *prev;
  void *data;
};

struct list 
{
  struct listnode *head;
  struct listnode *tail;
  unsigned int count;
  int (*cmp) (void *val1, void *val2);
  int (*del) (void *val);
};

#define nextnode(X) ((X) = (X)->next)
#define listhead(X) ((X)->head)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define getdata(X) ((X)->data)

list list_init();
listnode list_lookup_node (list, void *);
void list_add_node (list, void *);
void list_add_sort_node (list, void *);
void list_add_node_prev (list, listnode, void *);
void list_add_node_next (list, listnode, void *);
void list_add_list (list, list);
void list_delete_by_val (list, void *);
void list_delete_all_node (list);
void list_delete_all (list);
void list_free (list);
void list_delete_node (list, listnode);

struct list *list_new ();

/* From newlist.c */
void list_delete (struct list *);
void *listnode_delete (struct list *list, void *val);

/* List iteration macro. */
#define LIST_LOOP(L,V,N) \
  for ((N) = (L)->head; (N); (N) = (N)->next) \
    if (((V) = (N)->data) != NULL)

#endif /* _ZEBRA_LINKLIST_H */
