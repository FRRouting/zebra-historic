/*
 * $Id: linklist.h,v 1.11 1999/02/19 17:01:48 developer Exp $
 *
 * generic linked list header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

typedef struct _list *list;
typedef struct _listnode *listnode;

struct _list 
{
  listnode head;
  listnode tail;
  void *up;
  unsigned int count;
};

struct _listnode 
{
  listnode next;
  listnode prev;
  void *data;
};

list list_init();

#define nextnode(X) ((X) = (X)->next)
#define listhead(X) ((X)->head)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
#define getdata(X) ((X)->data)

listnode list_lookup_node (list, void *);
void list_add_node (list, void *);
void list_delete_by_val (list, void *);

#endif /* _ZEBRA_LINKLIST_H */
