/*
 * Route filtering function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include "prefix.h"
#include "filter.h"
#include "memory.h"

/* Filter element of access list */
struct filter
{
  /* For doubly linked list. */
  struct filter *next;
  struct filter *prev;

  /* Filter type information. */
  enum filter_type type;

  /* If this filter is "any" match then this flag is set. */
  int any;

  /* Prefix information. */
  struct prefix prefix;
};

/* List of access_list. */
struct access_list_list
{
  struct access_list *head;
  struct access_list *tail;
};

/* Master structure of access_list. */
struct access_master
{
  /* List of access_list which name is number. */
  struct access_list_list num;

  /* List of access_list which name is string. */
  struct access_list_list str;

  /* Hook function which is executed when new access_list is added. */
  void (*add_hook) ();

  /* Hook function which is executed when access_list is deleted. */
  void (*delete_hook) ();
};

/* Static structure of all access_list's master. */
static struct access_master access_master = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  NULL,
  NULL,
};

/* Allocate new filter structure. */
struct filter *
filter_new ()
{
  struct filter *new;

  new = XMALLOC (MTYPE_FILTER, sizeof (struct filter));
  bzero (new, sizeof (struct filter));
  return new;
}

void
filter_free (struct filter *filter)
{
  XFREE (MTYPE_FILTER, filter);
}

/* Return string of filter_type. */
static char *
filter_type_str (struct filter *filter)
{
  switch (filter->type)
    {
    case FILTER_PERMIT:
      return "permit";
      break;
    case FILTER_DENY:
      return "deny";
      break;
    case FILTER_DYNAMIC:
      return "dynamic";
      break;
    default:
      return "";
      break;
    }
}

/* Allocate and make new filter. */
struct filter *
filter_make (struct prefix *prefix, enum filter_type type)
{
  struct filter *filter;

  filter = filter_new ();

  /* If prefix is NULL then this is "any" match directive. */
  if (prefix == NULL)
    filter->any = 1;
  else
    prefix_copy (&filter->prefix, prefix);

  filter->type = type;

  return filter;
}

struct filter *
filter_lookup (struct access_list *access, struct prefix *prefix,
	       enum filter_type type)
{
  struct filter *filter;

  for (filter = access->head; filter; filter = filter->next)
    {
      if (prefix == NULL)
	{
	  if (filter->any == 1 && filter->type == type)
	    return filter;
	}
      else
	{
	  if (prefix_same (&filter->prefix, prefix) && filter->type == type)
	    return filter;
	}
    }
  return NULL;
}

/* If filter match to the prefix then return 1. */
static int
filter_match (struct filter *filter, struct prefix *p)
{
  return prefix_match (&filter->prefix, p);
}

/* Allocate new access list structure. */
struct access_list *
access_list_new ()
{
  struct access_list *new;

  new = XMALLOC (MTYPE_ACCESS_LIST, sizeof (struct access_list));
  bzero (new, sizeof (struct access_list));
  return new;
}

/* Free allocated access_list. */
void
access_list_free (struct access_list *access)
{
  XFREE (MTYPE_ACCESS_LIST, access);
}

/* Delete access_list from access_master and free it. */
void
access_list_delete (struct access_list *access)
{
  struct access_list_list *list;

  if (access->type == ACCESS_TYPE_NUMBER)
    list = &access_master.num;
  else
    list = &access_master.str;

  if (access->next)
    access->next->prev = access->prev;
  else
    list->tail = access->prev;

  if (access->prev)
    access->prev->next = access->next;
  else
    list->head = access->next;

  access_list_free (access);
}

/* Insert new access list to list of access_list.  Each acceess_list
   is sorted by the name. */
struct access_list *
access_list_insert (char *name)
{
  int i;
  long number;
  struct access_list *access;
  struct access_list *point;
  struct access_list_list *list;

  /* Allocate new access_list and copy given name. */
  access = access_list_new ();
  access->name = strdup (name);

  /* If name is made by all digit character.  We treat it as
     number. */
  for (number = 0, i = 0; i < strlen (name); i++)
    {
      if (isdigit (name[i]))
	number = (number * 10) + (name[i] - '0');
      else
	break;
    }

  /* In case of name is all digit character */
  if (i == strlen (name))
    {
      access->type = ACCESS_TYPE_NUMBER;

      /* Set access_list to number list. */
      list = &access_master.num;

      for (point = list->head; point; point = point->next)
	if (atol (point->name) >= number)
	  break;
    }
  else
    {
      access->type = ACCESS_TYPE_STRING;

      /* Set access_list to string list. */
      list = &access_master.str;
  
      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
	if (strcmp (point->name, name) >= 0)
	  break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = access;
      return access;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      access->prev = list->tail;
      list->tail->next = access;
      list->tail = access;
      return access;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      access->next = list->head;
      list->head->prev = access;
      list->head = access;
      return access;
    }

  /* Insertion is made at middle of the access_list. */
  access->next = point;
  access->prev = point->prev;

  if (point->prev)
    point->prev->next = access;
  point->prev = access;

  return access;
}

/* Lookup access_list from list of access_list by name. */
struct access_list *
access_list_lookup (char *name)
{
  struct access_list *access;

  if (name == NULL)
    return NULL;

  for (access = access_master.num.head; access; access = access->next)
    if (strcmp (access->name, name) == 0)
      return access;

  for (access = access_master.str.head; access; access = access->next)
    if (strcmp (access->name, name) == 0)
      return access;

  return NULL;
}

/* Get access list from list of access_list.  If there isn't matched
   access_list create new one and return it. */
struct access_list *
access_list_get (char *name)
{
  struct access_list *access;

  access = access_list_lookup (name);
  if (access == NULL)
    access = access_list_insert (name);
  return access;
}

/* Print out contents of access list to the terminal. */
void
access_list_print (struct access_list *access)
{
  struct filter *filter;

  printf ("access name %s\n", access->name);

  for (filter = access->head; filter; filter = filter->next)
    {
      if (filter->any)
	printf ("any %s\n", filter_type_str (filter));
      else
	{
	  struct prefix *p;
	  char buf[BUFSIZ];

	  p = &filter->prefix;

	  printf ("%s/%d %s\n", 
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ), 
		  p->prefixlen, filter_type_str (filter));
	}
    }
}

/* Apply access_list_print to the all of access_list.  For debug
   purpose. */
void
access_list_print_all ()
{
  struct access_list *access;

  for (access = access_master.num.head; access; access = access->next)
    access_list_print (access);
  for (access = access_master.str.head; access; access = access->next)
    access_list_print (access);
}

/* Apply access list to object (which should be struct prefix *). */
enum filter_type
access_list_apply (struct access_list *access, void *object)
{
  struct filter *filter;
  struct prefix *p;

  p = (struct prefix *) object;

  for (filter = access->head; filter; filter = filter->next)
    if (filter->any || filter_match (filter, p))
      return filter->type;

  return FILTER_DENY;
}

/* Add hook function. */
void
access_list_add_hook (void (*func) ())
{
  access_master.add_hook = func;
}

/* Delete hook function. */
void
access_list_delete_hook (void (*func) ())
{
  access_master.delete_hook = func;
}

/* Add new filter to the end of specified access_list. */
void
access_list_filter_add (struct access_list *access, struct filter *filter)
{
  filter->next = NULL;
  filter->prev = access->tail;

  if (access->tail)
    access->tail->next = filter;
  else
    access->head = filter;
  access->tail = filter;

  /* Run hook function. */
  if (access_master.add_hook)
    (*access_master.add_hook) ();
}

/* If access_list has no filter then return 1. */
static int
access_list_empty (struct access_list *access)
{
  if (access->head == NULL && access->tail == NULL)
    return 1;
  else
    return 0;
}

/* Delete filter from specified access_list.  If there is hook
   function execute it. */
void
access_list_filter_delete (struct access_list *access, struct filter *filter)
{
  if (filter->next)
    filter->next->prev = filter->prev;
  else
    access->tail = filter->prev;

  if (filter->prev)
    filter->prev->next = filter->next;
  else
    access->head = filter->next;

  filter_free (filter);

  /* If access_list becomes empty delete it from access_master. */
  if (access_list_empty (access))
    access_list_delete (access);

  /* Run hook function. */
  if (access_master.delete_hook)
    (*access_master.delete_hook) ();
}

#ifdef TEST
/**/
int
main ()
{
  int ret;
  struct prefix p;
  struct filter *filter;
  struct access_list *alist;
  
  /*
    access-list 1 deny 3ffe:1c00::0/24 refine
    access-list 1 permit any
  */
  alist = access_list_get ("1");

  access_list_print_all ();

  str2prefix ("3ffe:1c00::0/24" ,&p);
  filter = filter_make (&p, FILTER_DENY);
  access_list_filter_add (alist, filter);

  filter = filter_make (NULL, FILTER_PERMIT);
  access_list_filter_add (alist, filter);

  access_list_print (alist);

  str2prefix ("3ffe:1d00::1/128", &p);
  
  ret = access_list_apply (alist, &p);

  printf ("result %d\n", ret);

  exit (0);
}
#endif /* TEST */


/* Below is vty related part. */
#include "vector.h"
#include "vty.h"
#include "command.h"

DEFUN (access_list, access_list_cmd,
       "access-list NAME TYPE IP_ADDR",
       "Set access list definition\n"
       "Access list name\n"
       "Access list type\n"
       "Access list address\n")
{
  int ret;
  enum filter_type type;
  struct filter *filter;
  struct access_list *access;
  struct prefix p;

  /* Check of filter type. */
  if (strcmp (argv[1], "permit") == 0)
    type = FILTER_PERMIT;
  else if (strcmp (argv[1], "deny") == 0)
    type = FILTER_DENY;
  else
    {
      vty_out (vty, "filter type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[2], "any") == 0)
      filter = filter_make (NULL, type);
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[2], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
      filter = filter_make (&p, type);
    }

  /* Install new filter to the access_list. */
  access = access_list_get (argv[0]);
  access_list_filter_add (access, filter);

  return CMD_SUCCESS;
}

DEFUN (no_access_list, no_access_list_cmd,
       "no access-list NAME TYPE IP_ADDR",
       "Unset access list\n"
       "Set access list definition\n"
       "Access list name\n"
       "Access list type\n"
       "Access list address\n")
{
  int ret;
  enum filter_type type;
  struct filter *filter;
  struct access_list *access;
  struct prefix p;

  /* Check of filter type. */
  if (strcmp (argv[1], "permit") == 0)
    type = FILTER_PERMIT;
  else if (strcmp (argv[1], "deny") == 0)
    type = FILTER_DENY;
  else
    {
      vty_out (vty, "filter type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  /* Looking up access_list. */
  access = access_list_lookup (argv[0]);
  if (access == NULL)
    {
      vty_out (vty, "access-list %s doesn't exist\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check string format of prefix and prefixlen. */
  if (strcmp (argv[2], "any") == 0)
      filter = filter_lookup (access, NULL, type);
  else
    {
      ret = str2prefix (argv[2], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
      filter = filter_lookup (access, &p, type);
    }

  /* Looking up filter from access_list. */
  if (filter == NULL)
    {
      char buf[BUFSIZ];

      vty_out (vty, "access-list %s %s %s/%d doesn't exist\r\n", 
	       argv[0],
	       argv[1],
	       inet_ntop (p.family, &p.u.prefix, buf, BUFSIZ),
	       p.prefixlen);
      return CMD_WARNING;
    }

  /* Delete filter from access_list. */
  access_list_filter_delete (access, filter);

  return CMD_SUCCESS;
}

/* Access-list node. */
struct cmd_node access_node =
{
  ACCESS_NODE,
  ""				/* Access list has no interface. */
};

/* Configuration write function. */
int
config_write_access (struct vty *vty)
{
  struct access_list *access;
  struct filter *filter;
  char buf[BUFSIZ];
  struct prefix *p;

  for (access = access_master.num.head; access; access = access->next)
    for (filter = access->head; filter; filter = filter->next)
      {
	p = &filter->prefix;

	if (filter->any)
	  vty_out (vty,
		   "access-list %s %s any%s", 
		   access->name,
		   filter_type_str (filter),
		   VTY_NEWLINE);
	else
	  vty_out (vty,
		   "access-list %s %s %s/%d%s", 
		   access->name,
		   filter_type_str (filter),
		   inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen,
		   VTY_NEWLINE);
      }

  for (access = access_master.str.head; access; access = access->next)
    for (filter = access->head; filter; filter = filter->next)
      {
	p = &filter->prefix;

	if (filter->any)
	  vty_out (vty,
		   "access-list %s %s any%s", 
		   access->name,
		   filter_type_str (filter),
		   VTY_NEWLINE);
	else
	  vty_out (vty, 
		   "access-list %s %s %s/%d%s", 
		   access->name,
		   filter_type_str (filter),
		   inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		   p->prefixlen,
		   VTY_NEWLINE);
      }
  return 0;
}

/* Install vty related command. */
void
access_list_init ()
{
  install_node (&access_node, config_write_access);

  install_element (CONFIG_NODE, &access_list_cmd);
  install_element (CONFIG_NODE, &no_access_list_cmd);
}
