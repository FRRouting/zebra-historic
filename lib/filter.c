/* Route filtering function.
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
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include <stdlib.h>		/* for atol () */
#include <arpa/inet.h>		/* for inet_ntoa () */

#include "filter.h"
#include "route.h"
#include "memory.h"

/* Filter element of access list */
struct filter
{
  /* For doubly linked list. */
  struct filter *next;
  struct filter *prev;

  /* Filter information. */
  u_char type;
  u_char prefixlen;
  struct in_addr prefix;
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
};

/* Static structure of all access_list's master. */
static struct access_master access_master = 
{ 
  {NULL, NULL},
  {NULL, NULL} 
};

/* Local prototypes. */
static int filter_match (struct filter *, struct prefix_in *);
static void filter_free (struct filter *filter);

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

  /* Insertion is made at middle of access_list. */
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
    printf ("%s/%d %s\n", inet_ntoa (filter->prefix), filter->prefixlen, 
	    (filter->type == FILTER_PERMIT) ? "permit" : "deny");
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

/* Apply access list to prefix_in. */
enum filter_type
access_list_apply (struct access_list *access, struct prefix_in *pin)
{
  struct filter *filter;

  for (filter = access->head; filter; filter = filter->next)
    {
      if (filter_match (filter, pin))
	return filter->type;
    }
  return FILTER_DENY;
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

/* Delete filter from specified access_list. */
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
}

/* Filter related functions. */

/* Mask bits for matching. */
static u_char maskbit[] = 
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
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

/* Allocate and make new filter. */
struct filter *
filter_make (struct in_addr prefix, u_char prefixlen, enum filter_type type)
{
  struct filter *filter;

  filter = filter_new ();
  filter->prefix = prefix;
  filter->prefixlen = prefixlen;
  filter->type = type;
  return filter;
}

struct filter *
filter_lookup (struct access_list *access, 
	       struct in_addr prefix,
	       u_char prefixlen,
	       enum filter_type type)
{
  struct filter *filter;

  for (filter = access->head; filter; filter = filter->next)
    {
      if (filter->prefix.s_addr == prefix.s_addr &&
	  filter->prefixlen == prefixlen &&
	  filter->type == type)
	return filter;
    }
  return NULL;
}

/* Return string of filter_type. */
static char *
filter_type_str (enum filter_type type)
{
  switch (type)
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

/* If filter is matched with prefix_in return 1. */
static int
filter_match (struct filter *filter, struct prefix_in *pin)
{
  int offset;
  int shift;

  u_char *np = (u_char *)&filter->prefix;
  u_char *pp = (u_char *)&pin->prefix;

  if (filter->prefixlen > pin->prefixlen)
    return 0;

  offset = filter->prefixlen / 8;
  shift =  filter->prefixlen % 8;
  
  if (shift)
    if (maskbit[shift] & (np[offset] ^ pp[offset]))
      return 0;
  
  while (offset--)
    if (np[offset] != pp[offset])
      return 0;
  return 1;
}

#ifdef TEST
/**/
main ()
{
  int ret;
  struct prefix_in pin;
  struct filter *filter1;
  struct filter *filter2;
  struct access_list *alist;
  
  alist = access_list_get ("abc");
  alist = access_list_get ("20");
  alist = access_list_get ("9");
  alist = access_list_get ("90");
  alist = access_list_get ("abd");
  alist = access_list_get ("10");
  alist = access_list_get ("1");
  alist = access_list_get ("1ab");
  alist = access_list_get ("kuni-1");
  alist = access_list_get ("abc");
  alist = access_list_get ("20");
  alist = access_list_get ("9");
  alist = access_list_get ("90");
  alist = access_list_get ("abd");
  alist = access_list_get ("10");
  alist = access_list_get ("1");
  alist = access_list_get ("1ab");
  alist = access_list_get ("kuni-1");

  access_list_print_all ();
#if 0
  inet_aton ("10.0.0.0", &pin.prefix);
  pin.prefixlen = 8;
  filter1 = filter_make (pin.prefix, pin.prefixlen, FILTER_PERMIT);

  inet_aton ("10.0.0.0", &pin.prefix);
  pin.prefixlen = 9;
  filter2 = filter_make (pin.prefix, pin.prefixlen, FILTER_DENY);

  access_list_filter_add (alist, filter2);
  access_list_filter_add (alist, filter1);
  access_list_print (alist);

  inet_aton ("10.127.0.1", &pin.prefix);
  pin.prefixlen = 32;
  
  ret = access_list_apply (alist, &pin);

  printf ("result %d\n", ret);
#endif /* 0 */
}
#endif /* TEST */


/* Below is vty related part. */
#include "vector.h"
#include "vty.h"
#include "command.h"

DEFUN (access_list, access_list_cmd,
       "access-list NAME TYPE IPV4_ADDR",
       "Access list definition.")
{
  int ret;
  enum filter_type type;
  struct filter *filter;
  struct access_list *access;
  struct prefix_in pin;

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

  /* Check string format of ipv4 prefix and prefixlen. */
  ret = str2prefix_in (argv[2], &pin);
  if (ret <= 0)
    {
      vty_out (vty, "IPv4 prefix/prefixlen is malformed\r\n");
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  filter = filter_make (pin.prefix, pin.prefixlen, type);
  access = access_list_get (argv[0]);
  access_list_filter_add (access, filter);

  return CMD_SUCCESS;
}

DEFUN (no_access_list, no_access_list_cmd,
       "no access-list NAME TYPE IPV4_ADDR",
       "Access list definition.")
{
  int ret;
  enum filter_type type;
  struct filter *filter;
  struct access_list *access;
  struct prefix_in pin;

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

  /* Check string format of ipv4 prefix and prefixlen. */
  ret = str2prefix_in (argv[2], &pin);
  if (ret <= 0)
    {
      vty_out (vty, "IPv4 prefix/prefixlen is malformed\r\n");
      return CMD_WARNING;
    }

  /* Looking up access_list. */
  access = access_list_lookup (argv[0]);
  if (access == NULL)
    {
      vty_out (vty, "access-list %s doesn't exist\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Looking up filter from access_list. */
  filter = filter_lookup (access, pin.prefix, pin.prefixlen, type);
  if (filter == NULL)
    {
      vty_out (vty, "access-list %s %s %s/%d doesn't exist\r\n", 
	       argv[0],
	       filter_type_str (type),
	       inet_ntoa (pin.prefix),
	       pin.prefixlen);
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
config_write_access (struct vty *vty, vector v)
{
  struct access_list *access;
  struct filter *filter;

  for (access = access_master.num.head; access; access = access->next)
    for (filter = access->head; filter; filter = filter->next)
      vty_out (vty, 
	       "access-list %s %s %s/%d\r\n", 
	       access->name,
	       filter_type_str (filter->type),
	       inet_ntoa (filter->prefix),
	       filter->prefixlen);

  for (access = access_master.str.head; access; access = access->next)
    for (filter = access->head; filter; filter = filter->next)
      vty_out (vty, 
	       "access-list %s %s %s/%d\r\n", 
	       access->name,
	       filter_type_str (filter->type),
	       inet_ntoa (filter->prefix),
	       filter->prefixlen);
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
