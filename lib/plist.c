/*
 * Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
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
#include "command.h"
#include "memory.h"
#include "plist.h"

enum prefix_name_type
{
  PREFIX_TYPE_STRING,
  PREFIX_TYPE_NUMBER
};

struct prefix_list
{
  char *name;
  char *desc;

  enum prefix_name_type type;

  int count;
  struct prefix_list_entry *head;
  struct prefix_list_entry *tail;

  struct prefix_list *next;
  struct prefix_list *prev;
};

struct prefix_list_entry
{
  int seq;

  int le;
  int ge;

  enum prefix_list_type type;

  int any;
  struct prefix prefix;

  struct prefix_list_entry *next;
  struct prefix_list_entry *prev;
};

/* List of prefix_list. */
struct prefix_list_list
{
  struct prefix_list *head;
  struct prefix_list *tail;
};

/* Master structure of prefix_list. */
struct prefix_master
{
  /* List of prefix_list which name is number. */
  struct prefix_list_list num;

  /* List of prefix_list which name is string. */
  struct prefix_list_list str;

  /* Hook function which is executed when new prefix_list is added. */
  void (*add_hook) ();

  /* Hook function which is executed when prefix_list is deleted. */
  void (*delete_hook) ();
};

/* Static structure of all prefix_list's master. */
static struct prefix_master prefix_master = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  NULL,
  NULL,
};

/* Lookup prefix_list from list of prefix_list by name. */
struct prefix_list *
prefix_list_lookup (char *name)
{
  struct prefix_list *plist;

  if (name == NULL)
    return NULL;

  for (plist = prefix_master.num.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  for (plist = prefix_master.str.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  return NULL;
}

struct prefix_list *
prefix_list_new ()
{
  struct prefix_list *new;

  new = XMALLOC (MTYPE_PREFIX_LIST, sizeof (struct prefix_list));
  bzero (new, sizeof (struct prefix_list));
  return new;
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
struct prefix_list *
prefix_list_insert (char *name)
{
  int i;
  long number;
  struct prefix_list *plist;
  struct prefix_list *point;
  struct prefix_list_list *list;

  /* Allocate new prefix_list and copy given name. */
  plist = prefix_list_new ();
  plist->name = strdup (name);

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
      plist->type = PREFIX_TYPE_NUMBER;

      /* Set prefix_list to number list. */
      list = &prefix_master.num;

      for (point = list->head; point; point = point->next)
	if (atol (point->name) >= number)
	  break;
    }
  else
    {
      plist->type = PREFIX_TYPE_STRING;

      /* Set prefix_list to string list. */
      list = &prefix_master.str;
  
      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
	if (strcmp (point->name, name) >= 0)
	  break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      plist->prev = list->tail;
      list->tail->next = plist;
      list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      plist->next = list->head;
      list->head->prev = plist;
      list->head = plist;
      return plist;
    }

  /* Insertion is made at middle of the access_list. */
  plist->next = point;
  plist->prev = point->prev;

  if (point->prev)
    point->prev->next = plist;
  point->prev = plist;

  return plist;
}

struct prefix_list *
prefix_list_get (char *name)
{
  struct prefix_list *prefix_list;

  prefix_list = prefix_list_lookup (name);

  if (prefix_list == NULL)
    prefix_list = prefix_list_insert (name);
  return prefix_list;
}

struct prefix_list_entry *
prefix_list_entry_new ()
{
  struct prefix_list_entry *new;

  new = XMALLOC (MTYPE_PREFIX_LIST_ENTRY, sizeof (struct prefix_list_entry));
  bzero (new, sizeof (struct prefix_list_entry));
  return new;
}

void
prefix_list_entry_free (struct prefix_list_entry *pentry)
{
  XFREE (MTYPE_PREFIX_LIST_ENTRY, pentry);
}

struct prefix_list_entry *
prefix_list_entry_make (struct prefix *prefix, enum prefix_list_type type,
			int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  pentry = prefix_list_entry_new ();

  /* If prefix is NULL then this is "any" match directive. */
  if (prefix == NULL)
    pentry->any = 1;
  else
    prefix_copy (&pentry->prefix, prefix);

  pentry->type = type;
  pentry->seq = seq;
  pentry->le = le;
  pentry->ge = ge;

  return pentry;
}

/* Add hook function. */
void
prefix_list_add_hook (void (*func) ())
{
  prefix_master.add_hook = func;
}

/* Delete hook function. */
void
prefix_list_delete_hook (void (*func) ())
{
  prefix_master.delete_hook = func;
}

/* Calculate new sequential number. */
int
prefix_new_seq_get (struct prefix_list *plist)
{
  int maxseq;
  int newseq;
  struct prefix_list_entry *pentry;

  maxseq = newseq = 0;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (maxseq < pentry->seq)
	maxseq = pentry->seq;
    }

  newseq = ((maxseq / 5) * 5) + 5;
  
  return newseq;
}

/* Return prefix list entry which has same seq number. */
struct prefix_list_entry *
prefix_seq_check (struct prefix_list *plist, int seq)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (pentry->seq == seq)
      return pentry;
  return NULL;
}

void
prefix_list_entry_delete (struct prefix_list *plist, 
			  struct prefix_list_entry *pentry)
{
  if (plist == NULL || pentry == NULL)
    return;
  if (pentry->prev)
    pentry->prev->next = pentry->next;
  else
    plist->head = pentry->next;
  if (pentry->next)
    pentry->next->prev = pentry->prev;
  else
    plist->tail = pentry->prev;

  plist->count--;

  prefix_list_entry_free (pentry);
}

void
prefix_list_entry_add (struct prefix_list *plist,
		       struct prefix_list_entry *pentry)
{
  struct prefix_list_entry *replace;
  struct prefix_list_entry *point;

  /* Automatic asignment of seq no. */
  if (pentry->seq == -1)
    pentry->seq = prefix_new_seq_get (plist);

  /* Is there any same seq prefix list entry? */
  replace = prefix_seq_check (plist, pentry->seq);
  if (replace)
    prefix_list_entry_delete (plist, replace);

  /* Check insert point. */
  for (point = plist->head; point; point = point->next)
    if (point->seq >= pentry->seq)
      break;

  /* In case of this is the first element of the list. */
  pentry->next = point;

  if (point)
    {
      if (point->prev)
	point->prev->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = point->prev;
      point->prev = pentry;
    }
  else
    {
      if (plist->tail)
	plist->tail->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = plist->tail;
      plist->tail = pentry;
    }

  /* Increment count. */
  plist->count++;

  /* Run hook function. */
  if (prefix_master.add_hook)
    (*prefix_master.add_hook) ();
}

/* Return string of prefix_list_type. */
static char *
prefix_list_type_str (struct prefix_list_entry *pentry)
{
  switch (pentry->type)
    {
    case PREFIX_PERMIT:
      return "permit";
      break;
    case PREFIX_DENY:
      return "deny";
      break;
    default:
      return "";
      break;
    }
}

void
prefix_list_print (struct prefix_list *plist)
{
  struct prefix_list_entry *pentry;

  if (plist == NULL)
    return;

  printf ("ip prefix-list %s: %d entries\n", plist->name, plist->count);

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (pentry->any)
	printf ("any %s\n", prefix_list_type_str (pentry));
      else
	{
	  struct prefix *p;
	  char buf[BUFSIZ];
	  
	  p = &pentry->prefix;
	  
	  printf ("  seq %d %s %s/%d\n", 
		  pentry->seq,
		  prefix_list_type_str (pentry),
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		  p->prefixlen);
	}
    }
}

DEFUN (prefix_list, prefix_list_cmd,
       "ip prefix-list NAME TYPE IP_ADDR ...",
       IP_STR
       "Set prefix list definition\n"
       "Prefix list name\n"
       "Prefix list type\n"
       "Prefix list address\n")
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;

  /* Check of filter type. */
  if (strcmp (argv[1], "permit") == 0)
    type = PREFIX_PERMIT;
  else if (strcmp (argv[1], "deny") == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[2], "any") == 0)
      pentry = prefix_list_entry_make (NULL, type, -1, -1, -1);
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[2], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
      pentry = prefix_list_entry_make (&p, type, -1, -1, -1);
    }

  plist = prefix_list_get (argv[0]);

  /* seq, ge and le check. */
  argc -= 2;
  argv += 2;
  while (argc > 0)
    {
      ;
    }
  
  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return CMD_SUCCESS;
}

/* Prefix-list node. */
struct cmd_node prefix_node =
{
  PREFIX_NODE,
  ""				/* Prefix list has no interface. */
};

/* Configuration write function. */
int
config_write_prefix (struct vty *vty)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;

  for (plist = prefix_master.num.head; plist; plist = plist->next)
    for (pentry = plist->head; pentry; pentry = pentry->next)
      {
	vty_out (vty, "ip prefix-list seq %d %s",
		 pentry->seq, prefix_list_type_str (pentry));

	if (pentry->any)
	  vty_out (vty, " any");
	else
	  {
	    struct prefix *p = &pentry->prefix;
	    char buf[BUFSIZ];

	    vty_out (vty, " %s/%d",
		    inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		    p->prefixlen);
	  }
	if (pentry->le > 0)
	  vty_out (vty, " le %d", pentry->le);
	if (pentry->ge > 0)
	  vty_out (vty, " ge %d", pentry->ge);
	vty_out (vty, "%s", VTY_NEWLINE);
      }

  for (plist = prefix_master.str.head; plist; plist = plist->next)
    for (pentry = plist->head; pentry; pentry = pentry->next)
      {
	vty_out (vty, "ip prefix-list seq %d %s",
		 pentry->seq, prefix_list_type_str (pentry));

	if (pentry->any)
	  vty_out (vty, " any");
	else
	  {
	    struct prefix *p = &pentry->prefix;
	    char buf[BUFSIZ];

	    vty_out (vty, " %s/%d",
		    inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		    p->prefixlen);
	  }
	if (pentry->le > 0)
	  vty_out (vty, " le %d", pentry->le);
	if (pentry->ge > 0)
	  vty_out (vty, " ge %d", pentry->ge);
	vty_out (vty, "%s", VTY_NEWLINE);
      }
  
  return 0;
}

/* Install vty related command.*/
void
prefix_list_init ()
{
  install_node (&prefix_node, config_write_prefix);

  install_element (CONFIG_NODE, &prefix_list_cmd);
  install_element (CONFIG_NODE, &prefix_list_cmd);
}

#ifdef TEST
int
main ()
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;

  plist = prefix_list_get ("kuni");

  str2prefix ("10.0.0.0/8", &p);
  pentry = prefix_list_entry_make (&p, PREFIX_PERMIT, -1, -1, -1);
  prefix_list_entry_add (plist, pentry);

  str2prefix ("11.0.0.0/8", &p);
  pentry = prefix_list_entry_make (&p, PREFIX_PERMIT, 5, -1, -1);
  prefix_list_entry_add (plist, pentry);

  prefix_list_print (plist);

  exit (0);
}
#endif /* TEST */
