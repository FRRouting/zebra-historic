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

/* Static structure of IPv4 prefix_list's master. */
static struct prefix_master prefix_master_ipv4 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  NULL,
  NULL,
};

#ifdef HAVE_IPV6
/* Static structure of IPv6 prefix-list's master. */
static struct prefix_master prefix_master_ipv6 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  NULL,
  NULL,
};
#endif /* HAVE_IPV6*/

struct prefix_master *
prefix_master_get (int family)
{
  struct prefix_master *master = NULL;

  if (family == AF_INET)
    master = &prefix_master_ipv4;
#ifdef HAVE_IPV6
  else if (family == AF_INET6)
    master = &prefix_master_ipv6;
#endif /* HAVE_IPV6 */
  return master;
}

/* Lookup prefix_list from list of prefix_list by name. */
struct prefix_list *
prefix_list_lookup (int family, char *name)
{
  struct prefix_list *plist;
  struct prefix_master *master;

  if (name == NULL)
    return NULL;

  master = prefix_master_get (family);
  if (master == NULL)
    return NULL;

  for (plist = master->num.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  for (plist = master->str.head; plist; plist = plist->next)
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
prefix_list_insert (int family, char *name)
{
  int i;
  long number;
  struct prefix_list *plist;
  struct prefix_list *point;
  struct prefix_list_list *list;
  struct prefix_master *master;

  master = prefix_master_get (family);
  if (master == NULL)
    return NULL;

  /* Allocate new prefix_list and copy given name. */
  plist = prefix_list_new ();
  plist->name = strdup (name);
  plist->master = master;

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
      list = &master->num;

      for (point = list->head; point; point = point->next)
	if (atol (point->name) >= number)
	  break;
    }
  else
    {
      plist->type = PREFIX_TYPE_STRING;

      /* Set prefix_list to string list. */
      list = &master->str;
  
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
prefix_list_get (int family, char *name)
{
  struct prefix_list *prefix_list;

  prefix_list = prefix_list_lookup (family, name);

  if (prefix_list == NULL)
    prefix_list = prefix_list_insert (family, name);
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
  prefix_master_ipv4.add_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.delete_hook = func;
#endif /* HAVE_IPV6 */
}

/* Delete hook function. */
void
prefix_list_delete_hook (void (*func) ())
{
  prefix_master_ipv4.delete_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.delete_hook = func;
#endif /* HAVE_IPVt6 */
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

struct prefix_list_entry *
prefix_list_entry_lookup (struct prefix_list *plist, struct prefix *prefix,
			  enum prefix_list_type type, int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (prefix == NULL)
	{
	  if (pentry->any == 1 && pentry->type == type)
	    {
	      if (seq >= 0 && pentry->seq != seq)
		continue;
	      if (le >= 0 && pentry->le != le)
		continue;
	      if (ge >= 0 && pentry->ge != ge)
		continue;
	      return pentry;
	    }
	}
      else
	{
	  if (prefix_same (&pentry->prefix, prefix) && pentry->type == type)
	    {
	      if (seq >= 0 && pentry->seq != seq)
		continue;
	      if (le >= 0 && pentry->le != le)
		continue;
	      if (ge >= 0 && pentry->ge != ge)
		continue;
	      return pentry;
	    }
	}
    }

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

  if (plist->master->delete_hook)
    (*plist->master->delete_hook) ();
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
  if (plist->master->add_hook)
    (*plist->master->add_hook) ();
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

int
prefix_list_entry_match (struct prefix_list_entry *pentry, struct prefix *p)
{
  int ret;

  ret = prefix_match (&pentry->prefix, p);
  if (! ret)
    return 0;
  
  if (pentry->le >= 0)
    if (p->prefixlen > pentry->le)
      return 0;

  if (pentry->ge >= 0)
    if (p->prefixlen < pentry->ge)
      return 0;

  return 1;
}

enum prefix_list_type
prefix_list_apply (struct prefix_list *plist, void *object)
{
  struct prefix_list_entry *pentry;
  struct prefix *p;

  p = (struct prefix *) object;

  if (plist->count == 0)
    return PREFIX_PERMIT;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (prefix_list_entry_match (pentry, p))
      return pentry->type;

  return PREFIX_DENY;
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
	  
	  printf ("  seq %d %s %s/%d", 
		  pentry->seq,
		  prefix_list_type_str (pentry),
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		  p->prefixlen);
	  if (pentry->ge >= 0)
	    printf (" ge %d", pentry->ge);
	  if (pentry->le >= 0)
	    printf (" le %d", pentry->le);
	  printf ("\n");
	}
    }
}

DEFUN (ip_prefix_list, ip_prefix_list_cmd,
       "ip prefix-list NAME ...",
       IP_STR
       "Set prefix list definition\n"
       "Prefix list name\n"
       "Prefix list type\n")
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int optind;
  int any = 0;
  int seq = -1;
  int le = -1;
  int ge = -1;

  /* Get prefix_list with name. */
  plist = prefix_list_get (AF_INET, argv[0]);

  /* Set option index. */
  optind = 1;

  /* Check of first argument. */
  if (strcmp (argv[optind], "seq") == 0)
    {
      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify seq number\r\n");
	  return CMD_WARNING;
	}
      if (seq != -1)
	{
	  vty_out (vty, "Seq number is already specified\r\n");
	}
      seq = atoi (argv[optind]);

      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify type\r\n");
	  return CMD_WARNING;
	}
    }

  /* Check of filter type. */
  if (strcmp (argv[optind], "permit") == 0)
    type = PREFIX_PERMIT;
  else if (strcmp (argv[optind], "deny") == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  optind++;
  if (optind == argc)
    {
      vty_out (vty, "Please specify prefix\r\n");
      return CMD_WARNING;
    }
  
  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[optind], "any") == 0)
    any = 1;
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[optind], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
    }
  optind++;

  /* seq, ge and le check. */
  while (optind < argc)
    {
      if (strcmp (argv[optind], "seq") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify seq number\r\n");
	      return CMD_WARNING;
	    }
	  if (seq != -1)
	    {
	      vty_out (vty, "Seq number is already specified\r\n");
	    }
	  seq = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "ge") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify ge number\r\n");
	      return CMD_WARNING;
	    }
	  if (ge != -1)
	    {
	      vty_out (vty, "ge number is already specified\r\n");
	    }
	  ge = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "le") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify le number\r\n");
	      return CMD_WARNING;
	    }
	  if (le != -1)
	    {
	      vty_out (vty, "le number is already specified\r\n");
	    }
	  le = atoi (argv[optind++]);
	}
      else
	{
	  vty_out (vty, "Unknown prefix-list option: %s\r\n", argv[optind]);
	  return CMD_WARNING;
	}
    }

  if (any)
    pentry = prefix_list_entry_make (NULL, type, seq, le, ge);
  else
    pentry = prefix_list_entry_make (&p, type, seq, le, ge);
    
  
  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return CMD_SUCCESS;
}

DEFUN (no_ip_prefix_list, no_ip_prefix_list_cmd,
       "no ip prefix-list NAME ...",
       NO_STR
       IP_STR
       "Set prefix list definition\n"
       "Prefix list name\n"
       "Prefix list type\n")
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int optind;
  int any = 0;
  int seq = -1;
  int le = -1;
  int ge = -1;

  /* Check prefix list name. */
  plist = prefix_list_lookup (AF_INET, argv[0]);
  if (! plist)
    {
      vty_out (vty, "Can't find specified prefix-list\r\n");
      return CMD_WARNING;
    }

  /* Set parse start option index. */
  optind = 1;

  /* Check of first argument. */
  if (strcmp (argv[optind], "seq") == 0)
    {
      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify seq number\r\n");
	  return CMD_WARNING;
	}
      if (seq != -1)
	{
	  vty_out (vty, "Seq number is already specified\r\n");
	}
      seq = atoi (argv[optind]);

      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify type\r\n");
	  return CMD_WARNING;
	}
    }

  /* Check of filter type. */
  if (strcmp (argv[optind], "permit") == 0)
    type = PREFIX_PERMIT;
  else if (strcmp (argv[optind], "deny") == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  optind++;
  if (optind == argc)
    {
      vty_out (vty, "Please specify prefix\r\n");
      return CMD_WARNING;
    }

  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[optind], "any") == 0)
    any = 1;
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[optind], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
    }

  optind++;

  /* seq, ge and le check. */
  while (optind < argc)
    {
      if (strcmp (argv[optind], "seq") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify seq number\r\n");
	      return CMD_WARNING;
	    }
	  if (seq != -1)
	    {
	      vty_out (vty, "Seq number is already specified\r\n");
	    }
	  seq = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "ge") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify ge number\r\n");
	      return CMD_WARNING;
	    }
	  if (ge != -1)
	    {
	      vty_out (vty, "ge number is already specified\r\n");
	    }
	  ge = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "le") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify le number\r\n");
	      return CMD_WARNING;
	    }
	  if (le != -1)
	    {
	      vty_out (vty, "le number is already specified\r\n");
	    }
	  le = atoi (argv[optind++]);
	}
      else
	{
	  vty_out (vty, "Unknown option\r\n");
	  return CMD_WARNING;
	}
    }

  if (any)
    pentry = prefix_list_entry_lookup (plist, NULL, type, seq, le, ge);
  else
    pentry = prefix_list_entry_lookup (plist, &p, type, seq, le, ge);

  if (pentry == NULL)
    {
      vty_out (vty, "Can't find specified prefix-list\r\n");
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_delete (plist, pentry);

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (ipv6_prefix_list, ipv6_prefix_list_cmd,
       "ipv6 prefix-list NAME ...",
       IP_STR
       "Set prefix list definition\n"
       "Prefix list name\n"
       "Prefix list type\n")
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int optind;
  int any = 0;
  int seq = -1;
  int le = -1;
  int ge = -1;

  /* Get prefix_list with name. */
  plist = prefix_list_get (AF_INET6, argv[0]);

  /* Set option index. */
  optind = 1;

  /* Check of first argument. */
  if (strcmp (argv[optind], "seq") == 0)
    {
      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify seq number\r\n");
	  return CMD_WARNING;
	}
      if (seq != -1)
	{
	  vty_out (vty, "Seq number is already specified\r\n");
	}
      seq = atoi (argv[optind]);

      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify type\r\n");
	  return CMD_WARNING;
	}
    }

  /* Check of filter type. */
  if (strcmp (argv[optind], "permit") == 0)
    type = PREFIX_PERMIT;
  else if (strcmp (argv[optind], "deny") == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  optind++;
  if (optind == argc)
    {
      vty_out (vty, "Please specify prefix\r\n");
      return CMD_WARNING;
    }
  
  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[optind], "any") == 0)
    any = 1;
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[optind], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
    }
  optind++;

  /* seq, ge and le check. */
  while (optind < argc)
    {
      if (strcmp (argv[optind], "seq") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify seq number\r\n");
	      return CMD_WARNING;
	    }
	  if (seq != -1)
	    {
	      vty_out (vty, "Seq number is already specified\r\n");
	    }
	  seq = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "ge") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify ge number\r\n");
	      return CMD_WARNING;
	    }
	  if (ge != -1)
	    {
	      vty_out (vty, "ge number is already specified\r\n");
	    }
	  ge = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "le") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify le number\r\n");
	      return CMD_WARNING;
	    }
	  if (le != -1)
	    {
	      vty_out (vty, "le number is already specified\r\n");
	    }
	  le = atoi (argv[optind++]);
	}
      else
	{
	  vty_out (vty, "Unknown prefix-list option: %s\r\n", argv[optind]);
	  return CMD_WARNING;
	}
    }

  if (any)
    pentry = prefix_list_entry_make (NULL, type, seq, le, ge);
  else
    pentry = prefix_list_entry_make (&p, type, seq, le, ge);
    
  
  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_prefix_list, no_ipv6_prefix_list_cmd,
       "no ipv6 prefix-list NAME ...",
       NO_STR
       IP_STR
       "Set prefix list definition\n"
       "Prefix list name\n"
       "Prefix list type\n")
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int optind;
  int any = 0;
  int seq = -1;
  int le = -1;
  int ge = -1;

  /* Check prefix list name. */
  plist = prefix_list_lookup (AF_INET6, argv[0]);
  if (! plist)
    {
      vty_out (vty, "Can't find specified prefix-list\r\n");
      return CMD_WARNING;
    }

  /* Set parse start option index. */
  optind = 1;

  /* Check of first argument. */
  if (strcmp (argv[optind], "seq") == 0)
    {
      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify seq number\r\n");
	  return CMD_WARNING;
	}
      if (seq != -1)
	{
	  vty_out (vty, "Seq number is already specified\r\n");
	}
      seq = atoi (argv[optind]);

      optind++;
      if (optind == argc)
	{
	  vty_out (vty, "Please specify type\r\n");
	  return CMD_WARNING;
	}
    }

  /* Check of filter type. */
  if (strcmp (argv[optind], "permit") == 0)
    type = PREFIX_PERMIT;
  else if (strcmp (argv[optind], "deny") == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "prefix type must be [permit|deny]\r\n");
      return CMD_WARNING;
    }

  optind++;
  if (optind == argc)
    {
      vty_out (vty, "Please specify prefix\r\n");
      return CMD_WARNING;
    }

  /* "any" is special token of matching IP addresses.  */
  if (strcmp (argv[optind], "any") == 0)
    any = 1;
  else
    {
      /* Check string format of prefix and prefixlen. */
      ret = str2prefix (argv[optind], &p);
      if (ret <= 0)
	{
	  vty_out (vty, "IP address prefix/prefixlen is malformed\r\n");
	  return CMD_WARNING;
	}
    }

  optind++;

  /* seq, ge and le check. */
  while (optind < argc)
    {
      if (strcmp (argv[optind], "seq") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify seq number\r\n");
	      return CMD_WARNING;
	    }
	  if (seq != -1)
	    {
	      vty_out (vty, "Seq number is already specified\r\n");
	    }
	  seq = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "ge") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify ge number\r\n");
	      return CMD_WARNING;
	    }
	  if (ge != -1)
	    {
	      vty_out (vty, "ge number is already specified\r\n");
	    }
	  ge = atoi (argv[optind++]);
	}
      else if (strcmp (argv[optind], "le") == 0)
	{
	  optind++;

	  if (optind == argc)
	    {
	      vty_out (vty, "Please specify le number\r\n");
	      return CMD_WARNING;
	    }
	  if (le != -1)
	    {
	      vty_out (vty, "le number is already specified\r\n");
	    }
	  le = atoi (argv[optind++]);
	}
      else
	{
	  vty_out (vty, "Unknown option\r\n");
	  return CMD_WARNING;
	}
    }

  if (any)
    pentry = prefix_list_entry_lookup (plist, NULL, type, seq, le, ge);
  else
    pentry = prefix_list_entry_lookup (plist, &p, type, seq, le, ge);

  if (pentry == NULL)
    {
      vty_out (vty, "Can't find specified prefix-list\r\n");
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_delete (plist, pentry);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* Prefix-list node. */
struct cmd_node prefix_node =
{
  PREFIX_NODE,
  ""				/* Prefix list has no interface. */
};

/* Configuration write function. */
int
config_write_prefix_family (int family, struct vty *vty)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_master *master;
  int write = 0;

  master = prefix_master_get (family);
  if (master == NULL)
    return 0;

  for (plist = master->num.head; plist; plist = plist->next)
    for (pentry = plist->head; pentry; pentry = pentry->next)
      {
	vty_out (vty, "ip%s prefix-list %s seq %d %s",
		 family == AF_INET ? "" : "v6",
		 plist->name,
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
	if (pentry->le >= 0)
	  vty_out (vty, " le %d", pentry->le);
	if (pentry->ge >= 0)
	  vty_out (vty, " ge %d", pentry->ge);
	vty_out (vty, "%s", VTY_NEWLINE);
	write++;
      }

  for (plist = master->str.head; plist; plist = plist->next)
    for (pentry = plist->head; pentry; pentry = pentry->next)
      {
	vty_out (vty, "ip%s prefix-list %s seq %d %s",
		 family == AF_INET ? "" : "v6",
		 plist->name,
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
	if (pentry->le >= 0)
	  vty_out (vty, " le %d", pentry->le);
	if (pentry->ge >= 0)
	  vty_out (vty, " ge %d", pentry->ge);
	vty_out (vty, "%s", VTY_NEWLINE);
	write++;
      }
  
  return write;
}

int
config_write_prefix (struct vty *vty)
{
  int write;

  write = config_write_prefix_family (AF_INET, vty);

#ifdef HAVE_IPV6
  if (write)
    vty_out (vty, "!\r\n");
  write = config_write_prefix_family (AF_INET6, vty);
#endif /* HAVE_IPV6 */

  return write;
}

/* Install vty related command.*/
void
prefix_list_init ()
{
  install_node (&prefix_node, config_write_prefix);

  install_element (CONFIG_NODE, &ip_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_cmd);

#ifdef HAVE_IPV6
  install_element (CONFIG_NODE, &ipv6_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_cmd);
#endif /* HAVE_IPV6 */
}
