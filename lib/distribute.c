/*
 * Distribute list functions
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "hash.h"
#include "linklist.h"
#include "if.h"
#include "filter.h"
#include "memory.h"

/* distribute-list sit1-filter out sit1 */

/* Disctirubte list types. */
enum distribute_type
{
  DISTRIBUTE_IN,
  DISTRIBUTE_OUT,
  DISTRIBUTE_MAX
};

struct distribute
{
  /* Name of the interface. */
  char *ifname;

  /* Filter name of `in' and `out' */
  char *slot[DISTRIBUTE_MAX];
};

/* Hash of distribute list. */
struct Hash *disthash;

struct distribute *
distribute_new ()
{
  struct distribute *new;

  new = XMALLOC (MTYPE_DISTRIBUTE, sizeof (struct distribute));
  bzero (new, sizeof (struct distribute));

  return new;
}

/* Free distribute object. */
void
distribute_free (struct distribute *dist)
{
  if (dist->ifname)
    free (dist->ifname);
  if (dist->slot[DISTRIBUTE_IN])
    free (dist->slot[DISTRIBUTE_IN]);
  if (dist->slot[DISTRIBUTE_OUT])
    free (dist->slot[DISTRIBUTE_OUT]);

  XFREE (MTYPE_DISTRIBUTE, dist);
}

/* Lookup interface's distribute list. */
struct distribute *
distribute_lookup (char *ifname)
{
  struct distribute key;
  struct distribute *dist;

  key.ifname = ifname;

  dist = hash_search (disthash, &key);
  
  return dist;
}

/* Set distribute list to the interface */
void
distribute_apply (struct distribute *dist)
{
  struct interface *ifp;
  struct access_list *alist;

  ifp = if_lookup_by_name (dist->ifname);
  if (ifp == NULL)
    return;

  /* Set input distribute_list */
  if (dist->slot[DISTRIBUTE_IN])
    {
      alist = access_list_lookup (dist->slot[DISTRIBUTE_IN]);
      if (alist)
	ifp->distribute_in = alist;
    }
  else
    ifp->distribute_in = NULL;

  /* Set output distribute_list */
  if (dist->slot[DISTRIBUTE_OUT])
    {
      alist = access_list_lookup (dist->slot[DISTRIBUTE_OUT]);
      if (alist)
	ifp->distribute_out = alist;
    }
  else
    ifp->distribute_out = NULL;
}

/* Set distribute list to all interfaces. */
void
distribute_apply_all ()
{
  struct interface *ifp;
  struct distribute *dist;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      dist = distribute_lookup (ifp->name);

      if (dist)
	distribute_apply (dist);
    }
}

/* Apply input distribute-list to the prefix. */
enum filter_type
distribute_apply_in (struct interface *ifp, struct prefix *p)
{
  if (ifp->distribute_in)
    return (access_list_apply (ifp->distribute_in, p));

  return FILTER_PERMIT;
}

/* Apply input distribute-list to the prefix. */
enum filter_type
distribute_apply_out (struct interface *ifp, struct prefix *p)
{
  if (ifp->distribute_out)
    return (access_list_apply (ifp->distribute_out, p));

  return FILTER_PERMIT;
}

/* Make new distribute list and push into hash. */
struct distribute *
distribute_get (char *ifname)
{
  struct distribute *dist;

  dist = distribute_lookup (ifname);
  if (dist == NULL)
    {
      dist = distribute_new ();
      dist->ifname = strdup (ifname);
      hash_push (disthash, dist);
    }
  return dist;
}

unsigned int
distribute_hash_make (struct distribute *dist)
{
  unsigned int key;
  int i;

  key = 0;
  for (i = 0; i < strlen (dist->ifname); i++)
    key += dist->ifname[i];

  return key %= HASHTABSIZE;
}

/* If two distribute-list have same value then return 1 else return
   0. This function is used by hash package. */
int
distribute_cmp (struct distribute *dist1, struct distribute *dist2)
{
  if (strcmp (dist1->ifname, dist2->ifname) == 0)
    return 1;
  return 0;
}

/* Utility function. */
void
distribute_print (struct distribute *dist)
{
  printf ("distribute-list %s in %s out %s\n", dist->ifname, 
	  dist->slot[DISTRIBUTE_IN], dist->slot[DISTRIBUTE_OUT]);
}

/* Below is vty related part. */
#include "vector.h"
#include "vty.h"
#include "command.h"

/* Set access-list name to the distribute list. */
struct distribute *
distribute_set (char *ifname, enum distribute_type type, char *alist_name)
{
  struct distribute *dist;

  dist = distribute_get (ifname);

  if (type == DISTRIBUTE_IN)
    {
      if (dist->slot[DISTRIBUTE_IN])
	free (dist->slot[DISTRIBUTE_IN]);
      dist->slot[DISTRIBUTE_IN] = strdup (alist_name);
    }
  if (type == DISTRIBUTE_OUT)
    {
      if (dist->slot[DISTRIBUTE_OUT])
	free (dist->slot[DISTRIBUTE_OUT]);
      dist->slot[DISTRIBUTE_OUT] = strdup (alist_name);
    }

  /* Apply this distribute-list to the interface. */
  distribute_apply (dist);
  
  return dist;
}

/* Unset distribute-list.  If matched distribute-list exist then
   return 1. */
int
distribute_unset (char *ifname, enum distribute_type type, char *alist_name)
{
  struct distribute *dist;

  dist = distribute_lookup (ifname);
  if (!dist)
    return 0;

  if (type == DISTRIBUTE_IN)
    {
      if (!dist->slot[DISTRIBUTE_IN])
	return 0;
      if (strcmp (dist->slot[DISTRIBUTE_IN], alist_name) != 0)
	return 0;

      free (dist->slot[DISTRIBUTE_IN]);
      dist->slot[DISTRIBUTE_IN] = NULL;      
    }

  if (type == DISTRIBUTE_OUT)
    {
      if (!dist->slot[DISTRIBUTE_OUT])
	return 0;
      if (strcmp (dist->slot[DISTRIBUTE_OUT], alist_name) != 0)
	return 0;

      free (dist->slot[DISTRIBUTE_OUT]);
      dist->slot[DISTRIBUTE_OUT] = NULL;      
    }

  /* Apply this distribute-list to the interface. */
  distribute_apply (dist);

  /* If both out and in is NULL then free distribute list. */
  if (dist->slot[DISTRIBUTE_IN] == NULL &&
      dist->slot[DISTRIBUTE_OUT] == NULL)
    {
      hash_pull (disthash, dist);
      distribute_free (dist);
    }

  return 1;
}

DEFUN (districute_list, distribute_list_cmd,
       "distribute-list ALIST_NAME (in|out) IFNAME",
       "Distirbute list set\n"
       "Distirbute list access-list name\n"
       "Distribute list set to in\n"
       "Distribute list set to out\n"
       "Distribute list interface name\n")
{
  enum distribute_type type;
  struct distribute *dist;

  /* Check of distribute list type. */
  if (strcmp (argv[1], "in") == 0)
    type = DISTRIBUTE_IN;
  else if (strcmp (argv[1], "out") == 0)
    type = DISTRIBUTE_OUT;
  else
    {
      vty_out (vty, "distribute list direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  /* Get interface name corresponding distribute list. */
  dist = distribute_set (argv[2], type, argv[0]);

  return CMD_SUCCESS;
}       

DEFUN (no_districute_list, no_distribute_list_cmd,
       "no distribute-list ALIST_NAME (in|out) IFNAME",
       NO_STR
       "Distirbute list unset\n"
       "Distirbute list access-list name\n"
       "Distribute list to in\n"
       "Distribute list to out\n"
       "Distribute list interface name\n")
{
  int ret;
  enum distribute_type type;

  /* Check of distribute list type. */
  if (strcmp (argv[1], "in") == 0)
    type = DISTRIBUTE_IN;
  else if (strcmp (argv[1], "out") == 0)
    type = DISTRIBUTE_OUT;
  else
    {
      vty_out (vty, "distribute list direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  ret = distribute_unset (argv[2], type, argv[0]);
  if (! ret)
    {
      vty_out (vty, "distribute list doesn't exist\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}       

/* distribute-list node. */
struct cmd_node distribute_node =
{
  DISTRIBUTE_NODE,
  ""				/* Distirubte list has no interface. */
};

/* Configuration write function. */
int
config_write_distribute (struct vty *vty)
{
  int i;
  HashBacket *mp;
  int write = 0;

  for (i = 0; i < HASHTABSIZE; i++)
    for (mp = hash_head (disthash, i); mp; mp = mp->next)
      {
	struct distribute *dist;

	dist = mp->data;

	if (dist->slot[DISTRIBUTE_IN])
	  {
	    vty_out (vty, "distribute-list %s in %s%s", 
		     dist->slot[DISTRIBUTE_IN],
		     dist->ifname, VTY_NEWLINE);
	    write++;
	  }

	if (dist->slot[DISTRIBUTE_OUT])
	  {
	    vty_out (vty, "distribute-list %s out %s%s", 
		     dist->slot[DISTRIBUTE_OUT],
		     dist->ifname, VTY_NEWLINE);
	    write++;
	  }
      }
  return write;
}

/* Initialize distribute list related hash. */
void
distribute_init ()
{
  disthash = hash_new (HASHTABSIZE);
  disthash->hash_key = distribute_hash_make;
  disthash->hash_cmp = distribute_cmp;

  install_node (&distribute_node, config_write_distribute);

  install_element (CONFIG_NODE, &distribute_list_cmd);
  install_element (CONFIG_NODE, &no_distribute_list_cmd);
}
