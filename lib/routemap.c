/*
 * Route map function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include "vector.h"
#include "prefix.h"
#include "routemap.h"

/* Vector for route match rules. */
static vector route_match_vec;

/* Vector for route set rules. */
static vector route_set_vec;

/* Route map rule. This rule has both `match' rule and `set' rule. */
struct route_map_rule
{
  /* Rule type. */
  struct route_map_rule_cmd *cmd;

  /* For pretty printing. */
  char *rule_str;

  /* Pre-compiled match rule. */
  void *value;

  /* Linked list. */
  struct route_map_rule *next;
  struct route_map_rule *prev;
};

/* Making route map list. */
struct route_map_list
{
  struct route_map *head;
  struct route_map *tail;

  void (*add_hook) ();
  void (*delete_hook) ();
};

/* Master list of route map. */
static struct route_map_list route_map_master = { NULL, NULL, NULL, NULL };

static void
route_map_rule_delete (struct route_map_rule_list *,
		       struct route_map_rule *);

/* New route map allocation. Please note route map's name must be
   specified. */
static struct route_map *
route_map_new (char *name)
{
  struct route_map *new;

  new =  XMALLOC (MTYPE_ROUTE_MAP, sizeof (struct route_map));
  bzero (new, sizeof (struct route_map));
  new->name = XSTRDUP (MTYPE_ROUTE_MAP_NAME, name);
  return new;
}

/* Add new name to route_map. */
static struct route_map *
route_map_add (char *name)
{
  struct route_map *map;
  struct route_map_list *list;

  map = route_map_new (name);
  list = &route_map_master;
    
  map->next = NULL;
  map->prev = list->tail;
  if (list->tail)
    list->tail->next = map;
  else
    list->head = map;
  list->tail = map;

  /* Execute hook. */
  if (route_map_master.add_hook)
    (*route_map_master.add_hook) ();

  return map;
}

/* Route map delete from list. */
static void
route_map_delete (struct route_map *map)
{
  struct route_map_list *list;

  /* Return if route map doesn't exist. */
  if (map->head != NULL || map->tail != NULL)
    return;

  if (map->name)
    XFREE (MTYPE_ROUTE_MAP_NAME, map->name);

  list = &route_map_master;

  if (map->next)
    map->next->prev = map->prev;
  else
    list->tail = map->prev;

  if (map->prev)
    map->prev->next = map->next;
  else
    list->head = map->next;

  XFREE (MTYPE_ROUTE_MAP, map);

  /* Execute deletion hook. */
  if (route_map_master.delete_hook)
    (*route_map_master.delete_hook) ();
}

/* Lookup route map by route map name string. */
struct route_map *
route_map_lookup_by_name (char *name)
{
  struct route_map *map;

  for (map = route_map_master.head; map; map = map->next)
    if (strcmp (map->name, name) == 0)
      return map;
  return NULL;
}

/* Lookup route map.  If there isn't route map create one and return
   it. */
struct route_map *
route_map_get (char *name)
{
  struct route_map *map;

  map = route_map_lookup_by_name (name);
  if (map == NULL)
    map = route_map_add (name);
  return map;
}

/* Return route map's type string. */
static char *
route_map_type_str (enum route_map_type type)
{
  switch (type)
    {
    case ROUTE_MAP_PERMIT:
      return "permit";
      break;
    case ROUTE_MAP_DENY:
      return "deny";
      break;
    default:
      return "";
      break;
    }
}

/* For debug. */
void
route_map_print ()
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;

  for (map = route_map_master.head; map; map = map->next)
    for (index = map->head; index; index = index->next)
      {
	printf ("route-map %s %s %d\n", 
		map->name,
		route_map_type_str (index->type),
		index->pref);
	for (rule = index->match_list.head; rule; rule = rule->next)
	  printf (" match %s %s\n", rule->cmd->str, rule->rule_str);
	for (rule = index->set_list.head; rule; rule = rule->next)
	  printf (" set %s %s\n", rule->cmd->str, rule->rule_str);
      }
}

/* New route map allocation. Please note route map's name must be
   specified. */
struct route_map_index *
route_map_index_new ()
{
  struct route_map_index *new;

  new =  XMALLOC (MTYPE_ROUTE_MAP_INDEX, sizeof (struct route_map_index));
  bzero (new, sizeof (struct route_map_index));
  return new;
}

/* Free route map index. */
void
route_map_index_delete (struct route_map_index *index)
{
  struct route_map_rule *rule;
  struct route_map_rule *next;

  /* Free route match. */
  for (rule = index->match_list.head; rule; rule = next)
    {
      next = rule->next;
      route_map_rule_delete (&index->match_list, rule);
    }

  /* Free route set. */
  for (rule = index->set_list.head; rule; rule = rule->next)
    {
      next = rule->next;
      route_map_rule_delete (&index->set_list, rule);
    }

  /* Remove index from route map list. */
  if (index->next)
    index->next->prev = index->prev;
  else
    index->map->tail = index->prev;

  if (index->prev)
    index->prev->next = index->next;
  else
    index->map->head = index->next;
  
  /* If this route rule is the last one, delete route map itself. */
  route_map_delete (index->map);

  XFREE (MTYPE_ROUTE_MAP_INDEX, index);
}

/* Lookup index from route map. */
struct route_map_index *
route_map_index_lookup (struct route_map *map, enum route_map_type type,
			int pref)
{
  struct route_map_index *index;

  for (index = map->head; index; index = index->next)
    if (index->type == type &&
	index->pref == pref)
      return index;
  return NULL;
}

/* Add new index to route map. */
struct route_map_index *
route_map_index_add (struct route_map *map, enum route_map_type type,
		     int pref)
{
  struct route_map_index *index;
  struct route_map_index *point;

  /* Allocate new route map inex. */
  index = route_map_index_new ();
  index->map = map;
  index->type = type;
  index->pref = pref;
  
  /* Compare preference. */
  for (point = map->head; point; point = point->next)
    if (point->pref >= pref)
      break;

  if (map->head == NULL)
    {
      map->head = map->tail = index;
      return index;
    }

  if (point == NULL)
    {
      index->prev = map->tail;
      map->tail->next = index;
      map->tail = index;
      return index;
    }
  
  if (index == map->head)
    {
      index->next = map->head;
      map->head->prev = index;
      map->head = index;
      return index;
    }

  index->next = point;
  index->prev = point->prev;
  if (point->prev)
    point->prev->next = index;
  point->prev = index;

  return index;
}

/* Get route map index. */
struct route_map_index *
route_map_index_get (struct route_map *map, enum route_map_type type, 
		     int pref)
{
  struct route_map_index *index;

  index = route_map_index_lookup (map, type, pref);
  if (index == NULL)
    index = route_map_index_add (map, type, pref);
  return index;
}

/* New route map rule */
struct route_map_rule *
route_map_rule_new ()
{
  struct route_map_rule *new;

  new = XMALLOC (MTYPE_ROUTE_MAP_RULE, sizeof (struct route_map_rule));
  bzero (new, sizeof (struct route_map_rule));
  return new;
}

/* Install rule command to the match list. */
void
route_map_install_match (struct route_map_rule_cmd *cmd)
{
  vector_set (route_match_vec, cmd);
}

/* Install rule command to the set list. */
void
route_map_install_set (struct route_map_rule_cmd *cmd)
{
  vector_set (route_set_vec, cmd);
}

/* Lookup rule command from match list. */
struct route_map_rule_cmd *
route_map_lookup_match (char *name)
{
  int i;
  struct route_map_rule_cmd *rule;

  for (i = 0; i < vector_max (route_match_vec); i++)
    if ((rule = vector_slot (route_match_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
	return rule;
  return NULL;
}

/* Lookup rule command from set list. */
struct route_map_rule_cmd *
route_map_lookup_set (char *name)
{
  int i;
  struct route_map_rule_cmd *rule;

  for (i = 0; i < vector_max (route_set_vec); i++)
    if ((rule = vector_slot (route_set_vec, i)) != NULL)
      if (strcmp (rule->str, name) == 0)
	return rule;
  return NULL;
}

/* Add match and set rule to rule list. */
static void
route_map_rule_add (struct route_map_rule_list *list,
		    struct route_map_rule *rule)
{
  rule->next = NULL;
  rule->prev = list->tail;
  if (list->tail)
    list->tail->next = rule;
  else
    list->head = rule;
  list->tail = rule;
}

/* Delete rule from rule list. */
static void
route_map_rule_delete (struct route_map_rule_list *list,
		       struct route_map_rule *rule)
{
  if (rule->rule_str)
    XFREE (MTYPE_ROUTE_MAP_RULE_STR, rule->rule_str);

  if (rule->next)
    rule->next->prev = rule->prev;
  else
    list->tail = rule->prev;
  if (rule->prev)
    rule->prev->next = rule->next;
  else
    list->head = rule->next;

  XFREE (MTYPE_ROUTE_MAP_RULE, rule);
}

/* Add match statement to route map. */
int
route_map_add_match (struct route_map_index *index, char *match_name,
		     char *match_arg)
{
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;
  void *compile;

  /* First lookup rule for add match statement. */
  cmd = route_map_lookup_match (match_name);
  if (cmd == NULL)
    return ROUTE_MAP_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile= (*cmd->func_compile)(match_arg);
      if (compile == NULL)
	return ROUTE_MAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* Add new route map match rule. */
  rule = route_map_rule_new ();
  rule->cmd = cmd;
  rule->value = compile;
  rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, match_arg);

  /* Add new route match rule to linked list. */
  route_map_rule_add (&index->match_list, rule);

  return 0;
}

/* Delete specified route match rule. */
int
route_map_delete_match (struct route_map_index *index, char *match_name,
			char *match_arg)
{
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;

  cmd = route_map_lookup_match (match_name);
  if (cmd == NULL)
    return 1;
  
  for (rule = index->match_list.head; rule; rule = rule->next)
    if (rule->cmd == cmd && strcmp (rule->rule_str, match_arg) == 0)
      {
	route_map_rule_delete (&index->match_list, rule);
	/* return Success. */
	return 0;
      }
  /* Can't find matched rule. */
  return 1;
}

/* Add route-map set statement to the route map. */
int
route_map_add_set (struct route_map_index *index, char *set_name,
		   char *set_arg)
{
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;
  void *compile;

  cmd = route_map_lookup_set (set_name);
  if (cmd == NULL)
    return ROUTE_MAP_RULE_MISSING;

  /* Next call compile function for this match statement. */
  if (cmd->func_compile)
    {
      compile= (*cmd->func_compile)(set_arg);
      if (compile == NULL)
	return ROUTE_MAP_COMPILE_ERROR;
    }
  else
    compile = NULL;

  /* Add new route map match rule. */
  rule = route_map_rule_new ();
  rule->cmd = cmd;
  rule->value = compile;
  rule->rule_str = XSTRDUP (MTYPE_ROUTE_MAP_RULE_STR, set_arg);

  /* Add new route match rule to linked list. */
  route_map_rule_add (&index->set_list, rule);

  return 0;
}

/* Delete route map set rule. */
int
route_map_delete_set (struct route_map_index *index, char *set_name,
			char *set_arg)
{
  struct route_map_rule *rule;
  struct route_map_rule_cmd *cmd;

  cmd = route_map_lookup_set (set_name);
  if (cmd == NULL)
    return 1;
  
  for (rule = index->set_list.head; rule; rule = rule->next)
    if (rule->cmd == cmd && strcmp (rule->rule_str, set_arg) == 0)
      {
	route_map_rule_delete (&index->set_list, rule);
	/* Return Success. */
	return 0;
      }
  /* Can't find matched rule. */
  return 1;
}

/* Apply route map's each index to the object. */
int
route_map_apply_index (struct route_map_index *index, struct prefix *prefix,
                       void *object)
{
  int ret;
  struct route_map_rule *match;
  struct route_map_rule *set;
  
  /* Check all match rule and if there is no match rule return 0. */
  for (match = index->match_list.head; match; match = match->next)
    {
      /* Match function return zero for unsuccessful match. */
      ret = (*match->cmd->func_apply)(match->value, prefix, object);
      if (ret == 0)
	return ret;
    }

  /* Apply set statement to the object. */
  for (set = index->set_list.head; set; set = set->next)
    {
      ret = (*set->cmd->func_apply)(set->value, prefix, object);
      if (ret)
	return ret;
    }
  return 0;
}

/* Apply route map to the object. */
int
route_map_apply (struct route_map *map, struct prefix *prefix, void *object)
{
  int ret;
  struct route_map_index *index;

  for (index = map->head; index; index = index->next)
    {
      ret = route_map_apply_index (index, prefix, object);
      if (ret)
	return ret;
    }
  return 0;
}

void
route_map_add_hook (void (*func) ())
{
  route_map_master.add_hook = func;
}

void
route_map_delete_hook (void (*func) ())
{
  route_map_master.delete_hook = func;
}

void
route_map_init ()
{
  /* Make vector for match and set. */
  route_match_vec = vector_init (1);
  route_set_vec = vector_init (1);
}

/* VTY related functions. */
#include "vty.h"
#include "command.h"

DEFUN (route_map, route_map_cmd,
       "route-map NAME PERMIT PREF",
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map set operations\n"
       "Route map preference\n")
{
  int permit;
  int pref;
  struct route_map *map;
  struct route_map_index *index;

  /* Permit check. */
  if (strcmp (argv[1], "permit") == 0)
    permit = ROUTE_MAP_PERMIT;
  else if (strcmp (argv[1], "deny") == 0)
    permit = ROUTE_MAP_DENY;
  else
    {
      vty_out (vty, "the third field must be [permit|demy]\r\n");
      return CMD_WARNING;
    }

  /* Preference check. */
  pref = atoi (argv[2]);
  if (pref == 0)
    {
      vty_out (vty, "the fourth field must be positive integer");
      return CMD_WARNING;
    }

  /* Get route map. */
  map = route_map_get (argv[0]);
  index = route_map_index_get (map, permit, pref);

  vty->index = index;
  vty->node = RMAP_NODE;
  return CMD_SUCCESS;
}

DEFUN (no_route_map, no_route_map_cmd,
       "no route-map NAME PERMIT PREF",
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map set operations\n"
       "Route map preference\n")
{
  int permit;
  int pref;
  struct route_map *map;
  struct route_map_index *index;

  /* Permit check. */
  if (strcmp (argv[1], "permit") == 0)
    permit = ROUTE_MAP_PERMIT;
  else if (strcmp (argv[1], "deny") == 0)
    permit = ROUTE_MAP_DENY;
  else
    {
      vty_out (vty, "the third field must be [permit|demy]\r\n");
      return CMD_WARNING;
    }

  /* Preference. */
  pref = atoi (argv[2]);
  if (pref == 0)
    {
      vty_out (vty, "the fourth field must be positive integer\r\n");
      return CMD_WARNING;
    }

  /* Existence check. */
  map = route_map_lookup_by_name (argv[0]);
  if (map == NULL)
    {
      vty_out (vty, "can't find route-map with name %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Lookup route map index. */
  index = route_map_index_lookup (map, permit, pref);
  if (index == NULL)
    {
      vty_out (vty, "can't find route-map %s %s %s\r\n", 
	       argv[0], argv[1], argv[2]);
      return CMD_WARNING;
    }

  /* Delete index from route map. */
  route_map_index_delete (index);

  return CMD_SUCCESS;
}

/* Configuration write function. */
int
route_map_config_write (struct vty *vty)
{
  struct route_map *map;
  struct route_map_index *index;
  struct route_map_rule *rule;

  for (map = route_map_master.head; map; map = map->next)
    for (index = map->head; index; index = index->next)
      {
	vty_out (vty, "route-map %s %s %d%s", 
		 map->name,
		 route_map_type_str (index->type),
		 index->pref, VTY_NEWLINE);
	for (rule = index->match_list.head; rule; rule = rule->next)
	  vty_out (vty, " match %s %s%s", rule->cmd->str, rule->rule_str,
		   VTY_NEWLINE);
	for (rule = index->set_list.head; rule; rule = rule->next)
	  vty_out (vty, " set %s %s%s", rule->cmd->str, rule->rule_str,
		   VTY_NEWLINE);
      }
  return 0;
}

/* Route map node structure. */
struct cmd_node rmap_node =
{
  RMAP_NODE,
  "%s(config-route-map)# ",
};

/* Initialization of route map vector. */
void
route_map_init_vty ()
{
  /* Install route map top node. */
  install_node (&rmap_node, route_map_config_write);

  /* Install route map commands. */
  install_element (CONFIG_NODE, &route_map_cmd);
  install_element (CONFIG_NODE, &no_route_map_cmd);
  install_element (RMAP_NODE, &config_end_cmd);
  install_element (RMAP_NODE, &config_exit_cmd);
  install_element (RMAP_NODE, &config_help_cmd);
}
