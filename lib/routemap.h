/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_ROUTEMAP_H
#define _ZEBRA_ROUTEMAP_H

typedef enum 
{
  RM_MATCH,
  RM_DENYMATCH,
  RM_NOMATCH,
  RM_ERROR,
  RM_OKAY
} route_map_result_t;

typedef enum
{
  ROUTE_MAP_RIP,
  ROUTE_MAP_RIPNG,
  ROUTE_MAP_OSPF,
  ROUTE_MAP_OSPF6,
  ROUTE_MAP_BGP
} route_map_object_t;

/* Route map rule structure for matching and setting. */
struct route_map_rule_cmd
{
  /* Route map rule name (e.g. as-path, metric) */
  char *str;

  /* Function for value set or match. */
  route_map_result_t (*func_apply)(void *, struct prefix *, 
				   route_map_object_t, void *);

  /* Compile argument and return result as void *. */
  void *(*func_compile)(char *);

  /* Free allocated value by func_compile (). */
  void (*func_free)(void *);
};

/* Route map apply error. */
enum
{
  /* Route map rule is missing. */
  ROUTE_MAP_RULE_MISSING = 1,

  /* Route map rule can't compile */
  ROUTE_MAP_COMPILE_ERROR
};

/* Route map's type. */
enum route_map_type
{
  ROUTE_MAP_PERMIT,
  ROUTE_MAP_DENY
};


/* Route map rule list. */
struct route_map_rule_list
{
  struct route_map_rule *head;
  struct route_map_rule *tail;
};

/* Route map index structure. */
struct route_map_index
{
  struct route_map *map;

  /* Preference of this route map rule. */
  int pref;

  /* Route map type permit or deny. */
  enum route_map_type type;			

  /* Matching rule list. */
  struct route_map_rule_list match_list;
  struct route_map_rule_list set_list;

  /* Make linked list. */
  struct route_map_index *next;
  struct route_map_index *prev;
};

/* Route map list structure. */
struct route_map
{
  /* Name of route map. */
  char *name;

  /* Route map's rule. */
  struct route_map_index *head;
  struct route_map_index *tail;

  /* Make linked list. */
  struct route_map *next;
  struct route_map *prev;
};

/* Prototypes. */
void route_map_init ();
void route_map_init_vty ();

/* Add match statement to route map. */
int
route_map_add_match (struct route_map_index *index,
		     char *match_name,
		     char *match_arg);

/* Delete specified route match rule. */
int
route_map_delete_match (struct route_map_index *index,
			char *match_name,
			char *match_arg);

/* Add route-map set statement to the route map. */
int
route_map_add_set (struct route_map_index *index, 
		   char *set_name,
		   char *set_arg);

/* Delete route map set rule. */
int
route_map_delete_set (struct route_map_index *index, char *set_name,
                      char *set_arg);

/* Install rule command to the match list. */
void
route_map_install_match (struct route_map_rule_cmd *cmd);

/* Install rule command to the set list. */
void
route_map_install_set (struct route_map_rule_cmd *cmd);

/* Lookup route map by name. */
struct route_map *
route_map_lookup_by_name (char *name);

/* Apply route map to the object. */
route_map_result_t
route_map_apply (struct route_map *map, struct prefix *, 
		 route_map_object_t object_type, void *object);

void route_map_add_hook (void (*func) ());
void route_map_delete_hook (void (*func) ());

#endif /* _ZEBRA_ROUTEMAP_H */
