/* Route map function.
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

/* Route map rule structure for matching and setting. */
struct route_map_rule_cmd
{
  /* Route map rule name (e.g. as-path, metric) */
  char *str;

  /* Function for value set or match. */
  int (*func_apply)(void *, void *);

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

/* Install rule command to the match list. */
void
route_map_install_match (struct route_map_rule_cmd *cmd);
