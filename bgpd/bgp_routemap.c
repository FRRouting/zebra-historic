/* Route map function of bgpd.
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

#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "bgp_aspath.h"

#include "memory.h"
#include "filter.h"
#include "routemap.h"

/* Memo of cisco's route-map

 [match|set]

 match [as-path|community|interface|ip [address|next-hop|route-source]|length|metric|route-type|tag]

 set [as-path|automatic-tag|community|dampning|default|interface|ip [default|next-hop|precedence|tos]|level|local-preference|metric|metric-type|origin|tag|weight] 
*/ 

/*
route-map test permit 10
 match ip address 1
 set community no-export
!
route-map test permit 20
 set community no-export
!
route-map dml permit 10
 match ip address 10
 set metric 22
!
route-map dml permit 20
 set metric 33
 set community 3561:70 no-export
!
*/

/* Match function should return 1 if match is success else return
   0. */
int
route_match_ip_address (void *rule, void *object)
{
  int ret;
  struct access_list *alist;

  alist = access_list_lookup ((char *) rule);
  if (alist == NULL)
    return 0;

  return access_list_apply (alist, (struct prefix_in *) object);
}

/* Route map `ip address' match statement. */
void *
route_match_ip_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_TMP, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_TMP, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_address_compile,
  route_match_ip_address_free
};

/* Match function for as-path match.  I assume given object is */
int
route_match_aspath (void *rule, void *object)
{
  /* perform match. */
  ;
}

/* Compile function for as-path match. */
void *
route_match_aspath_compile (char *arg)
{
  return XSTRDUP (MTYPE_TMP, arg);
  /*
  ASPATH_regex *rp;

  rp = aspath_regex_comp (arg);
  return rp;
  */
}

/* Compile function for as-path match. */
void
route_match_aspath_free (void *rule)
{
  /*  aspath_regex_free (rule); */
  XFREE (MTYPE_TMP, rule);
}

/**/
struct route_map_rule_cmd route_match_aspath_cmd = 
{
  "as-path",
  route_match_aspath,
  route_match_aspath_compile,
  route_match_aspath_free
};

/**/
int
route_set_metric (void *rule, void *object)
{
  printf (" set metric value %s\n", rule);
}

/* Route map `ip address' match statement. */
void *
route_set_metric_compile (char *arg)
{
  return XSTRDUP (0, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_set_metric_free (void *rule)
{
  XFREE (0, rule);
}

/**/
struct route_map_rule_cmd route_set_metric_cmd = 
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};


#include "vector.h"
#include "vty.h"
#include "command.h"

int
bgp_route_rule_add (struct vty *vty,
		    struct route_map_index *index,
		    char *command,
		    char *arg)
{
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
	{
	case ROUTE_MAP_RULE_MISSING:
	  vty_out (vty, "Can't find rule.\r\n");
	  return CMD_WARNING;
	  break;
	case ROUTE_MAP_COMPILE_ERROR:
	  vty_out (vty, "Can't compile argument.\r\n");
	  return CMD_WARNING;
	  break;
	}
    }
  return CMD_SUCCESS;
}

DEFUN (match_ip_address, 
       match_ip_address_cmd,
       "match ip address ACCESS_LIST",
       "IP Address access-list match command.")
{
  return bgp_route_rule_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path AS_PATH",
       "AS path match.")
{
  return bgp_route_rule_add (vty, vty->index, "as-path", argv[0]);
}

DEFUN (no_match_ip_address, 
       no_match_ip_address_cmd,
       "no match ip address ACCESS_LIST",
       "Delete IP Address access-list match command.")
{
  int ret;
  struct route_map_index *index;

  /* Get route-map index structure. */
  index = vty->index;

  ret = route_map_delete_match (index, "ip address", argv[0]);
  if (ret)
    {
      vty_out (vty, "Can't find rule ip address %s.\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

bgp_route_map_init ()
{
  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_aspath_cmd);

  install_element (RMAP_NODE, &match_ip_address_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_cmd);
  install_element (RMAP_NODE, &match_aspath_cmd);
}
