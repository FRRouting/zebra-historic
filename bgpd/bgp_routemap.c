/*
 * Route map function of bgpd.
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

#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "routemap.h"
#include "command.h"
#include "linklist.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"

/* Memo of cisco's route-map

 match [as-path|
        community|
        interface|
        ip [address|next-hop|route-source]|
        length|
        metric|
        route-type|
        tag]

 set [as-path|
      automatic-tag|
      community|
      dampning|
      default|
      interface|
      ip [default|next-hop|precedence|tos]|
      level|
      local-preference|
      metric|
      metric-type|
      origin|
      tag|
      weight] 
*/ 

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
int
route_match_ip_address (void *rule, struct prefix *prefix, void *object)
{
  struct access_list *alist;

  alist = access_list_lookup ((char *) rule);
  if (alist == NULL)
    return 0;

  return access_list_apply (alist, prefix);
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
void *
route_match_ip_address_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_address_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
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
route_match_aspath (void *rule, struct prefix *prefix, void *object)
{
  /* perform match. */
  ;

  return 0;
}

/* Compile function for as-path match. */
void *
route_match_aspath_compile (char *arg)
{
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
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
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/**/
struct route_map_rule_cmd route_match_aspath_cmd = 
{
  "as-path",
  route_match_aspath,
  route_match_aspath_compile,
  route_match_aspath_free
};

/* `set ip nexthop IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
int
route_set_ip_nexthop (void *rule, struct prefix *prefix, void *object)
{
  struct in_addr *address;
  struct bgp_info *bgp_info;

  /* Fetch routemap's rule information. */
  address = rule;
  bgp_info = object;

  /* Set next hop value. */ 
  bgp_info->attr->nexthop = *address;

  return 0;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ip_nexthop_compile (char *arg)
{
  int ret;
  struct in_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ip_nexthop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ip_nexthop_cmd =
{
  "ip nexthop",
  route_set_ip_nexthop,
  route_set_ip_nexthop_compile,
  route_set_ip_nexthop_free
};


#ifdef HAVE_IPV6
/* `set ipv6 nexthop-global IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
int
route_set_ipv6_nexthop_global (void *rule, struct prefix *prefix, void *object)
{
  struct in6_addr *address;
  struct bgp_info *bgp_info;

  /* Fetch routemap's rule information. */
  address = rule;
  bgp_info = object;

  /* Set next hop value. */ 
  bgp_info->attr->mp_nexthop_global = *address;

  /* Set nexthop length. */
  if (bgp_info->attr->mp_nexthop_len == 0)
    bgp_info->attr->mp_nexthop_len = 16;

  return 0;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ipv6_nexthop_global_compile (char *arg)
{
  int ret;
  struct in6_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ipv6_nexthop_global_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ipv6_nexthop_global_cmd =
{
  "ipv6 nexthop global",
  route_set_ipv6_nexthop_global,
  route_set_ipv6_nexthop_global_compile,
  route_set_ipv6_nexthop_global_free
};

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
int
route_set_ipv6_nexthop_local (void *rule, struct prefix *prefix, void *object)
{
  struct in6_addr *address;
  struct bgp_info *bgp_info;

  /* Fetch routemap's rule information. */
  address = rule;
  bgp_info = object;

  /* Set next hop value. */ 
  bgp_info->attr->mp_nexthop_local = *address;

  /* Set nexthop length. */
  if (bgp_info->attr->mp_nexthop_len != 32)
    bgp_info->attr->mp_nexthop_len = 32;

  return 0;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
void *
route_set_ipv6_nexthop_local_compile (char *arg)
{
  int ret;
  struct in6_addr *address;

  address = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in6_addr));

  ret = inet_pton (AF_INET6, arg, address);

  if (ret == 0)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, address);
      return NULL;
    }

  return address;
}

/* Free route map's compiled `ip nexthop' value. */
void
route_set_ipv6_nexthop_local_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ipv6_nexthop_local_cmd =
{
  "ipv6 nexthop local",
  route_set_ipv6_nexthop_local,
  route_set_ipv6_nexthop_local_compile,
  route_set_ipv6_nexthop_local_free
};
#endif /* HAVE_IPV6 */


/* Set metric to attribute. */
int
route_set_metric (void *rule, struct prefix *prefix, void *object)
{
  char *metric;
  struct bgp_info *bgp_info;

  /* Fetch routemap's rule information. */
  metric = rule;
  bgp_info = object;

  /* Set next hop value. */ 
  bgp_info->attr->med = atoi (metric);

  return 0;
}

/* set metric compilation. */
void *
route_set_metric_compile (char *arg)
{
  /* Metric value shoud be integer.  Check needed at here XXX. */
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
void
route_set_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_cmd = 
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  route_set_metric_free,
};

/* Add bgp route map rule. */
int
bgp_route_match_add (struct vty *vty, struct route_map_index *index,
		    char *command, char *arg)
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

/* Add bgp route map rule. */
int
bgp_route_set_add (struct vty *vty, struct route_map_index *index,
		   char *command, char *arg)
{
  int ret;

  ret = route_map_add_set (index, command, arg);
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

/* Hook function for updating route_map assignment. */
void
bgp_route_map_update ()
{
  listnode node;
  extern list peer_list;
  struct peer *peer;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      peer = getdata (node);

      if (peer->route_map[BGP_FILTER_IN].name)
	peer->route_map[BGP_FILTER_IN].map = 
	  route_map_lookup_by_name (peer->route_map[BGP_FILTER_IN].name);

      if (peer->route_map[BGP_FILTER_OUT].name)
	peer->route_map[BGP_FILTER_OUT].map = 
	  route_map_lookup_by_name (peer->route_map[BGP_FILTER_OUT].name);
    }
}

#define MATCH_STR "Match values from routing table\n"

DEFUN (match_ip_address, 
       match_ip_address_cmd,
       "match ip address ACCESS_LIST",
       MATCH_STR
       IP_STR
       "Address\n"
       "IP Address access-list match command\n")
{
  return bgp_route_match_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (no_match_ip_address, 
       no_match_ip_address_cmd,
       "no match ip address ACCESS_LIST",
       NO_STR
       MATCH_STR
       IP_STR
       "IP address\n"
       "Delete IP Address access-list match command\n")
{
  int ret;
  struct route_map_index *index;

  /* Get route-map index structure. */
  index = vty->index;

  ret = route_map_delete_match (index, "ip address", argv[0]);
  if (ret)
    {
      vty_out (vty, "Can't find rule match ip address %s.\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path AS_PATH",
       MATCH_STR
       "AS Path\n"
       "AS Path\n")
{
  return bgp_route_match_add (vty, vty->index, "as-path", argv[0]);
}

DEFUN (set_ip_nexthop,
       set_ip_nexthop_cmd,
       "set ip nexthop IP_ADDR",
       "Set value\n"
       "IP address\n"
       "Next hop\n"
       "IP Address\n")
{
  return bgp_route_set_add (vty, vty->index, "ip nexthop", argv[0]);
}

DEFUN (no_set_ip_nexthop,
       no_set_ip_nexthop_cmd,
       "no set ip nexthop IP_ADDR",
       NO_STR
       "Set value\n"
       "IP address\n"
       "Next hop\n"
       "IP Address\n")
{
  int ret;
  struct route_map_index *index;

  /* Get route-map index structure. */
  index = vty->index;

  ret = route_map_delete_set (index, "ip nexthop", argv[0]);
  if (ret)
    {
      vty_out (vty, "Can't find rule set ip nexthop %s.\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (set_ipv6_nexthop_global,
       set_ipv6_nexthop_global_cmd,
       "set ipv6 nexthop global IP_ADDR",
       "Set value\n"
       "IPv6 address\n"
       "Next hop\n"
       "Global\n"
       "IP Address\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 nexthop global", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_global,
       no_set_ipv6_nexthop_global_cmd,
       "no set ipv6 nexthop global IP_ADDR",
       NO_STR
       "Set value\n"
       "IPv6 address\n"
       "Next hop\n"
       "Global\n"
       "IP Address\n")
{
  int ret;
  struct route_map_index *index;

  /* Get route-map index structure. */
  index = vty->index;

  ret = route_map_delete_set (index, "ipv6 nexthop global", argv[0]);
  if (ret)
    {
      vty_out (vty, "Can't find rule set ipv6 nexthop global %s.\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (set_ipv6_nexthop_local,
       set_ipv6_nexthop_local_cmd,
       "set ipv6 nexthop local IP_ADDR",
       "Set value\n"
       "IPv6 address\n"
       "Next hop\n"
       "Local\n"
       "IP Address\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 nexthop local", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_local,
       no_set_ipv6_nexthop_local_cmd,
       "no set ipv6 nexthop local IP_ADDR",
       NO_STR
       "Set value\n"
       "IPv6 address\n"
       "Next hop\n"
       "Local\n"
       "IP Address\n")
{
  int ret;
  struct route_map_index *index;

  /* Get route-map index structure. */
  index = vty->index;

  ret = route_map_delete_set (index, "ipv6 nexthop local", argv[0]);
  if (ret)
    {
      vty_out (vty, "Can't find rule set ipv6 nexthop local %s.\r\n", argv[0]);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* Initialization of route map. */
void
bgp_route_map_init ()
{
  route_map_init ();
  route_map_init_vty ();
  route_map_add_hook (bgp_route_map_update);

  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_aspath_cmd);
  route_map_install_set (&route_set_ip_nexthop_cmd);
  route_map_install_set (&route_set_metric_cmd);

  install_element (RMAP_NODE, &match_ip_address_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_cmd);
  install_element (RMAP_NODE, &match_aspath_cmd);
  install_element (RMAP_NODE, &set_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_set_ip_nexthop_cmd);

#ifdef HAVE_IPV6
  route_map_install_set (&route_set_ipv6_nexthop_global_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_local_cmd);

  install_element (RMAP_NODE, &set_ipv6_nexthop_global_cmd);
  install_element (RMAP_NODE, &set_ipv6_nexthop_local_cmd);
#endif
}
