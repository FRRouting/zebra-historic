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
#include "regex-gnu.h"
#include "buffer.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_regex.h"

/* Memo of cisco's route-map

 match as-path          :  Done
       community        :  Not yet
       interface        :  Not yet
       ip address       :  Done
       ip next-hop      :  Done
       ip route-source  :  (This will be not implemented by bgpd)
       length           :  (This will be not implemented by bgpd)
       metric           :  Done
       route-type       :  (This will be not implemented by bgpd)
       tag              :  (This will be not implemented by bgpd)

 set  as-path           :  Not yet
      automatic-tag     :  (This will be not implemented by bgpd)
      community         :  Not yet
      dampning          :  Not yet
      default           :  (This will be not implemented by bgpd)
      interface         :  (This will be not implemented by bgpd)
      ip default        :  (This will be not implemented by bgpd)
      ip next-hop       :  Done
      ip precedence     :  (This will be not implemented by bgpd)
      ip tos            :  (This will be not implemented by bgpd)
      level             :  (This will be not implemented by bgpd)
      local-preference  :  Done
      metric            :  Done
      metric-type       :  (This will be not implemented by bgpd)
      origin            :  Not yet
      tag               :  (This will be not implemented by bgpd)
      weight            :  Not yet

  Local extention

  set ipv6 nexthop global: Done
  set ipv6 nexthop local : Done


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

/* `match ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
int
route_match_ip_next_hop (void *rule, struct prefix *prefix, void *object)
{
  struct in_addr *addr;
  struct bgp_info *bgp_info;

  addr = rule;
  bgp_info = object;

  if (IPV4_ADDR_CMP (&bgp_info->attr->nexthop, rule) == 0)
    return 1;
  else
    return 0;
}

/* Route map `ip next-hop' match statement. `arg' is IP address
   string. */
void *
route_match_ip_next_hop_compile (char *arg)
{
  struct in_addr *addr;
  int ret;

  addr = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (struct in_addr));

  ret = inet_aton (arg, addr);
  if (!ret)
    {
      XFREE (MTYPE_ROUTE_MAP_COMPILED, addr);
      return NULL;
    }

  return addr;
}

/* Free route map's compiled `ip address' value. */
void
route_match_ip_next_hop_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
struct route_map_rule_cmd route_match_ip_next_hop_cmd =
{
  "ip next-hop",
  route_match_ip_next_hop,
  route_match_ip_next_hop_compile,
  route_match_ip_next_hop_free
};

/* `match metric METRIC' */

/* Match function return 1 if match is success else return zero. */
int
route_match_metric (void *rule, struct prefix *prefix, void *object)
{
  u_int32_t *med;
  struct bgp_info *bgp_info;

  med = rule;
  bgp_info = object;

  if (bgp_info->attr->med == *med)
    return 1;
  else
    return 0;
}

/* Route map `match metric' match statement. `arg' is MED value */
void *
route_match_metric_compile (char *arg)
{
  u_int32_t *med;

  med = XMALLOC (MTYPE_ROUTE_MAP_COMPILED, sizeof (u_int32_t));
  *med = atoi (arg);

  return med;
}

/* Free route map's compiled `match metric' value. */
void
route_match_metric_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_metric_cmd =
{
  "metric",
  route_match_metric,
  route_match_metric_compile,
  route_match_metric_free
};

/* Match function for as-path match.  I assume given object is */
int
route_match_aspath (void *rule, struct prefix *prefix, void *object)
{
  regex_t *regex;
  struct bgp_info *bgp_info;

  regex = rule;
  bgp_info = object;
  
  /* Perform match. */
  return bgp_regexec (regex, bgp_info->attr->aspath);
}

/* Compile function for as-path match. */
void *
route_match_aspath_compile (char *arg)
{
  regex_t *regex;

  regex = bgp_regcomp (arg);
  if (! regex)
    return NULL;

  return regex;
}

/* Compile function for as-path match. */
void
route_match_aspath_free (void *rule)
{
  regex_t *regex = rule;

  bgp_regex_free (regex);
}

/* Route map commands for aspath matching. */
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

/* Set local preference. */
int
route_set_local_pref (void *rule, struct prefix *prefix, void *object)
{
  char *pref;
  struct bgp_info *bgp_info;

  /* Fetch routemap's rule information. */
  pref = rule;
  bgp_info = object;

  /* Set next hop value. */ 
  bgp_info->attr->local_pref = atoi (pref);

  return 0;
}

/* set local preference compilation. */
void *
route_set_local_pref_compile (char *arg)
{
  /* Local preference value shoud be integer.  Check needed at here XXX. */
  return XSTRDUP (MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's local preference value. */
void
route_set_local_pref_free (void *rule)
{
  XFREE (MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set local preference rule structure. */
struct route_map_rule_cmd route_set_local_pref_cmd = 
{
  "local-preference",
  route_set_local_pref,
  route_set_local_pref_compile,
  route_set_local_pref_free,
};

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
  bgp_info->attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);
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

/* Free route map's compiled `set metric' value. */
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

/* Delete bgp route map rule. */
int
bgp_route_match_delete (struct vty *vty, struct route_map_index *index,
			char *command, char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
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

/* Delete bgp route map rule. */
int
bgp_route_set_delete (struct vty *vty, struct route_map_index *index,
		      char *command, char *arg)
{
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      vty_out (vty, "Can't find rule %s %s.\r\n", command, arg);
      return CMD_WARNING;
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
  return bgp_route_match_delete (vty, vty->index, "ip address", argv[0]);
}

DEFUN (match_ip_next_hop, 
       match_ip_next_hop_cmd,
       "match ip next-hop IP_ADDR",
       MATCH_STR
       IP_STR
       "Next hop of the route\n"
       "IP Address of the next hop\n")
{
  return bgp_route_match_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_match_ip_next_hop,
       no_match_ip_next_hop_cmd,
       "no match ip next-hop IP_ADDR",
       NO_STR
       MATCH_STR
       IP_STR
       "Next hop of the route\n"
       "IP Address of the next hop\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (match_metric, 
       match_metric_cmd,
       "match metric MED",
       MATCH_STR
       "Metric\n"
       "MED value\n")
{
  return bgp_route_match_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_match_metric,
       no_match_metric_cmd,
       "no match metric MED",
       NO_STR
       MATCH_STR
       "Metric\n"
       "MED value\n")
{
  return bgp_route_match_delete (vty, vty->index, "metric", argv[0]);
}


DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path ...",
       MATCH_STR
       "AS Path\n"
       "AS Path\n")
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_match_add (vty, vty->index, "as-path", regstr);
}

DEFUN (no_match_aspath,
       no_match_aspath_cmd,
       "no match as-path ...",
       NO_STR
       MATCH_STR
       "AS Path\n"
       "AS Path\n")
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;

  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	first = 1;

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  return bgp_route_match_delete (vty, vty->index, "as-path", regstr);
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
  return bgp_route_set_delete (vty, vty->index, "ip nexthop", argv[0]);
}

DEFUN (set_metric,
       set_metric_cmd,
       "set metric METRIC",
       "Set value\n"
       "Metric\n"
       "MED value\n")
{
  return bgp_route_set_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric METRIC",
       NO_STR
       "Set value\n"
       "Metric\n"
       "MED value\n")
{
  return bgp_route_set_delete (vty, vty->index, "metric", argv[0]);
}

DEFUN (set_local_pref,
       set_local_pref_cmd,
       "set local-preference LOCAL_PREF",
       "Set value\n"
       "Local preference\n"
       "Local preference value\n")
{
  return bgp_route_set_add (vty, vty->index, "local-preference", argv[0]);
}

DEFUN (no_set_local_pref,
       no_set_local_pref_cmd,
       "no set local-preference LOCAL_PREF",
       NO_STR
       "Set value\n"
       "Local preference\n"
       "Local preference value\n")
{
  return bgp_route_set_delete (vty, vty->index, "local-preference", argv[0]);
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
  return bgp_route_set_delete (vty, vty->index, "ipv6 nexthop global", argv[0]);
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
  return bgp_route_set_delete (vty, vty->index, "ipv6 nexthop local", argv[0]);
}

/* Initialization of route map. */
void
bgp_route_map_init ()
{
  route_map_init ();
  route_map_init_vty ();
  route_map_add_hook (bgp_route_map_update);

  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_next_hop_cmd);
  route_map_install_match (&route_match_aspath_cmd);
  route_map_install_match (&route_match_metric_cmd);

  route_map_install_set (&route_set_ip_nexthop_cmd);
  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_local_pref_cmd);

  install_element (RMAP_NODE, &match_ip_address_cmd);
  install_element (RMAP_NODE, &no_match_ip_address_cmd);

  install_element (RMAP_NODE, &match_ip_next_hop_cmd);
  install_element (RMAP_NODE, &no_match_ip_next_hop_cmd);

  install_element (RMAP_NODE, &match_aspath_cmd);
  install_element (RMAP_NODE, &no_match_aspath_cmd);

  install_element (RMAP_NODE, &match_metric_cmd);
  install_element (RMAP_NODE, &no_match_metric_cmd);

  install_element (RMAP_NODE, &set_ip_nexthop_cmd);
  install_element (RMAP_NODE, &no_set_ip_nexthop_cmd);

  install_element (RMAP_NODE, &set_metric_cmd);
  install_element (RMAP_NODE, &no_set_metric_cmd);

  install_element (RMAP_NODE, &set_local_pref_cmd);
  install_element (RMAP_NODE, &no_set_local_pref_cmd);
  

#ifdef HAVE_IPV6
  route_map_install_set (&route_set_ipv6_nexthop_global_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_local_cmd);

  install_element (RMAP_NODE, &set_ipv6_nexthop_global_cmd);
  install_element (RMAP_NODE, &set_ipv6_nexthop_local_cmd);
#endif
}
