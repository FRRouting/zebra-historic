/* Route object related function for route server.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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

#include "prefix.h"
#include "table.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"

/* For bgp_zebra.c */
void bgp_zebra_announce (struct prefix *, struct bgp_info *, struct bgp *);
void bgp_zebra_withdraw (struct prefix *, struct bgp_info *);

#define DISTRIBUTE_IN_NAME(F)   ((F)->dlist[BGP_FILTER_IN].name)
#define DISTRIBUTE_IN_V4(F)     ((F)->dlist[BGP_FILTER_IN].v4)
#define DISTRIBUTE_IN_V6(F)     ((F)->dlist[BGP_FILTER_IN].v6)
#define DISTRIBUTE_OUT_NAME(F)  ((F)->dlist[BGP_FILTER_OUT].name)
#define DISTRIBUTE_OUT_V4(F)    ((F)->dlist[BGP_FILTER_OUT].v4)
#define DISTRIBUTE_OUT_V6(F)    ((F)->dlist[BGP_FILTER_OUT].v6)

#define PREFIX_LIST_IN_NAME(F)  ((F)->plist[BGP_FILTER_IN].name)
#define PREFIX_LIST_IN_V4(F)    ((F)->plist[BGP_FILTER_IN].v4)
#define PREFIX_LIST_IN_V6(F)    ((F)->plist[BGP_FILTER_IN].v6)
#define PREFIX_LIST_OUT_NAME(F) ((F)->plist[BGP_FILTER_OUT].name)
#define PREFIX_LIST_OUT_V4(F)   ((F)->plist[BGP_FILTER_OUT].v4)
#define PREFIX_LIST_OUT_V6(F)   ((F)->plist[BGP_FILTER_OUT].v6)

#define FILTER_LIST_IN_NAME(F)  ((F)->aslist[BGP_FILTER_IN].name)
#define FILTER_LIST_IN(F)       ((F)->aslist[BGP_FILTER_IN].aslist)
#define FILTER_LIST_OUT_NAME(F) ((F)->aslist[BGP_FILTER_OUT].name)
#define FILTER_LIST_OUT(F)      ((F)->aslist[BGP_FILTER_OUT].aslist)

#define ROUTE_MAP_IN_NAME(F)    ((F)->map[BGP_FILTER_IN].name)
#define ROUTE_MAP_IN(F)         ((F)->map[BGP_FILTER_IN].map)
#define ROUTE_MAP_OUT_NAME(F)   ((F)->map[BGP_FILTER_OUT].name)
#define ROUTE_MAP_OUT(F)        ((F)->map[BGP_FILTER_OUT].map)

/* Static annoucement peer. */
struct peer *peer_self;

/* Extern from bgp_dump.c */
extern char *bgp_origin_str[];
extern char *bgp_origin_long_str[];

struct route_node *
bgp_route_node_get (struct bgp *bgp, afi_t afi, safi_t safi, struct prefix *p,
		    struct prefix_rd *prd)
{
  struct route_node *rn;
  struct route_table *table;

  if (safi == SAFI_MPLS_VPN)
    {
      rn = route_node_get (bgp->rib[afi][safi], (struct prefix *) prd);

      if (rn->info == NULL)
	rn->info = route_table_init ();
      else
	route_unlock_node (rn);
      table = rn->info;
    }
  else
    table = bgp->rib[afi][safi];

  return route_node_get (table, p);
}

/* Allocate new bgp info structure. */
struct bgp_info *
bgp_info_new ()
{
  struct bgp_info *new;

  new = XMALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
  memset (new, 0, sizeof (struct bgp_info));

  return new;
}

/* Free bgp route information. */
void
bgp_info_free (struct bgp_info *br)
{
  if (br->bgp_damp_info)
    br->bgp_damp_info->bgp_info = NULL;
  if (br->attr)
    bgp_attr_unintern (br->attr);
  XFREE (MTYPE_BGP_ROUTE, br);
}

/* Allocate new bgp info structure. */
struct bgp_info_tag *
bgp_info_tag_new ()
{
  struct bgp_info_tag *new;

  new = XMALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info_tag));
  memset (new, 0, sizeof (struct bgp_info_tag));

  return new;
}

/* Add bgp route infomation to routing table node. */
void
bgp_info_add (struct bgp_info **rp, struct bgp_info *ri)
{
  ri->next = *rp;
  ri->prev = NULL;
  if (*rp)
    (*rp)->prev = ri;
  *rp = ri;
}

/* Delete rib from rib list. */
void
bgp_info_delete (struct bgp_info **rp, struct bgp_info *ri)
{
  if (ri->next)
    ri->next->prev = ri->prev;

  if (ri->prev)
    ri->prev->next = ri->next;
  else
    *rp = ri->next;
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
u_int32_t
bgp_med_value (struct attr *attr, struct bgp *bgp)
{
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    return attr->med;
  else
    {
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_MED_MISSING_AS_WORST))
	return 4294967295ul;
      else
	return 0;
    }
}

/* Compare two bgp route entity.  br is preferable then return 1. */
int
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist)
{
  u_int32_t new_pref;
  u_int32_t exist_pref;
  u_int32_t new_med;
  u_int32_t exist_med;
  struct in_addr new_id;
  struct in_addr exist_id;
  int new_cluster;
  int exist_cluster;
  int internal_as_route = 0;
  int confed_as_route = 0;
  int ret;

  if (new == NULL)
    return 0;
  if (exist == NULL)
    return 1;

  if (new->type == ZEBRA_ROUTE_CONNECT)
    return 1;
  if (exist->type == ZEBRA_ROUTE_CONNECT)
    return 0;

  if (new->type == ZEBRA_ROUTE_STATIC)
    return 1;
  if (exist->type == ZEBRA_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_AGGREGATE)
    return 1;
  if (exist->sub_type == BGP_ROUTE_AGGREGATE)
    return 0;

  if (new->sub_type == BGP_ROUTE_STATIC)
    return 1;
  if (exist->sub_type == BGP_ROUTE_STATIC)
    return 0;

  /* Weight check. */
  if (new->attr->weight > exist->attr->weight)
    return 1;
  if (new->attr->weight < exist->attr->weight)
    return 0;

  /* Local preference check. */
  if (new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    new_pref = new->attr->local_pref;
  else
    new_pref = bgp->default_local_pref;

  if (exist->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    exist_pref = exist->attr->local_pref;
  else
    exist_pref = bgp->default_local_pref;
    
  if (new_pref > exist_pref)
    return 1;
  if (new_pref < exist_pref)
    return 0;

  /* AS path length check. */
  if (! CHECK_FLAG (bgp->config, BGP_CONFIG_ASPATH_IGNORE))
    {
      if (new->attr->aspath->count < exist->attr->aspath->count)
	return 1;
      if (new->attr->aspath->count > exist->attr->aspath->count)
	return 0;
    }

  /* Origin check. */
  if (new->attr->origin < exist->attr->origin)
    return 1;
  if (new->attr->origin > exist->attr->origin)
    return 0;

  /* Compare MED. */
  internal_as_route = (new->attr->aspath->length == 0
		      && exist->attr->aspath->length == 0);
  confed_as_route = (new->attr->aspath->length > 0
		    && exist->attr->aspath->length > 0
		    && new->attr->aspath->count == 0
		    && exist->attr->aspath->count == 0);
  
  if (CHECK_FLAG (bgp->config, BGP_CONFIG_ALWAYS_COMPARE_MED)
      || (CHECK_FLAG (bgp->config, BGP_CONFIG_MED_CONFED)
	 && confed_as_route)
      || aspath_cmp_left (new->attr->aspath, exist->attr->aspath)
      || aspath_cmp_left_confed (new->attr->aspath, exist->attr->aspath)
      || internal_as_route)
    {
      new_med = bgp_med_value (new->attr, bgp);
      exist_med = bgp_med_value (exist->attr, bgp);

      if (new_med < exist_med)
	return 1;
      if (new_med > exist_med)
	return 0;
    }

  /* Peer type. */
  if (peer_sort (new->peer) == BGP_PEER_EBGP 
      && peer_sort (exist->peer) == BGP_PEER_IBGP)
    return 1;
  if (peer_sort (new->peer) == BGP_PEER_EBGP 
      && peer_sort (exist->peer) == BGP_PEER_CONFED)
    return 1;
  if (peer_sort (new->peer) == BGP_PEER_IBGP 
      && peer_sort (exist->peer) == BGP_PEER_EBGP)
    return 0;
  if (peer_sort (new->peer) == BGP_PEER_IBGP 
      && peer_sort (exist->peer) == BGP_PEER_CONFED)
    return 0;
  if (peer_sort (new->peer) == BGP_PEER_CONFED 
      && peer_sort (exist->peer) == BGP_PEER_EBGP)
    return 0;
  if (peer_sort (new->peer) == BGP_PEER_CONFED 
      && peer_sort (exist->peer) == BGP_PEER_IBGP)
    return 1;

  /* If both paths are external, prefer the path that was received
     first (the oldest one).  This step minimizes route-flap, since a
     newer path won't displace an older one, even if it was the
     preferred route based on the additional decision criteria below.  */
  if (! CHECK_FLAG (bgp->config, BGP_CONFIG_COMPARE_ROUTER_ID)
      && peer_sort (new->peer) == BGP_PEER_EBGP
      && peer_sort (exist->peer) == BGP_PEER_EBGP)
    {
      if (new->selected)
	return 1;
      if (exist->selected)
	return 0;
    }

  /* Rourter-ID comparision. */
  if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    new_id.s_addr = new->attr->originator_id.s_addr;
  else
    new_id.s_addr = new->peer->remote_id.s_addr;
  if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    exist_id.s_addr = exist->attr->originator_id.s_addr;
  else
    exist_id.s_addr = exist->peer->remote_id.s_addr;

  if (ntohl (new_id.s_addr) < ntohl (exist_id.s_addr))
    return 1;
  if (ntohl (new_id.s_addr) > ntohl (exist_id.s_addr))
    return 0;

  /* Cluster length comparision. */
  if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    new_cluster = new->attr->cluster->length;
  else
    new_cluster = 0;
  if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    exist_cluster = exist->attr->cluster->length;
  else
    exist_cluster = 0;

  if (new_cluster < exist_cluster)
    return 1;
  if (new_cluster > exist_cluster)
    return 0;

  /* Neighbor addres comparision. */
  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    return 0;
  if (ret == -1)
    return 1;

  return 1;
}

enum filter_type
bgp_input_filter (struct peer_conf *conf, struct prefix *p, struct attr *attr)
{
  struct bgp_filter *filter;

  filter = &conf->filter;

  if (p->family == AF_INET)
    {
      if (DISTRIBUTE_IN_NAME (filter))
	if (access_list_apply (DISTRIBUTE_IN_V4 (filter), p) == FILTER_DENY)
	  return FILTER_DENY;

      if (PREFIX_LIST_IN_NAME (filter))
	if (prefix_list_apply (PREFIX_LIST_IN_V4 (filter), p) == PREFIX_DENY)
	  return FILTER_DENY;
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    {
      if (DISTRIBUTE_IN_NAME (filter))
	if (access_list_apply (DISTRIBUTE_IN_V6 (filter), p) == FILTER_DENY)
	  return FILTER_DENY;

      if (PREFIX_LIST_IN_NAME (filter))
	if (prefix_list_apply (PREFIX_LIST_IN_V6 (filter), p) == PREFIX_DENY)
	  return FILTER_DENY;
    }
#endif /* HAVE_IPV6 */
  
  if (FILTER_LIST_IN_NAME (filter))
    {
      if (as_list_apply (FILTER_LIST_IN (filter), attr->aspath) == AS_FILTER_DENY)
	return FILTER_DENY;
    }

  return FILTER_PERMIT;
}

enum filter_type
bgp_output_filter (struct peer_conf *conf, struct prefix *p, struct attr *attr)
{
  struct bgp_filter *filter;

  filter = &conf->filter;

  if (p->family == AF_INET)
    {
      if (DISTRIBUTE_OUT_NAME (filter))
	if (access_list_apply (DISTRIBUTE_OUT_V4 (filter), p) == FILTER_DENY)
	  return FILTER_DENY;

      if (PREFIX_LIST_OUT_NAME (filter))
	if (prefix_list_apply (PREFIX_LIST_OUT_V4 (filter), p) == PREFIX_DENY)
	  return FILTER_DENY;
    }
#ifdef HAVE_IPV6
  else if (p->family == AF_INET6)
    {
      if (DISTRIBUTE_OUT_NAME (filter))
	if (access_list_apply (DISTRIBUTE_OUT_V6 (filter), p) == FILTER_DENY)
	  return FILTER_DENY;

      if (PREFIX_LIST_OUT_NAME (filter))
	if (prefix_list_apply (PREFIX_LIST_OUT_V6 (filter), p) == PREFIX_DENY)
	  return FILTER_DENY;
    }
#endif /* HAVE_IPV6 */  

  if (FILTER_LIST_OUT_NAME (filter))
    if (as_list_apply (FILTER_LIST_OUT (filter), attr->aspath) == AS_FILTER_DENY)
      return FILTER_DENY;

  return FILTER_PERMIT;
}

/* If community attribute includes no_export then return 1. */
int
bgp_community_filter (struct peer *peer, struct attr *attr)
{
  if (attr->community)
    {
      /* NO_ADVERTISE check. */
      if (community_include (attr->community, COMMUNITY_NO_ADVERTISE))
	return 1;

      /* NO_EXPORT check. */
      if (peer_sort (peer) == BGP_PEER_EBGP &&
	  community_include (attr->community, COMMUNITY_NO_EXPORT))
	return 1;
    }
  return 0;
}

int
bgp_cluster_filter (struct peer_conf *conf, struct attr *attr)
{
  struct in_addr cluster_id;

  /* Route reflection loop check. */
  if (attr->cluster)
    {
      if (conf->bgp->config & BGP_CONFIG_CLUSTER_ID)
	cluster_id = conf->bgp->cluster;
      else
	cluster_id = conf->bgp->id;
      
      if (cluster_loop_check (attr->cluster, cluster_id))
	return 1;
    }
  return 0;
}

/* Delete all kernel routes. */
void
bgp_terminate ()
{
  struct bgp *bgp;
  struct listnode *nn;
  struct route_node *rn;
  struct route_table *table;
  struct bgp_info *ri;

  LIST_LOOP (bgp_list, bgp, nn)
    {
      table = bgp->rib[AFI_IP][SAFI_UNICAST];

      for (rn = route_top (table); rn; rn = route_next (rn))
	for (ri = rn->info; ri; ri = ri->next)
	  if (ri->selected 
	      && ri->type == ZEBRA_ROUTE_BGP 
	      && ri->sub_type == BGP_ROUTE_NORMAL)
	    bgp_zebra_withdraw (&rn->p, ri);

      table = bgp->rib[AFI_IP6][SAFI_UNICAST];

      for (rn = route_top (table); rn; rn = route_next (rn))
	for (ri = rn->info; ri; ri = ri->next)
	  if (ri->selected 
	      && ri->type == ZEBRA_ROUTE_BGP 
	      && ri->sub_type == BGP_ROUTE_NORMAL)
	    bgp_zebra_withdraw (&rn->p, ri);
    }
}

void
bgp_reset ()
{
  vty_reset ();
  bgp_zclient_reset ();
  access_list_reset ();
  prefix_list_reset ();
}

/* Apply filters and return interned struct attr. */
struct attr *
bgp_input_modifier (struct peer *peer, struct peer_conf *conf, 
		    struct prefix *p, struct attr *attr)
{
  struct attr new;
  struct bgp_filter *filter;
  struct bgp_info info;
  route_map_result_t ret;

  filter = &conf->filter;

  /* Apply default weight value. */
  if (peer->config & PEER_CONFIG_WEIGHT)
    attr->weight = peer->weight;

  /* Route map apply. */
  if (ROUTE_MAP_IN_NAME (filter))
    {
      /* Duplicate current value to new strucutre for modification. */
      new = *attr;
      info.peer = peer;
      info.attr = &new;

      /* Apply BGP route map to the attribute. */
      ret = route_map_apply (ROUTE_MAP_IN (filter), p, RMAP_BGP, &info);
      if (ret == RMAP_DENYMATCH)
	{
	  /* Free newly generated AS path and community by route-map. */
	  bgp_attr_flush (&new);
	  return NULL;
	}

      /* Pont new generated attribute. */
      attr = &new;
    }
  return bgp_attr_intern (attr);
}

/* Set a route to Adj-RIBs-In or Adj-RIBs-Out.  In case of attr is
   NULL, it only store prefix information. */
int
bgp_adj_set (struct route_table *table, struct prefix *p, struct attr *attr,
	     struct prefix_rd *prd)
{
  struct route_node *rn;

  if (table == NULL)
    return 0;

  if (p->safi == SAFI_MPLS_VPN)
    {
      rn = route_node_get (table, (struct prefix *)prd);
      if (rn->info == NULL)
	rn->info = route_table_init ();
      else
	route_unlock_node (rn);

      table = rn->info;
    }

  rn = route_node_get (table, p);
  if (rn->info)
    {
      if (rn->info != rn)
	bgp_attr_unintern (rn->info);
      route_unlock_node (rn);
    }

  if (attr)
    rn->info = bgp_attr_intern (attr);
  else
    rn->info = rn;

  return 0;
}

/* Unset a route from Adj-RIBs-In or Adj-RIBs-Out.  If bgp_adj_set()
   only store prefix information, this function detect it and properly
   unset it. */
int
bgp_adj_unset (struct route_table *table, struct prefix *p,
	       struct prefix_rd *prd)
{
  struct route_node *rn;

  if (table == NULL)
    return 0;

  if (p->safi == SAFI_MPLS_VPN)
    {
      rn = route_node_lookup (table, (struct prefix *)prd);
      if (rn == NULL)
	return -1;
      table = rn->info;
    }

  rn = route_node_lookup (table, p);
  if (rn == NULL)
    return -1;

  if (rn->info != rn)
    bgp_attr_unintern (rn->info);
  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);
  return 0;
}

/* Check the prefix is in Adj-RIBs-In or Adj-RIBs-Out. */
int
bgp_adj_lookup (struct route_table *table, struct prefix *p,
		struct prefix_rd *prd)
{
  struct route_node *rn;
  struct route_node *rm;

  rn = NULL;

  if (table == NULL)
    return 1;

  if (p->safi == SAFI_MPLS_VPN)
    {
      rn = route_node_lookup (table, (struct prefix *) prd);
      if (rn == NULL)
	return 0;
      table = rn->info;
    }

  rm = route_node_lookup (table, p);
  if (rm == NULL)
    return 0;

  route_unlock_node (rm);

  if (rn)
    route_unlock_node (rn);

  return 1;
}

/* Clear entire table. */
void
bgp_adj_clear (struct route_table *table, safi_t safi)
{
  struct route_node *rn;

  if (table == NULL)
    return;

  if (safi == SAFI_MPLS_VPN)
    {
      struct route_table *pt;
      struct route_node *rm;

      for (rm = route_top(table); rm; rm = route_next (rm))
	if ((pt = rm->info) != NULL)
	  {
	    for (rn = route_top (pt); rn; rn = route_next (rn)) 
	      if (rn->info)
		{
		  if (rn->info != rn)
		    bgp_attr_unintern (rn->info);
		  rn->info = NULL;
		  route_unlock_node (rn);
		}
	  }
      return;
    }
  
  for (rn = route_top (table); rn; rn = route_next (rn)) 
    if (rn->info)
      {
	if (rn->info != rn)
	  bgp_attr_unintern (rn->info);
	rn->info = NULL;
	route_unlock_node (rn);
      }
}

int
bgp_announce_check (struct bgp_info *ri, struct peer_conf *conf, 
		    struct prefix *p, struct attr *attr)
{
  int ret;
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct bgp_info info;
  struct peer *peer;
  struct peer *from;
  struct bgp *bgp;

  from = ri->peer;
  peer = conf->peer;
  filter = &conf->filter;
  bgp = conf->bgp;
  
  /* Do not send back route to sender. */
  if (from == peer)
    return 0;

  /* Aggregate-address suppress check. */
  if (ri->suppress)
    return 0;

  /* If community is not disabled check the no-export and local. */
  if (CHECK_FLAG (peer->flags, PEER_FLAG_SEND_COMMUNITY) 
      && bgp_community_filter (peer, ri->attr))
    return 0;

  /* If the attribute has originator-id and it is same as remote
     peer's id. */
  if (ri->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&peer->remote_id, &ri->attr->originator_id))
	{
	  if (BGP_DEBUG (filter, FILTER))  
	    zlog (peer->log, LOG_INFO,
		  "%s [Update:SEND] %s/%d originator-id is same as remote router-id",
		  peer->host,
		  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		  p->prefixlen);
	  return 0;
	}
    }
  
  /* Output filter check. */
  if (bgp_output_filter (conf, p, ri->attr) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
	zlog (peer->log, LOG_INFO,
	      "%s [Update:SEND] %s/%d is filtered",
	      peer->host,
	      inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	      p->prefixlen);
      return 0;
    }

  /* Default route check. */
  if (p->family == AF_INET && p->u.prefix4.s_addr == INADDR_ANY 
      && ! (CHECK_FLAG (peer->flags, PEER_FLAG_DEFAULT_ORIGINATE)))
    {
      if (BGP_DEBUG (filter, FILTER))  
        zlog (peer->log, LOG_INFO,
	      "%s [Update:SEND] default route announcement is suppressed",
	      peer->host);
      return 0;
    }
#ifdef HAVE_IPV6
  if (p->family == AF_INET6 && p->prefixlen == 0 
      && ! (CHECK_FLAG (peer->flags, PEER_FLAG_DEFAULT_ORIGINATE)))
    {
      if (BGP_DEBUG (filter, FILTER))  
        zlog (peer->log, LOG_INFO,
	      "%s [Update:SEND] IPv6 default route announcement is suppressed",
	      peer->host);
      return 0;
    }
#endif /* HAVE_IPV6 */

  /* AS path loop check. */
  if (aspath_loop_check (ri->attr->aspath, peer->as))
    {
      if (BGP_DEBUG (filter, FILTER))  
        zlog (peer->log, LOG_INFO, 
	      "%s [Update:SEND] suppress announcement to peer AS %d is AS path.",
	      peer->host, peer->as);
      return 0;
    }

  /* If we're a CONFED we need to loop check the CONFED ID too */
  if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
    {
      if (aspath_loop_check(ri->attr->aspath, bgp->confederation_id))
	{
	  if (BGP_DEBUG (filter, FILTER))  
	    zlog (peer->log, LOG_INFO, 
		  "%s [Update:SEND] suppress announcement to peer AS %d is AS path.",
		  peer->host,
		  bgp->confederation_id);
	  return 0;
	}      
    }

  /* IBGP reflection check. */
  if (peer_sort (from) == BGP_PEER_IBGP && peer_sort (peer) == BGP_PEER_IBGP)
    {
      /* A route from a Client peer. */
      if (CHECK_FLAG (from->flags, PEER_FLAG_REFLECTOR_CLIENT))
	{
	  /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
	  /* no bgp client-to-client reflection check. */
	  if (CHECK_FLAG (bgp->config, BGP_CONFIG_NO_CLIENT_TO_CLIENT))
	    if (CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
	      return 0;
	}
      else
	{
	  /* A route from a Non-client peer. Reflect to all other
	     clients. */
	  if (! CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
	    return 0;
	}
    }

  /* For modify attribute, copy it to temporary structure. */
  *attr = *ri->attr;

  /* If local-preference is not set. */
  if ((peer_sort (peer) == BGP_PEER_IBGP 
       || peer_sort (peer) == BGP_PEER_CONFED) 
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (peer_sort (peer) == BGP_PEER_EBGP 
      && attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));

  /* next-hop-set */
  if ((p->family == AF_INET && attr->nexthop.s_addr == 0)
#ifdef HAVE_IPV6
      || (p->family == AF_INET6 && ri->peer == peer_self)
#endif /* HAVE_IPV6 */
      || (! CHECK_FLAG (peer->flags, PEER_FLAG_RSERVER_CLIENT)
	  && ! CHECK_FLAG (peer->flags, PEER_FLAG_TRANSPARENT_NEXTHOP)
	  && ((peer_sort (peer) == BGP_PEER_EBGP
	      && bgp_multiaccess_check_v4 (attr->nexthop, peer->host) == 0)
                || CHECK_FLAG (peer->flags, PEER_FLAG_NEXTHOP_SELF))))
    {
      /* Set IPv4 nexthop. */
      memcpy (&attr->nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);

#ifdef HAVE_IPV6
      /* Set IPv6 nexthop. */
      if (p->family == AF_INET6)
	{
	  /* IPv6 global nexthop must be included. */
	  memcpy (&attr->mp_nexthop_global, &peer->nexthop.v6_global, 
		  IPV6_MAX_BYTELEN);
	  attr->mp_nexthop_len = 16;
	  
	  /* If the peer is on shared nextwork and we have link-local
             nexthop set it. */
	  if (peer->shared_network 
	      && !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	    {
	      memcpy (&attr->mp_nexthop_local, &peer->nexthop.v6_local, 
		      IPV6_MAX_BYTELEN);
	      attr->mp_nexthop_len = 32;
	    }
	}
#endif /* HAVE_IPV6 */
    }
  else
    {
#ifdef HAVE_IPV6
      if (p->family == AF_INET6)
	{
	  /* Link-local address should not be transit to different peer. */
	  attr->mp_nexthop_len = 16;

	  /* Set link-local address for shared network peer. */
	  if (peer->shared_network 
	      && ! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	    {
	      memcpy (&attr->mp_nexthop_local, &peer->nexthop.v6_local, 
		      IPV6_MAX_BYTELEN);
	      attr->mp_nexthop_len = 32;
	    }
	}
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* If bgpd act as BGP-4+ route-reflector, do not send link-local
     address.*/
  if (CHECK_FLAG (peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
    attr->mp_nexthop_len = 16;

  /* If BGP-4+ link-local nexthop is not link-local nexthop. */
  if (! IN6_IS_ADDR_LINKLOCAL (&peer->nexthop.v6_local))
    attr->mp_nexthop_len = 16;
#endif /* HAVE_IPV6 */

  /* Route map apply. */
  if (ROUTE_MAP_OUT_NAME (filter))
    {
      info.peer = peer;
      info.attr = attr;
      
      ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info);
      if (ret == RMAP_DENYMATCH)
	{
	  bgp_attr_flush (attr);
	  return 0;
	}
    }
  return 1;
}

/* Announce selected routes to the conf->peer. */
void
bgp_announce_rib (struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct route_node *rn;
  struct bgp_info *ri;
  struct attr attr;

  for (rn = route_top (conf->bgp->rib[afi][safi]); rn; rn = route_next(rn))
    for (ri = rn->info; ri; ri = ri->next)
      if (CHECK_FLAG (conf->peer->flags, PEER_FLAG_RSERVER_CLIENT))
	{
	  if (bgp_announce_check (ri, conf, &rn->p, &attr))
	    {
	      bgp_update_send (conf, conf->peer, &rn->p, &attr, afi, safi,
			       ri->peer, NULL, NULL);
	      if (ROUTE_MAP_OUT (&conf->filter))
		bgp_attr_flush (&attr);
	    }
	}
      else
	{
	  if (ri->selected && ri->peer != conf->peer)
	    if (bgp_announce_check (ri, conf, &rn->p, &attr))
	      {	  
		bgp_update_send (conf, conf->peer, &rn->p, &attr, afi, safi,
				 ri->peer, NULL, NULL);
		bgp_adj_set (conf->peer->adj_out[afi][safi], &rn->p, &attr,
			     NULL);
	      }
	}
}

void
bgp_announce_rib_vpnv4 (struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct route_node *rn;
  struct route_node *rm;
  struct route_table *table;
  struct bgp_info_tag *ri;
  struct attr attr;

  for (rn = route_top (conf->bgp->rib[afi][safi]); rn; rn = route_next(rn))
    if ((table = (rn->info)) != NULL)
      {
	for (rm = route_top (table); rm; rm = route_next (rm))
	  for (ri = rm->info; ri; ri = ri->next)
	    if (CHECK_FLAG (conf->peer->flags, PEER_FLAG_RSERVER_CLIENT))
	      {
		if (bgp_announce_check ((struct bgp_info *)ri, conf,
					&rm->p, &attr))
		  {
		    bgp_update_send (conf, conf->peer, &rm->p, &attr,
				     afi, safi, ri->peer,
				     (struct prefix_rd *) &rn->p, ri->tag);
		    bgp_attr_flush (&attr);
		  }
	      }
	    else
	      {
		if (ri->selected && ri->peer != conf->peer)
		  if (bgp_announce_check ((struct bgp_info *)ri, conf,
					  &rm->p, &attr))
		    {	  
		      bgp_update_send (conf, conf->peer, &rm->p, &attr,
				       afi, safi, ri->peer,
				       (struct prefix_rd *) &rn->p, ri->tag);
		      bgp_adj_set (conf->peer->adj_out[afi][safi], &rm->p,
				   &attr, (struct prefix_rd *)&rn->p);
		    }
	      }
      }
}

/* Refresh routes conf->peer. */
void
bgp_refresh_rib (struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct route_node *rn;
  struct bgp_info *ri;
  struct attr attr;

  for (rn = route_top (conf->bgp->rib[afi][safi]); rn; rn = route_next(rn))
    for (ri = rn->info; ri; ri = ri->next)
      if (ri->selected && ri->peer != conf->peer)
	{
	  if (bgp_announce_check (ri, conf, &rn->p, &attr))
	    {	  
	      bgp_update_send (conf, conf->peer, &rn->p, &attr, afi, safi,
			       ri->peer, NULL, NULL);
	      bgp_adj_set (conf->peer->adj_out[afi][safi], &rn->p, &attr,
			   NULL);
	    }
	  else
	    {
	      /* Send withdraw to the peer */
	      if (bgp_adj_lookup (conf->peer->adj_out[afi][safi], &rn->p,
				  NULL))
		{
		  bgp_withdraw_send (conf->peer, &rn->p, afi, safi, NULL,
				     NULL);
		  bgp_adj_unset (conf->peer->adj_out[afi][safi], &rn->p, NULL);
		}
	    }
	}
}

/* Refresh routes conf->peer. */
void
bgp_refresh_rib_vpnv4 (struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct route_node *rn;
  struct route_node *rm;
  struct route_table *table;
  struct bgp_info_tag *ri;
  struct attr attr;

  for (rn = route_top (conf->bgp->rib[afi][safi]); rn; rn = route_next(rn))
    if ((table = rn->info) != NULL)
      {
	for (rm = route_top (table); rm; rm = route_next (rm))
	  for (ri = rm->info; ri; ri = ri->next)
	    if (ri->selected && ri->peer != conf->peer)
	      {
		if (bgp_announce_check ((struct bgp_info *)ri, conf, &rm->p,
					&attr))
		  {	  
		    bgp_update_send (conf, conf->peer, &rm->p, &attr,
				     afi, safi, ri->peer,
				     (struct prefix_rd *) &rn->p, ri->tag);
		    bgp_adj_set (conf->peer->adj_out[afi][safi], &rm->p,
				 &attr, (struct prefix_rd *) &rn->p);
	    }
	  else
	    {
	      /* Send withdraw to the peer */
	      if (bgp_adj_lookup (conf->peer->adj_out[afi][safi], &rm->p,
				  (struct prefix_rd *) &rn->p))
		{
		  bgp_withdraw_send (conf->peer, &rm->p, afi, safi,
				     (struct prefix_rd *) &rn->p, ri->tag);
		  bgp_adj_unset (conf->peer->adj_out[afi][safi],
				 &rm->p, (struct prefix_rd *) &rn->p);
		}
	    }
	}
      }
}

/* Announce current routing table to the peer when peer gets
   Established. */
void
bgp_announce_table (struct peer *peer)
{
  struct listnode *nn;
  struct peer_conf *conf;

  LIST_LOOP (peer->conf, conf, nn)
    {
      if (conf->peer->afc_nego[AFI_IP][SAFI_UNICAST])
	bgp_announce_rib (conf, AFI_IP, SAFI_UNICAST);
      if (conf->peer->afc_nego[AFI_IP][SAFI_MULTICAST])
	bgp_announce_rib (conf, AFI_IP, SAFI_MULTICAST);
      if (conf->peer->afc_nego[AFI_IP6][SAFI_UNICAST])
	bgp_announce_rib (conf, AFI_IP6, SAFI_UNICAST);
      if (conf->peer->afc_nego[AFI_IP6][SAFI_MULTICAST])
	bgp_announce_rib (conf, AFI_IP6, SAFI_MULTICAST);

      /* MPLS-VPN */
      if (conf->peer->afc_nego[AFI_IP][SAFI_MPLS_VPN])
	bgp_announce_rib_vpnv4 (conf, AFI_IP, SAFI_MPLS_VPN);
    }
}

/* Announce current routing table to the peer when peer gets
   Established. */
void
bgp_refresh_table (struct peer *peer, afi_t afi, safi_t safi)
{
  struct listnode *nn;
  struct peer_conf *conf;

  LIST_LOOP (peer->conf, conf, nn)
    {
      if (conf->peer->afc_nego[afi][safi])
	{
	  if (safi == SAFI_MPLS_VPN)
	    bgp_refresh_rib_vpnv4 (conf, afi, safi);
	  else
	    bgp_refresh_rib (conf, afi, safi);
	}
    }
}

/* Process changed routing entry. */
int
bgp_process (struct bgp *bgp, struct route_node *rn, afi_t afi, safi_t safi,
	     struct bgp_info *del, struct prefix_rd *prd, u_char *tag)
{
  struct prefix *p;
  struct bgp_info *ri;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct listnode *nn;
  struct peer_conf *conf_to;
  struct peer *peer_to;
  struct attr attr;
  struct bgp_info *ri1;
  struct bgp_info *ri2;

  p = &rn->p;

  /* bgp deterministic-med */
  new_select = NULL;
  if (CHECK_FLAG (bgp->config, BGP_CONFIG_DETERMINISTIC_MED))
    for (ri1 = rn->info; ri1; ri1 = ri1->next)
      {
	if (ri1->as_selected != 0)
	  continue;
	if (ri1->valid == 0
	    || CHECK_FLAG (ri1->flags, BGP_INFO_HISTORY) 
	    || CHECK_FLAG (ri1->flags, BGP_INFO_DAMPED))
	  {
	    ri1->as_selected = -1;
	    continue;
	  }
	new_select = ri1;
	if (ri1->next)
	  for (ri2 = ri1->next; ri2; ri2 = ri2->next)
	    {
	      if (ri2->as_selected != 0)
		continue;
	      if (ri2->valid == 0
		  || CHECK_FLAG (ri2->flags, BGP_INFO_HISTORY)
		  || CHECK_FLAG (ri2->flags, BGP_INFO_DAMPED))
		{
		  ri2->as_selected = -1;
		  continue;
		}
	      if (aspath_cmp_left (ri1->attr->aspath, ri2->attr->aspath) ||
		  aspath_cmp_left_confed (ri1->attr->aspath, ri2->attr->aspath))
		{
		  if (bgp_info_cmp (bgp, ri2, new_select))
		    {
		      new_select->as_selected = -1;
		      new_select = ri2;
		    }
		  else
		    ri2->as_selected = -1;
		}
	    }
	new_select->as_selected = 1;
      }

  /* Check old selected route and new selected route. */
  old_select = NULL;
  new_select = NULL;
  for (ri = rn->info; ri; ri = ri->next)
    {
      if (ri->selected)
	old_select = ri;

      if (ri->valid == 0
	  || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY)
	  || CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
	{
	  ri->as_selected = 0;
	  continue;
        }
      if (CHECK_FLAG (bgp->config, BGP_CONFIG_DETERMINISTIC_MED)
	  && ri->as_selected != 1)
	{
	  ri->as_selected = 0;
	  continue;
        }
      ri->as_selected = 0;

      if (bgp_info_cmp (bgp, ri, new_select))
	new_select = ri;
    }

  /* Nothing to do. */
  if (old_select && old_select == new_select)
    {
#ifndef OLD_RIB
      if (CHECK_FLAG (old_select->flags, BGP_INFO_CHANGED))
	bgp_zebra_announce (p, old_select, bgp);
#endif /* OLD_RIB */
      return 0;
    }

  if (old_select)
    old_select->selected = 0;
  if (new_select)
    new_select->selected = 1;

  /* Check each BGP peer. */
  LIST_LOOP (bgp->peer_conf, conf_to, nn)
    {
      peer_to = conf_to->peer;

      /* Announce route to Established peer. */
      if (peer_to->status != Established)
	continue;

      /* Address family configuration check. */
      if (! conf_to->peer->afc_nego[afi][safi])
	continue;

      /* Skip route server client. */
      if (CHECK_FLAG (conf_to->peer->flags, PEER_FLAG_RSERVER_CLIENT))
	continue;

      /* Announcement to peer->conf.  If the route is filtered,
         withdraw it. */
      if (new_select 
	  && bgp_announce_check (new_select, conf_to, p, &attr))
	{
	  /* Send update to the peer. */
	  bgp_update_send (conf_to, peer_to, p, &attr, afi, safi,
			   new_select->peer, prd, tag);
	  bgp_adj_set (peer_to->adj_out[afi][safi], p, &attr, prd);
	}
      else
	{
	  /* Send withdraw to the peer */
	  if (bgp_adj_lookup (peer_to->adj_out[afi][safi], p, prd))
	    {
	      bgp_withdraw_send (peer_to, p, afi, safi, prd, tag);
	      bgp_adj_unset (peer_to->adj_out[afi][safi], p, prd);
	    }
	}
    }

  /* FIB update. */
  if (safi == SAFI_UNICAST && ! bgp->name && ! no_kernel_mode)
    {
      if (new_select 
	  && new_select->type == ZEBRA_ROUTE_BGP 
	  && new_select->sub_type == BGP_ROUTE_NORMAL)
	bgp_zebra_announce (p, new_select, bgp);
      else
	{
	  /* In case of selected route is deleted check the pointer. */
	  if (! old_select && del && del->selected)
	    old_select = del;

	  /* Withdraw the route from the kernel. */
	  if (old_select 
	      && old_select->type == ZEBRA_ROUTE_BGP
	      && old_select->sub_type == BGP_ROUTE_NORMAL)
	    bgp_zebra_withdraw (p, old_select);
	}
    }
  return 0;
}

/* maximum-prefix check. */
int
bgp_maximum_prefix_overflow (struct peer_conf *conf, afi_t afi, safi_t safi)
{
  struct peer *peer;

  if (conf->pmax[afi][safi]
      && conf->pcount[afi][safi] >= conf->pmax[afi][safi])
    {
      peer = conf->peer;
      if (BGP_DEBUG (update, UPDATE))
	zlog (peer->log, LOG_INFO,
	      "%s [Update:RECV] Maximum prefix count overflow %d",
	      peer->host, conf->pmax[afi][safi]);

      bgp_stop (peer);
      peer->status = Idle;
      SET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
      return 1;
    }
  return 0;
}

void
bgp_implicit_withdraw (struct peer_conf *conf, struct bgp *bgp,
		       struct prefix *p, struct bgp_info *ri,
		       struct route_node *rn, afi_t afi, safi_t safi)
{
  conf->pcount[afi][safi]--;
  bgp_aggregate_decrement (bgp, p, ri, afi, safi);
  bgp_info_delete ((struct bgp_info **) &rn->info, ri);
  bgp_info_free (ri);
  route_unlock_node (rn);
}

/* Generic function for update BGP information.  This function only
   update routing table information.  To announce change we have to
   call bgp_process(). */
int
bgp_update (struct peer *peer, struct prefix *p, struct attr *attr, 
	    afi_t afi, safi_t safi, int type, int sub_type,
	    struct prefix_rd *prd, u_char *tag, int soft_reconfig)
{
  struct listnode *nn;
  struct route_node *rn;
  struct bgp *bgp;
  struct peer_conf *conf;
  struct attr *new_attr;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct bgp_info_tag *newtag;
  char buf[SU_ADDRSTRLEN];
  int status;
  int bgp_damp_update (struct bgp_info *);

  /* Check this route's origin is not static/aggregate/redistributed
     routes. */
  if (peer != peer_self && ! soft_reconfig)
    {
      /* If peer is soft reconfiguration enabled.  Record input packet for
	 further calculation. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_SOFT_RECONFIG))
	bgp_adj_set (peer->adj_in[afi][safi], p, attr, prd);
    }

  /* If attribute has invalid flag, do not process furthermore.
     Typical case of this is incoming route's attribute incldue
     remote-as. */
  if (attr->invalid)
    return -1;

  /* Kick each configuration BGP instance. */
  LIST_LOOP (peer->conf, conf, nn)
    {
      bgp = conf->bgp;

      /* Lookup node. */
      rn = bgp_route_node_get (bgp, afi, safi, p, prd);

      /* Check selected route and self inserted route. */
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
	  break;

      /* Route reflector cluster ID check. */
      if (bgp_cluster_filter (conf, attr))
	{
	  /* If the update is implicit withdraw. */
	  if (ri)
	    bgp_implicit_withdraw (conf, bgp, p, ri, rn, afi, safi);

	  if (BGP_DEBUG (update, UPDATE))  
	    zlog (peer->log, LOG_INFO, 
		  "%s rcvd UPDATE about %s/%d -- DENIED due to: reflected from the same cluster;",
		  peer->host,
		  inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		  p->prefixlen);
	  /* Process change. */
	  bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
	  route_unlock_node (rn);
	  continue;
	}

      /* Apply input filter and route-map.  Filter and route-map
         application logging is also don in the function. */
      if (bgp_input_filter (conf, p, attr) == FILTER_DENY)
	{
	  /* If the update is implicit withdraw. */
	  if (ri)
	    bgp_implicit_withdraw (conf, bgp, p, ri, rn, afi, safi);

	  if (BGP_DEBUG (update, UPDATE))
	    {
	      zlog (peer->log, LOG_INFO,
		    "%s rcvd UPDATE about %s/%d -- DENIED due to: configured filter;",
		    peer->host,
		    inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		    p->prefixlen);
	    }
	  /* Process change. */
	  bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
	  route_unlock_node (rn);
	  continue;
	}

      /* Apply input route-map. */
      new_attr = bgp_input_modifier (peer, conf, p, attr);
      if (new_attr == NULL)
	{
	  /* If the update is implicit withdraw. */
	  if (ri)
	    bgp_implicit_withdraw (conf, bgp, p, ri, rn, afi, safi);

	  if (BGP_DEBUG (update, UPDATE))
	    {
	      zlog (peer->log, LOG_INFO,
		    "%s rcvd UPDATE about %s/%d -- DENIED due to: configured filter;",
		    peer->host,
		    inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		    p->prefixlen);
	    }
	  /* Process change. */
	  bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
	  route_unlock_node (rn);
	  continue;
	}

      /* If the peer is EBGP and nexthop is not on connected route,
         discard it.*/
      if ((afi == AFI_IP) && peer_sort (peer) == BGP_PEER_EBGP
	  && peer->ttl == 1)
	{
	  if (bgp_nexthop_lookup (peer, new_attr->nexthop, NULL) == 0)
	    {
	      /* If the update is implicit withdraw. */
	      if (ri)
		bgp_implicit_withdraw (conf, bgp, p, ri, rn, afi, safi);

	      if (BGP_DEBUG (update, UPDATE))  
		{
		  zlog (peer->log, LOG_INFO,
			"%s rcvd UPDATE about %s/%d -- DENIED due to: non-connected next-hop;",
			peer->host,
			inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
			p->prefixlen);
		}
	      /* Process change. */
	      bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
	      route_unlock_node (rn);
	      continue;
	    }
	}

      /* If the update is implicit withdraw. */
      if (ri)
	{
	  UNSET_FLAG (ri->flags, BGP_INFO_HISTORY);

	  /* BGP flap dampening. */
	  status = BGP_DAMP_DISABLED;

	  if (ri->bgp_damp_info)
	    status = bgp_damp_update (ri);

	  if (status == BGP_DAMP_DISCONTINUE)
	    {
	      ri->uptime = time (NULL);
	      continue;
	    }

 	  /* Duplicate route check.  Temporary disable until problem
             is fixed. -- kunihiro */
 	  if (attrhash_cmp (ri->attr, new_attr))
 	    {
 	      if (BGP_DEBUG (update, UPDATE))  
 		{
 		  zlog (peer->log, LOG_INFO,
			"%s rcvd %s/%d...duplicate ignored",
 			peer->host,
			inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
 			p->prefixlen);
 		}
	      ri->uptime = time (NULL);
	      /* Process change. */
	      bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
 	      route_unlock_node (rn);
 	      continue;
 	    }

	  /* If the update is implicit withdraw. */
	  bgp_implicit_withdraw (conf, bgp, p, ri, rn, afi, safi);
	  ri = NULL;
	}

      /* Received Logging. */
      if (BGP_DEBUG (update, UPDATE))  
	{
	  zlog (peer->log, LOG_INFO, "%s rcvd %s/%d",
		peer->host,
		inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		p->prefixlen);
	}

      conf->pcount[afi][safi]++;

      /* Make new BGP info. */
      if (ri && ri->bgp_damp_info)
	new = ri;
      else
	{
	  if (safi == SAFI_MPLS_VPN)
	    {
	      newtag = bgp_info_tag_new ();
	      memcpy (newtag->tag, tag, 3);

	      new = (struct bgp_info *) newtag;
	    }
	  else
	    {
	      new = bgp_info_new ();
	    }
	}

      new->type = type;
      new->sub_type = sub_type;
      new->peer = peer;
      new->attr = new_attr;
      new->uptime = time (NULL);

      if ((afi == AFI_IP) && (peer_sort (peer) == BGP_PEER_IBGP))
	new->valid = bgp_nexthop_lookup (peer, new_attr->nexthop, NULL);
      else
        new->valid = 1;

      /* Aggregate address increment. */
      bgp_aggregate_increment (bgp, p, new, afi, safi);
  
      /* Register new BGP information. */
      if (! new->bgp_damp_info)
	bgp_info_add ((struct bgp_info **) &rn->info, new);

      /* If maximum prefix count is configured and current prefix
	 count exeed it. */
      if (bgp_maximum_prefix_overflow (conf, afi, safi))
	return -1;

      /* Process change. */
      bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
    }
  return 0;
}

/* Generic function for withdraw BGP information */
int
bgp_withdraw (struct peer *peer, struct prefix *p, struct attr *attr, 
	     int afi, int safi, int type, int sub_type, struct prefix_rd *prd,
	      u_char *tag)
{
  struct peer_conf *conf;
  struct listnode *nn;
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];
  struct route_node *rn;
  struct bgp_info *ri;
  int bgp_damp_withdraw(struct bgp_info *);
  int status;

  if (peer != peer_self)
    {
      /* If peer is soft reconfiguration enabled.  Record input packet for
	 further calculation. */
      if (CHECK_FLAG (peer->flags, PEER_FLAG_SOFT_RECONFIG))
	bgp_adj_unset (peer->adj_in[afi][safi], p, prd);
    }

  LIST_LOOP (peer->conf, conf, nn)
    {
      bgp = conf->bgp;

      /* Logging. */
      if (BGP_DEBUG (update, UPDATE))  
	zlog (peer->log, LOG_INFO, "%s rcvd UPDATE about %s/%d -- withdrawn",
	      peer->host, inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
	      p->prefixlen);

      /* Lookup node. */
      rn = bgp_route_node_get (bgp, afi, safi, p, prd);

      /* Check selected route and self inserted route. */
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == peer && ri->type == type && ri->sub_type == sub_type)
	  break;

      /* Withdraw specified route from routing table. */
      if (ri)
	{
	  status = BGP_DAMP_DISABLED;

	  if (ri->selected && (peer_sort (peer) != BGP_PEER_IBGP))
	    {
	      status = bgp_damp_withdraw (ri);

	      if (status == BGP_DAMP_CONTINUE)
		{
		  bgp_aggregate_decrement (bgp, p, ri, afi, safi);
		  bgp_process (bgp, rn, afi, safi, ri, prd, tag);
		  conf->pcount[afi][safi]--;
		}
	    }

	  if (status == BGP_DAMP_DISABLED)
	    {
	      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
	      bgp_info_delete ((struct bgp_info **) &rn->info, ri);
	      bgp_process (bgp, rn, afi, safi, ri, prd, tag);
	      bgp_info_free (ri);
	      route_unlock_node (rn);

	      /* Prefix count updates. */
	      conf->pcount[afi][safi]--;
	    }
	}
      else
	{
	  if (BGP_DEBUG (update, UPDATE))  
	    zlog (peer->log, LOG_INFO, 
		  "%s Can't find the route %s/%d", peer->host,
		  inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		  p->prefixlen);
	}

      /* Unlock route_node_get() lock. */
      route_unlock_node (rn);
    }
  return 0;
}

/* Parser of NLRI octet stream.  Withdraw NLRI is recognized by NULL
   attr value. */
int
nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int ret;

  /* Check peer status. */
  if (peer->status != Established)
    return 0;
  
  pnt = packet->nlri;
  lim = pnt + packet->length;

  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length. */
      p.prefixlen = *pnt++;
      p.family = afi2family (packet->afi);
      p.safi = packet->safi;
      
      /* Already checked in nlri_sanity_check().  We do double check
         here. */
      if ((packet->afi == AFI_IP && p.prefixlen > 32)
	  || (packet->afi == AFI_IP6 && p.prefixlen > 128))
	return -1;

      /* Packet size overflow check. */
      psize = PSIZE (p.prefixlen);

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
	return -1;

      /* Fetch prefix from NLRI packet. */
      memcpy (&p.u.prefix, pnt, psize);

      /* Translate update.  Convert unicast update to multicast update. */
      if (packet->safi == SAFI_UNICAST && peer->translate_update)
	{
	  if (attr)
	    ret = bgp_update (peer, &p, attr, packet->afi, SAFI_MULTICAST,
			      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL, 0);
	  else
	    ret = bgp_withdraw (peer, &p, attr, packet->afi, SAFI_MULTICAST,
				ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL);
	  if (ret < 0)
	    return -1;
	}	  

      /* Do not process unicast update when translate update is
         only to multicast. */
      if (packet->safi == SAFI_UNICAST 
	  && peer->translate_update == SAFI_MULTICAST)
	continue;

      /* Normal process. */
      if (attr)
	ret = bgp_update (peer, &p, attr, packet->afi, packet->safi, 
			  ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL, 0);
      else
	ret = bgp_withdraw (peer, &p, attr, packet->afi, packet->safi, 
			    ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL);

      /* Address family configuration mismatch or maximum-prefix count
         overflow. */
      if (ret < 0)
	return -1;
    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

/* NLRI encode syntax check routine. */
int
nlri_sanity_check (struct peer *peer, int afi, u_char *pnt, bgp_size_t length)
{
  u_char *end;
  u_char prefixlen;
  int psize;

  end = pnt + length;

  /* RFC1771 6.3 The NLRI field in the UPDATE message is checked for
     syntactic validity.  If the field is syntactically incorrect,
     then the Error Subcode is set to Invalid Network Field. */

  while (pnt < end)
    {
      prefixlen = *pnt++;
      
      /* Prefix length check. */
      if ((afi == AFI_IP && prefixlen > 32)
	  || (afi == AFI_IP6 && prefixlen > 128))
	{
	  plog_err (peer->log, 
		    "%s [Error] Update packet error (wrong prefix length %d)",
		    peer->host, prefixlen);
	  bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_INVAL_NETWORK);
	  return -1;
	}

      /* Packet size overflow check. */
      psize = PSIZE (prefixlen);

      if (pnt + psize > end)
	{
	  plog_err (peer->log, 
		    "%s [Error] Update packet error"
		    " (prefix data overflow prefix size is %d)",
		    peer->host, psize);
	  bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_INVAL_NETWORK);
	  return -1;
	}

      pnt += psize;
    }

  /* Packet length consistency check. */
  if (pnt != end)
    {
      plog_err (peer->log,
		"%s [Error] Update packet error"
		" (prefix length mismatch with total length)",
		peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_INVAL_NETWORK);
      return -1;
    }
  return 0;
}

/* Soft reconfiguration for input. */
void
bgp_soft_reconfig_in (struct peer *peer, afi_t afi, safi_t safi)
{
  int ret;
  struct route_node *rn;
  struct attr *attr;

  for (rn = route_top (peer->adj_in[afi][safi]); rn; rn = route_next (rn))
    if ((attr = rn->info) != NULL)
      {
	ret = bgp_update (peer, &rn->p, attr, afi, safi,
			  ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
			  NULL, NULL, 1);
      
	/* Address family configuration mismatch or maximum-prefix count
	   overflow. */
	if (ret < 0)
	  {
	    route_unlock_node (rn);
	    return;
	  }
      }
}

/* Remove all routes from the peer. */
void
bgp_route_clear_with_afi (struct peer *peer, struct bgp *bgp, afi_t afi,
			  safi_t safi)
{
  struct route_node *rn;
  struct bgp_info *ri;
  struct bgp_info *next;

  for (rn = route_top (bgp->rib[afi][safi]); rn; rn = route_next (rn))
    for (ri = rn->info; ri; ri = next)
      {
	next = ri->next;

	if (ri->peer == peer)
	  {
	    bgp_aggregate_decrement (bgp, &rn->p, ri, afi, safi);
	    bgp_info_delete ((struct bgp_info **) &rn->info, ri);
	    bgp_process (bgp, rn, afi, safi, ri, NULL, NULL);
	    bgp_info_free (ri);
	    route_unlock_node (rn);
	  }
      }
}

void
bgp_route_clear_with_afi_vpnv4 (struct peer *peer, struct bgp *bgp, afi_t afi,
				safi_t safi)
{
  struct route_node *rn;
  struct route_node *rm;
  struct route_table *table;
  struct bgp_info_tag *ri;
  struct bgp_info_tag *next;

  for (rn = route_top (bgp->rib[afi][safi]); rn; rn = route_next (rn))
    if ((table = (rn->info)) != NULL)
      {
	for (rm = route_top (table); rm; rm = route_next (rm))
	  for (ri = rm->info; ri; ri = ri->next)
	    {
	      next = ri->next;

	      if (ri->peer == peer)
		{
		  bgp_aggregate_decrement (bgp, &rm->p, (struct bgp_info *)ri,
					   afi, safi);
		  bgp_info_delete ((struct bgp_info **) &rm->info,
				   (struct bgp_info *)ri);
		  bgp_process (bgp, rm, afi, safi, (struct bgp_info *)ri,
			       (struct prefix_rd *)&rn->p, ri->tag);
		  bgp_info_free ((struct bgp_info *)ri);
		  route_unlock_node (rm);
		}
	    }
      }
}
  
/* Remove all routes from the peer. */
void
bgp_route_clear (struct peer *peer)
{
  struct listnode *nn;
  struct peer_conf *conf;

  /* Clear BGP routes. */
  LIST_LOOP (peer->conf, conf, nn)
    {
      bgp_route_clear_with_afi (peer, conf->bgp, AFI_IP, SAFI_UNICAST);
      bgp_route_clear_with_afi (peer, conf->bgp, AFI_IP, SAFI_MULTICAST);
      bgp_route_clear_with_afi (peer, conf->bgp, AFI_IP6, SAFI_UNICAST);
      bgp_route_clear_with_afi (peer, conf->bgp, AFI_IP6, SAFI_MULTICAST);
      bgp_route_clear_with_afi_vpnv4 (peer, conf->bgp, AFI_IP, SAFI_MPLS_VPN);

      /* Clear prefix counter. */
      conf->pcount[AFI_IP][SAFI_UNICAST] = 0;
      conf->pcount[AFI_IP][SAFI_MULTICAST] = 0;
      conf->pcount[AFI_IP][SAFI_MPLS_VPN] = 0;
      conf->pcount[AFI_IP6][SAFI_UNICAST] = 0;
      conf->pcount[AFI_IP6][SAFI_MULTICAST] = 0;
    }

  /* Clear Adj-RIB-In information. */
  bgp_adj_clear (peer->adj_in[AFI_IP][SAFI_UNICAST], SAFI_UNICAST);
  bgp_adj_clear (peer->adj_in[AFI_IP][SAFI_MULTICAST], SAFI_MULTICAST);
  bgp_adj_clear (peer->adj_in[AFI_IP6][SAFI_UNICAST], SAFI_UNICAST);
  bgp_adj_clear (peer->adj_in[AFI_IP6][SAFI_MULTICAST], SAFI_MULTICAST);

  /* Clear Adj-RIB-Out information. */
  bgp_adj_clear (peer->adj_out[AFI_IP][SAFI_UNICAST], SAFI_UNICAST);
  bgp_adj_clear (peer->adj_out[AFI_IP][SAFI_MULTICAST], SAFI_MULTICAST);
  bgp_adj_clear (peer->adj_out[AFI_IP][SAFI_MPLS_VPN], SAFI_MPLS_VPN);
  bgp_adj_clear (peer->adj_out[AFI_IP6][SAFI_UNICAST], SAFI_UNICAST);
  bgp_adj_clear (peer->adj_out[AFI_IP6][SAFI_MULTICAST], SAFI_MULTICAST);
}


/* BGP static route configuration. */
struct bgp_static
{
  safi_t safi;
  int backdoor;
};

struct bgp_static *
bgp_static_new ()
{
  struct bgp_static *new;
  new = XMALLOC (MTYPE_BGP_STATIC, sizeof (struct bgp_static));
  memset (new, 0, sizeof (struct bgp_static));
  return new;
}

void
bgp_static_free (struct bgp_static *bgp_static)
{
  XFREE (MTYPE_BGP_STATIC, bgp_static);
}

void
bgp_static_update (struct bgp *bgp, struct prefix *p, u_int16_t afi,
		   u_char safi)
{
  struct route_node *rn;
  struct bgp_info *new;

  rn = bgp_route_node_get (bgp, afi, safi, p, NULL);

  /* Make new BGP info. */
  new = bgp_info_new ();
  new->type = ZEBRA_ROUTE_BGP;
  new->sub_type = BGP_ROUTE_STATIC;
  new->peer = peer_self;
  new->valid = 1;
  new->attr = bgp_attr_default_intern (BGP_ORIGIN_IGP);
  new->uptime = time (NULL);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add ((struct bgp_info **) &rn->info, new);

  /* Process change. */
  bgp_process (bgp, rn, afi, safi, NULL, NULL, NULL);
}

void
bgp_static_update_vpnv4 (struct bgp *bgp, struct prefix *p, u_int16_t afi,
			 u_char safi, struct prefix_rd *prd, u_char *tag)
{
  struct route_node *rn;
  struct bgp_info_tag *new;

  rn = bgp_route_node_get (bgp, afi, safi, p, prd);

  /* Make new BGP info. */
  new = bgp_info_tag_new ();
  new->type = ZEBRA_ROUTE_BGP;
  new->sub_type = BGP_ROUTE_STATIC;
  new->peer = peer_self;
  new->attr = bgp_attr_default_intern (BGP_ORIGIN_IGP);
  new->uptime = time (NULL);
  memcpy (new->tag, tag, 3);

  /* Aggregate address increment. */
  bgp_aggregate_increment (bgp, p, (struct bgp_info *) new, afi, safi);
  
  /* Register new BGP information. */
  bgp_info_add ((struct bgp_info **) &rn->info, (struct bgp_info *) new);

  /* Process change. */
  bgp_process (bgp, rn, afi, safi, NULL, prd, tag);
}

void
bgp_static_withdraw (struct bgp *bgp, struct prefix *p, u_int16_t afi,
		     u_char safi)
{
  struct route_node *rn;
  struct bgp_info *ri;

  rn = bgp_route_node_get (bgp, afi, safi, p, NULL);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete ((struct bgp_info **) &rn->info, ri);
      bgp_process (bgp, rn, afi, safi, ri, NULL, NULL);
      bgp_info_free (ri);
      route_unlock_node (rn);
    }

  /* Unlock route_node_lookup. */
  route_unlock_node (rn);
}

void
bgp_static_withdraw_vpnv4 (struct bgp *bgp, struct prefix *p, u_int16_t afi,
			   u_char safi, struct prefix_rd *prd, u_char *tag)
{
  struct route_node *rn;
  struct bgp_info *ri;

  rn = bgp_route_node_get (bgp, afi, safi, p, prd);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete ((struct bgp_info **) &rn->info, ri);
      bgp_process (bgp, rn, afi, safi, ri, prd, tag);
      bgp_info_free (ri);
      route_unlock_node (rn);
    }

  /* Unlock route_node_lookup. */
  route_unlock_node (rn);
}

/* Configure static BGP network. */
int
bgp_static_set (struct vty *vty, struct bgp *bgp, char *ip_str, u_int16_t afi,
		u_char safi, int backdoor)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct route_node *rn;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);
  p.safi = safi;

  /* Set BGP static route configuration. */
  rn = route_node_get (bgp->route[afi], &p);

  if (rn->info)
    {
      /* Configuration change. */
      bgp_static = rn->info;

      if (backdoor)
	{
	  if (bgp_static->safi && SAFI_UNICAST)
	    bgp_static_withdraw (bgp, &p, afi, SAFI_UNICAST);

	  if (bgp_static->safi && SAFI_MULTICAST)
	    bgp_static_withdraw (bgp, &p, afi, SAFI_MULTICAST);
	}
      else
	{
	  /* Unicast configuration update. */
	  if (bgp_static->safi & SAFI_UNICAST)
	    {
	      if (! (safi & SAFI_UNICAST))
		bgp_static_withdraw (bgp, &p, afi, SAFI_UNICAST);
	    }
	  else
	    {
	      if (safi & SAFI_UNICAST)
		bgp_static_update (bgp, &p, afi, SAFI_UNICAST);
	    }
	  /* Multicast configuration update. */
	  if (bgp_static->safi & SAFI_MULTICAST)
	    {
	      if (! (safi & SAFI_MULTICAST))
		bgp_static_withdraw (bgp, &p, afi, SAFI_MULTICAST);
	    }
	  else
	    {
	      if (safi & SAFI_MULTICAST)
		bgp_static_update (bgp, &p, afi, SAFI_MULTICAST);
	    }
	}

      bgp_static->safi = safi;
      bgp_static->backdoor = backdoor;

      route_unlock_node (rn);
    }
  else
    {
      /* New configuration. */
      bgp_static = bgp_static_new ();
      bgp_static->safi = safi;
      bgp_static->backdoor = backdoor;
      rn->info = bgp_static;

      if (! backdoor)
	{
	  if (safi & SAFI_UNICAST)
	    bgp_static_update (bgp, &p, afi, SAFI_UNICAST);
	  if (safi & SAFI_MULTICAST)
	    bgp_static_update (bgp, &p, afi, SAFI_MULTICAST);
	}
    }
  return CMD_SUCCESS;
}

/* Configure static BGP network. */
int
bgp_static_unset (struct vty *vty, struct bgp *bgp, char *ip_str,
		  u_int16_t afi, u_char safi)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct route_node *rn;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  rn = route_node_lookup (bgp->route[afi], &p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified static route configuration.%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static = rn->info;

  /* Configuration check. */
  if (safi)
    {
      if (bgp_static->safi != safi)
	{
	  vty_out (vty, "Can't find specified static route configuration.%s",
		   VTY_NEWLINE);
	  route_unlock_node (rn);
	  return CMD_WARNING;
	}
    }

  /* Unicast configuration update. */
  if (! bgp_static->backdoor)
    {
      if (bgp_static->safi & SAFI_UNICAST)
	bgp_static_withdraw (bgp, &p, afi, SAFI_UNICAST);
      if (bgp_static->safi & SAFI_MULTICAST)
	bgp_static_withdraw (bgp, &p, afi, SAFI_MULTICAST);
    }

  /* Clear configuration. */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Called from bgp_delete().  Delete all static routes from the BGP
   instance. */
void
bgp_static_delete (struct bgp *bgp)
{
  struct route_node *rn;
  struct bgp_static *bgp_static;

  for (rn = route_top (bgp->route[AFI_IP]); rn; rn = route_next (rn))
    if ((bgp_static = rn->info) != NULL )
      {      
	if (bgp_static->safi & SAFI_UNICAST)
	  bgp_static_withdraw (bgp, &rn->p, AFI_IP, SAFI_UNICAST);
	if (bgp_static->safi & SAFI_MULTICAST)
	  bgp_static_withdraw (bgp, &rn->p, AFI_IP, SAFI_MULTICAST);

	bgp_static_free (bgp_static);
	rn->info = NULL;
	route_unlock_node (rn);
      }

  for (rn = route_top (bgp->route[AFI_IP6]); rn; rn = route_next (rn))
    if ((bgp_static = rn->info) != NULL )
      {      
	if (bgp_static->safi & SAFI_UNICAST)
	  bgp_static_withdraw (bgp, &rn->p, AFI_IP6, SAFI_UNICAST);
	if (bgp_static->safi & SAFI_MULTICAST)
	  bgp_static_withdraw (bgp, &rn->p, AFI_IP6, SAFI_MULTICAST);

	bgp_static_free (bgp_static);
	rn->info = NULL;
	route_unlock_node (rn);
      }
}

int
bgp_static_set_vpnv4 (struct vty *vty, char *ip_str, char *rd_str,
		      char *tag_str)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  u_char tag[3];

  bgp = vty->index;

  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);
  p.safi = SAFI_MPLS_VPN;

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static_update_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);

  return CMD_SUCCESS;
}

/* Configure static BGP network. */
int
bgp_static_unset_vpnv4 (struct vty *vty, char *ip_str, char *rd_str,
			char *tag_str)
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct prefix_rd prd;
  u_char tag[3];

  bgp = vty->index;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);
  p.safi = SAFI_MPLS_VPN;

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static_withdraw_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);

  return CMD_SUCCESS;
}

DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (bgp_network_multicast,
       bgp_network_multicast_cmd,
       "network A.B.C.D/M nlri multicast",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_MULTICAST, 0);
}

DEFUN (bgp_network_unicast_multicast,
       bgp_network_unicast_multicast_cmd,
       "network A.B.C.D/M nlri unicast multicast",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, 
			 SAFI_UNICAST_MULTICAST, 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP, 0);
}

DEFUN (no_bgp_network_multicast,
       no_bgp_network_multicast_cmd,
       "no network A.B.C.D/M nlri multicast",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP, SAFI_MULTICAST);
}

DEFUN (no_bgp_network_unicast_multicast,
       no_bgp_network_unicast_multicast_cmd,
       "no network A.B.C.D/M nlri unicast multicast",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP,
			   SAFI_UNICAST_MULTICAST);
}

DEFUN (no_bgp_network_backdoor,
       no_bgp_network_backdoor_cmd,
       "no network A.B.C.D/M backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "ipv6 bgp network X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (ipv6_bgp_network_multicast,
       ipv6_bgp_network_multicast_cmd,
       "ipv6 bgp network X:X::X:X/M nlri multicast",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6, SAFI_MULTICAST, 0);
}

DEFUN (ipv6_bgp_network_unicast_multicast,
       ipv6_bgp_network_unicast_multicast_cmd,
       "ipv6 bgp network X:X::X:X/M nlri unicast multicast",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6,
			 SAFI_UNICAST_MULTICAST, 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no ipv6 bgp network X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, 0);
}

DEFUN (no_ipv6_bgp_network_multicast,
       no_ipv6_bgp_network_multicast_cmd,
       "no ipv6 bgp network X:X::X:X/M nlri multicast",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, SAFI_MULTICAST);
}

DEFUN (no_ipv6_bgp_network_unicast_multicast,
       no_ipv6_bgp_network_unicast_multicast_cmd,
       "no ipv6 bgp network X:X::X:X/M nlri unicast multicast",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, 
			   SAFI_UNICAST_MULTICAST);
}
#endif /* HAVE_IPV6 */

/* Aggreagete address:

  advertise-map  Set condition to advertise attribute
  as-set         Generate AS set path information
  attribute-map  Set attributes of aggregate
  route-map      Set parameters of aggregate
  summary-only   Filter more specific routes from updates
  suppress-map   Conditionally filter more specific routes from updates
  <cr>
 */
struct bgp_aggregate
{
  /* Summary-only flag. */
  u_char summary_only;

  /* Route-map for aggregated route. */
  struct route_map *map;

  /* Suppress-count. */
  unsigned long count;

  /* SAFI configuration. */
  safi_t safi;
};

struct bgp_aggregate *
bgp_aggregate_new ()
{
  struct bgp_aggregate *new;
  new = XMALLOC (MTYPE_BGP_AGGREGATE, sizeof (struct bgp_aggregate));
  memset (new, 0, sizeof (struct bgp_aggregate));
  return new;
}

void
bgp_aggregate_free (struct bgp_aggregate *aggregate)
{
  XFREE (MTYPE_BGP_AGGREGATE, aggregate);
}     

void
bgp_aggregate_increment (struct bgp *bgp, struct prefix *p,
			 struct bgp_info *ri, afi_t afi, safi_t safi)
{
  struct route_node *child;
  struct route_node *rn;
  struct route_node *rm;
  struct bgp_aggregate *aggregate;
  unsigned long activate;
  struct bgp_info *new;
  struct prefix q;

  /* MPLS-VPN aggregation is not yet supported. */
  if (safi == SAFI_MPLS_VPN)
    return;

  if (p->prefixlen == 0)
    return;

  if (! ri->valid
      || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY)
      || CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
    return;

  prefix_copy (&q, p);
  q.prefixlen--;
  
  child = route_node_get (bgp->aggregate[afi], &q);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = rn->parent)
    if ((aggregate = rn->info) != NULL)
      {
	activate = 0;

	/* SAFI check. */
	if (aggregate->safi & safi)
	  {
	    /* Suppress this route. */
	    if (aggregate->summary_only)
	      ri->suppress++;
	
	    if (! aggregate->count)
	      activate++;
	      
	    aggregate->count++;
	  }

	/* Activate aggreagete route. */
	if (activate)
	  {
	    rm = bgp_route_node_get (bgp, afi, safi, &rn->p, NULL);

	    new = bgp_info_new ();
	    new->type = ZEBRA_ROUTE_BGP;
	    new->sub_type = BGP_ROUTE_AGGREGATE;
	    new->peer = peer_self;
	    new->valid = 1;
	    new->attr = bgp_attr_aggregate_intern (bgp);
	    new->uptime = time (NULL);
		
	    bgp_info_add ((struct bgp_info **) &rm->info, new);
		
	    /* Process change. */
	    bgp_process (bgp, rm, afi, safi, NULL, NULL, NULL);
	  }
      }
  route_unlock_node (child);
}

void
bgp_aggregate_decrement (struct bgp *bgp, struct prefix *p, 
			 struct bgp_info *del, afi_t afi, safi_t safi)
{
  struct route_node *child;
  struct route_node *rn;
  struct route_node *rm;
  struct bgp_aggregate *aggregate;
  struct bgp_info *ri;
  struct prefix q;

  /* MPLS-VPN aggregation is not yet supported. */
  if (safi == SAFI_MPLS_VPN)
    return;

  if (p->prefixlen == 0)
    return;

  if (! del->valid
      || CHECK_FLAG (del->flags, BGP_INFO_HISTORY)
      || CHECK_FLAG (del->flags, BGP_INFO_DAMPED))
    return;

  prefix_copy (&q, p);
  q.prefixlen--;

  child = route_node_get (bgp->aggregate[afi], &q);

  /* Aggregate address configuration check. */
  for (rn = child; rn; rn = rn->parent)
    if ((aggregate = rn->info) != NULL)
      {
	/* SAFI check. */
	if (aggregate->safi & safi)
	  {
	    /* Suppress this route. */
	    if (aggregate->summary_only)
	      del->suppress--;
	
	    aggregate->count--;
	  }

	/* Deactivate aggreagete route. */
	if (aggregate->count == 0)
	  {
	    rm = bgp_route_node_get (bgp, afi, safi, &rn->p, NULL);

	    for (ri = rm->info; ri; ri = ri->next)
	      if (ri->peer == peer_self 
		  && ri->type == ZEBRA_ROUTE_BGP
		  && ri->sub_type == BGP_ROUTE_AGGREGATE)
		break;

	    /* Withdraw static BGP route from routing table. */
	    if (ri)
	      {
		bgp_info_delete ((struct bgp_info **) &rm->info, ri);
		bgp_process (bgp, rm, afi, safi, ri, NULL, NULL);
		bgp_info_free (ri);
		route_unlock_node (rm);
	      }
	    route_unlock_node (rm);
	  }
      }
  route_unlock_node (child);
}

void
bgp_aggregate_add (struct bgp *bgp, struct prefix *p, afi_t afi, safi_t safi,
		   struct bgp_aggregate *aggregate)
{
  struct route_table *table;
  struct route_node *top;
  struct route_node *rn;
  struct bgp_info *new;
  struct bgp_info *ri;
  unsigned long match;
  struct prefix q;

  table = bgp->rib[afi][safi];

  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;
    
  prefix_copy (&q, p);
  q.prefixlen++;

  /* If routes exists below this node, generate aggregate routes. */
  top = route_node_get (table, &q);
  for (rn = route_node_get (table, &q); rn; rn = route_next_until (rn, top))
    {
      match = 0;

      for (ri = rn->info; ri; ri = ri->next)
	{
	  if (! ri->valid
	      || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY)
	      || CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
	    continue;

	  if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	    {
	      if (aggregate->summary_only)
		{
		  ri->suppress++;
		  match++;
		}
	      aggregate->count++;
	    }
	}

      /* If this node is suppressed, process the change. */
      if (match)
	bgp_process (bgp, rn, afi, safi, NULL, NULL, NULL);
    }
  route_unlock_node (top);

  /* Add aggregate route to BGP table. */
  if (aggregate->count)
    {
      rn = route_node_get (table, p);

      new = bgp_info_new ();
      new->type = ZEBRA_ROUTE_BGP;
      new->sub_type = BGP_ROUTE_AGGREGATE;
      new->peer = peer_self;
      new->valid = 1;
      new->attr = bgp_attr_aggregate_intern (bgp);
      new->uptime = time (NULL);

      bgp_info_add ((struct bgp_info **) &rn->info, new);

      /* Process change. */
      bgp_process (bgp, rn, afi, safi, NULL, NULL, NULL);
    }
}

void
bgp_aggregate_delete (struct bgp *bgp, struct prefix *p, afi_t afi, 
		      safi_t safi, struct bgp_aggregate *aggregate)
{
  struct route_table *table;
  struct route_node *top;
  struct route_node *rn;
  struct bgp_info *ri;
  unsigned long match;
  struct prefix q;

  table = bgp->rib[afi][safi];

  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;

  prefix_copy (&q, p);
  q.prefixlen++;

  /* If routes exists below this node, generate aggregate routes. */
  top = route_node_get (table, &q);
  for (rn = route_node_get (table, &q); rn; rn = route_next_until (rn, top))
    {
      match = 0;

      for (ri = rn->info; ri; ri = ri->next)
	{
	  if (! ri->valid
	      || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY)
	      || CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
	    continue;

	  if (ri->sub_type != BGP_ROUTE_AGGREGATE)
	    {
	      if (aggregate->summary_only)
		{
		  ri->suppress--;

		  if (ri->suppress == 0)
		    match++;
		}
	      aggregate->count--;
	    }
	}

      /* If this node is suppressed, process the change. */
      if (match)
	bgp_process (bgp, rn, afi, safi, NULL, NULL, NULL);
    }
  route_unlock_node (top);

  /* Delete aggregate route from BGP table. */
  rn = route_node_get (table, p);

  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == peer_self 
	&& ri->type == ZEBRA_ROUTE_BGP
	&& ri->sub_type == BGP_ROUTE_AGGREGATE)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete ((struct bgp_info **) &rn->info, ri);
      bgp_process (bgp, rn, afi, safi, ri, NULL, NULL);
      bgp_info_free (ri);
      route_unlock_node (rn);
    }

  /* Unlock route_node_lookup. */
  route_unlock_node (rn);
}

#define AGGREGATE_SUMMARY_ONLY 1

int
bgp_aggregate_set (struct vty *vty, char *prefix_str, afi_t afi, safi_t safi,
		   u_char summary_only)
{
  int ret;
  struct prefix p;
  struct route_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);
  p.safi = SAFI_UNICAST;

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = route_node_get (bgp->aggregate[afi], &p);

  if (rn->info)
    {
      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
      route_unlock_node (rn);
      return CMD_WARNING;
    }

  /* Make aggregate address structure. */
  aggregate = bgp_aggregate_new ();
  aggregate->summary_only = summary_only;
  aggregate->safi = safi;
  rn->info = aggregate;

  /* Aggregate address insert into BGP routing table. */
  if (safi & SAFI_UNICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (safi & SAFI_MULTICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  return CMD_SUCCESS;
}

int
bgp_aggregate_unset (struct vty *vty, char *prefix_str, afi_t afi, safi_t safi,
		     u_char summary_only)
{
  int ret;
  struct prefix p;
  struct route_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = route_node_lookup (bgp->aggregate[afi], &p);
  if (! rn)
    {
      vty_out (vty, "There is no aggregate-address configuration.%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  aggregate = rn->info;
  if (aggregate->safi & SAFI_UNICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (aggregate->safi & SAFI_MULTICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  /* Unlock aggregate address configuration. */
  rn->info = NULL;
  bgp_aggregate_free (aggregate);
  route_unlock_node (rn);
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, SAFI_UNICAST,
			    AGGREGATE_SUMMARY_ONLY);
}

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (no_aggregate_address_summary_only,
       no_aggregate_address_summary_only_cmd,
       "no aggregate-address A.B.C.D/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP, SAFI_UNICAST,
			      AGGREGATE_SUMMARY_ONLY);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 
			    AGGREGATE_SUMMARY_ONLY);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST, 
			      AGGREGATE_SUMMARY_ONLY);
}
#endif /* HAVE_IPV6 */

/* Redistribute route treatment. */
void
bgp_redistribute_add (struct prefix *p, struct in_addr *nexthop, u_char type)
{
  struct bgp *bgp;
  struct listnode *nn;
  struct bgp_info *new;
  struct route_node *rn;
  struct attr attr;
  struct attr attr_new;
  struct bgp_info info;
  afi_t afi;
  int ret;
  struct aspath *aspath;

  LIST_LOOP (bgp_list, bgp, nn)
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
	{
	  /* Make default attribute. */
	  bgp_attr_default_set (&attr, BGP_ORIGIN_INCOMPLETE);
	  if (nexthop)
	    attr.nexthop = *nexthop;
	  aspath = attr.aspath;

	  /* Apply route-map. */
	  if (bgp->rmap[afi][type].map)
	    {
	      info.peer = peer_self;
	      info.attr = &attr;

	      ret = route_map_apply (bgp->rmap[afi][type].map, p, RMAP_BGP,
				     &info);
	      if (ret == RMAP_DENYMATCH)
		{
		  /* Free uninterned attribute. */
		  bgp_attr_flush (&attr_new);
		  return;
		}
	    }

	  new = bgp_info_new ();
	  new->type = type;
	  new->peer = peer_self;
	  new->valid = 1;
	  new->attr = bgp_attr_intern (&attr);
	  new->uptime = time (NULL);

	  /* Unintern original. */
	  aspath_unintern (aspath);
	  
	  rn = bgp_route_node_get (bgp, afi, SAFI_UNICAST, p, NULL);
	  bgp_aggregate_increment (bgp, p, new, afi, SAFI_UNICAST);
	  bgp_info_add ((struct bgp_info **) &rn->info, new);
	  bgp_process (bgp, rn, afi, SAFI_UNICAST, NULL, NULL, NULL);
	}
    }
}

void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  struct bgp *bgp;
  struct listnode *nn;
  afi_t afi;
  struct route_node *rn;
  struct bgp_info *ri;

  LIST_LOOP (bgp_list, bgp, nn)
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
	{
	  rn = bgp_route_node_get (bgp, afi, SAFI_UNICAST, p, NULL);

	  for (ri = rn->info; ri; ri = ri->next)
	    if (ri->peer == peer_self
		&& ri->type == type)
	      break;

	  if (ri)
	    {
	      bgp_aggregate_decrement (bgp, p, ri, afi, SAFI_UNICAST);
	      bgp_info_delete ((struct bgp_info **) &rn->info, ri);
	      bgp_process (bgp, rn, afi, SAFI_UNICAST, ri, NULL, NULL);
	      bgp_info_free (ri);
	      route_unlock_node (rn);
	    }
	  route_unlock_node (rn);
	}
    }
}

/* Withdraw specified route type's route. */
void
bgp_redistribute_withdraw (struct bgp *bgp, afi_t afi, int type)
{
  struct route_node *rn;
  struct bgp_info *ri;
  struct route_table *table;

  table = bgp->rib[afi][SAFI_UNICAST];

  for (rn = route_top (table); rn; rn = route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->next)
	if (ri->peer == peer_self
	    && ri->type == type)
	  break;

      if (ri)
	{
	  bgp_aggregate_decrement (bgp, &rn->p, ri, afi, SAFI_UNICAST);
	  bgp_info_delete ((struct bgp_info **) &rn->info, ri);
	  bgp_process (bgp, rn, afi, SAFI_UNICAST, ri, NULL, NULL);
	  bgp_info_free (ri);
	  route_unlock_node (rn);
	}
    }
}

/* Static function to display route. */
void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  char buf[BUFSIZ];

  len = vty_out (vty, "%s/%d", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen);
  len = 19 - len;
  if (len < 0)
    len = 0;
  vty_out (vty, "%*s", len, " ");
}

/* Calculate line number of output data. */
int
vty_calc_line (struct vty *vty, unsigned long length)
{
  return vty->width ? (((vty->obuf->length - length) / vty->width) + 1) : 1;
}

enum bgp_display_type
{
  normal_list,
};

/* called from terminal list command */
int
route_vty_out (struct vty *vty, struct prefix *p, struct bgp_info *binfo)
{
  struct attr *attr;
  unsigned long length = 0;

  length = vty->obuf->length;

  /* Route status display. */
  if (binfo->suppress)
    vty_out (vty, "s");
  else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "h");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    vty_out (vty, "d");
  else if (binfo->selected)
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route. */
    if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
      vty_out (vty, "i");
    else
      vty_out (vty, " ");
  
  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      if (p->family == AF_INET)
	{
	  if (p->safi == SAFI_MPLS_VPN)
	    vty_out (vty, "%-16s", inet_ntoa (attr->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
#ifdef HAVE_IPV6      
      else if (p->family == AF_INET6)
	{
	  char buf[BUFSIZ];
	  char buf1[BUFSIZ];
	  if (attr->mp_nexthop_len == 16)
	    vty_out (vty, "%s", 
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ));
	  else if (attr->mp_nexthop_len == 32)
	    vty_out (vty, "%s(%s)",
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		     inet_ntop (AF_INET6, &attr->mp_nexthop_local, buf1, BUFSIZ));
	  
	}
#endif /* HAVE_IPV6 */

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, "%7lu", attr->med);
      else
	vty_out (vty, "       ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%7lu", attr->local_pref);
      else
	vty_out (vty, "       ");

      vty_out (vty, "%7u ",attr->weight);
    
    /* Print aspath */
    if (attr->aspath)
      aspath_print_vty (vty, attr->aspath);

    /* Print origin */
    if (strlen (attr->aspath->str) == 0)
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    else
      vty_out (vty, " %s", bgp_origin_str[attr->origin]);
  }
  vty_out (vty, "%s", VTY_NEWLINE);

  return vty_calc_line (vty, length);
}  

/* called from terminal list command */
void
route_vty_out_tmp (struct vty *vty, struct prefix *p, struct attr *attr)
{
  /* Route status display. */
  vty_out (vty, "*");
  vty_out (vty, ">");
  vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  if (attr) 
    {
      if (p->family == AF_INET)
	vty_out (vty, "%-16s", inet_ntoa(attr->nexthop));
#ifdef HAVE_IPV6      
      else if (p->family == AF_INET6)
	{
	  char buf[BUFSIZ];
	  char buf1[BUFSIZ];
	  if (attr->mp_nexthop_len == 16)
	    vty_out (vty, "%s", 
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ));
	  else if (attr->mp_nexthop_len == 32)
	    vty_out (vty, "%s(%s)",
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		     inet_ntop (AF_INET6, &attr->mp_nexthop_local, buf1, BUFSIZ));
	  
	}
#endif /* HAVE_IPV6 */

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
	vty_out (vty, "%7lu", attr->med);
      else
	vty_out (vty, "       ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%7lu", attr->local_pref);
      else
	vty_out (vty, "       ");

      vty_out (vty, "%7lu ",attr->weight);
    
    /* Print aspath */
    if (attr->aspath)
      aspath_print_vty (vty, attr->aspath);

    /* Print origin */
    if (strlen (attr->aspath->str) == 0)
      vty_out (vty, "%s", bgp_origin_str[attr->origin]);
    else
      vty_out (vty, " %s", bgp_origin_str[attr->origin]);
  }

  vty_out (vty, "%s", VTY_NEWLINE);
}  

int
route_vty_out_tag (struct vty *vty, struct prefix *p,
		   struct bgp_info *binfo)
{
  struct attr *attr;
  unsigned long length = 0;
  u_int32_t label = 0;
  struct bgp_info_tag *btag;

  length = vty->obuf->length;

  /* Route status display. */
  if (binfo->suppress)
    vty_out (vty, "s");
  else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "h");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    vty_out (vty, "d");
  else if (binfo->selected)
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route. */
    if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
      vty_out (vty, "i");
    else
      vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      if (p->family == AF_INET)
	{
	  if (p->safi == SAFI_MPLS_VPN)
	    vty_out (vty, "%-16s", inet_ntoa (attr->mp_nexthop_global_in));
	  else
	    vty_out (vty, "%-16s", inet_ntoa (attr->nexthop));
	}
#ifdef HAVE_IPV6      
      else if (p->family == AF_INET6)
	{
	  char buf[BUFSIZ];
	  char buf1[BUFSIZ];
	  if (attr->mp_nexthop_len == 16)
	    vty_out (vty, "%s", 
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ));
	  else if (attr->mp_nexthop_len == 32)
	    vty_out (vty, "%s(%s)",
		     inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		     inet_ntop (AF_INET6, &attr->mp_nexthop_local, buf1, BUFSIZ));
	  
	}
#endif /* HAVE_IPV6 */
    }

  btag = (struct bgp_info_tag *)binfo;
  label = decode_label (btag->tag);

  vty_out (vty, "%10ld", label);

  vty_out (vty, "%s", VTY_NEWLINE);

  return vty_calc_line (vty, length);
}  

#ifdef HAVE_IPV6      
void
route_vty_out_route_ipv6 (struct prefix *p, struct vty *vty)
{
  int len;
  char buf[BUFSIZ];

  len = vty_out (vty, "%s/%d", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen);
  len = 40 - len;
  if (len < 0)
    len = 0;
  vty_out (vty, "%*s", len, " ");
}

/* called from terminal list command */
int
route_vty_out_ipv6 (struct vty *vty, struct prefix *p, struct bgp_info *binfo)
{
  struct attr *attr;
  unsigned long length;
  int line = 0;

  length = vty->obuf->length;

  /* Route status display. */
  if (binfo->suppress)
    vty_out (vty, "s");
  else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (binfo->selected)
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route. */
    if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
      vty_out (vty, "i");
    else
      vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route_ipv6 (p, vty);

  /* Print attribute */
  attr = binfo->attr;

  /* Med */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    vty_out (vty, "%7lu", attr->med);
  else
    vty_out (vty, "       ");

  /* Local-pref */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    vty_out (vty, "%7lu", attr->local_pref);
  else
    vty_out (vty, "       ");

  /* Weight */
  vty_out (vty, "%7lu ",attr->weight);
    
  /* Print aspath */
  if (attr->aspath)
    aspath_print_vty (vty, attr->aspath);

  /* Print origin */
  if (strlen (attr->aspath->str) == 0)
    vty_out (vty, "%s", bgp_origin_str[attr->origin]);
  else
    vty_out (vty, " %s", bgp_origin_str[attr->origin]);

  vty_out (vty, "%s", VTY_NEWLINE);

  line = vty_calc_line (vty, length);
  length = vty->obuf->length;

  if (attr) 
    {
      char buf[BUFSIZ];
      char buf1[BUFSIZ];

      if (attr->mp_nexthop_len == 16)
	vty_out (vty, "     %s%s", 
		 inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		 VTY_NEWLINE);
      else if (attr->mp_nexthop_len == 32)
	vty_out (vty, "     %s(%s)%s",
		 inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		 inet_ntop (AF_INET6, &attr->mp_nexthop_local, buf1, BUFSIZ),
		 VTY_NEWLINE);
    }
  return line + vty_calc_line (vty, length);
}  

/* called from terminal list command */
void
route_vty_out_ipv6_tmp (struct vty *vty, struct prefix *p, struct attr *attr)
{
  /* Selected tag display. */
  vty_out (vty, "*> ");

  /* print prefix and mask */
  route_vty_out_route_ipv6 (p, vty);

  /* Med */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    vty_out (vty, "%7lu", attr->med);
  else
    vty_out (vty, "       ");

  /* Local-pref */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    vty_out (vty, "%7lu", attr->local_pref);
  else
    vty_out (vty, "       ");

  /* Weight */
  vty_out (vty, "%7lu ",attr->weight);
    
  /* Print aspath */
  if (attr->aspath)
    aspath_print_vty (vty, attr->aspath);

  /* Print origin */
  if (strlen (attr->aspath->str) == 0)
    vty_out (vty, "%s", bgp_origin_str[attr->origin]);
  else
    vty_out (vty, " %s", bgp_origin_str[attr->origin]);

  vty_out (vty, "%s", VTY_NEWLINE);

  if (attr) 
    {
      char buf[BUFSIZ];
      char buf1[BUFSIZ];

      if (attr->mp_nexthop_len == 16)
	vty_out (vty, "     %s%s", 
		 inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		 VTY_NEWLINE);
      else if (attr->mp_nexthop_len == 32)
	vty_out (vty, "     %s(%s)%s",
		 inet_ntop (AF_INET6, &attr->mp_nexthop_global, buf, BUFSIZ),
		 inet_ntop (AF_INET6, &attr->mp_nexthop_local, buf1, BUFSIZ),
		 VTY_NEWLINE);
    }
}  
#endif /* HAVE_IPV6 */

void
route_vty_out_detail (struct vty *vty, struct prefix *p, 
		      struct bgp_info *binfo)
{
  char buf[INET6_ADDRSTRLEN];
  char buf1[BUFSIZ];
  struct attr *attr;
  struct bgp *bgp;
  int sockunion_vty_out (struct vty *, union sockunion *);
	
  attr = binfo->attr;
  bgp = bgp_get_default ();

    if (attr)
      {
  /* Line1 display AS-path, Aggregator */
        if (attr->aspath)
          {
            vty_out (vty, "  ");
	    if (binfo->peer == peer_self || attr->aspath->length == 0)
              vty_out (vty, "Local");
	    else
              aspath_print_vty (vty, attr->aspath);
          }

	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR)
	    || CHECK_FLAG (binfo->peer->flags, PEER_FLAG_REFLECTOR_CLIENT)
	    || CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY)
	    || CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
	  {
	    vty_out (vty, ",");

	    if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))
	      vty_out (vty, " (aggregated by %d %s)", attr->aggregator_as,
			inet_ntoa (attr->aggregator_addr));
	    if (CHECK_FLAG (binfo->peer->flags, PEER_FLAG_REFLECTOR_CLIENT))
	      vty_out (vty, " (Received from a RR-client)");
	    if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
	      vty_out (vty, " (history entry)");
	    else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
	      vty_out (vty, " (suppressed due to dampening)");
	  }
        vty_out (vty, "%s", VTY_NEWLINE);
	  
  /* Line2 display Next-hop, Neighbor, Router-id */
	if (p->family == AF_INET)
	  {
	  vty_out (vty, "    %s", p->safi == SAFI_MPLS_VPN ?
		   inet_ntoa (attr->mp_nexthop_global_in) :
		   inet_ntoa (attr->nexthop));
	  }
#ifdef HAVE_IPV6
	else
	  {
	    vty_out (vty, "    %s",
	 	     inet_ntop (AF_INET6, &attr->mp_nexthop_global,
				buf, INET6_ADDRSTRLEN));
	  }
#endif /* HAVE_IPV6 */

	if (binfo->peer == peer_self)
	  {
	    vty_out (vty, " from %s ", 
		     p->family == AF_INET ? "0.0.0.0" : "::");
	    vty_out (vty, "(%s)", inet_ntoa(bgp->id));
	  }
	else
	  {
            if (! binfo->valid)
              vty_out (vty, " (inaccessible)"); 
            vty_out (vty, " from %s", sockunion2str (&binfo->peer->su, buf, SU_ADDRSTRLEN));
	    if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	      vty_out (vty, " (%s)", inet_ntoa (attr->originator_id));
	    else
              vty_out (vty, " (%s)", inet_ntop (AF_INET, &binfo->peer->remote_id, buf1, BUFSIZ));
	  }
        vty_out (vty, "%s", VTY_NEWLINE);

#ifdef HAVE_IPV6
	/* display nexthop local */
	if (attr->mp_nexthop_len == 32)
	  {
	    vty_out (vty, "    (%s)%s",
		     inet_ntop (AF_INET6, &attr->mp_nexthop_local,
				buf, INET6_ADDRSTRLEN),
				VTY_NEWLINE);
	    }
#endif /* HAVE_IPV6 */

  /* Line 3 display Origin, Med, Locpref, Weight, valid, Int/Ext/Local, Atomic, best */
	vty_out (vty, "      Origin %s", bgp_origin_long_str[attr->origin]);
	  
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
	  vty_out (vty, ", metric %lu", attr->med, VTY_NEWLINE);
	  
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
	  vty_out (vty, ", localpref %lu", attr->local_pref);
	else
	  vty_out (vty, ", localpref %lu", bgp->default_local_pref);

        if (attr->weight != 0)
          vty_out (vty, ", weight %lu", attr->weight);
	
        if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
          vty_out (vty, ", valid");

	if (binfo->peer != peer_self)
	  {
	    if (binfo->peer->as == binfo->peer->local_as)
              vty_out (vty, ", internal");
	    else 
	      vty_out (vty, ", %s", 
	        (bgp_confederation_peers_check(bgp, binfo->peer->as) ? "confed-external" : "external"));
	  }
	else if (binfo->sub_type == BGP_ROUTE_AGGREGATE)
          vty_out (vty, ", aggregated, local");
	else if (binfo->type != ZEBRA_ROUTE_BGP)
          vty_out (vty, ", sourced");
	else
	  vty_out (vty, ", sourced, local");

	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
	  vty_out (vty, ", atomic-aggregate");
	  
	if (binfo->selected)
          vty_out (vty, ", best");

	vty_out (vty, "%s", VTY_NEWLINE);
	  
  /* Line 4 display Community */
	if (attr->community)
	  {
	    vty_out (vty, "      Community:");
	    community_print_vty (vty, attr->community);
	    vty_out (vty, "%s", VTY_NEWLINE);
	  }
	  
  /* Line 5 display Extended-community */
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
	  {
	    vty_out (vty, "      Extended Community:");
	    ecommunity_vty_out (vty, attr->ecommunity);
	    vty_out (vty, "%s", VTY_NEWLINE);
	  }
	  
  /* Line 6 display Originator, Cluster-id */
	if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) ||
	   (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)))
          {
	    if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	      vty_out (vty, "      Originator: %s", inet_ntoa (attr->originator_id));

            if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
              {
                int i;
                vty_out (vty, ", Cluster list: ");
                for (i = 0; i < attr->cluster->length / 4; i++)
	          vty_out (vty, "%s ", inet_ntoa (attr->cluster->list[i]));
              }
	    vty_out (vty, "%s", VTY_NEWLINE);
	  }

        if (binfo->bgp_damp_info)
	  bgp_damp_info_print (vty, binfo);

  /* Line 7 display Uptime */
	vty_out (vty, "      Last update: %s", ctime (&binfo->uptime));
      }
  vty_out (vty, "%s", VTY_NEWLINE);
}  

#define BGP_SHOW_V4_HEADER "   Network            Next Hop         Metric LocPrf Weight Path%s"
#define BGP_SHOW_V6_HEADER "   Network                                  Metric LocPrf Weight Path%s"

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_neighbor,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact
};

int
bgp_show_callback (struct vty *vty, int unlock)
{
  struct route_node *rn;
  struct bgp_info *ri;
  int count;
  int limit;
  int display;

  rn = vty->output_rn;
  count = 0;
  limit = ((vty->lines == 0) 
	   ? 10 : (vty->lines > 0 
		   ? vty->lines : vty->height - 2));
  limit = limit > 0 ? limit : 2;

  /* Quit of display. */
  if (unlock && rn)
    {
      route_unlock_node (rn);
      if (vty->output_clean)
	(*vty->output_clean) (vty);
      vty->output_rn = NULL;
      vty->output_func = NULL;
      vty->output_clean = NULL;
      vty->output_arg = NULL;
      return 0;
    }

  for (; rn; rn = route_next (rn)) 
    if (rn->info != NULL)
      {
	display = 0;

	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (vty->output_type == bgp_show_type_regexp)
	      {
		regex_t *regex = vty->output_arg;

		if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_prefix_list)
	      {
		struct prefix_list *plist = vty->output_arg;
		
		if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_filter_list)
	      {
		struct as_list *as_list = vty->output_arg;

		if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_neighbor)
	      {
		union sockunion *su = vty->output_arg;

		if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_community_all)
	      {
		if (! ri->attr->community)
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_community)
	      {
		struct community *com = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_match (ri->attr->community, com))
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_community_exact)
	      {
		struct community *com = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_cmp (ri->attr->community, com))
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_community_list)
	      {
		struct community_list *list = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_list_match (ri->attr->community, list))
		  continue;
	      }
	    if (vty->output_type == bgp_show_type_community_list_exact)
	      {
		struct community_list *list = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_list_match_exact (ri->attr->community, list))
		  continue;
	      }
	    
	    if (rn->p.family == AF_INET)
	      {
		count += route_vty_out (vty, &rn->p, ri);
		display++;
	      }
#ifdef HAVE_IPV6
	    else if (rn->p.family == AF_INET6)
	      {
		count += route_vty_out_ipv6 (vty, &rn->p, ri);
		display++;
	      }
#endif /* HAVE_IPV6 */
	  }

	if (display)
	  vty->output_count++;

	/* Remember current pointer then suspend output. */
	if (count >= limit)
	  {
	    vty->status = VTY_CONTINUE;
	    vty->output_rn = route_next (rn);;
	    vty->output_func = bgp_show_callback;
	    return 0;
	  }
      }

  /* Total line display. */
  if (vty->output_count)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, vty->output_count, VTY_NEWLINE);

  if (vty->output_clean)
    (*vty->output_clean) (vty);

  vty->status = VTY_CONTINUE;
  vty->output_rn = NULL;
  vty->output_func = NULL;
  vty->output_clean = NULL;
  vty->output_arg = NULL;

  return 0;
}

int
bgp_show (struct vty *vty, char *view_name, afi_t afi, safi_t safi,
	  enum bgp_show_type type)
{
  struct bgp *bgp;
  struct bgp_info *ri;
  struct route_node *rn;
  struct route_table *table;
  int header = 1;
  int count;
  int limit;
  int display;

  limit = ((vty->lines == 0) 
	   ? 10 : (vty->lines > 0 
		   ? vty->lines : vty->height - 2));
  limit = limit > 0 ? limit : 2;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  count = 0;

  /* This is first entry point, so reset total line. */
  vty->output_count = 0;
  vty->output_type = type;

  table = bgp->rib[afi][safi];

  /* Start processing of routes. */
  for (rn = route_top (table); rn; rn = route_next (rn)) 
    if (rn->info != NULL)
      {
	display = 0;


	for (ri = rn->info; ri; ri = ri->next)
	  {
	    if (type == bgp_show_type_regexp)
	      {
		regex_t *regex = vty->output_arg;
		    
		if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
		  continue;
	      }
	    if (type == bgp_show_type_prefix_list)
	      {
		struct prefix_list *plist = vty->output_arg;
		    
		if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_filter_list)
	      {
		struct as_list *as_list = vty->output_arg;

		if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
		  continue;
	      }
	    if (type == bgp_show_type_neighbor)
	      {
		union sockunion *su = vty->output_arg;

		if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
		  continue;
	      }
	    if (type == bgp_show_type_community_all)
	      {
		if (! ri->attr->community)
		  continue;
	      }
	    if (type == bgp_show_type_community)
	      {
		struct community *com = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_match (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_exact)
	      {
		struct community *com = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_cmp (ri->attr->community, com))
		  continue;
	      }
	    if (type == bgp_show_type_community_list)
	      {
		struct community_list *list = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_list_match (ri->attr->community, list))
		  continue;
	      }
	    if (type == bgp_show_type_community_list_exact)
	      {
		struct community_list *list = vty->output_arg;

		if (! ri->attr->community ||
		    ! community_list_match_exact (ri->attr->community, list))
		  continue;
	      }
	    
	    if (header)
	      {
		vty_out (vty, "BGP table version is 0, local router ID is %s%s", inet_ntoa (bgp->id), VTY_NEWLINE);
		vty_out (vty, "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal%s", VTY_NEWLINE);
		vty_out (vty, "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s", VTY_NEWLINE, VTY_NEWLINE);
		if (afi == AFI_IP)
		  vty_out (vty, BGP_SHOW_V4_HEADER, VTY_NEWLINE);
		else if (afi == AFI_IP6)
		  vty_out (vty, BGP_SHOW_V6_HEADER, VTY_NEWLINE);
		count += 5;
		header = 0;
	      }

	    if (afi == AFI_IP)
	      {
		count += route_vty_out (vty, &rn->p, ri);
		display++;
	      }
#ifdef HAVE_IPV6
	    else if (afi == AFI_IP6)
	      {
		count += route_vty_out_ipv6 (vty, &rn->p, ri);
		display++;
	      }
#endif /* HAVE_IPV6 */

	  }
	if (display)
	  vty->output_count++;

	/* Remember current pointer then suspend output. */
	if (count >= limit  && vty->type != VTY_SHELL_SERV)
	  {
	    vty->status = VTY_START;
	    vty->output_rn = route_next (rn);
	    vty->output_func = bgp_show_callback;
	    vty->output_type = type;

	    return CMD_SUCCESS;
	  }
      }

  /* No route is displayed */
  if (vty->output_count == 0)
    {
      if (type == bgp_show_type_normal)
	vty_out (vty, "No BGP network exists%s", VTY_NEWLINE);
    }
  else
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, vty->output_count, VTY_NEWLINE);

  /* Clean up allocated resources. */
  if (vty->output_clean)
    (*vty->output_clean) (vty);

  vty->status = VTY_START;
  vty->output_rn = NULL;
  vty->output_func = NULL;
  vty->output_clean = NULL;
  vty->output_arg = NULL;

  return CMD_SUCCESS;
}

/* Display specified route of BGP table. */
int
bgp_show_route (struct vty *vty, char *view_name, char *ip_str,
		afi_t afi, safi_t safi, int prefix_check)
{
  int ret;
  int count = 0;
  int best = 0;
  int suppress = 0;
  int no_export = 0;
  int no_advertise = 0;
  int local_as = 0;
  char buf[INET6_ADDRSTRLEN];
  struct bgp *bgp;
  struct prefix match;
  struct prefix *p;
  struct route_node *rn;
  struct bgp_info *ri;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
	{
	  vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
	{
	  vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  /* Lookup route node. */
  rn = route_node_match (bgp->rib[afi][safi], &match);
  if (rn == NULL) 
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
 
  p = &rn->p; 
  if (prefix_check)
    {
      if (p->prefixlen != match.prefixlen)
        {
          vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Header of detailed BGP route information */  
  for (ri = rn->info; ri; ri = ri->next)
    {
      count++;
      if (ri->selected)
	{
	  best = count;
	  if (ri->suppress)
	    suppress = 1;
	  if (ri->attr->community != NULL)
	    {
	      if (community_include (ri->attr->community, COMMUNITY_NO_ADVERTISE))
		no_advertise = 1;
	      if (community_include (ri->attr->community, COMMUNITY_NO_EXPORT))
		no_export = 1;
	      if (community_include (ri->attr->community, COMMUNITY_LOCAL_AS))
		local_as = 1;
	    }
	}
    }
  vty_out (vty, "BGP routing table entry for %s/%d%s",
          inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN),
          p->prefixlen, VTY_NEWLINE); 
  
  vty_out (vty, "Paths: (%d available", count);
  if (best)
    {
      vty_out (vty, ", best #%d", best);
      vty_out (vty, ", table Default-IP-Routing-Table");
    }
  else
    vty_out (vty, ", no best path"); 
  if (no_advertise)
    vty_out (vty, ", not advertised to any peer");
  else if (no_export)
    vty_out (vty, ", not advertised to EBGP peer");
  else if (local_as)
    vty_out (vty, ", not advertised outside local AS");
  if (suppress)
    vty_out (vty, ", Advertisements suppressed by an aggregate.");
  vty_out (vty, ")%s", VTY_NEWLINE);

  /* Node is locked by route_node_match(). */
  for (ri = rn->info; ri; ri = ri->next)
    route_vty_out_detail (vty, &rn->p, ri);
    
  /* Work is done, so unlock the node. */
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal);
}

DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show ip bgp ipv4 (unicast|multicast)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST, bgp_show_type_normal);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal);
}

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (show_ip_bgp_ipv4_route,
       show_ip_bgp_ipv4_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, 0);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (show_ip_bgp_ipv4_prefix,
       show_ip_bgp_ipv4_prefix_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, 1);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (show_ip_bgp_view,
       show_ip_bgp_view_cmd,
       "show ip bgp view WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n")
{
  return bgp_show (vty, argv[0], AFI_IP, SAFI_UNICAST, bgp_show_type_normal);
}

DEFUN (show_ip_bgp_view_route,
       show_ip_bgp_view_route_cmd,
       "show ip bgp view WORD A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (show_ip_bgp_view_prefix,
       show_ip_bgp_view_prefix_cmd,
       "show ip bgp view WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, 1);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal);
}

DEFUN (show_ipv6_bgp_route,
       show_ipv6_bgp_route_cmd,
       "show ipv6 bgp X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (show_ipv6_bgp_prefix,
       show_ipv6_bgp_prefix_cmd,
       "show ipv6 bgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, 1);
}

DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp",
       SHOW_STR
       IP_STR
       MBGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal);
}

DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, 0);
}

DEFUN (show_ipv6_mbgp_prefix,
       show_ipv6_mbgp_prefix_cmd,
       "show ipv6 mbgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, 1);
}
#endif

void
bgp_show_regexp_clean (struct vty *vty)
{
  bgp_regex_free (vty->output_arg);
}

int
bgp_show_regexp (struct vty *vty, int argc, char **argv, u_int16_t afi,
		 u_char safi)
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;
  regex_t *regex;
  
  first = 0;
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
	buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty->output_arg = regex;
  vty->output_clean = bgp_show_regexp_clean;

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_regexp);
}

DEFUN (show_ip_bgp_regexp, 
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_regexp, 
       show_ip_bgp_ipv4_regexp_cmd,
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_MULTICAST);

  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_regexp, 
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ipv6_mbgp_regexp, 
       show_ipv6_mbgp_regexp_cmd,
       "show ipv6 mbgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

int
bgp_show_prefix_list (struct vty *vty, char *prefix_list_str, u_int16_t afi,
		      u_char safi)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (afi2family (afi), prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s", prefix_list_str, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  vty->output_arg = plist;

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_prefix_list);
}

DEFUN (show_ip_bgp_prefix_list, 
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_prefix_list, 
       show_ip_bgp_ipv4_prefix_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the prefix-list\n"
       "IP prefix-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_MULTICAST);

  return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_prefix_list, 
       show_ipv6_bgp_prefix_list_cmd,
       "show ipv6 bgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ipv6_mbgp_prefix_list, 
       show_ipv6_mbgp_prefix_list_cmd,
       "show ipv6 mbgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

int
bgp_show_filter_list (struct vty *vty, char *filter, u_int16_t afi,
		      u_char safi)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name%s", filter, VTY_NEWLINE);	    
      return CMD_WARNING;
    }

  vty->output_arg = as_list;

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_filter_list, 
       show_ip_bgp_filter_list_cmd,
       "show ip bgp filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_filter_list, 
       show_ip_bgp_ipv4_filter_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_MULTICAST);
  
  return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_filter_list, 
       show_ipv6_bgp_filter_list_cmd,
       "show ipv6 bgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ipv6_mbgp_filter_list, 
       show_ipv6_mbgp_filter_list_cmd,
       "show ipv6 mbgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
    return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		     bgp_show_type_community_all);
}

DEFUN (show_ip_bgp_ipv4_community_all,
       show_ip_bgp_ipv4_community_all_cmd,
       "show ip bgp ipv4 (unicast|multicast) community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
		     bgp_show_type_community_all);
 
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
		   bgp_show_type_community_all);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_community_all,
       show_ipv6_bgp_community_all_cmd,
       "show ipv6 bgp community",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
		   bgp_show_type_community_all);
}

DEFUN (show_ipv6_mbgp_community_all,
       show_ipv6_mbgp_community_all_cmd,
       "show ipv6 mbgp community",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST,
		   bgp_show_type_community_all);
}
#endif /* HAVE_IPV6 */

int
bgp_show_community (struct vty *vty, int argc, char **argv, int exact,
		                          u_int16_t afi, u_char safi)
{
  struct community *com;
  struct buffer *b;
  int i;
  char *str;
  int first = 0;

  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
	{
	  if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
	    continue;
	  first = 1;
	}
      
      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  com = community_str2com (str);
  free (str);
  if (! com)
    {
      vty_out (vty, "%% Community malformed: %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty->output_arg = com;

  if (exact)
    return bgp_show (vty, NULL, afi, safi, bgp_show_type_community_exact);

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_community);
}

DEFUN (show_ip_bgp_community,
       show_ip_bgp_community_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community3_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_community,
       show_ip_bgp_community4_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, argc, argv, 0, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community3_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community4_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_community_exact,
       show_ip_bgp_community_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community3_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community4_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community (vty, argc, argv, 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community (vty, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community3_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
       
ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community4_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_community,
       show_ipv6_bgp_community_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community3_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community4_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
DEFUN (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community3_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community4_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
       
DEFUN (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, argc, argv, 0, AFI_IP6, SAFI_MULTICAST);
}

ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community3_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community4_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
	
DEFUN (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, argc, argv, 1, AFI_IP6, SAFI_MULTICAST);
}

ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community3_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community4_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
#endif /* HAVE_IPV6 */

int
bgp_show_community_list (struct vty *vty, char *com, int exact,
			 u_int16_t afi, u_char safi)
{
  struct community_list *list;

  list = community_list_lookup (com);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com, VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty->output_arg = list;

  if (exact)
    return bgp_show (vty, NULL, afi, safi, bgp_show_type_community_list_exact);

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_community_list);
}

DEFUN (show_ip_bgp_community_list,
       show_ip_bgp_community_list_cmd,
       "show ip bgp community-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list,
       show_ip_bgp_ipv4_community_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_MULTICAST);
  
  return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_community_list_exact,
       show_ip_bgp_community_list_exact_cmd,
       "show ip bgp community-list WORD exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list WORD exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_MULTICAST);
 
  return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_UNICAST);
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp_community_list,
       show_ipv6_bgp_community_list_cmd,
       "show ipv6 bgp community-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ipv6_mbgp_community_list,
       show_ipv6_mbgp_community_list_cmd,
       "show ipv6 mbgp community-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_MULTICAST);
}

DEFUN (show_ipv6_bgp_community_list_exact,
       show_ipv6_bgp_community_list_exact_cmd,
       "show ipv6 bgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
}

DEFUN (show_ipv6_mbgp_community_list_exact,
       show_ipv6_mbgp_community_list_exact_cmd,
       "show ipv6 mbgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

void
show_adj_route (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
		int in)
{
  struct route_table *table;
  struct route_node *rn;
  struct prefix *p;
  struct attr *attr;
  unsigned long output_count;
  int header = 1;

  if (in)
    table = peer->adj_in[afi][safi];
  else
    table = peer->adj_out[afi][safi];

  output_count = 0;

  for (rn = route_top (table); rn; rn = route_next (rn))
    if ((attr = rn->info) != NULL)
      {
	p = &rn->p;

	if (header)
	  {
	    if (afi == AFI_IP)
	      vty_out (vty, BGP_SHOW_V4_HEADER, VTY_NEWLINE);
	    else if (afi == AFI_IP6)
	      vty_out (vty, BGP_SHOW_V6_HEADER, VTY_NEWLINE);
	    header = 0;
	  }

	if (p->family == AF_INET)
	  {
	    route_vty_out_tmp (vty, p, attr);
	    output_count++;
	  }
#ifdef HAVE_IPV6
	else if (p->family == AF_INET6)
	  {
	    route_vty_out_ipv6_tmp (vty, p, attr);
	    output_count++;
	  }
#endif /* HAVE_IPV6 */
      }
  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
	     VTY_NEWLINE, output_count, VTY_NEWLINE);
}

int
peer_adj_routes (struct vty *vty, char *ip_str, afi_t afi, safi_t safi, int in)
{
  int ret;
  struct peer *peer;
  union sockunion su;

  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return CMD_WARNING;
    }
  peer = peer_lookup_by_su (&su);
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (in && ! CHECK_FLAG (peer->flags, PEER_FLAG_SOFT_RECONFIG))
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  show_adj_route (vty, peer, afi, safi, in);

  return CMD_SUCCESS;
}

DEFUN (neighbor_advertised_route,
       neighbor_advertised_route_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP, SAFI_UNICAST, 0);
}

DEFUN (ipv4_neighbor_advertised_route,
       ipv4_neighbor_advertised_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, argv[1], AFI_IP, SAFI_MULTICAST, 0);

  return peer_adj_routes (vty, argv[1], AFI_IP, SAFI_UNICAST, 0);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_neighbor_advertised_route,
       ipv6_bgp_neighbor_advertised_route_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0);
}

DEFUN (ipv6_mbgp_neighbor_advertised_route,
       ipv6_mbgp_neighbor_advertised_route_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP6, SAFI_MULTICAST, 0);
}
#endif /* HAVE_IPV6 */

DEFUN (neighbor_received_routes,
       neighbor_received_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP, SAFI_UNICAST, 1);
}

DEFUN (ipv4_neighbor_received_routes,
       ipv4_neighbor_received_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, argv[1], AFI_IP, SAFI_MULTICAST, 1);

  return peer_adj_routes (vty, argv[1], AFI_IP, SAFI_UNICAST, 1);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_neighbor_received_routes,
       ipv6_bgp_neighbor_received_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP6, SAFI_UNICAST, 1);
}

DEFUN (ipv6_mbgp_neighbor_received_routes,
       ipv6_mbgp_neighbor_received_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  return peer_adj_routes (vty, argv[0], AFI_IP6, SAFI_MULTICAST, 1);
}
#endif /* HAVE_IPV6 */

void
bgp_show_neighbor_route_clean (struct vty *vty)
{
  union sockunion *su;

  su = vty->output_arg;
  XFREE (MTYPE_SOCKUNION, su);
}

int
bgp_show_neighbor_route (struct vty *vty, char *ip_str, u_int16_t afi,
		                          u_char safi)
{
  union sockunion *su;
  struct peer *peer;

  su = sockunion_str2su (ip_str);
  if (su == NULL)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
	       return CMD_WARNING;
    }

  peer = peer_lookup_by_su (su);
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      XFREE (MTYPE_SOCKUNION, su);
      return CMD_WARNING;
    }
 
  vty->output_arg = su;
  vty->output_clean = bgp_show_neighbor_route_clean;

  return bgp_show (vty, NULL, afi, safi, bgp_show_type_neighbor);
}

DEFUN (neighbor_routes,
       neighbor_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, argv[0], AFI_IP, SAFI_UNICAST);
}

DEFUN (ipv4_neighbor_routes,
       ipv4_neighbor_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_neighbor_route (vty, argv[1], AFI_IP, SAFI_MULTICAST);

  return bgp_show_neighbor_route (vty, argv[1], AFI_IP, SAFI_UNICAST);
}
#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_neighbor_routes,
       ipv6_bgp_neighbor_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (ipv6_mbgp_neighbor_routes,
       ipv6_mbgp_neighbor_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, argv[0], AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

struct route_table *bgp_distance_table;

struct bgp_distance
{
  /* Distance value for the IP source prefix. */
  u_char distance;

  /* Name of the access-list to be matched. */
  char *access_list;
};

struct bgp_distance *
bgp_distance_new ()
{
  struct bgp_distance *new;
  new = XMALLOC (MTYPE_BGP_DISTANCE, sizeof (struct bgp_distance));
  memset (new, 0, sizeof (struct bgp_distance));
  return new;
}

void
bgp_distance_free (struct bgp_distance *bdistance)
{
  XFREE (MTYPE_BGP_DISTANCE, bdistance);
}

int
bgp_distance_set (struct vty *vty, char *distance_str, char *ip_str,
		  char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct route_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get BGP distance node. */
  rn = route_node_get (bgp_distance_table, (struct prefix *) &p);
  if (rn->info)
    {
      bdistance = rn->info;
      route_unlock_node (rn);
    }
  else
    {
      bdistance = bgp_distance_new ();
      rn->info = bdistance;
    }

  /* Set distance value. */
  bdistance->distance = distance;

  /* Reset access-list configuration. */
  if (bdistance->access_list)
    {
      free (bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = strdup (access_list_str);

  return CMD_SUCCESS;
}

int
bgp_distance_unset (struct vty *vty, char *distance_str, char *ip_str,
		    char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct route_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  rn = route_node_lookup (bgp_distance_table, (struct prefix *)&p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bdistance = rn->info;

  if (bdistance->access_list)
    free (bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  route_unlock_node (rn);
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

void
bgp_distance_reset ()
{
  struct route_node *rn;
  struct bgp_distance *bdistance;

  for (rn = route_top (bgp_distance_table); rn; rn = route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
	if (bdistance->access_list)
	  free (bdistance->access_list);
	bgp_distance_free (bdistance);
	rn->info = NULL;
	route_unlock_node (rn);
      }
}

/* Apply BGP information to distance method. */
u_char
bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, struct bgp *bgp)
{
  struct route_node *rn;
  struct prefix_ipv4 q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  if (p->family != AF_INET)
    return 0;

  peer = rinfo->peer;

  if (peer->su.sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family = AF_INET;
  q.prefix = peer->su.sin.sin_addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  /* Check source address. */
  rn = route_node_match (bgp_distance_table, (struct prefix *) &q);
  if (rn)
    {
      bdistance = rn->info;
      route_unlock_node (rn);

      if (bdistance->access_list)
	{
	  alist = access_list_lookup (AF_INET, bdistance->access_list);
	  if (alist == NULL)
	    return 0;
	  if (access_list_apply (alist, p) == FILTER_DENY)
	    return 0;

	  return bdistance->distance;
	}
      else
	return bdistance->distance;
    }

  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      /* Backdoor check. */
      rn = route_node_lookup (bgp->route[AFI_IP], p);
      if (rn)
	{
	  bgp_static = rn->info;
	  route_unlock_node (rn);

	  if (bgp_static->backdoor)
	    {
	      if (bgp->distance_local)
		return bgp->distance_local;
	      else
		return ZEBRA_IBGP_DISTANCE_DEFAULT;
	    }
	}

      if (bgp->distance_ebgp)
	return bgp->distance_ebgp;
    }
  else
    {
      if (bgp->distance_ibgp)
	return bgp->distance_ibgp;
    }

  return 0;
}

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp <1-255> <1-255> <1-255>",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp = atoi (argv[0]);
  bgp->distance_ibgp = atoi (argv[1]);
  bgp->distance_local = atoi (argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp <1-255> <1-255> <1-255>",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp= 0;
  bgp->distance_ibgp = 0;
  bgp->distance_local = 0;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_distance,
       no_bgp_distance2_cmd,
       "no distance bgp",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance <1-255> A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance <1-255> A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance <1-255> A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance <1-255> A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  return bgp_damp_enable (vty, argc, argv);
}

ALIAS (bgp_damp_set,
       bgp_damp_set2_cmd,
       "bgp dampening <1-45>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n")

ALIAS (bgp_damp_set,
       bgp_damp_set3_cmd,
       "bgp dampening",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")
{
  return bgp_damp_disable (vty);
}

/* Configuration of static route announcement and aggregate
   information. */
int
bgp_config_write_network (struct vty *vty, struct bgp *bgp, afi_t afi)
{
  char *v6str;
  struct route_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  struct bgp_aggregate *bgp_aggregate;
  char buf[SU_ADDRSTRLEN];
  
  /* Address family check. */
  if (afi == AFI_IP)
    v6str = " ";
  else if (afi == AFI_IP6)
    v6str = " ipv6 bgp ";
  else
    return 0;

  /* Network configuration. */
  for (rn = route_top (bgp->route[afi]); rn; rn = route_next (rn)) 
    if ((bgp_static = rn->info) != NULL)
      {
	p = &rn->p;

	vty_out (vty, "%snetwork %s/%d", v6str,
		 inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN), 
		 p->prefixlen);

	if (bgp_static->safi == SAFI_MULTICAST)
	  vty_out (vty, " nlri multicast");
	if (bgp_static->safi == SAFI_UNICAST_MULTICAST)
	  vty_out (vty, " nlri unicast multicast");

	if (bgp_static->backdoor)
	  vty_out (vty, " backdoor");

	vty_out (vty, "%s", VTY_NEWLINE);
      }

  /* Aggregate-address configuration. */
  for (rn = route_top (bgp->aggregate[afi]); rn; rn = route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
	p = &rn->p;

	vty_out (vty, "%saggregate-address %s/%d", v6str,
		 inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
		 p->prefixlen);

	if (bgp_aggregate->summary_only)
	  vty_out (vty, " summary-only");
	
	vty_out (vty, "%s", VTY_NEWLINE);
      }

  return 0;
}

int
bgp_config_write_distance (struct vty *vty, struct bgp *bgp)
{
  struct route_node *rn;
  struct bgp_distance *bdistance;

  /* Distance configuration. */
  if (bgp->distance_ebgp
      && bgp->distance_ibgp
      && bgp->distance_local
      && (bgp->distance_ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT
	  || bgp->distance_ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT
	  || bgp->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT))
    vty_out (vty, " distance bgp %d %d %d%s",
	     bgp->distance_ebgp, bgp->distance_ibgp, bgp->distance_local,
	     VTY_NEWLINE);
  
  for (rn = route_top (bgp_distance_table); rn; rn = route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
	vty_out (vty, " distance %d %s/%d %s%s", bdistance->distance,
		 inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		 bdistance->access_list ? bdistance->access_list : "",
		 VTY_NEWLINE);
      }

  return 0;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init ()
{
  /* Make static announcement peer. */
  peer_self = peer_new ();
  peer_self->host = "Static announcement";

  /* Init BGP distance table. */
  bgp_distance_table = route_table_init ();

  /* IPv4 BGP commands. */
  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &bgp_network_multicast_cmd);
  install_element (BGP_NODE, &bgp_network_unicast_multicast_cmd);
  install_element (BGP_NODE, &bgp_network_backdoor_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_multicast_cmd);
  install_element (BGP_NODE, &no_bgp_network_unicast_multicast_cmd);
  install_element (BGP_NODE, &no_bgp_network_backdoor_cmd);

  install_element (BGP_NODE, &aggregate_address_cmd);
  install_element (BGP_NODE, &aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &no_aggregate_address_cmd);
  install_element (BGP_NODE, &no_aggregate_address_summary_only_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_route_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_filter_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_all_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_route_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_view_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_all_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd);

  install_element (VIEW_NODE, &neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &ipv4_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &ipv4_neighbor_advertised_route_cmd);

  install_element (VIEW_NODE, &neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &ipv4_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &ipv4_neighbor_received_routes_cmd);

  install_element (VIEW_NODE, &neighbor_routes_cmd);
  install_element (VIEW_NODE, &ipv4_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &neighbor_routes_cmd);
  install_element (ENABLE_NODE, &ipv4_neighbor_routes_cmd);

#ifdef HAVE_IPV6
  /* IPv6 BGP commands. */
  install_element (BGP_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &ipv6_bgp_network_multicast_cmd);
  install_element (BGP_NODE, &ipv6_bgp_network_unicast_multicast_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_network_multicast_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_network_unicast_multicast_cmd);

  install_element (BGP_NODE, &ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &ipv6_aggregate_address_summary_only_cmd);
  install_element (BGP_NODE, &no_ipv6_aggregate_address_cmd);
  install_element (BGP_NODE, &no_ipv6_aggregate_address_summary_only_cmd);

  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_community_list_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_filter_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_all_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community2_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community3_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community4_exact_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_exact_cmd);

  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_route_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_filter_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_all_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_exact_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_exact_cmd);

  install_element (VIEW_NODE, &ipv6_bgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_advertised_route_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd);

  install_element (VIEW_NODE, &ipv6_bgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_received_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_received_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_received_routes_cmd);

  install_element (VIEW_NODE, &ipv6_bgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_bgp_neighbor_routes_cmd);
  install_element (VIEW_NODE, &ipv6_mbgp_neighbor_routes_cmd);
  install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_routes_cmd);
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance_cmd);
  install_element (BGP_NODE, &no_bgp_distance2_cmd);
  install_element (BGP_NODE, &bgp_distance_source_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_cmd);
  install_element (BGP_NODE, &bgp_distance_source_access_list_cmd);
  install_element (BGP_NODE, &no_bgp_distance_source_access_list_cmd);

  install_element (BGP_NODE, &bgp_damp_set_cmd);
  install_element (BGP_NODE, &bgp_damp_set2_cmd);
  install_element (BGP_NODE, &bgp_damp_set3_cmd);
  install_element (BGP_NODE, &bgp_damp_unset_cmd);
}
