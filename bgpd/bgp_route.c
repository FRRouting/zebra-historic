/*
 * Route object related function for route server.
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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_filter.h"

/* For bgp_zebra.c */
void bgp_zebra_announce (struct prefix *p, struct bgp_info *info);
void bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info);

/* BGP Routing Information Base. */
struct route_table *bgp_table_ipv4;
struct route_table *bgp_static_ipv4;
struct route_table *bgp_aggregate_ipv4;

#ifdef HAVE_IPV6
struct route_table *bgp_table_ipv6;
struct route_table *bgp_static_ipv6;
struct route_table *bgp_aggregate_ipv6;
#endif /* HAVE_IPV6 */

/* Static annoucement peer. */
struct peer *peer_self;

/* BGP peer lists. */
extern list peer_list;

/* Macros which easy to access peer's filter. */
#define DISTRIBUTE_IN(P)    ((P)->distribute[BGP_FILTER_IN].list)
#define DISTRIBUTE_OUT(P)   ((P)->distribute[BGP_FILTER_OUT].list)
#define PREFIX_LIST_IN(P)   ((P)->plist[BGP_FILTER_IN].plist)
#define PREFIX_LIST_OUT(P)  ((P)->plist[BGP_FILTER_OUT].plist)
#define FILTER_LIST_IN(P)   ((P)->filter[BGP_FILTER_IN].filter)
#define FILTER_LIST_OUT(P)  ((P)->filter[BGP_FILTER_OUT].filter)
#define ROUTE_MAP_IN(P)     ((P)->route_map[BGP_FILTER_IN].map)
#define ROUTE_MAP_OUT(P)    ((P)->route_map[BGP_FILTER_OUT].map)

/* Extern from bgp_dump.c */
char *bgp_origin_long_str[] = {"IGP","EGP","Incomplete"};
extern char *bgp_origin_str[];

/* Allocate new bgp info structure. */
struct bgp_info *
bgp_info_new ()
{
  struct bgp_info *new;

  new = XMALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
  bzero (new, sizeof (struct bgp_info));

  return new;
}

/* Free bgp route information. */
void
bgp_info_free (struct bgp_info *br)
{
  if (br->attr)
    bgp_attr_free (br->attr);
  XFREE (MTYPE_BGP_ROUTE, br);
}

/* Compare two bgp route entity.  br is preferable then return 1. */
int
bgp_info_cmp (struct bgp_info *new, struct bgp_info *exist)
{
  if (new->type == ZEBRA_ROUTE_CONNECT)
    return 1;
  if (exist->type == ZEBRA_ROUTE_CONNECT)
    return 0;

  if (new->type == ZEBRA_ROUTE_STATIC)
    return 1;
  if (exist->type == ZEBRA_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_STATIC)
    return 1;
  if (exist->sub_type == BGP_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_AGGREGATE)
    return 1;
  if (exist->sub_type == BGP_ROUTE_AGGREGATE)
    return 0;

  /* Weight check. */
  if (new->attr->weight > exist->attr->weight)
    return 1;
  if (new->attr->weight < exist->attr->weight)
    return 0;

  /* Local preference check. */
  if ((new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)) &&
      (exist->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)))
  {
      if (new->attr->local_pref > exist->attr->local_pref)
	return 1;
      if (new->attr->local_pref < exist->attr->local_pref)
	return 0;
    }

  /* AS path length check. */
  if (new->attr->aspath->count < exist->attr->aspath->count)
    return 1;
  if (new->attr->aspath->count > exist->attr->aspath->count)
    return 0;

  /* Origin check. */
  if (new->attr->origin < exist->attr->origin)
    return 1;
  if (new->attr->origin > exist->attr->origin)
    return 0;

  /* MED check. */
  if ((new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)) &&
      (new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)))
    {
      if (new->attr->med < exist->attr->med)
	return 1;
      if (new->attr->med > exist->attr->med)
	return 0;
    }

  /* Peer type. */
  if (bgp_peer_sort (new->peer) == BGP_PEER_EBGP &&
      bgp_peer_sort (exist->peer) == BGP_PEER_IBGP)
    return 1;
  if (bgp_peer_sort (new->peer) == BGP_PEER_IBGP &&
      bgp_peer_sort (exist->peer) == BGP_PEER_EBGP)
    return 0;

  return 1;
}

/* Add bgp route infomation to routing table node. */
void
bgp_info_add (struct bgp_info **rp, struct bgp_info *br)
{
  struct bgp_info *cp;
  struct bgp_info *pp;
  struct bgp_info *selected;

  /* Preserve current selected bgp route. */
  selected = *rp;

  for (cp = pp = *rp; cp; cp = cp->next)
    {
      if (bgp_info_cmp (br, cp))
	break;
      pp = cp;
    }

  if (cp == pp)
    {
      *rp = br;

      if (cp)
	cp->prev = br;
      br->next = cp;
    }
  else
    {
      if (pp)
	pp->next = br;
      br->prev = pp;

      if (cp)
	cp->prev = br;
      br->next = cp;
    }

  if (selected == *rp)
    return;

  /* Make this route selected. */
  if (selected)
    selected->selected = 0;
  br->selected = 1;
}

/* Delete rib from rib list. */
void
bgp_info_delete (struct bgp_info **rp, struct bgp_info *rib)
{
  if (rib->next)
    rib->next->prev = rib->prev;
  if (rib->prev)
    rib->prev->next = rib->next;
  else
    *rp = rib->next;
}

enum filter_type
bgp_output_filter (struct peer *peer, struct prefix *p, struct bgp_info *info)
{
  /* Distribute list apply. */
  if (DISTRIBUTE_OUT (peer))
    if (access_list_apply (DISTRIBUTE_OUT (peer), p) == FILTER_DENY)
      return FILTER_DENY;

  /* Prefix list apply. */
  if (PREFIX_LIST_OUT (peer))
    if (prefix_list_apply (PREFIX_LIST_OUT (peer), p) == PREFIX_DENY)
      return FILTER_DENY;

  /* Filter list apply. */
  if (FILTER_LIST_OUT (peer))
    if (as_list_apply (FILTER_LIST_OUT(peer), 
		       info->attr->aspath) == AS_FILTER_DENY)
      return FILTER_DENY;

  return FILTER_PERMIT;
}

/* Utility function for looking up route node from prefix specific
   address family tree. */
static struct route_node *
nlri_node_get (struct prefix *p)
{
  if (p->family == AF_INET)
    return route_node_get (bgp_table_ipv4, p);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    return route_node_get (bgp_table_ipv6, p);
#endif /* HAVE_IPV6 */
  return NULL;
}

/* Aggreagete address:

  advertise-map  Set condition to advertise attribute
  as-set         Generate AS set path information
  attribute-map  Set attributes of aggregate
  route-map      Set parameters of aggregate
  summary-only   Filter more specific routes from updates
  suppress-map   Conditionally filter more specific routes from updates
  <cr>

 */

/* If community attribute includes no_export then return 1. */
int
bgp_community_filter (struct peer *peer, struct bgp_info *info)
{
  if (info->attr->community)
    {
      /* NO_ADVERTISE check. */
      if (community_include (info->attr->community, COMMUNITY_NO_ADVERTISE))
	return 1;

      /* NO_EXPORT check. */
      if (bgp_peer_sort (peer) == BGP_PEER_EBGP &&
	  community_include (info->attr->community, COMMUNITY_NO_EXPORT))
	return 1;
    }
  return 0;
}

/* Announce the prefix and information. */
void
bgp_announce (struct peer *peer, struct prefix *p, struct bgp_info *info)
{
  route_map_result_t ret;
  struct attr attr;
  struct bgp_info bgp_info;

  /* Aggregated and suppressed. */
  if (info->suppress_count)
    return;

  /* Community check. */
  if (peer->send_community)
    if (bgp_community_filter (peer, info))
      return;

  /* Apply output filter. */
  if (bgp_output_filter (peer, p, info) == FILTER_DENY)
    {
      /* I want logging at here. */
      return;
    }

  /* Default route check. */
  if (p->family == AF_INET &&
      p->u.prefix4.s_addr == INADDR_ANY &&
      ! (peer->config & PEER_DEFAULT_ORIGINATE))
    {
      /* Yes! I want logging at here. */
      return;
    }

  if (p->family == AF_INET6 &&
      (p->prefixlen == 0) &&
      ! (peer->config & PEER_DEFAULT_ORIGINATE))
    {
      zlog(peer->log, LOG_INFO,
          "suppress ipv6 default route announcement to %d",
          peer->as);
      return;
    }


  /* AS path loop check */
  if (aspath_loop_check (info->attr->aspath, peer->as))
    {
      zlog (peer->log, LOG_INFO, 
	    "suppress announcement due to peer %d is in aspath.",
	    peer->as);
      return;
    }

  /* IBGP reflection check. */
  if (bgp_peer_sort (peer) == BGP_PEER_IBGP &&
      bgp_peer_sort (info->peer) == BGP_PEER_IBGP)
    {
      /* A route from a Client peer. */
      if (info->peer->reflector_client)
	{
	  /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
	}
      else
	{
	  /* A route from a Non-client peer. Reflect to all other
	     clients. */
	  if (! peer->reflector_client)
	    return;
	}
    }

  /* For modify attribute, copy it to temporary structure. */
  attr = *info->attr;

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps */
  if (bgp_peer_sort (peer) == BGP_PEER_EBGP && 
      attr.flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    attr.flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));

  /* When route is static then set nexthop to self. */
  if (peer->nexthop_self ||
      bgp_peer_sort (peer) == BGP_PEER_EBGP ||
      info->type == ZEBRA_ROUTE_STATIC || 
      info->type == ZEBRA_ROUTE_CONNECT ||
      info->sub_type == BGP_ROUTE_STATIC || 
      info->sub_type == BGP_ROUTE_AGGREGATE)
    {
      memcpy (&attr.nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);

#ifdef HAVE_IPV6
      if (p->family == AF_INET6)
	{
	  memcpy (&attr.mp_nexthop_global, &peer->nexthop.v6_global, 
		  IPV6_MAX_BYTELEN);
	  if (attr.mp_nexthop_len < 16)
	    attr.mp_nexthop_len = 16;

	  if (peer->shared_network &&
	      !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	    {
	      memcpy (&attr.mp_nexthop_local, &peer->nexthop.v6_local, 
		      IPV6_MAX_BYTELEN);
	      if (attr.mp_nexthop_len < 32)
		attr.mp_nexthop_len = 32;
	    }
	  else
	    {
	      attr.mp_nexthop_len = 16;
	    }
	}
#endif /* HAVE_IPV6 */
    }
  else
    {
#ifdef HAVE_IPV6
      /* Link-local address should not be transit to different peer. */
      attr.mp_nexthop_len = 16;

      if (peer->shared_network &&
	  !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
	{
	  memcpy (&attr.mp_nexthop_local, &peer->nexthop.v6_local, 
		  IPV6_MAX_BYTELEN);
	  if (attr.mp_nexthop_len < 32)
	    attr.mp_nexthop_len = 32;
	}
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* If bgpd act as BGP-4+ route-reflector, does not send link-local
     addres.*/
  if (peer->reflector_client)
    attr.mp_nexthop_len = 16;
#endif /* HAVE_IPV6 */

  /* If local-preference is not set. */
  if ((bgp_peer_sort (peer) == BGP_PEER_IBGP) && 
      (! (attr.flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr.local_pref = DEFAULT_LOCAL_PREF;
    }

  /* Route map apply. */
  if (ROUTE_MAP_OUT (peer))
    {
      /* Route map may generates new attribute.  So we copy
         attribute to new one. */
      if (attr.aspath)
	attr.aspath = aspath_dup (attr.aspath);
      if (attr.community)
	attr.community = community_dup (attr.community);

      /* Make routemap object. */
      bgp_info.peer = peer;
      bgp_info.attr = &attr;
      
      /* Apply route map to duplicated attribute. */
      ret = route_map_apply (ROUTE_MAP_OUT (peer), p, ROUTE_MAP_BGP, 
			     &bgp_info);

      /* Send packet to the peer, only if it wasn't denied by the route-map. */
      if(ret != RM_DENYMATCH)
	bgp_update_send (peer, p, &attr);

      /* Free tempolary aspath. */
      if (attr.aspath)
	aspath_free (attr.aspath);
      if (attr.community)
	community_free (attr.community);
    }
  else
    bgp_update_send (peer, p, &attr);
}

/* Announce current routing table to the peer. */
void
bgp_announce_table (struct peer *peer)
{
  struct route_node *node;
  struct bgp_info *info;

  if (peer->family == AF_INET)
    for (node = route_top (bgp_table_ipv4); node; node = route_next (node))
      if ((info = node->info) != NULL)
	if (info->selected && info->peer != peer)
	  bgp_announce (peer, &node->p, info);

#ifdef HAVE_IPV6
  if (peer->family == AF_INET6)
    for (node = route_top (bgp_table_ipv6); node; node = route_next (node))
      if ((info = node->info) != NULL)
	if (info->selected && info->peer != peer)
	  bgp_announce (peer, &node->p, info);
#endif /* HAVE_IPV6 */
}

/* Delete all routes. */
void
bgp_terminate ()
{
  struct route_node *node;
  struct bgp_info *info;

  for (node = route_top (bgp_table_ipv4); node; node = route_next (node))
    if ((info = node->info) != NULL)
      if (info->selected && 
	  info->type == ZEBRA_ROUTE_BGP && 
	  info->sub_type == BGP_ROUTE_NORMAL)
	bgp_zebra_withdraw (&node->p, info);

#ifdef HAVE_IPV6
  for (node = route_top (bgp_table_ipv6); node; node = route_next (node))
    if ((info = node->info) != NULL)
      if (info->selected &&
	  info->type == ZEBRA_ROUTE_BGP &&
	  info->sub_type == BGP_ROUTE_NORMAL)
	bgp_zebra_withdraw (&node->p, info);
#endif /* HAVE_IPV6 */
}

void
bgp_reset ()
{
  vty_reset ();
  bgp_zclient_reset ();
  access_list_reset ();
  prefix_list_reset ();
}

/* Update routing information of each peer.  Yes we need attribute
   information here. */
void
nlri_update (struct prefix *p, struct bgp_info *info)
{
  listnode node;
  struct peer *peer;

  for (node = listhead (peer_list); node; nextnode (node))
    if ((peer = getdata (node)) != NULL)
      {
	if (peer != info->peer &&
	    peer->family == p->family &&
	    peer->status == Established)
	  bgp_announce (peer, p, info);
      }

  /* Kernel routing update. */
  if (info->type == ZEBRA_ROUTE_BGP && info->sub_type == BGP_ROUTE_NORMAL)
    bgp_zebra_announce (p, info);
}

void
nlri_withdraw (struct prefix *p, struct bgp_info *info)
{
  listnode node;
  struct peer *peer;

  for (node = listhead (peer_list); node; nextnode (node))
    if ((peer = getdata (node)) != NULL)
      if (peer != info->peer &&
	  peer->family == p->family &&
	  peer->status == Established)
	bgp_withdraw_send (peer, p);

  /* Kernel routing update. */
  if (info->type == ZEBRA_ROUTE_BGP && info->sub_type == BGP_ROUTE_NORMAL)
    bgp_zebra_withdraw (p, info);
}

/* Check is needed after route is withdrawed. */
void
nlri_reselect (struct prefix *p, struct bgp_info *info, struct bgp_info *del)
{
  /* Withdraw route. */
  if (info)
    {
      if (del->selected)
	{
	  info->selected = 1;
	  nlri_update (p, info);
	}
    }
  else
    nlri_withdraw (p, del);
}

void
bgp_aggregate_route (struct prefix *p, struct bgp_info *bgp_info)
{
  struct route_node *node = NULL;
  struct bgp_info *aggregate_info;

  if (bgp_info->sub_type == BGP_ROUTE_AGGREGATE)
    return;

  if (p->family == AF_INET)
    node = route_node_match (bgp_aggregate_ipv4, p);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    node = route_node_match (bgp_aggregate_ipv6, p);
#endif /* HAVE_IPV6 */

  if (! node)
    return;

  aggregate_info = node->info;

  aggregate_info->aggregate_count++;
  bgp_info->suppress_count++;
}

/* Process NLRI information. */
void
nlri_process (struct prefix *p, struct bgp_info *info)
{
  int repflag;
  struct route_node *node;
  struct bgp_info *replace;
  struct bgp_info *announced;
  struct bgp_info *updated;

  /* Replace flag. */
  repflag = 0;

  /* Lookup node. */
  node = nlri_node_get (p);
  if (!node)
    return;

  /* Remember currently announced route. */
  announced = (struct bgp_info *) node->info;
  if (! announced || ! announced->selected)
    announced = NULL;
    
  /* Check is this prefix is already announced from same peer. */
  for (replace = node->info; replace; replace = replace->next)
    if (replace->peer == info->peer)
      {
	bgp_info_delete ((struct bgp_info **) &node->info, replace);
	bgp_info_free (replace);
	route_unlock_node (node);
	repflag = 1;
	break;
      }

  /* If there is no replace route. */
  if (!replace)
    info->peer->prefix_count++;

  /* Aggregate check. */
  bgp_aggregate_route (p, info);

  /* Add route to the node. */
  bgp_info_add ((struct bgp_info **)&node->info, info);

  /* Announce to the remote peer. */
  updated = (struct bgp_info *) node->info;

  if (updated != announced)
    nlri_update (p, info);
}

/* Input BGP packet filter.  This function apply distribute-list and
   filter-list to the route. */
enum filter_type
bgp_input_filter (struct prefix *p, struct peer *peer, struct attr *attr)
{
  /* Distribute list apply. */
  if (DISTRIBUTE_IN (peer))
    if (access_list_apply (DISTRIBUTE_IN (peer), p) == FILTER_DENY)
      return FILTER_DENY;

  /* Prefix list apply. */
  if (PREFIX_LIST_IN (peer))
    if (prefix_list_apply (PREFIX_LIST_IN (peer), p) == PREFIX_DENY)
      return FILTER_DENY;
  
  /* Filter list apply. */
  if (FILTER_LIST_IN (peer))
    if (as_list_apply (FILTER_LIST_IN (peer), attr->aspath) == FILTER_DENY)
      return FILTER_DENY;

  /* Route reflection loop check. */
  if (bgp_peer_sort (peer) == BGP_PEER_IBGP && attr->cluster)
    {
      struct in_addr originator;

      /* Cluster list check. */
      if (peer->bgp->config & BGP_CONFIG_CLUSTER_ID)
	originator.s_addr = peer->bgp->cluster;
      else
	originator.s_addr = peer->bgp->ident;

      if (cluster_loop_check (attr->cluster, originator))
	return FILTER_DENY;
    }

  return FILTER_PERMIT;
}

/* Apply filters and return interned struct attr. */
struct attr *
bgp_input_modifier (struct prefix *p, struct peer *peer, struct attr *attr)
{
  route_map_result_t ret;
  struct attr newattr;
  struct bgp_info bgp_info;
  struct aspath *aspath;

  /* Apply default weight value. */
  if (peer->config & PEER_CONFIG_WEIGHT)
    attr->weight = peer->weight;

  /* Route map apply. */
  if (ROUTE_MAP_IN (peer))
    {
      newattr = *attr;

      /* Duplicate AS path and community for modification. */
      if (attr->aspath)
	newattr.aspath = aspath_dup (attr->aspath);

      if (attr->community)
	newattr.community = community_dup (attr->community);
      
      /* Make routemap object. */
      bgp_info.peer = peer;
      bgp_info.attr = &newattr;

      /* Apply route map to duplicated attribute. */
      ret = route_map_apply (ROUTE_MAP_IN (peer), p, ROUTE_MAP_BGP, &bgp_info);

      if (ret == RM_DENYMATCH)
	{
	  aspath_free(newattr.aspath);

	  if (newattr.community)
	    community_free (newattr.community);

	  return NULL;
	}

      /* To intern new attribute it's important to aspath points out
         real interned aspath structure. */
      aspath = aspath_parse (newattr.aspath->data, 
			     newattr.aspath->length);
      aspath_free (newattr.aspath);
      newattr.aspath = aspath;

      /* The same thing about community attribute. */
      if (newattr.community)
	{
	  struct community *com;

	  com = community_parse ((char *) newattr.community->val,
				 newattr.community->size * 4);
	  community_free (newattr.community);
	  newattr.community = com;
	}

      return bgp_attr_intern (&newattr);
    }

  /* After all intern attribute and return it. */
  return bgp_attr_intern (attr);
}

/* Parse route and add route into radix tree. */
void
nlri_parse (struct peer *peer, struct attr *attr, u_char *pnt, int len, 
	    int family)
{
  int psize;
  struct prefix p;
  u_char *end;
  struct attr *attrnew;
  char attrstr[BUFSIZ];
  struct bgp_info *br;
  char buf[BUFSIZ];

  /* When protocol is BGP-4+ NLRI length may be zero. */
  if (!len) 
    return;

  /* Check peer's family type. */
  if (family != peer->family)
    return;

  for (end = pnt + len; pnt < end; pnt += psize)
    {
      /* Fetch one prefix from NLRI. */
      bzero (&p, sizeof p);
      p.family = family;
      p.prefixlen = *pnt++;

      /* Check prefix length of incoming route. */
      if ((family == AF_INET && p.prefixlen > IPV4_MAX_BITLEN) ||
	  (family == AF_INET6 && p.prefixlen > IPV6_MAX_BITLEN))
	{
	  zlog (peer->log, LOG_ERR, "Wrong prefix length %s/%d len %d",
		inet_ntop (family, &p.u.prefix, buf, BUFSIZ),
		p.prefixlen, len);
	  return;
	}

      /* Fetch prefix length. */
      psize = PSIZE (p.prefixlen);

      if (pnt + psize > end)
	{
	  zlog (peer->log, LOG_ERR, 
		"Wrong prefix length. It exceeds end of packet %d",
		p.prefixlen);
	  return;
	}

      /* Copy prefix from nlri. */
      memcpy (&p.u.prefix, pnt, psize);

      /* Incoming packet filter. */
      if (bgp_input_filter (&p, peer, attr) == FILTER_DENY)
	{
	  zlog (peer->log, LOG_INFO, "Update:[%s] %s/%d is filtered",
		peer->host, inet_ntop(family, &p.u.prefix, buf, BUFSIZ),
		p.prefixlen);
	  continue;
	}

      /* Incoming packet modifier by route-maps. */
      attrnew = bgp_input_modifier (&p, peer, attr);
      if (attrnew == NULL)
	continue;

      /* Make attribute dump string. */
      bgp_dump_attr (peer, attrnew, attrstr, BUFSIZ);

      /* Logging. */
      zlog (peer->log, LOG_INFO, "Update:[%s] %s/%d %s",
	    peer->host, inet_ntop(family, &p.u.prefix, buf, BUFSIZ),
	    p.prefixlen, attrstr);

      br = bgp_info_new ();
      br->type = ZEBRA_ROUTE_BGP;
      br->sub_type = BGP_ROUTE_NORMAL;
      br->peer = peer;
      br->attr = attrnew;
      br->uptime = time (NULL);

      /* Process this information. */
      nlri_process (&p, br);
    }
  return;
}

int
nlri_delete (struct peer *peer, struct prefix *p)
{
  struct route_node *node;
  struct bgp_info *del;
  char buf[BUFSIZ];

  /* First look up routing table node. */
  node = nlri_node_get (p);
  if (!node)
    return 0;

  for (del = node->info; del; del = del->next)
    if (del->peer == peer)
      break;

  /* Withdraw route from route list. */
  if (del == NULL)
    {
      zlog (peer->log, LOG_INFO, "Withdraw:[%s] %s/%d (does not exist)",
	    peer->host, inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
	    (int) p->prefixlen);
      route_unlock_node (node);
      return 0;
    }

  zlog (peer->log, LOG_INFO, "Withdraw:[%s] %s/%d (exist)",
	peer->host, inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
	(int) p->prefixlen);

  bgp_info_delete ((struct bgp_info **) &node->info, del);

  /* Reselect route. */
  nlri_reselect (&node->p, (struct bgp_info *)node->info, del);

  bgp_info_free (del);

  peer->prefix_count--;

  route_unlock_node (node);

  route_unlock_node (node);

  return 1;
}

/* Withdraw handling routine */
void
nlri_unfeasible (struct peer *peer, bgp_size_t unfeasible_len)
{
  u_char *pnt;
  u_char *endp;
  int psize;
  struct prefix p;

  /* Set data start pointer. */
  pnt = stream_pnt (peer->ibuf);
  endp = pnt + unfeasible_len;
  
  while (pnt < endp)
    {
      bzero (&p, sizeof p);
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      psize = PSIZE (p.prefixlen);
      memcpy (&p.u.prefix4, pnt, psize);

      if (peer->family == AF_INET)
	nlri_delete (peer, &p);

      pnt += psize;
    }

  stream_forward (peer->ibuf, unfeasible_len);
}

void
bgp_aggregate_update (struct prefix *p, struct bgp_info *aggregate_info)
{
  struct route_node *aggregate;
  struct route_node *node;
  struct bgp_info *info;

  /* First of all get routing table node. */
  aggregate = nlri_node_get (p);
  /* aggregate->info = aggregate_info; */

  /* We assume summary-only behavior. */
  for (node = route_lock_node (aggregate); node; 
       node = route_next_until (node, aggregate))
    for (info = node->info; info; info = info->next)
      {
	if (info->selected && info->suppress_count == 0)
	  {
	    /* Withdraw the route. */
	    nlri_withdraw (&node->p, info);
	    /* info->selected = 0; */
	  }
	info->suppress_count++;
	aggregate_info->aggregate_count++;
      }

  /* if (aggregate_info->aggregate_count) */
  nlri_process (p, aggregate_info);
}
  
/* Delete peer's all route. */
void
bgp_peer_delete (struct peer *peer)
{
  struct route_node *np;
  struct bgp_info *br;
  struct bgp_info *next;

  for (np = route_top (bgp_table_ipv4); np; np = route_next (np))
    {
      for (br = np->info; br; br = next)
	{
	  /* Preserve next pointer. */
	  next = br->next;
	  if (br->peer == peer)
	    {
	      bgp_info_delete ((struct bgp_info **) &np->info, br);

	      /* If withdraw or new announcement needed. */
	      nlri_reselect (&np->p, (struct bgp_info *)np->info, br);

	      bgp_info_free (br);
	      route_unlock_node (np);
	    }
	}
    }

#ifdef HAVE_IPV6
  for (np = route_top (bgp_table_ipv6); np; np = route_next (np))
    for (br = np->info; br; br = next)
      {
	/* Preserve next pointer. */
	next = br->next;
	if (br->peer == peer)
	  {
	    bgp_info_delete ((struct bgp_info **) &np->info, br);

	    /* If withdraw or new announcement needed. */
	    nlri_reselect (&np->p, (struct bgp_info *)np->info, br);

	    bgp_info_free (br);
	    route_unlock_node (np);
	  }
      }
#endif /* HAVE_IPV6 */

  peer->prefix_count = 0;
}

/* Withdraw specified route type's route. */
void
bgp_redistribute_withdraw (struct bgp *bgp, int family, int route_type)
{
  struct route_node *rp;
  struct bgp_info *binfo;
  struct bgp_info *next;

  if (family == ZEBRA_FAMILY_IPV4)
    for (rp = route_top (bgp_table_ipv4); rp; rp = route_next (rp))
      {
	for (binfo = rp->info; binfo; binfo = next)
	  {
	    next = binfo->next;

	    if (binfo->type == route_type)
	      {
		bgp_info_delete ((struct bgp_info **) &rp->info, binfo);
		nlri_reselect (&rp->p, (struct bgp_info *)rp->info, binfo);
		bgp_info_free (binfo);
		route_unlock_node (rp);
	      }
	  }
      }

#ifdef HAVE_IPV6
  if (family == ZEBRA_FAMILY_IPV6)
    for (rp = route_top (bgp_table_ipv6); rp; rp = route_next (rp))
      for (binfo = rp->info; binfo; binfo = next)
	{
	  next = binfo->next;

	  if (binfo->type == route_type)
	    {
	      bgp_info_delete ((struct bgp_info **) &rp->info, binfo);
	      nlri_reselect (&rp->p, (struct bgp_info *)rp->info, binfo);
	      bgp_info_free (binfo);
	      route_unlock_node (rp);
	    }
	}
#endif /* HAVE_IPV6 */
}

void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  char buf[BUFSIZ];

  len = vty_out (vty, "%s/%d", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen);
  len = 20 - len;
  if (len < 0)
    len = 0;
  vty_out (vty, "%*s", len, " ");
}

/* called from terminal list command */
void
route_vty_out (struct vty *vty, struct prefix *p, struct bgp_info *binfo)
{
  struct attr *attr;

  /* Selected tag display. */
  vty_out (vty, "%s%s ", binfo->selected ? "*" : " ", binfo->suppress_count ? "s" : " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  attr = binfo->attr;
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
	vty_out (vty, "%10lu", attr->med);
      else
	vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
	vty_out (vty, "%10lu", attr->local_pref);
      else
	vty_out (vty, "          ");

      vty_out (vty, "%10lu ",attr->weight);
    
    /* Print aspath */
    if (attr->aspath)
      aspath_print_vty (vty, attr->aspath);

    /* Print origin */
    vty_out (vty, " %s", bgp_origin_str[attr->origin]);
  }

  vty_out (vty, "%s", VTY_NEWLINE);
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
void
route_vty_out_ipv6 (struct vty *vty, struct prefix *p, struct bgp_info *binfo)
{
  struct attr *attr;

  /* Selected tag display. */
  vty_out (vty, "%s%s ", binfo->selected ? "*" : " ", 
	   binfo->suppress_count ? "s" : " ");

  /* print prefix and mask */
  route_vty_out_route_ipv6 (p, vty);

  /* Print attribute */
  attr = binfo->attr;

  /* Local-pref */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    vty_out (vty, "%6lu", attr->local_pref);
  else
    vty_out (vty, "      ");

  /* Weight */
  vty_out (vty, "%6lu ",attr->weight);
    
  /* Print aspath */
  if (attr->aspath)
    aspath_print_vty (vty, attr->aspath);

  /* Print origin */
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
  struct attr *attr;

  /* Header of detailed BGP route information. */
  vty_out (vty, "%s%s/%d%s",
	   binfo->selected ? "*" : " ",
	   inet_ntop (p->family, &p->u.prefix, buf, INET6_ADDRSTRLEN),
	   p->prefixlen,
	   VTY_NEWLINE);

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      /* Print aspath */
      if (attr->aspath)
	{
	  vty_out (vty, "\tASPath: ");
	  aspath_print_vty (vty, attr->aspath);
	}

      /* show nex hop */
      if (attr)
	{
	  vty_out (vty, "(%s)%s", bgp_origin_long_str[attr->origin],
		   VTY_NEWLINE);
	  vty_out (vty, "\tNexthop: %s%s", inet_ntoa(attr->nexthop),
		   VTY_NEWLINE);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
	    vty_out (vty, "\tMED: %lu%s", attr->med,
		     VTY_NEWLINE);

	  vty_out (vty, "\tWeight: %lu%s", attr->weight,
		   VTY_NEWLINE);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
	    vty_out (vty, "\tLocalpref: %lu%s", attr->local_pref,
		     VTY_NEWLINE);
	  
	  if (attr->community)
	    {
	      vty_out (vty, "\tCommunity:");
	      community_print_vty (vty, attr->community);
	      vty_out (vty, "%s", VTY_NEWLINE);
	    }
	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
	    vty_out (vty, "\tAtomic Aggregate%s", VTY_NEWLINE);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))
	    vty_out (vty, "\tAggregator AS %d [%s]%s", attr->aggregator_as,
		     inet_ntoa(attr->aggregator_addr),
		     VTY_NEWLINE);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	    vty_out (vty, "\tOriginator ID: %s%s",
		     inet_ntoa (attr->originator_id),
		     VTY_NEWLINE);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
	    {
	      int i;
	      vty_out (vty, "\tCluster List: ");
	      for (i = 0; i < attr->cluster->length / 4; i++)
		vty_out (vty, "%s ", inet_ntoa (attr->cluster->list[i]));
	      vty_out (vty, "%s", VTY_NEWLINE);
	    }
#ifdef HAVE_IPV6
	  if (attr->mp_nexthop_len == 16)
	    {
	      vty_out (vty, "\tIPv6 nexthop global: ");
	      vty_out (vty, "%s%s",
		       inet_ntop (AF_INET6, &attr->mp_nexthop_global,
				  buf, INET6_ADDRSTRLEN),
		                  VTY_NEWLINE);
	    }
	  else if (attr->mp_nexthop_len == 32)
	    {
	      vty_out (vty, "\tIPv6 nexthop global: ");
	      vty_out (vty, "%s%s",
		       inet_ntop (AF_INET6, &attr->mp_nexthop_global,
				  buf, INET6_ADDRSTRLEN),
		                  VTY_NEWLINE);
	      vty_out (vty, "\tIPv6 nexthop local: ");
	      vty_out (vty, "%s%s",
		       inet_ntop (AF_INET6, &attr->mp_nexthop_local,
				  buf, INET6_ADDRSTRLEN),
		                  VTY_NEWLINE);
	    }
#endif /* HAVE_IPV6 */

	  /* Uptime display. */
	  vty_out (vty, "\tLast update: %s", ctime (&binfo->uptime));
	}
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}  

/* BGP route print out function. */
DEFUN (show_ip_bgp, show_ip_bgp_cmd,
       "show ip bgp [IPV4_ADDR]",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP address\n")
{
  int ret;
  struct route_node *node;
  struct bgp_info *route;
  struct prefix_ipv4 match;

  route = NULL;

  /* `show ip bgp' command shows all of bgp routes. */
  if (argc == 0)
    {
      int count;

      /* Header print out. */
      vty_out (vty, "   Network             Next Hop            Metric    LocPrf    Weight Path%s", VTY_NEWLINE);

      /* We try to set counter to ten. */
      count = 10;

      /* Start processing of routes. */
      for (node = route_top (bgp_table_ipv4); node; node = route_next (node)) 
	for (route = node->info; route; route = route->next)
	  {
	    route_vty_out (vty, &node->p, route);

	    /* Decrement counter. */
	    count--;
	    if (count == 0)
	      {
		/* We need to preserve function pointer and process
                   pointer. */
		/* vty->; */
	      }
	  }

      return CMD_SUCCESS;
    }

  /* `show ip bgp IPV4_ADDR command shows specified route's
     information. */
  ret = inet_aton (argv[0], &match.prefix);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  match.family = AF_INET;
  match.prefixlen = IPV4_MAX_BITLEN;
  
  /* Lookup route node. */
  node = route_node_match (bgp_table_ipv4, (struct prefix *) &match);

  if (node == NULL) 
    {
      vty_out (vty, "can't find route%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Node is locked by route_node_lookup. */
  for (route = node->info; route; route = route->next)
    route_vty_out_detail (vty, &node->p, route);

  /* Work is done, so unlock the node. */
  route_unlock_node (node);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_regexp, 
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .REGEXP",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show regular expression matched bgp routes\n"
       "AS path regular expression\n")
{
  int i;
  int ret;
  struct buffer *b;
  char *regstr;
  int first;
  struct route_node *node;
  struct bgp_info *route;
  regex_t *regex;
  
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

  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      vty_out (vty, "can't compile regexp %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = route_top (bgp_table_ipv4); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      {
	ret = bgp_regexec (regex, route->attr->aspath);
	if (ret != REG_NOMATCH)
	  route_vty_out (vty, &node->p, route);
      }
  bgp_regex_free (regex);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_prefix_list, 
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list PLIST_NAME",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show prefix-list matched bgp routes\n"
       "Prefix-list name\n")
{
  int ret;
  struct prefix_list *plist;
  struct route_node *node;
  struct bgp_info *route;

  plist = prefix_list_lookup (AF_INET, argv[0]);
  if (plist == NULL)
    {
      vty_out (vty, "Can't find prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = route_top (bgp_table_ipv4); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      {
	ret = prefix_list_apply (plist, &node->p);
	if (ret == PREFIX_PERMIT)
	  route_vty_out (vty, &node->p, route);
      }

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp [IPV6ADDRESS]",
       SHOW_STR
       IP_STR
       "Show bgpd's own routing information of IPv6\n")
{
  int ret;
  struct route_node *node;
  struct bgp_info *route;
  struct prefix_ipv6 match;

  if (argc == 0)
    {
      vty_out (vty, "%s   Network                                LocPrf Weight Path%s", VTY_NEWLINE,
	       VTY_NEWLINE);

      /* Start processing of routes. */
      for (node = route_top (bgp_table_ipv6); node; node = route_next (node)) 
	for (route = node->info; route; route = route->next)
	  route_vty_out_ipv6 (vty, &node->p, route);
      return CMD_SUCCESS;
    }

  ret = str2prefix_ipv6 (argv[0], &match);
  if (! ret)
    {
      vty_out (vty, "address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  match.prefixlen = IPV6_MAX_BITLEN;

  /* Lookup route node. */
  node = route_node_match (bgp_table_ipv6, (struct prefix *) &match);

  if (node == NULL) 
    {
      vty_out (vty, "can't find route%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Node is locked by route_node_lookup. */
  for (route = node->info; route; route = route->next)
    route_vty_out_detail (vty, &node->p, route);

  /* Work is done, so unlock the node. */
  route_unlock_node (node);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_bgp_regexp, 
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .REGEXP",
       SHOW_STR
       IP_STR
       BGP_STR
       "Show regular expression matched bgp routes\n"
       "AS path regular expression\n")
{
  int i;
  int ret;
  struct buffer *b;
  char *regstr;
  int first;
  struct route_node *node;
  struct bgp_info *route;
  regex_t *regex;
  
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

  regex = bgp_regcomp (regstr);
  if (! regex)
    {
      vty_out (vty, "can't compile regexp %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = route_top (bgp_table_ipv6); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      {
	ret = bgp_regexec (regex, route->attr->aspath);
	if (ret != REG_NOMATCH)
	  route_vty_out (vty, &node->p, route);
      }
  bgp_regex_free (regex);

  return CMD_SUCCESS;
}
#endif

/* Configure static BGP network. */
DEFUN (bgp_network,
       bgp_network_cmd,
       "network PREFIX",
       "Announce network setup\n"
       "Static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  node = route_node_get (bgp_static_ipv4, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.%s", VTY_NEWLINE);
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_BGP;
  bgp_info->sub_type = BGP_ROUTE_STATIC;
  bgp_info->peer = peer_self;
  bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_IGP);
  bgp_info->uptime = time (NULL);
  node->info = bgp_info;

  nlri_process (&p, bgp_info);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network PREFIX",
       NO_STR
       "Announce network setup\n"
       "Delete static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct route_node *np;
  struct prefix_ipv4 p;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask_ipv4 (&p);

  np = route_node_get (bgp_static_ipv4, (struct prefix *) &p);
  if (!np->info)
    {
      vty_out (vty, "Can't find specified static route configuration.%s", VTY_NEWLINE);
      route_unlock_node (np);
      return CMD_WARNING;
    }

  nlri_delete (peer_self, (struct prefix *) &p);

  /* bgp_attr_free (np->info); */
  np->info = NULL;

  route_unlock_node (np);
  route_unlock_node (np);

  return CMD_SUCCESS;
}

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address PREFIX summary-only",
       "Aggreagete network\n"
       "Network\n"
       "Mask\n")
{
  int ret;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  ret = str2prefix (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Prefix is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* IPv4 aggregate address support. */
  if (p.family == AF_INET)
    {
      apply_mask (&p);

      node = route_node_get (bgp_aggregate_ipv4, &p);
      if (node->info)
	{
	  vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
	  route_unlock_node (node);
	  return CMD_WARNING;
	}
      bgp_info = bgp_info_new ();
      bgp_info->type = ZEBRA_ROUTE_BGP;
      bgp_info->sub_type = BGP_ROUTE_AGGREGATE;
      bgp_info->peer = peer_self;
      bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);
      bgp_info->uptime = time (NULL);

      node->info = bgp_info;

      /* Aggregate address insert into BGP routing table. */
      bgp_aggregate_update (&p, bgp_info);

      return CMD_SUCCESS;
    }

  /* IPv6 aggregate addess support. */
  vty_out (vty, "Sorry not yet supported.%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Configure static BGP network. */
DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "ipv6 bgp network PREFIX",
       IPV6_STR
       BGP_STR
       "Announce network setup\n"
       "Static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct prefix_ipv6 p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify valid address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask_ipv6 (&p);
  
  node = route_node_get (bgp_static_ipv6, (struct prefix *)&p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.%s", VTY_NEWLINE);
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_BGP;
  bgp_info->sub_type = BGP_ROUTE_STATIC;
  bgp_info->peer = peer_self;
  bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_IGP);
  bgp_info->uptime = time (NULL);
  node->info = bgp_info;

  nlri_process ((struct prefix *) &p, bgp_info);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no ipv6 bgp network PREFIX",
       NO_STR
       IPV6_STR
       BGP_STR
       "Announce network setup\n"
       "Delete static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct route_node *node;
  struct prefix_ipv6 p;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv6 (argv[0], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify valid address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask_ipv6 (&p);
  
  node = route_node_get (bgp_static_ipv6, (struct prefix *)&p);
  if (! node->info)
    {
      vty_out (vty, "Can't find specified static route configuration.%s",
	       VTY_NEWLINE);
      route_unlock_node (node);
      return CMD_WARNING;
    }

  nlri_delete (peer_self, (struct prefix *) &p);

  node->info = NULL;

  route_unlock_node (node);
  route_unlock_node (node);

  return CMD_SUCCESS;
}

DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address PREFIX summary-only",
       "Aggregate network\n"
       "Network\n"
       "Mask\n")
{
  int ret;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  ret = str2prefix (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Prefix is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* IPv4 aggregate address support. */
  if (p.family == AF_INET6)
    {
      apply_mask (&p);

      node = route_node_get (bgp_aggregate_ipv6, &p);
      if (node->info)
	{
	  vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
	  route_unlock_node (node);
	  return CMD_WARNING;
	}
      bgp_info = bgp_info_new ();
      bgp_info->type = ZEBRA_ROUTE_BGP;
      bgp_info->sub_type = BGP_ROUTE_AGGREGATE;
      bgp_info->peer = peer_self;
      bgp_info->attr = bgp_attr_make_default (BGP_ORIGIN_INCOMPLETE);
      bgp_info->uptime = time (NULL);

      node->info = bgp_info;

      /* Aggregate address insert into BGP routing table. */
      bgp_aggregate_update (&p, bgp_info);

      return CMD_SUCCESS;
    }

  vty_out (vty, "Sorry, wrong address family.%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

#endif /* HAVE_IPV6 */

/* Configuration of static route announcement and aggregate
   information. */
int
config_write_network (struct vty *vty, struct bgp *bgp, int family)
{
  struct route_node *rn;
  struct bgp_route *route;
  char buf[BUFSIZ];
  
  if (family == AF_INET)
    {
      for (rn = route_top (bgp_static_ipv4); rn; rn = route_next (rn)) 
	if ((route = rn->info) != NULL)
	  vty_out (vty, " network %s/%d%s", 
		   inet_ntop (AF_INET, &rn->p.u.prefix4, buf, BUFSIZ), 
		   rn->p.prefixlen,
		   VTY_NEWLINE);
      for (rn = route_top (bgp_aggregate_ipv4); rn; rn = route_next (rn))
	if ((route = rn->info) != NULL)
	  vty_out (vty, " aggregate-address %s/%d summary-only%s",
		   inet_ntop (AF_INET, &rn->p.u.prefix4, buf, BUFSIZ),
		   rn->p.prefixlen,
		   VTY_NEWLINE);
    }

#ifdef HAVE_IPV6
  if (family == AF_INET6)
    {
      for (rn = route_top (bgp_static_ipv6); rn; rn = route_next (rn)) 
	if ((route = rn->info) != NULL)
	  vty_out (vty, "ipv6 bgp network %s/%d%s", 
		   inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
		   rn->p.prefixlen,
		   VTY_NEWLINE);
      for (rn = route_top (bgp_aggregate_ipv6); rn; rn = route_next (rn))
	if ((route = rn->info) != NULL)
	  vty_out (vty, "ipv6 bgp aggregate-address %s/%d summary-only%s",
		   inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ),
		   rn->p.prefixlen,
		   VTY_NEWLINE);
    }
#endif /* HAVE_IPV6 */  
  return 0;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init ()
{
  /* Make static announcement peer. */
  peer_self = peer_new ();
  peer_self->host = "Static announcement";

  /* IPv4 related table and commands. */
  bgp_table_ipv4 = route_table_init ();
  bgp_static_ipv4 = route_table_init ();
  bgp_aggregate_ipv4 = route_table_init ();

  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_prefix_list_cmd);

  install_element (ENABLE_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_prefix_list_cmd);

  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &aggregate_address_cmd);

#ifdef HAVE_IPV6
  /* IPv6 related table and commands. */
  bgp_table_ipv6 = route_table_init ();
  bgp_static_ipv6 = route_table_init ();
  bgp_aggregate_ipv6 = route_table_init ();

  install_element (BGP_NODE, &ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_network_cmd);
  install_element (BGP_NODE, &ipv6_aggregate_address_cmd);

  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_regexp_cmd);
#endif /* HAVE_IPV6 */
}
