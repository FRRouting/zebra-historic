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
#include "zebra/zebra.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_packet.h"

/* For bgp_zebra.c */
void bgp_zebra_announce (struct prefix *p, struct bgp_info *info);
void bgp_zebra_withdraw (struct prefix *p, struct bgp_info *info);

/* BGP Routing Information Base. */
struct route_table *bgp_table_ipv4;
struct route_table *bgp_static_ipv4;

#ifdef HAVE_IPV6
struct route_table *bgp_table_ipv6;
struct route_table *bgp_static_ipv6;
#endif /* HAVE_IPV6 */

/* Static annoucement peer. */
struct peer *peer_self;

/* BGP peer lists. */
extern list peer_list;

/* Macros which easy to access peer's filter. */
#define DISTRIBUTE_IN(P)    ((P)->distribute[BGP_FILTER_IN].list)
#define DISTRIBUTE_OUT(P)   ((P)->distribute[BGP_FILTER_OUT].list)
#define FILTER_LIST_IN(P)   ((P)->filter[BGP_FILTER_IN].filter)
#define FILTER_LIST_OUT(P)  ((P)->filter[BGP_FILTER_OUT].filter)
#define ROUTE_MAP_IN(P)     ((P)->route_map[BGP_FILTER_IN].map)
#define ROUTE_MAP_OUT(P)    ((P)->route_map[BGP_FILTER_OUT].map)

/* Extern from bgp_dump.c */
char *bgp_origin_long_str[] = {"IGP","EGP","Incomplete"};

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
  if (new->type == ZEBRA_ROUTE_STATIC)
    return 1;
  if (exist->type == ZEBRA_ROUTE_STATIC)
    return 0;

  /* AS path length check. */
  if (new->attr->aspath->hop_count < exist->attr->aspath->hop_count)
    return 1;
  if (new->attr->aspath->hop_count > exist->attr->aspath->hop_count)
    return 0;

  /* Local preference check. */
  if (new->attr->local_pref > exist->attr->local_pref)
    return 1;
  if (new->attr->local_pref < exist->attr->local_pref)
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

/* called from BGP Update packet */
void
bgp_log_route(struct prefix *p,struct bgp_info *info, int dup)
{
  struct attr *attr;
  char addr[BUFSIZ];

  attr = info->attr;

  strlcpy(addr, inet_ntoa(p->u.prefix4), BUFSIZ);

  zlog (info->peer->log, LOG_INFO, "    NLRI: %s/%d %s", addr, p->prefixlen, 
	dup ? "[replace]" : "");
}

/* Announce the prefix and information. */
void
bgp_announce (struct peer *peer, struct prefix *p, struct bgp_info *info)
{
  struct attr attr;
  struct bgp_info bgp_info;

  /* Distribute list apply. */
  if (DISTRIBUTE_OUT (peer))
    if (access_list_apply (DISTRIBUTE_OUT (peer), p) == FILTER_DENY)
      return;

  /* Filter list apply. */
  if (FILTER_LIST_OUT (peer))
    ;

  /* Route map apply. */
  if (ROUTE_MAP_OUT (peer))
    {
      /* Route map may generates new attribute.  So we copy
         attribute to new one. */
      attr = *info->attr;
      if (attr.aspath)
	attr.aspath = aspath_dup (attr.aspath);

      /* Make routemap object. */
      bgp_info.peer = peer;
      bgp_info.attr = &attr;
      
      /* Apply route map to duplicated attribute. */
      route_map_apply (ROUTE_MAP_OUT (peer), p, &bgp_info);

      /* Send packet to the peer. */
      bgp_update_send (peer, p, &attr);

      /* Free tempolary aspath. */
      if (attr.aspath)
	aspath_undup (attr.aspath);
    }
  else
    bgp_update_send (peer, p, info->attr);
}

/* Announce current routing table to the peer. */
void
bgp_announce_table (struct peer *peer)
{
  struct route_node *node;
  struct bgp_info *info;

  for (node = route_top (bgp_table_ipv4); node; node = route_next (node))
    if ((info = node->info) != NULL)
      if (info->selected && info->peer != peer)
	bgp_announce (peer, &node->p, info);

#ifdef HAVE_IPV6
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
      if (info->selected && info->type == ZEBRA_ROUTE_BGP)
	bgp_zebra_withdraw (&node->p, info);

#ifdef HAVE_IPV6
  for (node = route_top (bgp_table_ipv6); node; node = route_next (node))
    if ((info = node->info) != NULL)
      if (info->selected && info->type == ZEBRA_ROUTE_BGP)
	bgp_zebra_withdraw (&node->p, info);
#endif /* HAVE_IPV6 */
}

/* Utility function for looking up route node from prefix specific
   address family tree. */
static struct route_node *
nlri_node_lookup (struct prefix *p)
{
  if (p->family == AF_INET)
    return route_node_get (bgp_table_ipv4, p);
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    return route_node_get (bgp_table_ipv6, p);
#endif /* HAVE_IPV6 */
  return NULL;
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
      if (peer != info->peer && peer->status == Established)
	bgp_announce (peer, p, info);

  /* Kernel routing update. */
  if (info->type == ZEBRA_ROUTE_BGP)
    bgp_zebra_announce (p, info);
}

void
nlri_withdraw (struct prefix *p, struct bgp_info *info)
{
  listnode node;
  struct peer *peer;

  for (node = listhead (peer_list); node; nextnode (node))
    if ((peer = getdata (node)) != NULL)
      if (peer != info->peer && peer->status == Established)
	bgp_withdraw_send (peer, p);

  /* Kernel routing update. */
  if (info->type == ZEBRA_ROUTE_BGP)
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
  node = nlri_node_lookup (p);
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
	repflag = 1;
	break;
      }

  /* If there is no replace route. */
  if (!replace)
    info->peer->prefix_count++;

  /* Add route to the node. */
  bgp_info_add ((struct bgp_info **)&node->info, info);

  /* Announce to the remote peer. */
  updated = (struct bgp_info *) node->info;

  if (updated != announced)
    nlri_update (p, info);

  /* Now bgpd's route loggin is one line for one prefix so this line
     is commented out. */
  /* bgp_log_route (p, info, repflag); */
}

/* Apply filters and return interned struct attr. */
struct attr *
nlri_apply (struct prefix *p, struct peer *peer, struct attr *attr)
{
  struct attr newattr;
  struct bgp_info bgp_info;
  struct aspath *aspath;

  /* Distribute list apply. */
  if (DISTRIBUTE_IN (peer))
    if (access_list_apply (DISTRIBUTE_IN (peer), p) == FILTER_DENY)
      return NULL;

  /* Filter list apply. */
  if (FILTER_LIST_IN (peer))
    ;

  /* Route map apply. */
  if (ROUTE_MAP_IN (peer))
    {
      newattr = *attr;
      if (attr->aspath)
	newattr.aspath = aspath_dup (attr->aspath);
      
      /* Make routemap object. */
      bgp_info.peer = peer;
      bgp_info.attr = &newattr;

      /* Apply route map to duplicated attribute. */
      route_map_apply (ROUTE_MAP_IN (peer), p, &bgp_info);

      /* To intern new attribute it's important to aspath points out
         real interned aspath structure. */
      aspath = aspath_parse (newattr.aspath->data, 
			     newattr.aspath->length);
      aspath_undup (newattr.aspath);
      newattr.aspath = aspath;

      return bgp_attr_intern (&newattr);
    }

  /* After all intern attribute and return it. */
  return bgp_attr_intern (attr);
}

/* Parse route and add route into radix tree. */
void
nlri_parse (struct peer *peer, struct attr *attr, 
	    u_char *pnt, int len, int family)
{
  int psize;
  struct prefix p;
  u_char *end;
  struct attr *newattr;
  char attrstr[BUFSIZ];
  struct bgp_info *br;
  char buf[BUFSIZ];

  /* When protocol is BGP-4+ NLRI length may be zero. */
  if (!len) 
    return;

  /* Make attribute dump string. */
  bgp_dump_attr (peer, attr, attrstr, BUFSIZ);

  /* Set end pointer. */
  end = pnt + len;

  while (pnt < end)
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

      psize = PSIZE (p.prefixlen);

      if (pnt + psize > end)
	{
	  zlog (peer->log, LOG_ERR, 
		"Wrong prefix length exeeds end of packet %d", p.prefixlen);
	  return;
	}

      memcpy (&p.u.prefix, pnt, psize);

      /* Logging. */
      zlog (peer->log, LOG_INFO, "Update:[%s] %s/%d %s",
	    peer->host, inet_ntop(family, &p.u.prefix, buf, BUFSIZ),
	    p.prefixlen, attrstr);

      /* Apply filters route-maps. */
      newattr = nlri_apply (&p, peer, attr);
      if (newattr == NULL)
	return;

      br = bgp_info_new ();
      br->type = ZEBRA_ROUTE_BGP;
      br->peer = peer;
      br->attr = newattr;

      /* Process this information. */
      nlri_process (&p, br);

      /* Forward pointer. */
      pnt += psize;
    }
  return;
}

int
nlri_delete (struct peer *peer, struct prefix *p)
{
  struct route_node *node;
  struct bgp_info *del;

  /* First look up routing table node. */
  node = nlri_node_lookup (p);
  if (!node)
    return 0;

  for (del = node->info; del; del = del->next)
    if (del->peer == peer)
      break;

  /* Withdraw route from route list. */
  if (del == NULL)
    {
      zlog (peer->log, LOG_INFO, "Withdraw:[%s] %s/%d (not exist)",
	    peer->host, inet_ntoa(p->u.prefix4), (int) p->prefixlen);
      route_unlock_node (node);
      return 0;
    }

  zlog (peer->log, LOG_INFO, "Withdraw:[%s] %s/%d (exist)",
	peer->host, inet_ntoa(p->u.prefix4), (int) p->prefixlen);

  bgp_info_delete ((struct bgp_info **) &node->info, del);

  /* Reselect route. */
  nlri_reselect (&node->p, (struct bgp_info *)node->info, del);

  bgp_info_free (del);

  peer->prefix_count--;

  route_unlock_node (node);

  return 1;
}

/* withdraw handling routine */
void
nlri_unfeasible (struct peer *peer, bgp_size_t unfeasible_len)
{
  u_char *pnt;
  u_char *end;
  int psize;
  struct prefix p;

  /* Set data start pointer. */
  pnt = stream_pnt (peer->ibuf);
  end = pnt + unfeasible_len;
  
  while (pnt < end)
    {
      bzero (&p, sizeof p);
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      psize = PSIZE (p.prefixlen);
      memcpy (&p.u.prefix4, pnt, psize);

      nlri_delete (peer, &p);

      pnt += psize;
    }
  stream_forward (peer->ibuf, unfeasible_len);
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
	    bgp_info_free (br);
	    route_unlock_node (np);
	  }
      }
#endif /* HAVE_IPV6 */

  peer->prefix_count = 0;
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
  vty_out (vty, "%s  ", binfo->selected ? "*" : " ");

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

      vty_out (vty, "%10lu%10lu%10lu ",
	       attr->med, attr->local_pref, attr->weight);
    
    /* Print aspath */
    if (attr->aspath)
      aspath_print_vty (vty, attr->aspath);

    /* Print origin */
    vty_out (vty, " %s", bgp_origin_long_str[attr->origin]);
  }

  vty_out (vty, "\r\n");
}  

void
route_vty_out_detail (struct vty *vty, struct prefix *p, 
		      struct bgp_info *binfo)
{
  char buf[BUFSIZ];
  struct attr *attr;

  /* Header of detailed BGP route information. */
  vty_out (vty, " %s/%d\r\n",
	   inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
	   p->prefixlen);

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
	  vty_out (vty, "(%s)\r\n", bgp_origin_long_str[attr->origin]);
	  vty_out (vty, "\tNexthop: %s\r\n", inet_ntoa(attr->nexthop));

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
	    vty_out (vty, "\tMED: %lu\r\n", attr->med);

	  vty_out (vty, "\tWeight: %lu\r\n", attr->weight);

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
	    vty_out (vty, "\tLocalpref: %lu\r\n", attr->local_pref);
	  
	  if (attr->community)
	    {
	      vty_out (vty, "\tCommunity:");
	      community_print_vty (vty, attr->community);
	      vty_out (vty, "\r\n");
	    }
	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
	    vty_out (vty, "\tAtomic Aggregate\r\n");

	  if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR))
	    vty_out (vty, "\tAggregator AS%d [%s]\r\n", attr->aggregator_as,
		     inet_ntoa(attr->aggregator_addr));
	}
    }
  vty_out (vty, "\r\n");
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
      vty_out (vty, "   Network             Next Hop            Metric    LocPrf    Weight Path\r\n");

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
      vty_out (vty, "address is malformed\r\n");
      return CMD_WARNING;
    }
  match.family = AF_INET;
  match.prefixlen = IPV4_MAX_BITLEN;
  
  /* Lookup route node. */
  node = route_node_match (bgp_table_ipv4, (struct prefix *) &match);

  if (node == NULL) 
    {
      vty_out (vty, "can't find route\r\n");
      return CMD_WARNING;
    }

  /* Node is locked by route_node_lookup. */
  for (route = node->info; route; route = route->next)
    route_vty_out_detail (vty, &node->p, route);

  /* Work is done, so unlock the node. */
  route_unlock_node (node);

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       "Show bgpd's own routing information of IPv6\n")
{
  struct route_node *node;
  struct bgp_info *route;
  
  vty_out (vty, "\r\nNetwork                  Next Hop       Metric    LocPrf Path\r\n");

  /* Start processing of routes. */
  for (node = route_top (bgp_table_ipv6); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      route_vty_out (vty, &node->p, route);

  return CMD_SUCCESS;
}

/* Network configuration for IPv6. */
int
bgp_network_config_ipv6 (struct vty *vty, char *address_str)
{
  int ret;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  ret = str2prefix_ipv6 (address_str, (struct prefix_ipv6 *) &p);
  if (!ret)
    {
      vty_out (vty, "Please specify valid address\r\n");
      return CMD_WARNING;
    }

  apply_mask_ipv6 ((struct prefix_ipv6 *) &p);
  
  node = route_node_get (bgp_static_ipv6, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_STATIC;
  bgp_info->peer = peer_self;
  bgp_info->attr = bgp_attr_make_default ();
  node->info = bgp_info;

  nlri_process (&p, bgp_info);

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
#ifdef HAVE_IPV6
      return bgp_network_config_ipv6 (vty, argv[0]);
#endif /* HAVE_IPV6 */

      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask ((struct prefix_ipv4 *) &p);

  node = route_node_get (bgp_static_ipv4, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_STATIC;
  bgp_info->peer = peer_self;
  bgp_info->attr = bgp_attr_make_default ();
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
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  apply_mask (&p);

  np = route_node_get (bgp_static_ipv4, (struct prefix *) &p);
  if (!np->info)
    {
      vty_out (vty, "Can't find specified static route configuration.\r\n");
      route_unlock_node (np);
      return CMD_WARNING;
    }

  nlri_delete (peer_self, (struct prefix *) &p);

  /* bgp_attr_free (np->info); */
  np->info = NULL;

  route_unlock_node (np);

  return CMD_SUCCESS;
}

/* Configuration of static route announcement. */
int
config_write_network (struct vty *vty, struct bgp *bgp)
{
  struct route_node *node;
  struct bgp_route *route;
  char buf[BUFSIZ];
  
  for (node = route_top (bgp_static_ipv4); node; node = route_next (node)) 
    if ((route = node->info) != NULL)
      vty_out (vty, " network %s/%d%s", 
	       inet_ntoa (node->p.u.prefix4), node->p.prefixlen, VTY_NEWLINE);
#ifdef HAVE_IPV6
  for (node = route_top (bgp_static_ipv6); node; node = route_next (node)) 
    if ((route = node->info) != NULL)
      vty_out (vty, " network %s/%d%s", 
	       inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ),
	       node->p.prefixlen, VTY_NEWLINE);
#endif /* HAVE_IPV6 */

  return 0;
}

/* Allocate routing table structure and install commands. */
void
bgp_route_init ()
{
  /* Make static announcement peer. */
  peer_self = peer_new ();
  peer_self->host = "Static annucement";

  /* IPv4 related table and commands. */
  bgp_table_ipv4 = route_table_init ();
  bgp_static_ipv4 = route_table_init ();

  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_cmd);
  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);

#ifdef HAVE_IPV6
  /* IPv6 related table and commands. */
  bgp_table_ipv6 = route_table_init ();
  bgp_static_ipv6 = route_table_init ();

  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
#endif /* HAVE_IPV6 */
}
