/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"	/* For ZEBRA_SERV_PATH. */

#ifdef OLD_RIB
u_int32_t zlookup_query (struct in_addr);
#else
struct bgp_nexthop_cache *zlookup_query (struct in_addr);
#endif /* OLD_RIB */

/* Only one BGP scan thread are activated at the same time. */
struct thread *bgp_scan_thread = NULL;

/* BGP scan interval. */
int bgp_scan_interval;

/* Route table for connected route. */
struct route_table *bgp_connected;

/* Route table for next-hop lookup cache. */
struct route_table *bgp_nexthop_cache;
struct route_table *cache1;
struct route_table *cache2;

/* BGP nexthop cache value structure. */
struct bgp_nexthop_cache
{
  u_int32_t valid;
#ifndef OLD_RIB
  u_char changed;
  u_char nexthop_num;
  u_int32_t metric;
  struct nexthop *nexthop;
#endif /* OLD_RIB */
};

static struct zclient *zlookup = NULL;

struct bgp_nexthop_cache *
bgp_nexthop_cache_new ()
{
  struct bgp_nexthop_cache *new;

  new = XMALLOC (MTYPE_BGP_NEXTHOP_CACHE, sizeof (struct bgp_nexthop_cache));
  memset (new, 0, sizeof (struct bgp_nexthop_cache));
  return new;
}

void
bgp_nexthop_cache_free (struct bgp_nexthop_cache *bnc)
{
  XFREE (MTYPE_BGP_NEXTHOP_CACHE, bnc);
}

#ifndef OLD_RIB
int
bgp_nexthop_same (struct nexthop *n1, struct nexthop *n2)
{
  if (n1->type != n2->type)
    return 0;

  switch (n1->type)
    {
    case ZEBRA_NEXTHOP_IPV4:
      if (! IPV4_ADDR_SAME (&n1->gate.ipv4, &n2->gate.ipv4))
	return 0;
      break;
    case ZEBRA_NEXTHOP_IFINDEX:
    case ZEBRA_NEXTHOP_IFNAME:
      if (n1->ifindex != n2->ifindex)
	return 0;
      break;
    }
  return 1;
}

int
bgp_nexthop_cache_changed (struct bgp_nexthop_cache *bnc1,
			   struct bgp_nexthop_cache *bnc2)
{
  int i;
  struct nexthop *n1, *n2;

  if (bnc1->nexthop_num != bnc2->nexthop_num)
    return 1;

  n1 = bnc1->nexthop;
  n2 = bnc2->nexthop;
  for (i = 0; i < bnc1->nexthop_num; i++)
    {
      if (! bgp_nexthop_same (n1, n2))
	return 1;

      n1 = n1->next;
      n2 = n2->next;
    }
  return 0;
}
#endif /* OLD_RIB */

/* Check specified next-hop is reachable or not. */
u_int32_t
bgp_nexthop_lookup (struct peer *peer, struct in_addr addr, int *changed)
{
  struct route_node *rn;
  struct prefix p;
  struct bgp_nexthop_cache *bnc;

  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = addr;

  /* If lookup is not enabled, return valid. */
  if (zlookup->sock < 0)
    return 1;

  /* EBGP */
  if (peer_sort (peer) == BGP_PEER_EBGP && peer->ttl == 1)
    {
      rn = route_node_match (bgp_connected, &p);
      if (rn)
	{
	  route_unlock_node (rn);
	  return 1;
	}
      return 0;
    }

  /* IBGP or ebgp-multihop */
  rn = route_node_get (bgp_nexthop_cache, &p);

  if (rn->info)
    {
      bnc = rn->info;
      route_unlock_node (rn);
    }
  else
    {
#ifdef OLD_RIB
      bnc = bgp_nexthop_cache_new ();
      bnc->valid = zlookup_query (addr);
#else
      bnc = zlookup_query (addr);
      if (bnc)
	{
	  struct route_table *old;
	  struct route_node *oldrn;
	  struct bgp_nexthop_cache *oldbnc;

	  if (changed)
	    {
	      if (bgp_nexthop_cache == cache1)
		old = cache2;
	      else
		old = cache1;

	      oldrn = route_node_lookup (old, &p);
	      if (oldrn)
		{
		  oldbnc = oldrn->info;

		  bnc->changed = bgp_nexthop_cache_changed (bnc, oldbnc);
		}
	    }
	}
      else
	{
	  bnc = bgp_nexthop_cache_new ();
	  bnc->valid = 0;
	}
#endif /* OLD_RIB */
      rn->info = bnc;
    }

#ifndef OLD_RIB
  if (changed)
    *changed = bnc->changed;
#endif /* OLD_ RIB */

  return bnc->valid;
}

/* Reset and free all BGP nexthop cache. */
void
bgp_nexthop_cache_reset (struct route_table *table)
{
  struct route_node *rn;
  struct bgp_nexthop_cache *bnc;

  for (rn = route_top (table); rn; rn = route_next (rn))
    if ((bnc = rn->info) != NULL)
      {
	bgp_nexthop_cache_free (bnc);
	rn->info = NULL;
	route_unlock_node (rn);
      }
}

int
bgp_scan (struct thread *t)
{
  struct route_node *rn;
  struct bgp *bgp;
  struct bgp_info *bi;
  u_int32_t valid;
  int changed;
  int bgp_process (struct bgp *, struct route_node *, afi_t, safi_t,
		   struct bgp_info *, struct prefix_rd *, u_char *);

  bgp_scan_thread = 
    thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);
  
#ifdef OLD_RIB
  bgp_nexthop_cache_reset (bgp_nexthop_cache);
#else
  if (bgp_nexthop_cache == cache1)
    bgp_nexthop_cache = cache2;
  else
    bgp_nexthop_cache = cache1;
#endif /* OLD_RIB */

  bgp = bgp_get_default ();
  if (bgp == NULL)
    return 0;

  for (rn = route_top (bgp->rib[AFI_IP][SAFI_UNICAST]); rn;
       rn = route_next (rn))
    {
      for (bi = rn->info; bi; bi = bi->next)
	{
	  if (bi->type == ZEBRA_ROUTE_BGP && bi->sub_type == BGP_ROUTE_NORMAL)
	    {
	      changed = 0;
	      valid = bgp_nexthop_lookup (bi->peer, bi->attr->nexthop, &changed);

	      if (changed)
		{		
		  SET_FLAG (bi->flags, BGP_INFO_CHANGED);
		}
	      else
		UNSET_FLAG (bi->flags, BGP_INFO_CHANGED);

	      if (valid != bi->valid)
		{
		  if (bi->valid)
		    {
		      bgp_aggregate_decrement (bgp, &rn->p, bi, AFI_IP,
					       SAFI_UNICAST);
		      bi->valid = valid;
		    }
		  else
		    {
		      bi->valid = valid;
		      bgp_aggregate_increment (bgp, &rn->p, bi, AFI_IP,
					       SAFI_UNICAST);
		    }
		  bgp_process (bgp, rn, AFI_IP, SAFI_UNICAST, NULL, NULL,
			       NULL);
		}
	      else if (valid && changed)
		{
		  bgp_process (bgp, rn, AFI_IP, SAFI_UNICAST, NULL, NULL,
			       NULL);
		}
	    }
	}
    }

#ifndef OLD_RIB
  if (bgp_nexthop_cache == cache1)
    bgp_nexthop_cache_reset (cache2);
  else
    bgp_nexthop_cache_reset (cache1);
#endif /* OLD_RIB */

  return 0;
}

void
bgp_connected_add (struct connected *ifc)
{
  struct prefix_ipv4 p;
  struct prefix_ipv4 *addr;
  struct prefix_ipv4 *dest;
  struct interface *ifp;
  struct route_node *rn;

  ifp = ifc->ifp;

  if (! ifp)
    return;

  if (if_is_loopback (ifp))
    return;

  addr = (struct prefix_ipv4 *) ifc->address;
  dest = (struct prefix_ipv4 *) ifc->destination;

  if (addr->family == AF_INET)
    {
      memset (&p, 0, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = addr->prefixlen;

      if (if_is_pointopoint (ifp))
	p.prefix = dest->prefix;
      else
	p.prefix = addr->prefix;

      apply_mask_ipv4 (&p);

      if (prefix_ipv4_any (&p))
	return;

      rn = route_node_get (bgp_connected, (struct prefix *) &p);
      if (rn->info)
	route_unlock_node (rn);
      else
	rn->info = ifc;
    }
}

void
bgp_connected_delete (struct connected *ifc)
{
  struct prefix_ipv4 p;
  struct prefix_ipv4 *addr;
  struct prefix_ipv4 *dest;
  struct interface *ifp;
  struct route_node *rn;

  ifp = ifc->ifp;

  if (! ifp)
    return;

  if (if_is_loopback (ifp))
    return;

  addr = (struct prefix_ipv4 *) ifc->address;
  dest = (struct prefix_ipv4 *) ifc->destination;

  if (addr->family == AF_INET)
    {
      memset (&p, 0, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = addr->prefixlen;

      if (if_is_pointopoint (ifp))
	p.prefix = dest->prefix;
      else
	p.prefix = addr->prefix;

      apply_mask_ipv4 (&p);

      if (prefix_ipv4_any (&p))
	return;

      rn = route_node_lookup (bgp_connected, (struct prefix *) &p);
      if (! rn)
	return;

      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
    }
}

#ifndef OLD_RIB
/* Add nexthop to the end of the list.  */
void
zlookup_nexthop_add (struct bgp_nexthop_cache *bnc, struct nexthop *nexthop)
{
  struct nexthop *last;

  for (last = bnc->nexthop; last && last->next; last = last->next)
    ;
  if (last)
    last->next = nexthop;
  else
    bnc->nexthop = nexthop;
  nexthop->prev = last;
}
#endif /* ! OLD_RIB */

#ifdef OLD_RIB
u_int32_t
#else
struct bgp_nexthop_cache *
#endif /* OLD_RIB */
zlookup_read ()
{
  struct stream *s;
  u_int16_t length;
  u_char command;
  int nbytes;
  struct in_addr raddr;
  u_int32_t result;
#ifndef OLD_RIB
  int i;
  u_char nexthop_num;
  struct nexthop *nexthop;
  struct bgp_nexthop_cache *bnc;
#endif /* OLD_RIB */

  s = zlookup->ibuf;
  stream_reset (s);

  nbytes = stream_read (s, zlookup->sock, 2);
  length = stream_getw (s);

  nbytes = stream_read (s, zlookup->sock, length - 2);
  command = stream_getc (s);
  raddr.s_addr = stream_get_ipv4 (s);
#ifdef OLD_RIB
  result = stream_getl (s);

  return result;
#else
  result = stream_getl (s);
  nexthop_num = stream_getc (s);

#if 0
  printf ("-----------------\n");
  printf ("nbytes %d\n", nbytes);
  printf ("Length %d\n", length);
  printf ("Command %d\n", command);
  printf ("addr %s\n", inet_ntoa (raddr));
  printf ("result %d\n", result);
  printf ("nexthop_num %d\n", nexthop_num);
#endif /* 0 */

  if (nexthop_num)
    {
      bnc = bgp_nexthop_cache_new ();
      bnc->valid = 1;
      bnc->metric = result;
      bnc->nexthop_num = nexthop_num;

      for (i = 0; i < nexthop_num; i++)
	{
	  nexthop = XMALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
	  memset (nexthop, 0, sizeof (struct nexthop));
	  nexthop->type = stream_getc (s);
	  switch (nexthop->type)
	    {
	    case ZEBRA_NEXTHOP_IPV4:
	      nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
	      break;
	    case ZEBRA_NEXTHOP_IFINDEX:
	    case ZEBRA_NEXTHOP_IFNAME:
	      nexthop->ifindex = stream_getl (s);
	      break;
	    }
	  zlookup_nexthop_add (bnc, nexthop);
	}
    }
  else
    return NULL;

  return bnc;
#endif /* OLD_RIB */
}

#ifdef OLD_RIB
u_int32_t
#else
struct bgp_nexthop_cache *
#endif /* OLD_RIB */
zlookup_query (struct in_addr addr)
{
  int ret;
  struct stream *s;

  /* Check socket. */
  if (zlookup->sock < 0)
    {
#ifdef OLD_RIB
      return -1;
#else
      return NULL;
#endif
    }

  s = zlookup->obuf;
  stream_reset (s);
  stream_putw (s, 7);
  stream_putc (s, ZEBRA_IPV4_NEXTHOP_LOOKUP);
  stream_put_in_addr (s, &addr);

  ret = writen (zlookup->sock, s->data, 7);
  if (ret < 0)
    zlog_err ("can't write to zlookup->sock");
  if (ret == 0)
    zlog_err ("zlookup->sock connection closed");

  return zlookup_read ();
}

/* Connect to zebra for nexthop lookup. */
int
zlookup_connect (struct thread *t)
{
  struct zclient *zlookup;

  zlookup = THREAD_ARG (t);
  zlookup->t_connect = NULL;

  if (zlookup->sock != -1)
    return 0;

#ifdef HAVE_TCP_ZEBRA
  zlookup->sock = zclient_socket ();
#else
  zlookup->sock = zclient_socket_un (ZEBRA_SERV_PATH);
#endif /* HAVE_TCP_ZEBRA */
  if (zlookup->sock < 0)
    return -1;

  /* Make BGP scan thread. */
  bgp_scan_thread = 
    thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);

  return 0;
}

/* Check specified multiaccess next-hop. */
u_int32_t
bgp_multiaccess_check_v4 (struct in_addr nexthop, char *peer)
{
  struct route_node *rn1;
  struct route_node *rn2;
  struct prefix p1;
  struct prefix p2;
  struct in_addr addr;
  int ret;

  ret = inet_aton (peer, &addr);
  if (! ret)
    return 0;

  memset (&p1, 0, sizeof (struct prefix));
  p1.family = AF_INET;
  p1.prefixlen = IPV4_MAX_BITLEN;
  p1.u.prefix4 = nexthop;
  memset (&p2, 0, sizeof (struct prefix));
  p2.family = AF_INET;
  p2.prefixlen = IPV4_MAX_BITLEN;
  p2.u.prefix4 = addr;

  /* If bgp scan is not enabled, return invalid. */
  if (zlookup->sock < 0)
    return 0;

  rn1 = route_node_match (bgp_connected, &p1);
  if (! rn1)
    return 0;
  
  rn2 = route_node_match (bgp_connected, &p2);
  if (! rn2)
    return 0;

  if (rn1 == rn2)
    return 1;

  return 0;
}

DEFUN (bgp_scan_time,
       bgp_scan_time_cmd,
       "bgp scan-time <5-60>",
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n"
       "Scanner interval (seconds)\n")
{
  bgp_scan_interval = atoi (argv[0]);

  if (bgp_scan_thread)
    {
      thread_cancel (bgp_scan_thread);
      bgp_scan_thread = 
	thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_scan_time,
       no_bgp_scan_time_cmd,
       "no bgp scan-time",
       NO_STR
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n")
{
  bgp_scan_interval = BGP_SCAN_INTERVAL_DEFAULT;

  if (bgp_scan_thread)
    {
      thread_cancel (bgp_scan_thread);
      bgp_scan_thread = 
	thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);
    }

  return CMD_SUCCESS;
}

ALIAS (no_bgp_scan_time,
       no_bgp_scan_time_val_cmd,
       "no bgp scan-time <5-60>",
       NO_STR
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n"
       "Scanner interval (seconds)\n")

DEFUN (show_ip_bgp_scan,
       show_ip_bgp_scan_cmd,
       "show ip bgp scan",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP scan status\n")
{
  struct route_node *rn;
  struct bgp_nexthop_cache *bnc;

  if (bgp_scan_thread)
    vty_out (vty, "BGP scan is running%s", VTY_NEWLINE);
  else
    vty_out (vty, "BGP scan is not running%s", VTY_NEWLINE);
  vty_out (vty, "BGP scan interval is %d%s", bgp_scan_interval, VTY_NEWLINE);

  vty_out (vty, "Current BGP nexthop cache:%s", VTY_NEWLINE);
  for (rn = route_top (bgp_nexthop_cache); rn; rn = route_next (rn))
    if ((bnc = rn->info) != NULL)
      vty_out (vty, " %s [%d]%s", inet_ntoa (rn->p.u.prefix4), bnc->valid,
	       VTY_NEWLINE);

  vty_out (vty, "BGP connected route:%s", VTY_NEWLINE);
  for (rn = route_top (bgp_connected); rn; rn = route_next (rn))
    if (rn->info != NULL)
      vty_out (vty, " %s/%d%s", inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
	       VTY_NEWLINE);

  return CMD_SUCCESS;
}

int
bgp_config_write_scan_time (struct vty *vty)
{
  if (bgp_scan_interval != BGP_SCAN_INTERVAL_DEFAULT)
    vty_out (vty, " bgp scan-time %d%s", bgp_scan_interval, VTY_NEWLINE);
  return CMD_SUCCESS;
}

void
bgp_scan_init ()
{
  zlookup = zclient_new ();
  zlookup->sock = -1;
  zlookup->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  zlookup->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  zlookup->t_connect = thread_add_event (master, zlookup_connect, zlookup, 0);

  bgp_scan_interval = BGP_SCAN_INTERVAL_DEFAULT;

  cache1 = route_table_init ();
  cache2 = route_table_init ();
  bgp_nexthop_cache = cache1;
  bgp_connected = route_table_init ();

  install_element (BGP_NODE, &bgp_scan_time_cmd);
  install_element (BGP_NODE, &no_bgp_scan_time_cmd);
  install_element (BGP_NODE, &no_bgp_scan_time_val_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_scan_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_scan_cmd);
}
