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

u_int32_t zlookup_query (struct in_addr);

/* Only one BGP scan thread are activated at the same time. */
struct thread *bgp_scan_thread = NULL;

/* BGP scan interval. */
int bgp_scan_interval;

/* Route table for connected route. */
struct route_table *bgp_connected;

/* Route table for next-hop lookup cache. */
struct route_table *bgp_nexthop_cache;

/* BGP nexthop cache value structure. */
struct bgp_nexthop_cache
{
  u_int32_t valid;
};

static struct zclient *zlookup = NULL;

struct bgp_nexthop_cache *
bgp_nexthop_cache_new ()
{
  struct bgp_nexthop_cache *new;

  new = XMALLOC (0, sizeof (struct bgp_nexthop_cache));
  memset (new, 0, sizeof (struct bgp_nexthop_cache));
  return new;
}

void
bgp_nexthop_cache_free (struct bgp_nexthop_cache *bnc)
{
  XFREE (0, bnc);
}

/* Check specified next-hop is reachable or not. */
u_int32_t
bgp_nexthop_lookup (struct peer *peer, struct in_addr addr)
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
      bnc = bgp_nexthop_cache_new ();
      bnc->valid = zlookup_query (addr);
      rn->info = bnc;
    }
  return bnc->valid;
}

/* Reset and free all BGP nexthop cache. */
void
bgp_nexthop_cache_reset ()
{
  struct route_node *rn;
  struct bgp_nexthop_cache *bnc;

  for (rn = route_top (bgp_nexthop_cache); rn; rn = route_next (rn))
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
  int bgp_process (struct bgp *, struct route_node *, afi_t, safi_t,
		   struct bgp_info *, struct prefix_rd *, u_char *);

  bgp_scan_thread = 
    thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);
  
  bgp_nexthop_cache_reset ();

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
	      valid = bgp_nexthop_lookup (bi->peer, bi->attr->nexthop);

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
	    }
	}
    }
  return 0;
}

void
bgp_connected_add (struct connected *c)
{
  struct prefix_ipv4 *p;
  struct prefix_ipv4 rib;
  struct route_node *rn;

  p = (struct prefix_ipv4 *)c->address;

  if (if_is_loopback (c->ifp))
    return;

  if (p->family == AF_INET)
    {
      rib = *p;
      apply_mask_ipv4 (&rib);

      rn = route_node_get (bgp_connected, (struct prefix *) &rib);
      if (rn->info)
	route_unlock_node (rn);
      else
	rn->info = c;
    }
}

void
bgp_connected_delete (struct connected *c)
{
  struct prefix_ipv4 *p;
  struct prefix_ipv4 rib;
  struct route_node *rn;

  p = (struct prefix_ipv4 *)c->address;

  if (if_is_loopback (c->ifp))
    return;

  if (p->family == AF_INET)
    {
      rib = *p;
      apply_mask_ipv4 (&rib);

      rn = route_node_lookup (bgp_connected, (struct prefix *)&rib);
      if (! rn)
	return;

      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
    }
}

u_int32_t
zlookup_read ()
{
  struct stream *s;
  u_int16_t length;
  u_char command;
  u_int32_t result;
  int nbytes;
  struct in_addr raddr;

  s = zlookup->ibuf;
  stream_reset (s);

  nbytes = read (zlookup->sock, s->data, 11);

  length = stream_getw (s);
  command = stream_getc (s);
  raddr.s_addr = stream_get_ipv4 (s);
  result = stream_getl (s);

#if 0
  printf ("nbytes %d\n", nbytes);
  printf ("Length %d\n", length);
  printf ("Command %d\n", command);
  printf ("addr %s\n", inet_ntoa (raddr));
  printf ("Result %d\n", result);
#endif /* 0 */

  return result;
}

u_int32_t
zlookup_query (struct in_addr addr)
{
  int ret;
  struct stream *s;

  /* Check socket. */
  if (zlookup->sock < 0)
    return -1;

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

  zlookup->sock = zclient_socket ();
  if (zlookup->sock < 0)
    return -1;

  /* Make BGP scan thread. */
  bgp_scan_thread = 
    thread_add_timer (master, bgp_scan, NULL, bgp_scan_interval);

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

  bgp_nexthop_cache = route_table_init ();
  bgp_connected = route_table_init ();

  install_element (BGP_NODE, &bgp_scan_time_cmd);
  install_element (BGP_NODE, &no_bgp_scan_time_cmd);
  install_element (BGP_NODE, &no_bgp_scan_time_val_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_scan_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_scan_cmd);
}
