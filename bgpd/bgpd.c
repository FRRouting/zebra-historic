/*
 * BGP-4, BGP-4+, BGP-5 daemon program
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
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "table.h"
#include "linklist.h"
#include "command.h"
#include "sockunion.h"
#include "network.h"
#include "memory.h"
#include "roken.h"
#include "filter.h"
#include "routemap.h"
#include "str.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"

/* List head of bgp instance list. */
list bgp_list;

/* List of all bgp peer. */
list peer_list;

/* BGP multiple instance option. */
char bgp_multiple_instance;

#define BGP_CONFIG_ROUTER_ID 1

/* Top node of bgpd's routing table. */
extern struct route_table *bgp_table_ipv4;
#ifdef HAVE_IPV6
extern struct route_table *bgp_table_ipv6;
#endif /* HAVE_IPV6 */

/* Allocate new bgp structure. */
struct bgp *
bgp_new (u_int16_t as)
{
  struct bgp *bgp = (struct bgp *) malloc (sizeof (struct bgp));
  bzero (bgp, sizeof (struct bgp));

  bgp->as = as;
  bgp->ident = 0;
  bgp->peer = list_init ();
  list_add_node (bgp_list, bgp);

  return bgp;
}

/* Check peer's AS number and determin is this peer IBPG or EBGP */
int
bgp_peer_sort (struct peer *peer)
{
  if (peer->bgp == NULL)
    return BGP_PEER_INTERNAL;

  if (peer->as == peer->bgp->as)
    return BGP_PEER_IBGP;
  else
    return BGP_PEER_EBGP;
}

/* BGP structure specify by asno. */
struct bgp *
bgp_lookup_by_as (u_int16_t as)
{
  struct bgp *bgp; 
  listnode node;

  node = listhead (bgp_list);
  while (node)
    {
      bgp = getdata (node);
      if (bgp->as == as)
	return bgp;
      nextnode (node);
    }
  return NULL;
}

/* allocate new peer object */
struct peer *
peer_new ()
{
  struct peer *peer;

  /* Allocate new peer. */
  peer = XMALLOC (MTYPE_BGP_PEER, sizeof (struct peer));
  bzero (peer, sizeof (struct peer));

  /* Set default value. */
  peer->fd = -1;
  peer->v_start = BGP_INIT_START_TIMER;
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME_BIG;
  peer->v_keepalive = BGP_DEFAULT_KEEPALIVE;
  peer->status = Idle;
  peer->ostatus = Idle;
  peer->version = BGP_VERSION_4;
  peer->prefix_count = 0;
  peer->ibuf = stream_new (BGP_MAX_PACKET_SIZE);

  /* Set output buffer. */
  peer->obuf = stream_fifo_new ();

  return peer;
}

void
peer_free (struct peer *peer)
{
  if (peer->su)
    XFREE (MTYPE_TMP, peer->su);
  if (peer->su_local)
    XFREE (MTYPE_TMP, peer->su_local);
  XFREE (MTYPE_BGP_PEER, peer);
}

void
peer_clear (struct peer *peer)
{
  if (peer->fd >= 0)
    {
      close (peer->fd);
      peer->fd = -1;
    }
}

/* Delete all peer.  Called from bgp_terminate(). */
void
peer_delete_all ()
{
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      struct peer *peer;

      peer = getdata (node);
      peer_clear (peer);
      peer_free (peer);
    }
}

/* Delete peer from confguration. */
void
peer_delete (struct peer *peer)
{
  /* Free allocated host character. */
  if (peer->host)
    XFREE (0, peer->host);

  /* Free software timers. */
#define timer_off(X) \
  if (X) \
    { \
      thread_cancel (X); \
      (X) = NULL; \
    }

  timer_off (peer->t_start);
  timer_off (peer->t_keepalive);
  timer_off (peer->t_holdtime);
  timer_off (peer->t_connect);
  timer_off (peer->t_asorig);
  timer_off (peer->t_routeadv);

  /* Free peer structure. */
  XFREE (MTYPE_BGP_PEER, peer);
}

/* Peer lookup by ip address character. */
struct peer *
peer_lookup_by_su (union sockunion *su)
{
  struct peer *peer;
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      peer = getdata (node);
      if (sockunion_sameprefix (peer->su, su))
	return peer;
    }
  return NULL;
}

/* Neighbor lookup by ip address character. */
struct peer *
peer_lookup_from_bgp (struct bgp *bgp, char *addr)
{
  struct peer *peer;
  listnode node;
  union sockunion *su;

  su = sockunion_str2su (addr);
  if (su == NULL)
    return NULL;

  for (node = listhead (bgp->peer); node; nextnode (node))
    {
      peer = getdata (node);
      if (sockunion_sameprefix (peer->su, su))
	return peer;
    }
  return NULL;
}

/* Neighbor lookup by host name. */
struct peer *
peer_lookup_by_host (char *host)
{
  struct peer *peer;
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      peer = getdata (node);
      if (strcmp (peer->host, host) == 0)
	return peer;
    }
  return NULL;
}

struct peer *
peer_lookup_by_logformat (char *str)
{
  char *start;
  char *end;
  char peernamebuf[256];
  struct peer *peer;
  extern list peer_list;

  start = strrchr (str, '[');
  end = strrchr (str, ']');

  if (start == NULL || end == NULL)
    return NULL;
  
  memcpy (peernamebuf, start + 1, end - start - 1);
  peernamebuf[end - start - 1] = '\0';

  peer = (struct peer *) peer_lookup_by_host (peernamebuf);
  if (peer == NULL)
    {
      peer = peer_new();
      peer->host = strdup (peernamebuf);
      list_add_node (peer_list, peer);
    }

  return peer;
}

/* Sockunion union output to vty interface. Return printed strings
   length. */
int
sockunion_vty_out (struct vty *vty, union sockunion *su)
{
  char str[BUFSIZ];

  switch (su->sa.sa_family)
    {
    case AF_INET:
      inet_ntop (AF_INET, &su->sin.sin_addr, str, sizeof (str));
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      inet_ntop (AF_INET6, &su->sin6.sin6_addr, str, sizeof (str));
      break;
#endif /* HAVE_IPV6 */
    }

  vty_out (vty, "%s", str);

  return strlen (str);
}

void
peer_uptime_vty (struct vty *vty, struct peer *peer)
{

#define TIME_BUF 25
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

  time_t uptime;
  struct tm *tm;
  char timebuf [TIME_BUF];

  /* If there is no connection has been done before print `never'. */
  if (peer->uptime == 0)
    {
      vty_out (vty, "never   ");
      return;
    }

  /* Get current time. */
  time (&uptime);
  uptime -= peer->uptime;
  tm = gmtime (&uptime);

  /* Making formatted timer strings. */
  if (uptime < ONE_DAY_SECOND)
    snprintf (timebuf, TIME_BUF, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (uptime < ONE_WEEK_SECOND)
    snprintf (timebuf, TIME_BUF, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    snprintf (timebuf, TIME_BUF, "%02dw%dd%02dh", 
	      tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);

  /* Out puts to vty. */
  vty_out (vty, "%8s", timebuf);
}

/* Enable BGP mutliple instance configuration. */
DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       BGP_STR
       "Enable bgp multiple instance\n")
{
  bgp_multiple_instance = 1;
  return CMD_SUCCESS;
}

DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       NO_STR
       BGP_STR
       "BGP multiple instance\n")
{
  if (listcount (bgp_list) > 1)
    {
      vty_out (vty, "There are more than two active bgp instances.\r\n");
      return CMD_WARNING;
    }
  
  bgp_multiple_instance = 0;
  return CMD_SUCCESS;
}

/* router bgp AS_NO command.*/
DEFUN (router_bgp, 
       router_bgp_cmd, 
       "router bgp AS_NO", 
       "Enable a routing process\n"
       "Start BGP configuration\n"
       "AS number\n")
{
  struct bgp *bgp;
  u_int16_t as;

  /* Check duplicate instance as same AS value. */
  as = strtol (argv[0], NULL, 10);

  /* Check existing bgp. */
  bgp = bgp_lookup_by_as (as);

  /* There is already active bgp instance. */
  if (bgp != NULL)
    {
      vty->node = BGP_NODE;
      vty->index = bgp;
      return CMD_SUCCESS;
    }

  if (!bgp_multiple_instance && !list_isempty (bgp_list))
    {
      bgp = getdata (listhead (bgp_list));
      
      vty_out (vty, "bgp is already running: AS is %d.\r\n", bgp->as);
      return CMD_WARNING;
    }
  
  /* Make new bgp instance. */
  bgp = bgp_new (as);

  /* Set current bgp point. */
  vty->node = BGP_NODE;
  vty->index = bgp;

  return CMD_SUCCESS;
}

DEFUN (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id IPV4_ADDRESS",
       BGP_STR
       "Set my own router identifier\n"
       "IP Address\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr bgp_ident;

  bgp = (struct bgp *) vty->index;
  
  ret = inet_aton (argv[0], &bgp_ident);
  bgp->ident = bgp_ident.s_addr;
  if (!ret)
    {
      vty_out (vty, "malformed bgp router identifier\r\n");
      return CMD_WARNING;
    }
  bgp->config |= BGP_CONFIG_ROUTER_ID;
  return CMD_SUCCESS;
}

DEFUN (no_router_bgp, 
       no_router_bgp_cmd, 
       "no router bgp AS_NO", 
       NO_STR
       "Enable a routing process\n"
       "Start BGP configuration\n"
       "AS number\n")
{
  struct bgp *bgp;
  struct peer *peer;
  listnode node;
  u_int16_t as;

  as = strtol (argv[0], NULL, 10);

  bgp = bgp_lookup_by_as (as);

  if (bgp == NULL)
    {
      vty_out (vty, "There isn't active bgp instance under as number %d.\r\n", as);
      return CMD_WARNING;
    }

  for (node = listhead (bgp->peer); node; nextnode (node))
    {
      peer = getdata (node);
      ;
    }
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors [PEER]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "\n")
{
  struct peer *p;
  listnode node;

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down.\r\n");

  for (node = listhead (peer_list); node; nextnode (node))
    {
      p = getdata (node);

      vty_out (vty, "%-15s ", p->host);
      switch (p->version) {
      case BGP_VERSION_4:
	vty_out (vty, "4  ");
	break;
      case BGP_VERSION_MP_4:
	vty_out (vty, "4- ");
	break;
      case BGP_VERSION_MP_4_DRAFT_00:
	vty_out (vty, "4+ ");
	break;
      }
      vty_out(vty, "%5d %7d %7d %8d %4d %4d ", p->as,
	       p->open_in+p->update_in+p->withdrow_in+p->keepalive_in,
	       p->open_out+p->update_out+p->withdrow_out+p->keepalive_out,
	       0, 0, 0);

      peer_uptime_vty (vty, p);

      {
	struct in_addr bgp_ident;
	bgp_ident.s_addr = p->ident;
	vty_out (vty, "\r\n  Remote router ID %s\r\n",
		 inet_ntoa (bgp_ident));
      }
      vty_out (vty,
	       "  Status: %-12s keepalive: %d holdtime: %d"
	       "\r\n  open: in/out %d/%d"
	       "  update: in/out %d+%d/%d+%d"
	       "  keepalive: in/out %d/%d\r\n",
	       LOOKUP (bgp_status_msg, p->status),
	       p->v_keepalive, p->v_holdtime,
	       p->open_in, p->open_out,
	       p->update_in, p->withdrow_in,
	       p->update_out, p->withdrow_out,
	       p->keepalive_in, p->keepalive_out
	       );
      vty_out (vty, "  read thread: %s  write thread: %s\r\n", 
	       p->t_read ? "on" : "off",
	       p->t_write ? "on" : "off");

      if (p->distribute[BGP_FILTER_IN].name)
	vty_out (vty, "  distribute-list in: %s%s\r\n",
		 p->distribute[BGP_FILTER_IN].list ? "*" : "",
		 p->distribute[BGP_FILTER_IN].name);
      if (p->distribute[BGP_FILTER_OUT].name)
	vty_out (vty, "  distribute-list out: %s%s\r\n",
		 p->distribute[BGP_FILTER_OUT].list ? "*" : "",
		 p->distribute[BGP_FILTER_OUT].name);

      if (p->route_map[BGP_FILTER_IN].name)
	vty_out (vty, "  route-map in: %s%s\r\n",
		 p->route_map[BGP_FILTER_IN].map ? "*" : "",
		 p->route_map[BGP_FILTER_IN].name);
      if (p->route_map[BGP_FILTER_OUT].name)
	vty_out (vty, "  route-map out: %s%s\r\n",
		 p->route_map[BGP_FILTER_OUT].map ? "*" : "",
		 p->route_map[BGP_FILTER_OUT].name);

    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_summary, 
       show_ip_bgp_summary_cmd,
       "show ip bgp summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  listnode node;
  struct peer *peer;

  if (! listcount (peer_list))
    {
      vty_out (vty, "No neighbor is configured.\r\n");
      return CMD_SUCCESS;
    }

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent"
	   "   TblVer  InQ OutQ Up/Down  State/Pref\r\n");

  for (node = listhead (peer_list); node; nextnode (node))
    {
      int length;
      peer = getdata (node);
	  
      length = sockunion_vty_out (vty, peer->su);
      length = 15 - length;
      if (length < 0)
	length = 0;

      vty_out (vty, "%*s", length, " ");
      switch (peer->version) 
	{
	case BGP_VERSION_4:
	  vty_out (vty, " %d ", peer->version);
	  break;
	case BGP_VERSION_MP_4:
	  vty_out (vty, " 4-");
	  break;
	case BGP_VERSION_MP_4_DRAFT_00:
	  vty_out (vty, " 4+");
	  break;
	}
      vty_out (vty, " %5d %7d %7d %8d %4d %4d ",
	       peer->as,
	       peer->open_in + peer->update_in +
	       peer->withdrow_in + peer->keepalive_in,
	       peer->open_out + peer->update_out +
	       peer->withdrow_out + peer->keepalive_out,
	       0, 0, peer->obuf->count);
      peer_uptime_vty (vty, peer);
      if (peer->status == Established)
	vty_out (vty, " %9d\r\n", peer->prefix_count);
      else
	vty_out (vty, " %-11s\r\n", LOOKUP(bgp_status_msg, peer->status));
    }
  return CMD_SUCCESS;

}

DEFUN (show_ip_bgp_paths, 
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "AS path statistics\n")
{
  vty_out (vty, "Address Refcnt Path\r\n");
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_community, 
       show_ip_bgp_community_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
  vty_out (vty, "Address Refcnt Community\r\n");
  community_print_all_vty (vty);

  return CMD_SUCCESS;
}

DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       "neighbor IP_ADDR ebgp-multihop [TTL]",
       NEIGHBOR_STR
       "IP address\n"
       "Change TTL value of BGP connection\n"
       "TTL\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;

  peer = peer_lookup_from_bgp (bgp, argv[0]);
  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (argc == 2)
    peer->ttl = atoi (argv[1]);
  else
    peer->ttl = TTL_MAX;

  if (peer->ttl == 0)
    {
      vty_out (vty, "please specify plus integer value.\r\n");
      return CMD_WARNING;
    }

  if (peer->fd >= 0)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

DEFUN (neighbor_version,
       neighbor_version_cmd,
       "neighbor IP_ADDR version BGP_VERSION",
       NEIGHBOR_STR
       "IP address\n"
       "neighbor's bgp version\n"
       "Version\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (strcmp (argv[1], "bgp4") == 0)
    peer->version = BGP_VERSION_4;
  else if (strcmp (argv[1], "bgp4+") == 0)
    peer->version = BGP_VERSION_MP_4;
  else if (strcmp (argv[1], "bgp4+-draft-00") == 0)
    peer->version = BGP_VERSION_MP_4_DRAFT_00;
  else
    vty_out (vty, "bgp version malformed!\r\n");

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_version,
       no_neighbor_version_cmd,
       "no neighbor IP_ADDR version [BGP_VERSION]",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Set neighbor's bgp version to default [bgp4]\n"
       "Version\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  peer->version = BGP_VERSION_4;
  return CMD_SUCCESS;
}

DEFUN (neighbor_router_id,
       neighbor_router_id_cmd,
       "neighbor IP_ADDR router-id IP_ADDR",
       NEIGHBOR_STR
       "IP address\n"
       "Set neighbor's special router-id value\n"
       "IP address\n")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  struct in_addr bgp_ident;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  
  ret = inet_aton (argv[0], &bgp_ident);
  peer->myident = bgp_ident.s_addr;
  if (!ret)
    {
      vty_out (vty, "malformed bgp neighbor router identifier\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* Set route-map to the peer. */
static void
bgp_route_map_set (struct peer *peer, int direct, char *route_map)
{
  if (peer->route_map[direct].name)
    free (peer->route_map[direct].name);
  
  peer->route_map[direct].name = strdup (route_map);
  peer->route_map[direct].map = route_map_lookup_by_name (route_map);
}

/* Unset route-map from the peer. */
static int
bgp_route_map_unset (struct peer *peer, int direct, char *route_map)
{
  if (! peer->route_map[direct].name)
    return 1;

  if (strcmp (peer->route_map[direct].name, route_map) != 0)
    return 2;

  free (peer->route_map[direct].name);
  peer->route_map[direct].name = NULL;
  peer->route_map[direct].map = NULL;

  return 0;
}

/* Set distribute list to the peer. */
static void
bgp_distribute_set (struct peer *peer, int direct, char *alist)
{
  if (peer->distribute[direct].name)
    free (peer->distribute[direct].name);

  peer->distribute[direct].name = strdup (alist);
  peer->distribute[direct].list = access_list_lookup (alist);
}

/* When success return zero. */
static int
bgp_distribute_unset (struct peer *peer, int direct, char *alist)
{
  if (! peer->distribute[direct].name)
    return 1;

  if (strcmp (peer->distribute[direct].name, alist) != 0)
    return 2;

  free (peer->distribute[direct].name);
  peer->distribute[direct].name = NULL;
  peer->distribute[direct].list = NULL;

  return 0;
}

/* Update distribute list. */
void
bgp_distribute_update ()
{
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      struct peer *peer;

      peer = getdata (node);

      /* Input filter update. */
      if (peer->distribute[BGP_FILTER_IN].name)
	peer->distribute[BGP_FILTER_IN].list = 
	  access_list_lookup (peer->distribute[BGP_FILTER_IN].name);
      else
	peer->distribute[BGP_FILTER_IN].list = NULL;

      /* Output filter update. */
      if (peer->distribute[BGP_FILTER_OUT].name)
	peer->distribute[BGP_FILTER_OUT].list = 
	  access_list_lookup (peer->distribute[BGP_FILTER_OUT].name);
      else
	peer->distribute[BGP_FILTER_OUT].list = NULL;
    }
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       "neighbor IP_ADDR distribute-list ALIST_NAME TYPE",
       NEIGHBOR_STR
       "IP address\n"
       "Distribute list\n"
       "Accesslist name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_distribute_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       "no neighbor IP_ADDR distribute-list ALIST_NAME TYPE",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Distribute list\n"
       "Accesslist name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  int ret;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  ret = bgp_distribute_unset (peer, direct, argv[1]);
  if (ret)
    {
      vty_out (vty, "");
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       "neighbor IP_ADDR route-map ROUTE_MAP_NAME DIRECT",
       NEIGHBOR_STR
       "IP address\n"
       "Route map\n"
       "Route map name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       "no neighbor IP_ADDR route-map ROUTE_MAP_NAME DIRECT",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Route map\n"
       "Route map name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]\r\n");
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (neighbor_desc,
       neighbor_desc_cmd,
       "neighbor IP_ADDR description ...",
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description")
{
  int i;
  struct bgp *bgp;
  struct peer *peer;
  struct buffer *b;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (argc == 1)
    return CMD_SUCCESS;

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);

  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 1; i < argc; i++)
    {
      buffer_putstr (b, (u_char *)argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  peer->desc = buffer_getstr (b);
  buffer_free (b);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_desc,
       no_neighbor_desc_cmd,
       "no neighbor IP_ADDR description ...",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);
  peer->desc = NULL;

  return CMD_SUCCESS;
}

DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       "neighbor IP_ADDR shutdown",
       NEIGHBOR_STR
       "IP address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  bgp_stop (peer);
  fsm_change_status (peer, Idle);
  
  peer->shutdown = 1;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       "no neighbor IP_ADDR shutdown",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  bgp_timer_set (peer);
  peer->shutdown = 0;

  return CMD_SUCCESS;
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       "neighbor IP_ADDR interface IFNAME",
       NEIGHBOR_STR
       "IP address\n"
       "Interface\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  peer->ifname = strdup (argv[1]);

  return CMD_SUCCESS;
}

/* Make peer and enable further neighbor configuration. */
DEFUN (neighbor, 
       neighbor_cmd, 
       "neighbor IP_ADDR remote-as AS_NO [passive]",
       NEIGHBOR_STR
       "IP address\n"
       "Remote AS\n"
       "AS number\n"
       "Passive\n")
{
  struct bgp *bgp;
  struct peer *peer;
  u_int16_t as;
  union sockunion *su;

  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  /* If there is already same IP_ADDR peer, only change AS_NO. */
  if (peer)
    {
      /* Change of AS_NO. */

      /* If peer is established then clear it's peer and clear all
         resources and make it again. */

      /* XXXXX*/
      return CMD_WARNING;
    }

  /* This is new neighbor. */
  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed IP address.\r\n");
      return CMD_WARNING;
    }

  as = strtol (argv[1], NULL, 10);
  if (as == 0)
    {
      vty_out (vty, "AS path value malformed.\r\n");
      return CMD_WARNING;
    }

  /* Create peer. */
  peer = peer_new ();
  list_add_node (bgp->peer , peer);
  list_add_node (peer_list, peer);

  peer->bgp = bgp;
  peer->as = as;
  peer->su = su;
  peer->host = sockunion_su2str (su);
  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    peer->ttl = 255;
  else
    peer->ttl = 1;
  peer->fd = -1;

  /* If this peer is in passive mode star it in Active mode. */
  if (argc == 3 && (strcmp (argv[2], "passive") == 0))
    peer->status = Active;
  else
    peer->status = Idle;

  /* Setup timer. */
  bgp_timer_set (peer);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor IP_ADDR remote-as AS_NO",
       NO_STR
       NEIGHBOR_STR
       "IP Address\n"
       "Remote AS number\n"
       "AS number\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  /* There is no matched peer. */
  if (peer == NULL)
    {
      vty_out (vty, "Can't find peer %s.\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Check AS number. */
  if (peer->as != atoi (argv[1]))
    {
      vty_out (vty, "Different AS number for the peer %s.\r\n", argv[0]);
      return CMD_WARNING;
    }

  /* Now delete from the neighbor from lists. */
  list_delete_by_val (bgp->peer, peer);
  list_delete_by_val (peer_list, peer);

  /* Clear routes and deallocate peer structure. */
  bgp_stop (peer);
  peer_delete (peer);

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp,
       clear_ip_bgp_cmd, 
       "clear ip bgp IPADDR",
       "Reset functions\n"
       IP_STR
       BGP_STR
       "IP address\n")
{
  int cleared;
  struct bgp *bgp;
  struct peer *peer;
  listnode bgp_node;
  listnode peer_node;

  if (argc != 1)
    {
      vty_out (vty, "please specify neighbor's address\r\n");
      return CMD_WARNING;
    }

  /* Clear all bgp neighbor. */
  if (strcmp (argv[0], "*") == 0)
    {
      for (bgp_node = listhead (bgp_list); bgp_node; nextnode(bgp_node))
	{
	  bgp = getdata (bgp_node);
	  for (peer_node = listhead (bgp->peer); peer_node; 
	       nextnode (peer_node))
	    {
	      peer = getdata (peer_node);
	      BGP_EVENT_ADD (peer, BGP_Stop);
	    }
	}
      vty_out (vty, "All bgp neighbor cleared.\r\n");
      return CMD_WARNING;
    }

  /* Clear one bgp neighbor. */
  cleared = 0;

  for (bgp_node = listhead (bgp_list); bgp_node; nextnode (bgp_node))
    {
      bgp = getdata (bgp_node);
      peer = peer_lookup_from_bgp (bgp, argv[0]);
      if (peer)
	{
	  BGP_EVENT_ADD (peer, BGP_Stop);
	  cleared = 1;
	}
    }

  if (cleared)
    vty_out (vty, "Peer %s cleared.\r\n", argv[0]);
  else
    vty_out (vty, "Can't find peer %s.\r\n", argv[0]);

  return CMD_SUCCESS;
}

/* BGP peer configuration output function. */
void
bgp_peer_config_write (struct vty *vty, list bgp_peer)
{
  listnode node;
  struct peer *peer;

  for (node = listhead (bgp_peer); node; nextnode (node))
    {
      peer = getdata (node);

      /* remote-as print. */
      vty_out (vty, " neighbor ");
      sockunion_vty_out (vty, peer->su);
      vty_out (vty, " remote-as %d%s", peer->as, VTY_NEWLINE);

      /* Shutdown or not. */
      if (peer->shutdown)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " shutdown%s", VTY_NEWLINE);
	}

      /* Description. */
      if (peer->desc)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " description %s%s", peer->desc, VTY_NEWLINE);
	}

      /* BGP version print. */
      if (peer->version != BGP_VERSION_4)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  if (peer->version == BGP_VERSION_MP_4)
	    vty_out (vty, " version %s%s", "bgp4+", VTY_NEWLINE);
	  else if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
	    vty_out (vty, " version %s%s", "bgp4+-draft-00", VTY_NEWLINE);
	  else
	    vty_out (vty, " unknown version%s", VTY_NEWLINE);
	}

      /* ebgp-multihop print. */
      if (bgp_peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);

	  if (peer->ttl == TTL_MAX)
	    vty_out (vty, " ebgp-multihop%s", VTY_NEWLINE);
	  else
	    vty_out (vty, " ebgp-multihop %d%s", peer->ttl, VTY_NEWLINE);
	}

      /* distribute-list print. */
      if (peer->distribute[BGP_FILTER_IN].name)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " distribute-list %s in%s", 
		   peer->distribute[BGP_FILTER_IN].name, VTY_NEWLINE);
	}
      if (peer->distribute[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " distribute-list %s out%s", 
		   peer->distribute[BGP_FILTER_OUT].name, VTY_NEWLINE);
	}

      /* route-map print. */
      if (peer->route_map[BGP_FILTER_IN].name)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " route-map %s in%s", 
		   peer->route_map[BGP_FILTER_IN].name, VTY_NEWLINE);
	}
      if (peer->route_map[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " route-map %s out%s", 
		   peer->route_map[BGP_FILTER_OUT].name, VTY_NEWLINE);
	}
    }
}

/* BGP configuration write function. */
int
bgp_config_write (struct vty *vty)
{
  listnode node;
  struct bgp *bgp; 
  int config_write_network (struct vty *vty, struct bgp *bgp);

  /* BGP Multiple instance. */
  if (bgp_multiple_instance)
    {    
      vty_out (vty, "bgp multiple-instance%s", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  /* BGP neighbor's configuration. */
  for (node = listhead (bgp_list); node; nextnode (node))
    {
      bgp = getdata (node);

      vty_out (vty, "router bgp %d%s", bgp->as, VTY_NEWLINE);
      if (bgp->config & BGP_CONFIG_ROUTER_ID)
	{
	  struct in_addr ident;
	  ident.s_addr = bgp->ident;
	  vty_out (vty, " bgp router-id %s%s", inet_ntoa (ident), 
		   VTY_NEWLINE);
	}
      config_write_network (vty, bgp);
      bgp_peer_config_write (vty, bgp->peer);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

/* BGP node structure. */
struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

/* Install bgp related commands. */
void
bgp_init ()
{
  /* Install bgp top node. */
  install_node (&bgp_node, bgp_config_write);

  /* Install bgp commands. */
  install_element (VIEW_NODE, &show_ip_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_cmd);
  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &no_router_bgp_cmd);
  install_element (CONFIG_NODE, &bgp_multiple_instance_cmd);
  install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd);
  install_element (BGP_NODE, &config_end_cmd);
  install_element (BGP_NODE, &config_exit_cmd);
  install_element (BGP_NODE, &config_help_cmd);
  install_element (BGP_NODE, &neighbor_cmd);
  install_element (BGP_NODE, &no_neighbor_cmd);
  install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &bgp_router_id_cmd);
  install_element (BGP_NODE, &neighbor_version_cmd);
  install_element (BGP_NODE, &no_neighbor_version_cmd);
  install_element (BGP_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_NODE, &neighbor_desc_cmd);
  install_element (BGP_NODE, &no_neighbor_desc_cmd);
  install_element (BGP_NODE, &neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_neighbor_shutdown_cmd);
  install_element (BGP_NODE, &neighbor_interface_cmd);

  /* Make empty list of bgp and peer list. */
  bgp_list = list_init ();
  peer_list = list_init ();

  /* BGP multiple instance. */
  bgp_multiple_instance = 0;

  /* Init zebra. */
  zebra_init ();

  /* BGP inits. */
  bgp_attr_init ();
  bgp_dump_init ();
  bgp_route_init ();
  bgp_route_map_init ();

  /* Access list initialize. */
  access_list_init ();
  access_list_add_hook (bgp_distribute_update);
  access_list_delete_hook (bgp_distribute_update);
}
