/* BGP-4, BGP-4+ daemon program
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
#include "plist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_open.h"

/* List head of bgp instance list. */
list bgp_list;

/* List of all bgp peer. */
list peer_list;

/* BGP multiple instance option. */
char bgp_multiple_instance;

/* Top node of bgpd's routing table. */
extern struct route_table *bgp_table_ipv4;
#ifdef HAVE_IPV6
extern struct route_table *bgp_table_ipv6;
#endif /* HAVE_IPV6 */
#ifdef HAVE_MBGPV4 
extern struct route_table *mbgp_table_ipv4;
#endif /* HAVE_MBGPV4 */

#define min(a, b) ((a) < (b) ? (a) : (b))

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

  for (node = listhead (bgp_list); node; nextnode (node))
    {
      bgp = getdata (node);
      if (bgp->as == as)
	return bgp;
    }
  return NULL;
}

void
bgp_delete (struct bgp *bgp)
{
  struct peer *peer;
  listnode node;

  for (node = listhead (bgp->peer); node; nextnode (node))
    {
      peer = getdata (node);

      bgp_stop (peer);
      list_delete_by_val (peer_list, peer);
      peer_delete (peer);
    }

  list_delete_all (bgp->peer);
  list_delete_by_val (bgp_list, bgp);
  free (bgp);
}



/* RFC1771 6.8 Connection collision detection. */
int
bgp_collision_detect (struct peer *newpeer)
{
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      struct peer *peer;

      peer = getdata (node);

      /* Upon receipt of an OPEN message, the local system must
	 examine all of its connections that are in the OpenConfirm
	 state.  A BGP speaker may also examine connections in an
	 OpenSent state if it knows the BGP Identifier of the peer by
	 means outside of the protocol.  If among these connections
	 there is a connection to a remote BGP speaker whose BGP
	 Identifier equals the one in the OPEN message, then the local
	 system performs the following collision resolution procedure: */

      if (newpeer != peer &&
	  peer->status == OpenConfirm &&
	  newpeer->ident == peer->ident)
	{
	  /* 1. The BGP Identifier of the local system is compared to
	     the BGP Identifier of the remote system (as specified in
	     the OPEN message). */

	  if (peer->bgp->ident < newpeer->ident)
	    {
	      /* 2. If the value of the local BGP Identifier is less
		 than the remote one, the local system closes BGP
		 connection that already exists (the one that is
		 already in the OpenConfirm state), and accepts BGP
		 connection initiated by the remote system. */
	      bgp_notify_send (peer, BGP_NOTIFY_CEASE, 0);
	      return 0;
	    }
	  else
	    {
	      /* 3. Otherwise, the local system closes newly created
		 BGP connection (the one associated with the newly
		 received OPEN message), and continues to use the
		 existing one (the one that is already in the
		 OpenConfirm state). */
	      bgp_notify_send (newpeer, BGP_NOTIFY_CEASE, 0);
	      return 1;
	    }
	}
    }
  return 0;
}

#ifdef NEW_CODE
/* Peer creation by remote-as. */
int
bgp_peer_remote_as (struct bgp *bgp, char *peer_str, char *as_str, 
		    int afi, int safi)
{
  return 0;
}

/* Peer address family update by activate. */
int
bgp_peer_activate (struct peer *peer)
{
  return 0;
}
#endif /* NEW_CODE */

/* allocate new peer object */
struct peer *
peer_new ()
{
  struct peer *peer;
  struct servent *sp;

  /* Allocate new peer. */
  peer = XMALLOC (MTYPE_BGP_PEER, sizeof (struct peer));
  bzero (peer, sizeof (struct peer));

  /* Set default value. */
  peer->fd = -1;
  peer->v_start = BGP_INIT_START_TIMER;
  peer->v_connect = BGP_DEFAULT_CONNECT_RETRY;
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME;
  peer->v_keepalive = BGP_DEFAULT_KEEPALIVE;
  peer->status = Idle;
  peer->ostatus = Idle;
  peer->version = BGP_VERSION_4;
  peer->prefix_count = 0;
#ifdef HAVE_MBGPV4
  peer->prefix_count_multicastv4 = 0;
  peer->translate_update  = TRANSLATE_UPDATE_OFF;
#endif  
  peer->ibuf = stream_new (BGP_MAX_PACKET_SIZE);
  peer->capability_open = 1;

  /* Get service port number. */
  sp = getservbyname ("bgp", "tcp");
  peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs(sp->s_port);

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
  if (peer->su_remote)
    XFREE (MTYPE_TMP, peer->su_remote);
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

#if 0
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
#endif /* 0 */

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
  uptime = time (NULL);
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

struct peer *
peer_lookup_with_family (struct bgp *bgp, char *peer_name, int family)
{
  struct peer *peer;

  peer = peer_lookup_from_bgp (bgp, peer_name);

  if (! peer || peer->family != family)
    return NULL;
  else
    return peer;
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
      vty_out (vty, "There are more than two active bgp instances.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  bgp_multiple_instance = 0;
  return CMD_SUCCESS;
}

/* router bgp AS number command.*/
DEFUN (router_bgp, 
       router_bgp_cmd, 
       "router bgp <1-65535>",
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

  if (! bgp_multiple_instance && ! list_isempty (bgp_list))
    {
      bgp = getdata (listhead (bgp_list));
      
      vty_out (vty, "bgp is already running: AS is %d.%s", bgp->as, VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Make new bgp instance. */
  bgp = bgp_new (as);

  /* Set current bgp point. */
  vty->node = BGP_NODE;
  vty->index = bgp;

  return CMD_SUCCESS;
}

/* no router bgp AS number command.*/
DEFUN (no_router_bgp, 
       no_router_bgp_cmd, 
       "no router bgp <1-65535>",
       NO_STR
       "Disable a routing process\n"
       "Disable BGP configuration\n"
       "AS number\n")
{
  struct bgp *bgp;
  u_int16_t as;

  /* Check duplicate instance as same AS value. */
  as = strtol (argv[0], NULL, 10);

  /* Check existing bgp. */
  bgp = bgp_lookup_by_as (as);

  /* There is already active bgp instance. */
  if (bgp == NULL)
    {
      vty_out (vty, "There is no active bgp with AS number: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Delete all peer and bgp structure itself. */
  bgp_delete (bgp);

  return CMD_SUCCESS;
}

DEFUN (bgp_router_id, bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Set my own router identifier\n"
       "Router ID\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr bgp_ident;

  bgp = (struct bgp *) vty->index;
  
  ret = inet_aton (argv[0], &bgp_ident);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp->ident = bgp_ident.s_addr;
  bgp->config |= BGP_CONFIG_ROUTER_ID;

  return CMD_SUCCESS;
}

DEFUN (no_bgp_router_id, no_bgp_router_id_cmd,
       "no bgp router-id A.B.C.D",
       NO_STR
       BGP_STR
       "Set my own router identifier\n"
       "Router ID\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr bgp_ident;

  bgp = (struct bgp *) vty->index;
  
  ret = inet_aton (argv[0], &bgp_ident);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (bgp->ident != bgp_ident.s_addr)
    {
      vty_out (vty, "bgp router ID doesn't match exist one%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp->ident = 0;
  bgp->config &= ~BGP_CONFIG_ROUTER_ID;

  bgp_if_update_all ();

  return CMD_SUCCESS;
}

DEFUN (bgp_cluster_id, bgp_cluster_id_cmd,
       "bgp cluster-id A.B.C.D",
       BGP_STR
       "Set cluster identifier\n"
       "Cluster identifier\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr bgp_cluster;

  bgp = (struct bgp *) vty->index;

  ret = inet_aton (argv[0], &bgp_cluster);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp cluster identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp->cluster = bgp_cluster.s_addr;
  bgp->config |= BGP_CONFIG_CLUSTER_ID;

  return CMD_SUCCESS;
}

DEFUN (no_bgp_cluster_id, no_bgp_cluster_id_cmd,
       "no bgp cluster-id A.B.C.D",
       NO_STR
       BGP_STR
       "Set cluster identifier\n"
       "Cluster identifier\n")
{
  int ret;
  struct bgp *bgp;
  struct in_addr bgp_cluster;

  bgp = (struct bgp *) vty->index;

  ret = inet_aton (argv[0], &bgp_cluster);
  if (!ret)
    {
      vty_out (vty, "Malformed bgp cluster identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (bgp->cluster !=  bgp_cluster.s_addr)
    {
      vty_out (vty, "bgp cluster ID doesn't match exist one%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp->cluster = 0;
  bgp->config &= ~BGP_CONFIG_CLUSTER_ID;

  return CMD_SUCCESS;
}

void
bgp_peer_display (struct vty *vty, struct peer *p)
{
  char buf[BUFSIZ];

  vty_out (vty, "%-15s ", p->host);
  switch (p->version) 
    {
    case BGP_VERSION_4:
      vty_out (vty, "4  ");
      break;
    case BGP_VERSION_MP_4:
      vty_out (vty, "4+ ");
      break;
    case BGP_VERSION_MP_4_DRAFT_00:
      vty_out (vty, "4- ");
      break;
    }
  vty_out(vty, "%5d %7d %7d %8d %4d %4d ", p->as,
	  p->open_in+p->update_in+p->withdrow_in+p->keepalive_in,
	  p->open_out+p->update_out+p->withdrow_out+p->keepalive_out,
	  0, 0, 0);

  peer_uptime_vty (vty, p);
  vty_out (vty, "%s", VTY_NEWLINE);

  /* Description. */
  if (p->desc)
    vty_out (vty, "  Description: %s%s", p->desc, VTY_NEWLINE);

  /* Remote router ID */
  {
    struct in_addr bgp_ident;
    bgp_ident.s_addr = p->ident;
    vty_out (vty, "  Remote router ID %s%s", 
	     inet_ntoa (bgp_ident), VTY_NEWLINE);
  }

  /* Local address. */
  vty_out (vty, "  Local address: ");
  if (p->su_local)
    sockunion_vty_out (vty, p->su_local);
  else
    vty_out (vty, "None");

  /* Remote address. */
  vty_out (vty, "  Remote address: ");
  if (p->su_remote)
    sockunion_vty_out (vty, p->su_remote);
  else
    vty_out (vty, "None");
  vty_out (vty, "%s", VTY_NEWLINE);

  /* Nexthop display. */
  if (p->su_local)
    {
      vty_out (vty, "  Nexthop: %s%s", inet_ntop (AF_INET, &p->nexthop.v4,
						  buf, BUFSIZ),
	       VTY_NEWLINE);
#ifdef HAVE_IPV6
      vty_out (vty, "  Nexthop global: %s", 
	       inet_ntop (AF_INET6, &p->nexthop.v6_global, buf, BUFSIZ));
      vty_out (vty, "  Nexthop local: %s%s",
	       inet_ntop (AF_INET6, &p->nexthop.v6_local, buf, BUFSIZ),
	       VTY_NEWLINE);
      vty_out (vty, "  BGP connection: %s%s",
	       p->shared_network ? "shared network" : "not shared network",
	       VTY_NEWLINE);
#endif /* HAVE_IPV6 */
    }

  vty_out (vty,
	   "  Status: %-12s keepalive: %d holdtime: %d"
	   "%s  open: in/out %d/%d"
	   "  update: in/out %d+%d/%d+%d"
	   "  keepalive: in/out %d/%d%s",
	   LOOKUP (bgp_status_msg, p->status),
	   p->v_keepalive, p->v_holdtime,
	   VTY_NEWLINE,
	   p->open_in, p->open_out,
	   p->update_in, p->withdrow_in,
	   p->update_out, p->withdrow_out,
	   p->keepalive_in, p->keepalive_out,
	   VTY_NEWLINE
	   );

  /* Prefix count. */
  if (p->status == Established) {
#ifdef HAVE_MBGPV4
    vty_out (vty, "  Received prefix count unicast/multicast :%9d/%d%s", 
	     p->prefix_count,  p->prefix_count_multicastv4, VTY_NEWLINE);
#else
    vty_out (vty, "  Received prefix count: %d%s", p->prefix_count, 
	     VTY_NEWLINE);
#endif
  }
  vty_out (vty, "  read thread: %s  write thread: %s%s", 
	   p->t_read ? "on" : "off",
	   p->t_write ? "on" : "off",
	   VTY_NEWLINE);

  if (p->distribute[BGP_FILTER_IN].name)
    vty_out (vty, "  distribute-list in: %s%s%s",
	     p->distribute[BGP_FILTER_IN].list ? "*" : "",
	     p->distribute[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (p->distribute[BGP_FILTER_OUT].name)
    vty_out (vty, "  distribute-list out: %s%s%s",
	     p->distribute[BGP_FILTER_OUT].list ? "*" : "",
	     p->distribute[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);

  if (p->plist[BGP_FILTER_IN].name)
    vty_out (vty, "  prefix-list in: %s%s%s",
	     p->plist[BGP_FILTER_IN].plist ? "*" : "",
	     p->plist[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (p->plist[BGP_FILTER_OUT].name)
    vty_out (vty, "  prefix-list out: %s%s%s",
	     p->plist[BGP_FILTER_OUT].plist ? "*" : "",
	     p->plist[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);


  if (p->filter[BGP_FILTER_IN].name)
    vty_out (vty, "  filter-list in: %s%s%s",
	     p->filter[BGP_FILTER_IN].filter ? "*" : "",
	     p->filter[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (p->filter[BGP_FILTER_OUT].name)
    vty_out (vty, "  filter-list out: %s%s%s",
	     p->filter[BGP_FILTER_OUT].filter ? "*" : "",
	     p->filter[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);

  if (p->route_map[BGP_FILTER_IN].name)
    vty_out (vty, "  route-map in: %s%s%s",
	     p->route_map[BGP_FILTER_IN].map ? "*" : "",
	     p->route_map[BGP_FILTER_IN].name,
	     VTY_NEWLINE);
  if (p->route_map[BGP_FILTER_OUT].name)
    vty_out (vty, "  route-map out: %s%s%s",
	     p->route_map[BGP_FILTER_OUT].map ? "*" : "",
	     p->route_map[BGP_FILTER_OUT].name,
	     VTY_NEWLINE);

  if (p->ipv4_unicast_conf ||  p->ipv4_multicast_conf) {
    
    vty_out (vty, " Neighbor NLRI negotiation:%s", VTY_NEWLINE);
      if(p->ipv4_unicast_conf) 
	vty_out(vty, "  Configured for unicast ");
    
    if(p->ipv4_unicast_conf &&  p->ipv4_multicast_conf) 
      vty_out(vty, "and multicast ");
    else if( p->ipv4_multicast_conf) 
      vty_out(vty, "  Configured for multicast ");
    vty_out(vty, "routes%s", VTY_NEWLINE);
  }

  if(p->ipv4_unicast ||  p->ipv4_multicast) {
      if(p->ipv4_unicast) 
	vty_out(vty, "  Peer negotiated unicast ");
    
    if(p->ipv4_unicast &&  p->ipv4_multicast) 
      vty_out(vty, "and multicast ");
    else if( p->ipv4_multicast) 
      vty_out(vty, "  Peer negotiated multicast ");
    vty_out(vty, "routes%s", VTY_NEWLINE);
  }

  if (p->notify_data)
    bgp_capability_vty_out (vty, p);
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

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down.%s", VTY_NEWLINE);

  if (argc == 1)
    {
      p = peer_lookup_by_host (argv[0]);
      if (! p || p->family != AF_INET)
	{
	  vty_out (vty, "can't find neighbor %s%s", argv[0],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      bgp_peer_display (vty, p);
    }
  else
    {
      for (node = listhead (peer_list); node; nextnode (node))
	{
	  p = getdata (node);
	  if (p->family != AF_INET)
	    continue;
	  bgp_peer_display (vty, p);
	}
    }

  return CMD_SUCCESS;
}

#ifdef HAVE_MBGPV4 
DEFUN (show_ip_mbgp_neighbors,
       show_ip_mbgp_neighbors_cmd,
       "show ip mbgp neighbors [PEER]",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and MBGP neighbor connections\n"
       "\n")
{
  struct peer *p;
  listnode node;

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down.\r\n");

  if (argc == 1)
    {
      p = peer_lookup_by_host (argv[0]);
      if (! p)
	{
	  vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
	  return CMD_WARNING;
	}
      if(p->ipv4_multicast)
      bgp_peer_display (vty, p);
    }
  else
    {
      for (node = listhead (peer_list); node; nextnode (node))
	{
	  p = getdata (node);
	  if(p->ipv4_multicast)
	  bgp_peer_display (vty, p);
	}
    }

  return CMD_SUCCESS;
}
#endif /* HAVE_MBGPV4 */

#if 0
newlist *
peer_list_afi (struct bgp *bgp, int afi)
{
  if (afi == AFI_IP)
    return bgp->peer_v4;
  else if (afi == AFI_IP6)
    return bgp->peer_v6;
  else
    return NULL;
}

int
peer_config_afi (struct peer *peer, int afi, int safi)
{
  if (afi == AFI_IP)
    {
      if ((safi == SAFI_UNICAST && peer->ipv4_unicast_conf) ||
	  (safi == SAFI_MULTICAST && peer->ipv4_multicast_conf))
	return 1;
      else
	return 0;
    }
  else if (afi == AF_IP6)
    {
      if ((safi == SAFI_UNICAST && peer->ipv6_unicast_conf) ||
	  (safi == SAFI_MULTICAST && peer->ipv6_multicast_conf))
	return 1;
      else
	return 0;
    }
  else
    return 0;
}

/* Show neighbor summary information.
   Called from `show ip bgp summary'
               `show ip mbgp summary'
               `show ipv6 bgp summary'. */
int
bgp_show_summary (struct vty *vty, int afi, int safi)
{
  struct bgp *bgp;
  struct peer *peer;
  newnode *ll, *lm;
  int write = 0;

  /* Header string for each address family. */
  static char sum_header_ipv4[] = "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/Pref";
  static char sum_header_ipv6[] = "Neighbor                       AS       MsgRcvd MsgSent  Up/Down  State/Pref";

  LIST_LOOP (bgp_all, ll)
    {
      bgp = listdata (ll);

      LIST_LOOP (peer_list_afi (bgp, afi), lm)
	{
	  peer = listdata (lm);

	  if (peer_config_afi (peer, afi, safi))
	    {
	      if (! write)
		{
		  vty_out (vty, "%s%s",
			   afi == AFI_IP : sum_header_ipv4 ? sum_header_ipv6,
			   VTY_NEWLINE);
		  write++;
		}
	      ;
	    }
	}
    }

  if (! write)
    vty_out (vty, "No %s neighbor is configured%s",
	     afi == AFI_IP : "IPv4" ? "IPv6", VTY_NEWLINE);
}
#endif /* 0 */

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
  int first = 1;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      int length;
      peer = getdata (node);
	  
      if (peer->family != AF_INET)
	continue;

      if (first)
	{
	  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent"
		   "   TblVer  InQ OutQ Up/Down  State/Pref%s", VTY_NEWLINE);
	  first = 0;
	}

      length = sockunion_vty_out (vty, peer->su);
      length = 16 - length;
      if (length < 0)
	length = 0;

      vty_out (vty, "%*s", length, " ");
      switch (peer->version) 
	{
	case BGP_VERSION_4:
	  vty_out (vty, "%d ", peer->version);
	  break;
	case BGP_VERSION_MP_4:
	  vty_out (vty, "4+");
	  break;
	case BGP_VERSION_MP_4_DRAFT_00:
	  vty_out (vty, "4-");
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
	vty_out (vty, " %9d%s", peer->prefix_count,
		 VTY_NEWLINE);
      else
	vty_out (vty, " %-11s%s", LOOKUP(bgp_status_msg, peer->status),
		 VTY_NEWLINE);
    }

  if (first)
    vty_out (vty, "No IPv4 neighbor is configured%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

#ifdef HAVE_MBGPV4
DEFUN (show_ip_mbgp_summary, 
       show_ip_mbgp_summary_cmd,
       "show ip mbgp summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of MBGP neighbor status\n")
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
      length = 16 - length;
      if (length < 0)
	length = 0;

      vty_out (vty, "%*s", length, " ");
      switch (peer->version) 
	{
	case BGP_VERSION_4:
	  vty_out (vty, "%d ", peer->version);
	  break;
	case BGP_VERSION_MP_4:
	  vty_out (vty, "4+");
	  break;
	case BGP_VERSION_MP_4_DRAFT_00:
	  vty_out (vty, "4-");
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
	vty_out (vty, " %9d\r\n", peer->prefix_count_multicastv4);
      else
	vty_out (vty, " %-11s\r\n", LOOKUP(bgp_status_msg, peer->status));
    }
  return CMD_SUCCESS;

}
#endif /* HAVE_MBGPV4 */

DEFUN (show_ip_bgp_paths, 
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "AS path statistics\n")
{
  vty_out (vty, "Address Refcnt Path%s", VTY_NEWLINE);
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}

#ifdef HAVE_MBGPV4
DEFUN (show_ip_mbgp_paths, 
       show_ip_mbgp_paths_cmd,
       "show ip mbgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "AS path statistics\n")
{
  vty_out (vty, "Address Refcnt Path\r\n");
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}
#endif /* HAVE_MBGPV4 */

DEFUN (show_ip_bgp_community, 
       show_ip_bgp_community_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
  vty_out (vty, "Address Refcnt Community%s", VTY_NEWLINE);
  community_print_all_vty (vty);

  return CMD_SUCCESS;
}

#ifdef HAVE_MBGPV4 
DEFUN (show_ip_mbgp_community, 
       show_ip_mbgp_community_cmd,
       "show ip mbgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all mbgp community information\n")
{
  vty_out (vty, "Address Refcnt Community\r\n");
  community_print_all_vty (vty);

  return CMD_SUCCESS;
}
#endif /* HAVE_MBGPV4 */

DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       "neighbor PEER ebgp-multihop [TTL]",
       NEIGHBOR_STR
       "IP address\n"
       "Change TTL value of BGP connection\n"
       "TTL\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;

  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);
  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    peer->ttl = atoi (argv[1]);
  else
    peer->ttl = TTL_MAX;

  if (peer->ttl == 0)
    {
      vty_out (vty, "please specify plus integer value.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->fd >= 0)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

/* Set specified peer's BGP version.  This is */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       "neighbor PEER port PORT",
       NEIGHBOR_STR
       "IP address\n"
       "Neighbor's BGP port\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long port = 0;
  char *endptr = NULL;
  struct servent *sp;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (argc < 1)
    { 
      sp = getservbyname ("bgp", "tcp");
      peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);
    }
  else
    {
      port = strtoul (argv[1], &endptr, 10);
      if (port == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "port value error\r\n");
	  return CMD_WARNING;
	}

      if (port > 65535)
	{
	  vty_out (vty, "port value error\r\n");
	  return CMD_WARNING;
	}
    }

  /* Set peer port */
  peer->port = port;

  return CMD_SUCCESS;
}

DEFUN (neighbor_router_id,
       neighbor_router_id_cmd,
       "neighbor PEER router-id A.B.C.D",
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  ret = inet_aton (argv[0], &bgp_ident);
  peer->myident = bgp_ident.s_addr;
  if (!ret)
    {
      vty_out (vty, "malformed bgp neighbor router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       "neighbor PEER route-reflector-client",
       NEIGHBOR_STR
       "IP address\n"
       "Configure this neighbor as route reflector client\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (! peer->reflector_client)
    {
      bgp->reflector_cnt++;
      peer->reflector_client = 1;

      BGP_EVENT_ADD (peer, BGP_Stop);
    }

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       "no neighbor PEER route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Configure this neighbor as route reflector client\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->reflector_client)
    {
      bgp->reflector_cnt--;
      peer->reflector_client = 0;

      BGP_EVENT_ADD (peer, BGP_Stop);
    }

  return CMD_SUCCESS;
}

DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       "neighbor PEER send-community",
       NEIGHBOR_STR
       "IP address\n"
       "Configure send community attribute to this neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->send_community = 1;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       "no neighbor PEER send-community",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Configure send community attribute to this neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->send_community = 0;

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

static void
bgp_filter_set (struct peer *peer, int direct, char *flist)
{
  struct as_list *as_list_lookup (char *name);

  if (peer->filter[direct].name)
    free (peer->filter[direct].name);

  peer->filter[direct].name = strdup (flist);
  peer->filter[direct].filter = as_list_lookup (flist);
}

static int
bgp_filter_unset (struct peer *peer, int direct, char *flist)
{
  if (! peer->filter[direct].name)
    return 1;

  if (strcmp (peer->filter[direct].name, flist) != 0)
    return 2;

  free (peer->filter[direct].name);
  peer->filter[direct].name = NULL;
  peer->filter[direct].filter = NULL;

  return 0;
}

void
bgp_filter_update ()
{
  struct as_list *as_list_lookup (char *name);
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      struct peer *peer;

      peer = getdata (node);

      /* Input filter update. */
      if (peer->filter[BGP_FILTER_IN].name)
	peer->filter[BGP_FILTER_IN].filter = 
	  as_list_lookup (peer->filter[BGP_FILTER_IN].name);
      else
	peer->filter[BGP_FILTER_IN].filter = NULL;

      /* Output filter update. */
      if (peer->filter[BGP_FILTER_OUT].name)
	peer->filter[BGP_FILTER_OUT].filter = 
	  as_list_lookup (peer->filter[BGP_FILTER_OUT].name);
      else
	peer->filter[BGP_FILTER_OUT].filter = NULL;
    }
}

static void
bgp_prefix_list_set (struct peer *peer, int direct, char *alist)
{
  if (peer->plist[direct].name)
    free (peer->plist[direct].name);

  peer->plist[direct].name = strdup (alist);
  peer->plist[direct].plist = prefix_list_lookup (peer->family, alist);
}

static int
bgp_prefix_list_unset (struct peer *peer, int direct, char *alist)
{
  if (! peer->plist[direct].name)
    return 1;

  if (strcmp (peer->plist[direct].name, alist) != 0)
    return 2;

  free (peer->plist[direct].name);
  peer->plist[direct].name = NULL;
  peer->plist[direct].plist = NULL;

  return 0;
}

void
bgp_prefix_list_update ()
{
  listnode node;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      struct peer *peer;

      peer = getdata (node);

      /* Input filter update. */
      if (peer->plist[BGP_FILTER_IN].name)
	peer->plist[BGP_FILTER_IN].plist = 
	  prefix_list_lookup (peer->family,
			      peer->plist[BGP_FILTER_IN].name);
      else
	peer->plist[BGP_FILTER_IN].plist = NULL;

      /* Output filter update. */
      if (peer->plist[BGP_FILTER_OUT].name)
	peer->plist[BGP_FILTER_OUT].plist = 
	  prefix_list_lookup (peer->family,
			      peer->plist[BGP_FILTER_OUT].name);
      else
	peer->plist[BGP_FILTER_OUT].plist = NULL;
    }
}

/* Set distribute list to the peer. */
static void
bgp_distribute_set (struct peer *peer, int direct, char *alist)
{
  if (peer->distribute[direct].name)
    free (peer->distribute[direct].name);

  peer->distribute[direct].name = strdup (alist);
  peer->distribute[direct].list = 
    access_list_lookup (peer->family, alist);
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
	  access_list_lookup (peer->family,
			      peer->distribute[BGP_FILTER_IN].name);
      else
	peer->distribute[BGP_FILTER_IN].list = NULL;

      /* Output filter update. */
      if (peer->distribute[BGP_FILTER_OUT].name)
	peer->distribute[BGP_FILTER_OUT].list = 
	  access_list_lookup (peer->family,
			      peer->distribute[BGP_FILTER_OUT].name);
      else
	peer->distribute[BGP_FILTER_OUT].list = NULL;
    }
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       "neighbor PEER filter-list FLIST_NAME (in|out)",
       NEIGHBOR_STR
       "IP address\n"
       "Filter list\n"
       "as-path filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_filter_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       "no neighbor PEER filter-list FLIST_NAME (in|out)",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Filter list\n"
       "as-path filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_filter_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       "neighbor PEER prefix-list PLIST_NAME (in|out)",
       NEIGHBOR_STR
       "IP address\n"
       "Prefix list\n"
       "Prefix based filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set prefix list to the peer. */
  bgp_prefix_list_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       "no neighbor PEER prefix-list FLIST_NAME (in|out)",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Prefix list\n"
       "Prefix based filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_prefix_list_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       "neighbor PEER distribute-list ALIST_NAME (in|out)",
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_distribute_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       "no neighbor PEER distribute-list ALIST_NAME (in|out)",
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
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
       "neighbor PEER route-map ROUTE_MAP_NAME (in|out)",
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       "no neighbor PEER route-map ROUTE_MAP_NAME (in|out)",
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (neighbor_desc,
       neighbor_desc_cmd,
       "neighbor PEER description .DESCRIPTION",
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description strings\n")
{
  int i;
  struct bgp *bgp;
  struct peer *peer;
  struct buffer *b;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
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
       "no neighbor PEER description .DESCRIPTION",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description strings\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);
  peer->desc = NULL;

  return CMD_SUCCESS;
}

DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       "neighbor PEER shutdown",
       NEIGHBOR_STR
       "IP address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_stop (peer);
  fsm_change_status (peer, Idle);
  
  peer->shutdown = 1;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       "no neighbor PEER shutdown",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_timer_set (peer);
  peer->shutdown = 0;

  return CMD_SUCCESS;
}

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       "neighbor PEER update-source IFNAME",
       NEIGHBOR_STR
       "IP address\n"
       "Update source\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->update_source = sockunion_str2su (argv[1]);

  if (peer->update_source == NULL)
    {
      peer->update_if = strdup (argv[1]);
      if (peer->update_source)
	{
	  free (peer->update_source);
	  peer->update_source = NULL;
	}
      return CMD_SUCCESS;
    }

  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       "no neighbor PEER update-source",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Update source\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->update_source)
    {
      free (peer->update_source);
      peer->update_source = NULL;
    }
  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       "neighbor PEER next-hop-self",
       NEIGHBOR_STR
       "IP address\n"
       "Set nexthop value to self\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->nexthop_self = 1;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       "no neighbor PEER next-hop-self",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Set nexthop value to self\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->nexthop_self = 0;

  return CMD_SUCCESS;
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       "neighbor PEER weight <0-65535>",
       NEIGHBOR_STR
       "IP address\n"
       "Default weight value\n"
       "Weight value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long weight;
  char *endptr = NULL;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  weight = strtoul (argv[1], &endptr, 10);
  if (weight == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (weight > 65535)
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Set weight flag to peer configure. */
  peer->config |= PEER_CONFIG_WEIGHT;
  peer->weight = weight;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       "no neighbor PEER weight [<0-65535>]",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Default weight value\n"
       "Weight value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Unset weight flag from the peer configuration. */
  peer->config &= ~PEER_CONFIG_WEIGHT;

  return CMD_SUCCESS;
}

DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       "neighbor PEER default-originate",
       NEIGHBOR_STR
       "IP address\n"
       "Permit announcement of default route to the neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->config |= PEER_DEFAULT_ORIGINATE;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       "no neighbor PEER default-originate",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "Permit announcement of default route to the neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->config &= ~PEER_DEFAULT_ORIGINATE;

  return CMD_SUCCESS;
}

DEFUN (neighbor_timers_holdtime,
       neighbor_timers_holdtime_cmd,
       "neighbor PEER timers holdtime <0-65535>",
       NEIGHBOR_STR
       "IP address\n"
       "BGP timers\n"
       "BGP hold timer\n"
       "BGP hold timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long holdtime;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Hold time value check. */
  holdtime = strtoul (argv[1], &endptr, 10);

  if (holdtime == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime > 65535)
    {
      vty_out (vty, "hold time value must be <0,3-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime < 3 && holdtime != 0)
    {
      vty_out (vty, "hold time value must be either 0 or greater than 3%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_HOLDTIME;
  peer->holdtime = holdtime;

  /* Set value to timer setting. */
  peer->v_holdtime = holdtime;

  return CMD_SUCCESS;
}

DEFUN (neighbor_timers_keepalive,
       neighbor_timers_keepalive_cmd,
       "neighbor PEER timers keepalive <0-65535>",
       NEIGHBOR_STR
       "IP address\n"
       "BGP timers\n"
       "BGP keepalive timer\n"
       "BGP keepalive timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long keepalive;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Hold time value check. */
  keepalive = strtoul (argv[1], &endptr, 10);

  if (keepalive == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (keepalive > 65535)
    {
      vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_KEEPALIVE;
  peer->keepalive = keepalive;

  /* Set value to timer setting. */
  peer->v_keepalive = keepalive;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_timers_holdtime,
       no_neighbor_timers_holdtime_cmd,
       "no neighbor PEER timers holdtime [TIMER]",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "BGP timers\n"
       "BGP hold timer\n"
       "BGP hold timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long holdtime;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    {
      /* Hold time value check. */
      holdtime = strtoul (argv[1], &endptr, 10);

      if (holdtime == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (holdtime > 65535)
	{
	  vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (peer->holdtime != holdtime)
	{
	  vty_out (vty, "timer value does not match %s%s", argv[1],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_HOLDTIME;
  peer->holdtime = 0;

  /* Set timer setting to default value. */
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_timers_keepalive,
       no_neighbor_timers_keepalive_cmd,
       "no neighbor PEER timers keepalive [TIMER]",
       NO_STR
       NEIGHBOR_STR
       "IP address\n"
       "BGP timers\n"
       "BGP keepalive timer\n"
       "BGP keepalive timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long keepalive;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    {
      /* Hold time value check. */
      keepalive = strtoul (argv[1], &endptr, 10);

      if (keepalive == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (keepalive > 65535)
	{
	  vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (peer->keepalive != keepalive)
	{
	  vty_out (vty, "timer value does not match %s%s", argv[1],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_KEEPALIVE;
  peer->keepalive = 0;

  /* Set timer setting to default value. */
  peer->v_keepalive = min (BGP_DEFAULT_KEEPALIVE, peer->v_holdtime / 3);

  return CMD_SUCCESS;
}

/* Capability negotiation control. */
DEFUN (neighbor_dont_capability_negotiation,
       neighbor_dont_capability_negotiation_cmd,
       "neighbor PEER dont-capability-negotiation",
       NEIGHBOR_STR
       "Peer address\n"
       "Do not perform capability negotiation\n")
{
  struct bgp *bgp = (struct bgp *) vty->index;
  struct peer *peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Off capability negotiation. */
  peer->dont_capability = 1;
  return CMD_SUCCESS;
}

DEFUN (no_neighbor_dont_capability_negotiation,
       no_neighbor_dont_capability_negotiation_cmd,
       "no neighbor PEER dont-capability-negotiation",
       NO_STR
       NEIGHBOR_STR
       "Peer address\n"
       "Do not perform capability negotiation\n")
{
  struct bgp *bgp = (struct bgp *) vty->index;
  struct peer *peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set capability negotiation. */
  peer->dont_capability = 0;
  return CMD_SUCCESS;
}
#ifdef HAVE_MBGPV4
DEFUN (neighbor_translate_update,
       neighbor_translate_update_cmd,
       "neighbor PEER translate-update [nlri] [unicast] [multicast]",
       NEIGHBOR_STR
       "IP address\n"
       "translate bgp updates\n"
       "translate update\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 1) {
    peer->translate_update = TRANSLATE_UPDATE_UNICAST_MULTICAST;
    return CMD_SUCCESS;
  }

  if (strcmp (argv[1], "nlri") == 0 ) {
    if(( argc >= 2 && (strcmp (argv[2], "unicast") == 0)) && 
      argc >= 3 && (strcmp (argv[3], "multicast") == 0)) {
      peer->translate_update = TRANSLATE_UPDATE_UNICAST_MULTICAST;
      return CMD_SUCCESS;
    }
    else if( argc >= 2 && (strcmp (argv[2], "multicast") == 0)) {
      peer->translate_update = TRANSLATE_UPDATE_MULTICAST;
      return CMD_SUCCESS;
    }
  }
   vty_out (vty, "Illegal command%s", VTY_NEWLINE);
  return CMD_WARNING;
}
DEFUN (no_neighbor_translate_update,
       no_neighbor_translate_update_cmd,
       "no neighbor PEER translate-update [nlri] [unicast] [multicast]",
       NEIGHBOR_STR
       "IP address\n"
       "no translate bgp updates\n"
       "no translate update\n")
{
  struct bgp *bgp;
  struct peer *peer;
  int err=0;

  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET);
  

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 1) {
    peer->translate_update = TRANSLATE_UPDATE_OFF;
    return CMD_SUCCESS;
  }

  if (strcmp (argv[1], "nlri") == 0) {
    if(( argc >= 2 && (strcmp (argv[2], "unicast") == 0 )) && 
      argc >= 3 &&  (strcmp (argv[3], "multicast") == 0)) 
      peer->translate_update = TRANSLATE_UPDATE_OFF;
    else if( argc >= 2 && (strcmp (argv[2], "multicast") == 0))
      peer->translate_update = TRANSLATE_UPDATE_OFF;
    else err=1;
  }
  else err=1;

  if(err) {
    vty_out (vty, "No such command%s %s %s %s", argv[1],argv[2],argv[3],
	     VTY_NEWLINE);
    return CMD_WARNING;
  }
  else return CMD_SUCCESS;
}
#endif /* HAVE_MBGPV4 */


/* Make peer and enable further neighbor configuration. */
DEFUN (neighbor, 
       neighbor_cmd, 
       "neighbor PEER remote-as <1-65535> [nlri] [unicast] [multicast]", 
       /*       "neighbor PEER remote-as <1-65535> [passive]",*/
       NEIGHBOR_STR
       "IP address\n"
       "Remote AS\n"
       "AS number\n"
       "Passive\n")
{
  struct bgp *bgp;
  struct peer *peer;
  as_t as;
  union sockunion *su;
  char *endptr = NULL;

  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  /* If there is already same IP_ADDR peer, only change AS_NO. */
  if (peer)
    {
      if (peer->family != AF_INET)
	{
	  vty_out (vty, "Multiple protocol configuration for the same peer is not yet supported%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      /* Change of AS_NO. If peer is established then clear it's peer
         and clear all resources and make it again. */
      vty_out (vty, "Neighbor is already configured\r\n");
      return CMD_SUCCESS;
    }

  /* This is new neighbor. */
  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed IP address.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  as = strtoul (argv[1], &endptr, 10);
  if (as == 0 || as == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "AS path value malformed.%s", VTY_NEWLINE);
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
  peer->family = AF_INET;

  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    peer->ttl = 255;
  else
    peer->ttl = 1;
  peer->fd = -1;

  /* If this peer is in passive mode star it in Active mode. */
  if (argc == 3 && (strcmp (argv[2], "passive") == 0))
    {
      peer->passive = 1;
      peer->status = Active;
    }
  else
    {
      peer->passive = 0;
      peer->status = Idle;
    }

  /*  peer->ipv4_unicast_conf = peer->ipv4_multicast_conf = 0; */
  if (argc >= 3 && (strcmp (argv[2], "nlri") == 0)) { 
    if(strcmp (argv[3], "unicast") == 0) peer->ipv4_unicast_conf = 1;
    if(strcmp (argv[4], "multicast") == 0) peer->ipv4_multicast_conf = 1;
    if(strcmp (argv[3], "multicast") == 0 ) peer->ipv4_multicast_conf = 1;
    if(strcmp (argv[4], "unicast") == 0) peer->ipv4_unicast_conf = 1;
    if( peer->ipv4_unicast_conf == 0 && 
	peer->ipv4_multicast_conf == 0) {
      vty_out (vty, "Use either: nlri unicast multicast | nlri multicast\r\n");
      return CMD_WARNING;
    }
  }

  if((argc == 3 && peer->passive) ||  argc < 3 ) 
    peer->ipv4_unicast_conf = 1;
    
  /* Setup timer. */
  bgp_timer_set (peer);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor PEER remote-as <1-65535> [nlri] [unicast] [multicast]",
       /*       "no neighbor PEER remote-as <1-65535> [passive]", */
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
      vty_out (vty, "Can't find peer %s.%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->family != AF_INET)
    {
      vty_out (vty, "Can't remove different family peer.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check AS number. */
  if (peer->as != atoi (argv[1]))
    {
      vty_out (vty, "Different AS number for the peer %s.%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc > 2 && (strcmp (argv[2], "nlri") == 0)) { 
    if(strcmp (argv[3], "unicast") == 0) peer->ipv4_unicast_conf = 0;
    if(strcmp (argv[4], "multicast") == 0) peer->ipv4_multicast_conf = 0;
    if(strcmp (argv[3], "multicast") == 0 ) peer->ipv4_multicast_conf = 0;
    if(strcmp (argv[4], "unicast") == 0) peer->ipv4_unicast_conf = 0;
  }

  if(argc <= 2 )  peer->ipv4_unicast_conf = 0;

  /* Now delete from the neighbor from lists. */
  list_delete_by_val (bgp->peer, peer);
  list_delete_by_val (peer_list, peer);

  /* Clear routes and deallocate peer structure. */
  bgp_stop (peer);
  peer_delete (peer);

  return CMD_SUCCESS;
}

/* `clear ip bgp' related functions. */

/* BGP clear types. */
enum clear_type
{
  clear_all,
  clear_peer,
  clear_as
};

int
vty_clear_bgp (struct vty *vty, int family, enum clear_type type, char *arg)
{
  int cleared;
  struct bgp *bgp;
  struct peer *peer;
  listnode bnode;
  listnode pnode;
  as_t as;
  unsigned long as_ul;
  char *endptr = NULL;

  /* Clear all bgp neighbors. */
  if (type == clear_all)
    {
      for (bnode = listhead (bgp_list); bnode; nextnode(bnode))
	{
	  bgp = getdata (bnode);

	  for (pnode = listhead (bgp->peer); pnode; nextnode (pnode))
	    {
	      peer = getdata (pnode);

	      if (peer->family == family)
		BGP_EVENT_ADD (peer, BGP_Stop);
	    }
	}

      vty_out (vty, "All bgp neighbors cleared.%s", VTY_NEWLINE);

      return CMD_SUCCESS;
    }
  /* Clear specified peer. */
  else if (type == clear_peer)
    {
      cleared = 0;

      for (bnode = listhead (bgp_list); bnode; nextnode (bnode))
	{
	  bgp = getdata (bnode);

	  peer = peer_lookup_with_family (bgp, arg, family);

	  if (peer)
	    {
	      BGP_EVENT_ADD (peer, BGP_Stop);
	      cleared = 1;
	    }
	}

      if (cleared)
	vty_out (vty, "Peer %s cleared.%s", arg, VTY_NEWLINE);
      else
	vty_out (vty, "Can't find peer %s.%s", arg, VTY_NEWLINE);

      return CMD_SUCCESS;
    }
  /* AS based clear. */
  else if (type == clear_as)
    {
      cleared = 0;

      as_ul = strtoul(arg, &endptr, 10);

      if ((as_ul == ULONG_MAX) || (*endptr != '\0') || (as_ul > USHRT_MAX))
	{
	  vty_out (vty, "Invalid neighbor specifier: %s.%s", arg, 
		   VTY_NEWLINE);
	  return CMD_SUCCESS;
	}

      as = (as_t) as_ul;

      for (bnode = listhead (bgp_list); bnode; nextnode(bnode))
	{
	  bgp = getdata (bnode);
	  
	  for (pnode = listhead (bgp->peer); pnode; nextnode (pnode))
	    {
	      peer = getdata (pnode);

	      if (peer->family == family && peer->as == as)
	        {
		  BGP_EVENT_ADD (peer, BGP_Stop);
		  cleared = 1;
	        }
	    }
	}

      if (cleared)
	vty_out (vty, "All neighbors which AS is %s cleared.%s", arg, 
		 VTY_NEWLINE);
      else
	vty_out (vty, "No neighbor with AS %s found.%s", arg, VTY_NEWLINE);
           
      return CMD_SUCCESS;
    }

  /* Not reached. */
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear ip bgp *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "All peer clear\n")
{
  return vty_clear_bgp (vty, AF_INET, clear_all, NULL);
}

DEFUN (clear_ip_bgp_peer,
       clear_ip_bgp_peer_cmd, 
       "clear ip bgp PEER",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Peer address\n")
{
  return vty_clear_bgp (vty, AF_INET, clear_peer, argv[0]);
}

DEFUN (clear_ip_bgp_as,
       clear_ip_bgp_as_cmd,
       "clear ip bgp <1-65535>",
       CLEAR_STR
       IP_STR
       BGP_STR
       "AS number of the peers to be cleared.\n")
{
  return vty_clear_bgp (vty, AF_INET, clear_as, argv[0]);
}       

#ifdef HAVE_IPV6
DEFUN (clear_ipv6_bgp_all,
       clear_ipv6_bgp_all_cmd,
       "clear ipv6 bgp *",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "All peer clear\n")
{
  return vty_clear_bgp (vty, AF_INET6, clear_all, NULL);
}

DEFUN (clear_ipv6_bgp_peer,
       clear_ipv6_bgp_peer_cmd, 
       "clear ipv6 bgp PEER",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Peer address\n")
{
  return vty_clear_bgp (vty, AF_INET6, clear_peer, argv[0]);
}

DEFUN (clear_ipv6_bgp_as,
       clear_ipv6_bgp_as_cmd,
       "clear ipv6 bgp <1-65535>",
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "AS number of the peers to be cleared.\n")
{
  return vty_clear_bgp (vty, AF_INET6, clear_as, argv[0]);
}       

DEFUN (show_ipv6_bgp_neighbors,
       show_ipv6_bgp_neighbors_cmd,
       "show ipv6 bgp neighbors [PEER]",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Peer address\n")
{
  struct peer *p;
  listnode node;

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down.%s", VTY_NEWLINE);

  if (argc == 1)
    {
      p = peer_lookup_by_host (argv[0]);
      if (! p || p->family != AF_INET6)
	{
	  vty_out (vty, "can't find neighbor %s%s", argv[0],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
      bgp_peer_display (vty, p);
    }
  else
    {
      for (node = listhead (peer_list); node; nextnode (node))
	{
	  p = getdata (node);
	  if (p->family != AF_INET6)
	    continue;
	  bgp_peer_display (vty, p);
	}
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_bgp_summary, 
       show_ipv6_bgp_summary_cmd,
       "show ipv6 bgp summary",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  listnode node;
  struct peer *peer;
  int first = 1;

  for (node = listhead (peer_list); node; nextnode (node))
    {
      int length;
      peer = getdata (node);
	  
      if (peer->family != AF_INET6)
	continue;

      if (first)
	{
	  vty_out (vty, "Neighbor                       AS       MsgRcvd MsgSent  Up/Down  State/Pref%s", VTY_NEWLINE);
	  first = 0;
	}
      length = sockunion_vty_out (vty, peer->su);
      length = 27 - length;
      if (length < 0)
	length = 0;

      vty_out (vty, "%*s", length, " ");

      vty_out (vty, " %5d      %7d %7d   ",
	       peer->as,
	       peer->open_in + peer->update_in +
	       peer->withdrow_in + peer->keepalive_in,
	       peer->open_out + peer->update_out +
	       peer->withdrow_out + peer->keepalive_out);
      peer_uptime_vty (vty, peer);
      if (peer->status == Established)
	vty_out (vty, " %9d%s", peer->prefix_count,
		 VTY_NEWLINE);
      else
	vty_out (vty, "  %-11s%s", LOOKUP(bgp_status_msg, peer->status),
		 VTY_NEWLINE);
      if (peer->desc)
	vty_out (vty, "  Description: %s%s", peer->desc, VTY_NEWLINE);
    }

  if (first)
    vty_out (vty, "No IPv6 neighbor is configured.%s", VTY_NEWLINE);

  return CMD_SUCCESS;

}

/* Make peer and enable further neighbor configuration. */
DEFUN (ipv6_bgp_neighbor, 
       ipv6_bgp_neighbor_cmd, 
       "ipv6 bgp neighbor PEER remote-as <1-65535> [passive]",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Remote AS\n"
       "AS number\n"
       "Passive\n")
{
  struct bgp *bgp;
  struct peer *peer;
  u_int16_t as;
  union sockunion *su;
  char *endptr = NULL;

  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (peer)
    {
      if (peer->family != AF_INET6)
	{
	  vty_out (vty, "Multiple protocol configuration for the same peer is not yet supported%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      return CMD_SUCCESS;
    }

  /* This is new neighbor. */
  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed IP address.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  as = strtoul (argv[1], &endptr, 10);
  if (as == 0 || as == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "AS path value malformed.%s", VTY_NEWLINE);
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
  peer->family = AF_INET6;
  peer->ipv6_unicast_conf = 1;

  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    peer->ttl = 255;
  else
    peer->ttl = 1;
  peer->fd = -1;

  /* If this peer is in passive mode star it in Active mode. */
  if (argc == 3 && (strcmp (argv[2], "passive") == 0))
    {
      peer->passive = 1;
      peer->status = Active;
    }
  else
    {
      peer->passive = 0;
      peer->status = Idle;
    }

  /* Setup timer. */
  bgp_timer_set (peer);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor,
       no_ipv6_bgp_neighbor_cmd,
       "no ipv6 bgp neighbor PEER remote-as <1-65535> [passive]",
       NO_STR
       IPV6_STR
       BGP_STR
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
      vty_out (vty, "Can't find peer %s.%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->family != AF_INET6)
    {
      vty_out (vty, "Can't remove different family peer.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check AS number. */
  if (peer->as != atoi (argv[1]))
    {
      vty_out (vty, "Different AS number for the peer %s.%s", argv[0],
	       VTY_NEWLINE);
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

DEFUN (ipv6_bgp_neighbor_ebgp_multihop,
       ipv6_bgp_neighbor_ebgp_multihop_cmd,
       "ipv6 bgp neighbor PEER ebgp-multihop [TTL]",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Change TTL value of BGP connection\n"
       "TTL\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;

  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);
  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    peer->ttl = atoi (argv[1]);
  else
    peer->ttl = TTL_MAX;

  if (peer->ttl == 0)
    {
      vty_out (vty, "please specify plus integer value.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->fd >= 0)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

/* Set specified peer's BGP version.  This is */
DEFUN (ipv6_bgp_neighbor_version,
       ipv6_bgp_neighbor_version_cmd,
       "ipv6 bgp neighbor PEER version BGP_VERSION",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Neighbor's BGP version\n"
       "Neighbor's BGP version 4 or 4+ or 4-\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* BGP version string check. */
  if (strcmp (argv[1], "4") == 0)
    peer->version = BGP_VERSION_4;
  else if (strcmp (argv[1], "4+") == 0)
    peer->version = BGP_VERSION_MP_4;
  else if (strcmp (argv[1], "4-") == 0)
    peer->version = BGP_VERSION_MP_4_DRAFT_00;
  else
    vty_out (vty, "BGP version malformed!%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_version,
       no_ipv6_bgp_neighbor_version_cmd,
       "no ipv6 bgp neighbor PEER version [BGP_VERSION]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Set neighbor's BGP version to default [version 4]\n"
       "Version\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->version = BGP_VERSION_4;
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_interface,
       ipv6_bgp_neighbor_interface_cmd,
       "ipv6 bgp neighbor PEER interface IFNAME",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Interface\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->ifname)
    free (peer->ifname);
  peer->ifname = strdup (argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_interface,
       no_ipv6_bgp_neighbor_interface_cmd,
       "no ipv6 bgp neighbor PEER interface IFNAME",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Interface\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->ifname)
    free (peer->ifname);
  peer->ifname = NULL;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_desc,
       ipv6_bgp_neighbor_desc_cmd,
       "ipv6 bgp neighbor PEER description .DESCRIPTION",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description strings\n")
{
  int i;
  struct bgp *bgp;
  struct peer *peer;
  struct buffer *b;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
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

DEFUN (no_ipv6_bgp_neighbor_desc,
       no_ipv6_bgp_neighbor_desc_cmd,
       "no ipv6 bgp neighbor PEER description .DESCRIPTION",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Description\n"
       "Description strings\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->desc)
    XFREE (MTYPE_TMP, peer->desc);
  peer->desc = NULL;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_shutdown,
       ipv6_bgp_neighbor_shutdown_cmd,
       "ipv6 bgp neighbor PEER shutdown",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_stop (peer);
  fsm_change_status (peer, Idle);
  
  peer->shutdown = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_shutdown,
       no_ipv6_bgp_neighbor_shutdown_cmd,
       "no ipv6 bgp neighbor PEER shutdown",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Shutdown\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_timer_set (peer);
  peer->shutdown = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_route_reflector_client,
       ipv6_bgp_neighbor_route_reflector_client_cmd,
       "ipv6 bgp neighbor PEER route-reflector-client",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Configure this neighbor as route reflector client\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (! peer->reflector_client)
    {
      bgp->reflector_cnt++;
      peer->reflector_client = 1;

      BGP_EVENT_ADD (peer, BGP_Stop);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_route_reflector_client,
       no_ipv6_bgp_neighbor_route_reflector_client_cmd,
       "no ipv6 bgp neighbor PEER route-reflector-client",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Configure this neighbor as route reflector client\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->reflector_client)
    {
      bgp->reflector_cnt--;
      peer->reflector_client = 0;

      BGP_EVENT_ADD (peer, BGP_Stop);
    }

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_update_source,
       ipv6_bgp_neighbor_update_source_cmd,
       "ipv6 bgp neighbor PEER update-source IFNAME",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Update source\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->update_source = sockunion_str2su (argv[1]);

  if (peer->update_source == NULL)
    {
      peer->update_if = strdup (argv[1]);
      if (peer->update_source)
	{
	  free (peer->update_source);
	  peer->update_source = NULL;
	}
      return CMD_SUCCESS;
    }

  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_update_source,
       no_ipv6_bgp_neighbor_update_source_cmd,
       "no ipv6 bgp neighbor PEER update-source",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Update source\n"
       "Interface name\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer->update_source)
    {
      free (peer->update_source);
      peer->update_source = NULL;
    }
  if (peer->update_if)
    {
      free (peer->update_if);
      peer->update_if = NULL;
    }
  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_nexthop_self,
       ipv6_bgp_neighbor_nexthop_self_cmd,
       "ipv6 bgp neighbor PEER next-hop-self",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Set nexthop value to self\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->nexthop_self = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_nexthop_self,
       no_ipv6_bgp_neighbor_nexthop_self_cmd,
       "no ipv6 bgp neighbor PEER next-hop-self",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Set nexthop value to self\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->nexthop_self = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_timers_holdtime,
       ipv6_bgp_neighbor_timers_holdtime_cmd,
       "ipv6 bgp neighbor PEER timers holdtime <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "BGP timers\n"
       "BGP hold timer\n"
       "BGP hold timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long holdtime;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Hold time value check. */
  holdtime = strtoul (argv[1], &endptr, 10);

  if (holdtime == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime > 65535)
    {
      vty_out (vty, "hold time value must be <0,3-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (holdtime < 3 && holdtime != 0)
    {
      vty_out (vty, "hold time value must be either 0 or greater than 3%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_HOLDTIME;
  peer->holdtime = holdtime;

  /* Set value to timer setting. */
  peer->v_holdtime = holdtime;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_timers_keepalive,
       ipv6_bgp_neighbor_timers_keepalive_cmd,
       "ipv6 bgp neighbor PEER timers keepalive <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "BGP timers\n"
       "BGP keepalive timer\n"
       "BGP keepalive timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long keepalive;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Hold time value check. */
  keepalive = strtoul (argv[1], &endptr, 10);

  if (keepalive == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (keepalive > 65535)
    {
      vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set value to the configuration. */
  peer->config |= PEER_CONFIG_KEEPALIVE;
  peer->keepalive = keepalive;

  /* Set value to timer setting. */
  peer->v_keepalive = keepalive;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_timers_holdtime,
       no_ipv6_bgp_neighbor_timers_holdtime_cmd,
       "no ipv6 bgp neighbor PEER timers holdtime [TIMER]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "BGP timers\n"
       "BGP hold timer\n"
       "BGP hold timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long holdtime;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    {
      /* Hold time value check. */
      holdtime = strtoul (argv[1], &endptr, 10);

      if (holdtime == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (holdtime > 65535)
	{
	  vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (peer->holdtime != holdtime)
	{
	  vty_out (vty, "timer value does not match %s%s", argv[1],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_HOLDTIME;
  peer->holdtime = 0;

  /* Set timer setting to default value. */
  peer->v_holdtime = BGP_DEFAULT_HOLDTIME;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_timers_keepalive,
       no_ipv6_bgp_neighbor_timers_keepalive_cmd,
       "no ipv6 bgp neighbor PEER timers keepalive [TIMER]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "BGP timers\n"
       "BGP keepalive timer\n"
       "BGP keepalive timer value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long keepalive;
  char *endptr = NULL;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argc == 2)
    {
      /* Hold time value check. */
      keepalive = strtoul (argv[1], &endptr, 10);

      if (keepalive == ULONG_MAX || *endptr != '\0')
	{
	  vty_out (vty, "hold time value must be positive integer%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      if (keepalive > 65535)
	{
	  vty_out (vty, "hold time value must be <0-65535>%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (peer->keepalive != keepalive)
	{
	  vty_out (vty, "timer value does not match %s%s", argv[1],
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* Clear configuration. */
  peer->config &= ~PEER_CONFIG_KEEPALIVE;
  peer->keepalive = 0;

  /* Set timer setting to default value. */
  peer->v_keepalive = min (BGP_DEFAULT_KEEPALIVE, peer->v_holdtime / 3);

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_send_community,
       ipv6_bgp_neighbor_send_community_cmd,
       "ipv6 bgp neighbor PEER send-community",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Configure send community attribute to this neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->send_community = 1;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_send_community,
       no_ipv6_bgp_neighbor_send_community_cmd,
       "no ipv6 bgp neighbor PEER send-community",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Configure send community attribute to this neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->send_community = 0;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_weight,
       ipv6_bgp_neighbor_weight_cmd,
       "ipv6 bgp neighbor PEER weight <0-65535>",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Default weight value\n"
       "Weight value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  unsigned long weight;
  char *endptr = NULL;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  weight = strtoul (argv[1], &endptr, 10);
  if (weight == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (weight > 65535)
    {
      vty_out (vty, "weight value error%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  /* Set weight flag to peer configure. */
  peer->config |= PEER_CONFIG_WEIGHT;
  peer->weight = weight;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_weight,
       no_ipv6_bgp_neighbor_weight_cmd,
       "no ipv6 bgp neighbor PEER weight [<0-65535>]",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Default weight value\n"
       "Weight value\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Unset weight flag from the peer configuration. */
  peer->config &= ~PEER_CONFIG_WEIGHT;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_default_originate,
       ipv6_bgp_neighbor_default_originate_cmd,
       "ipv6 bgp neighbor PEER default-originate",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Permit announcement of default route to the neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->config |= PEER_DEFAULT_ORIGINATE;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_default_originate,
       no_ipv6_bgp_neighbor_default_originate_cmd,
       "no ipv6 bgp neighbor PEER default-originate",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "Permit announcement of default route to the neighbor\n")
{
  struct bgp *bgp;
  struct peer *peer;
  
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  peer->config &= ~PEER_DEFAULT_ORIGINATE;

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_filter_list,
       ipv6_bgp_neighbor_filter_list_cmd,
       "ipv6 bgp neighbor PEER filter-list FLIST_NAME (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Filter list\n"
       "as-path filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_filter_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_filter_list,
       no_ipv6_bgp_neighbor_filter_list_cmd,
       "no ipv6 bgp neighbor PEER filter-list FLIST_NAME (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Filter list\n"
       "as-path filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_filter_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_prefix_list,
       ipv6_bgp_neighbor_prefix_list_cmd,
       "ipv6 bgp neighbor PEER prefix-list PLIST_NAME (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Prefix list\n"
       "Prefix based filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set prefix list to the peer. */
  bgp_prefix_list_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_prefix_list,
       no_ipv6_bgp_neighbor_prefix_list_cmd,
       "no ipv6 bgp neighbor PEER prefix-list FLIST_NAME (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Prefix list\n"
       "Prefix based filter name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "filter direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_prefix_list_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (ipv6_bgp_neighbor_distribute_list,
       ipv6_bgp_neighbor_distribute_list_cmd,
       "ipv6 bgp neighbor PEER distribute-list ALIST_NAME (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Distribute list\n"
       "Accesslist name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_distribute_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_distribute_list,
       no_ipv6_bgp_neighbor_distribute_list_cmd,
       "no ipv6 bgp neighbor PEER distribute-list ALIST_NAME (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
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
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
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

DEFUN (ipv6_bgp_neighbor_route_map,
       ipv6_bgp_neighbor_route_map_cmd,
       "ipv6 bgp neighbor PEER route-map ROUTE_MAP_NAME (in|out)",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Route map\n"
       "Route map name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_set (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_bgp_neighbor_route_map,
       no_ipv6_bgp_neighbor_route_map_cmd,
       "no ipv6 bgp neighbor PEER route-map ROUTE_MAP_NAME (in|out)",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IPv6 address\n"
       "Route map\n"
       "Route map name\n"
       "[in|out]")
{
  struct bgp *bgp;
  struct peer *peer;
  int direct;
  
  /* One should be inside router bgp statement. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (!peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0],
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check filter direction. */
  if (strcmp (argv[2], "in") == 0)
    direct = BGP_FILTER_IN;
  else if (strcmp (argv[2], "out") == 0)
    direct = BGP_FILTER_OUT;
  else
    {
      vty_out (vty, "distribute direction must be [in|out]%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set distribute list to the peer. */
  bgp_route_map_unset (peer, direct, argv[1]);

  return CMD_SUCCESS;
}

/* Capability negotiation control. */
DEFUN (ipv6_neighbor_dont_capability_negotiation,
       ipv6_neighbor_dont_capability_negotiation_cmd,
       "ipv6 bgp neighbor PEER dont-capability-negotiation",
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "Peer address\n"
       "Do not perform capability negotiation\n")
{
  struct bgp *bgp = (struct bgp *) vty->index;
  struct peer *peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Off capability negotiation. */
  peer->dont_capability = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_neighbor_dont_capability_negotiation,
       no_ipv6_neighbor_dont_capability_negotiation_cmd,
       "no ipv6 bgp neighbor PEER dont-capability-negotiation",
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "Peer address\n"
       "Do not perform capability negotiation\n")
{
  struct bgp *bgp = (struct bgp *) vty->index;
  struct peer *peer = peer_lookup_with_family (bgp, argv[0], AF_INET6);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Set capability negotiation. */
  peer->dont_capability = 0;
  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* BGP peer configuration output function. */
void
bgp_peer_config_write (struct vty *vty, list bgp_peer, int family)
{
  listnode node;
  struct peer *peer;

  for (node = listhead (bgp_peer); node; nextnode (node))
    {
      peer = getdata (node);

      if (peer->family != family)
	continue;

      /* remote-as print. */
      vty_out (vty, "%s neighbor ",
	       peer->family == AF_INET ? "" :  "ipv6 bgp");
      sockunion_vty_out (vty, peer->su);
      vty_out (vty, " remote-as %d", peer->as);

      if (peer->ipv4_unicast_conf && peer->ipv4_multicast_conf)
	vty_out (vty, " nlri unicast multicast");
	  
      else if (peer->ipv4_multicast_conf)
	vty_out (vty, " nlri multicast");
	  
      vty_out (vty, "%s",VTY_NEWLINE );

      if (peer->passive) 
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " passive%s", VTY_NEWLINE);
	}

#ifdef HAVE_MBGPV4
      if (peer->translate_update) 
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  if( peer->translate_update == TRANSLATE_UPDATE_UNICAST_MULTICAST) 
	    vty_out (vty, " translate-update nlri unicast multicast%s", 
		     VTY_NEWLINE);
	  else if (peer->translate_update == TRANSLATE_UPDATE_MULTICAST) 
	    vty_out (vty, " translate-update nlri multicast%s", 
		     VTY_NEWLINE);
	}
#endif /* HAVE_MBGPV4 */

      /* Local port. */
      if (peer->port != BGP_PORT_DEFAULT)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " port %d", peer->port, VTY_NEWLINE);
	}

      /* Local interface name. */
      if (peer->ifname)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " interface %s%s", peer->ifname,
		   VTY_NEWLINE);
	}

      /* Update-source. */
      if (peer->update_if)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " update-source %s%s", peer->update_if,
		   VTY_NEWLINE);
	}

      if (peer->update_source)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " update-source %s%s", 
		   sockunion_su2str (peer->update_source),
		   VTY_NEWLINE);
	}

      /* Shutdown or not. */
      if (peer->shutdown)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " shutdown%s",
		   VTY_NEWLINE);
	}

      /* Description. */
      if (peer->desc)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " description %s%s", peer->desc,
		   VTY_NEWLINE);
	}

      /* BGP version print. */
      if (peer->version != BGP_VERSION_4)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);

	  if (peer->version == BGP_VERSION_MP_4)
	    vty_out (vty, " version %s%s", "4+",
		     VTY_NEWLINE);
	  else if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
	    vty_out (vty, " version %s%s", "4-",
		     VTY_NEWLINE);
	}

      /* Default information */
      if (peer->config & PEER_DEFAULT_ORIGINATE)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " default-originate%s",
		   VTY_NEWLINE);
	}

      /* Nexthop self. */
      if (peer->nexthop_self)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " next-hop-self%s",
		   VTY_NEWLINE);
	}

      /* Route reflector client. */
      if (peer->reflector_client)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " route-reflector-client%s",
		   VTY_NEWLINE);
	}

      /* ebgp-multihop print. */
      if (bgp_peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);

	  if (peer->ttl == TTL_MAX)
	    vty_out (vty, " ebgp-multihop%s",
		     VTY_NEWLINE);
	  else
	    vty_out (vty, " ebgp-multihop %d%s", peer->ttl,
		     VTY_NEWLINE);
	}

      /* send-community print. */
      if (peer->send_community)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);

	  vty_out (vty, " send-community%s", VTY_NEWLINE);
	}

      /* capability negotiation. */
      if (peer->dont_capability)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);

	  vty_out (vty, " dont-capability-negotiation%s", VTY_NEWLINE);
	}

      /* weight print. */
      if (peer->config & PEER_CONFIG_WEIGHT)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);

	  vty_out (vty, " weight %d%s", peer->weight,
		   VTY_NEWLINE);
	}

      /* distribute-list print. */
      if (peer->distribute[BGP_FILTER_IN].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " distribute-list %s in%s", 
		   peer->distribute[BGP_FILTER_IN].name,
		   VTY_NEWLINE);
	}
      if (peer->distribute[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " distribute-list %s out%s", 
		   peer->distribute[BGP_FILTER_OUT].name,
		   VTY_NEWLINE);
	}

      /* prefix-list print. */
      if (peer->plist[BGP_FILTER_IN].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " prefix-list %s in%s", 
		   peer->plist[BGP_FILTER_IN].name,
		   VTY_NEWLINE);
	}
      if (peer->plist[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " prefix-list %s out%s", 
		   peer->plist[BGP_FILTER_OUT].name,
		   VTY_NEWLINE);
	}

      /* filter-list print. */
      if (peer->filter[BGP_FILTER_IN].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " filter-list %s in%s", 
		   peer->filter[BGP_FILTER_IN].name,
		   VTY_NEWLINE);
	}
      if (peer->filter[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " filter-list %s out%s", 
		   peer->filter[BGP_FILTER_OUT].name,
		   VTY_NEWLINE);
	}

      /* route-map print. */
      if (peer->route_map[BGP_FILTER_IN].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " route-map %s in%s", 
		   peer->route_map[BGP_FILTER_IN].name,
		   VTY_NEWLINE);
	}
      if (peer->route_map[BGP_FILTER_OUT].name)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " route-map %s out%s", 
		   peer->route_map[BGP_FILTER_OUT].name,
		   VTY_NEWLINE);
	}

      if (peer->config & PEER_CONFIG_HOLDTIME)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " timers holdtime %ld%s", peer->holdtime,
		   VTY_NEWLINE);
	}
      if (peer->config & PEER_CONFIG_KEEPALIVE)
	{
	  vty_out (vty, "%s neighbor ",
		   peer->family == AF_INET ? "" :  "ipv6 bgp");
	  sockunion_vty_out (vty, peer->su);
	  vty_out (vty, " timers keepalive %ld%s", peer->keepalive,
		   VTY_NEWLINE);
	}    }
}

/* BGP configuration write function. */
int
bgp_config_write (struct vty *vty)
{
  listnode node;
  struct bgp *bgp; 
  int config_write_network (struct vty *vty, struct bgp *bgp, int family);
  int write = 0;

  /* BGP Multiple instance. */
  if (bgp_multiple_instance)
    {    
      vty_out (vty, "bgp multiple-instance%s", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  /* Each BGP instance configuration. */
  for (node = listhead (bgp_list); node; nextnode (node))
    {
      bgp = getdata (node);

      vty_out (vty, "router bgp %d%s", bgp->as,
	       VTY_NEWLINE);

      if (bgp->config & BGP_CONFIG_ROUTER_ID)
	{
	  struct in_addr ident;
	  ident.s_addr = bgp->ident;
	  vty_out (vty, " bgp router-id %s%s", inet_ntoa (ident), 
		   VTY_NEWLINE);
	}

      if (bgp->config & BGP_CONFIG_CLUSTER_ID)
	{
	  struct in_addr cluster;
	  cluster.s_addr = bgp->cluster;
	  vty_out (vty, " bgp cluster-id %s%s", inet_ntoa (cluster), 
		   VTY_NEWLINE);
	}
      config_write_network (vty, bgp, AF_INET);
      config_write_bgp_redistribute (vty, bgp, ZEBRA_FAMILY_IPV4);
      bgp_peer_config_write (vty, bgp->peer, AF_INET);

#ifdef HAVE_IPV6
      vty_out (vty, "!%s", VTY_NEWLINE);
      config_write_network (vty, bgp, AF_INET6);
      config_write_bgp_redistribute (vty, bgp, ZEBRA_FAMILY_IPV6);
      bgp_peer_config_write (vty, bgp->peer, AF_INET6);
#endif /* HAVE_IPV6 */

      write++;
    }
  return write;
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
  void as_list_add_hook (void (*func) ());
  void as_list_delete_hook (void (*func) ());

  /* Randomize. */
  srand (time (NULL));

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

  install_element (ENABLE_NODE, &clear_ip_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_peer_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_as_cmd);

  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &no_router_bgp_cmd);
  install_element (CONFIG_NODE, &bgp_multiple_instance_cmd);
  install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd);

  install_default (BGP_NODE);
  install_element (BGP_NODE, &neighbor_cmd);
  install_element (BGP_NODE, &no_neighbor_cmd);
  install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &bgp_router_id_cmd);
  install_element (BGP_NODE, &no_bgp_router_id_cmd);
  install_element (BGP_NODE, &bgp_cluster_id_cmd);
  install_element (BGP_NODE, &no_bgp_cluster_id_cmd);
  install_element (BGP_NODE, &neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &no_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &neighbor_filter_list_cmd);
  install_element (BGP_NODE, &no_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_neighbor_route_map_cmd);
  install_element (BGP_NODE, &neighbor_desc_cmd);
  install_element (BGP_NODE, &no_neighbor_desc_cmd);
  install_element (BGP_NODE, &neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_neighbor_shutdown_cmd);
  install_element (BGP_NODE, &neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &no_neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &neighbor_update_source_cmd);
  install_element (BGP_NODE, &no_neighbor_update_source_cmd);
  install_element (BGP_NODE, &neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &no_neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &no_neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &neighbor_send_community_cmd);
  install_element (BGP_NODE, &no_neighbor_send_community_cmd);
  install_element (BGP_NODE, &neighbor_weight_cmd);
  install_element (BGP_NODE, &no_neighbor_weight_cmd);
  install_element (BGP_NODE, &neighbor_default_originate_cmd);
  install_element (BGP_NODE, &no_neighbor_default_originate_cmd);
  install_element (BGP_NODE, &neighbor_port_cmd);
  install_element (BGP_NODE, &neighbor_dont_capability_negotiation_cmd);
  install_element (BGP_NODE, &no_neighbor_dont_capability_negotiation_cmd);

#ifdef HAVE_MBGPV4  
  install_element (BGP_NODE, &neighbor_translate_update_cmd);
  install_element (BGP_NODE, &no_neighbor_translate_update_cmd);

  install_element (VIEW_NODE, &show_ip_mbgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_paths_cmd);
  install_element (VIEW_NODE, &show_ip_mbgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_mbgp_community_cmd);
#endif /* HAVE_MBGPV4 */

#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_neighbors_cmd);

  install_element (ENABLE_NODE, &show_ipv6_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_neighbors_cmd);

  install_element (ENABLE_NODE, &clear_ipv6_bgp_all_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_bgp_as_cmd);

  install_element (BGP_NODE, &ipv6_bgp_neighbor_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_version_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_version_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_interface_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_distribute_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_prefix_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_filter_list_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_map_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_map_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_desc_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_desc_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_shutdown_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_shutdown_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_reflector_client_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_update_source_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_update_source_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_nexthop_self_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_holdtime_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_keepalive_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_send_community_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_send_community_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_weight_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_weight_cmd);
  install_element (BGP_NODE, &ipv6_bgp_neighbor_default_originate_cmd);
  install_element (BGP_NODE, &no_ipv6_bgp_neighbor_default_originate_cmd);
  install_element (BGP_NODE, &ipv6_neighbor_dont_capability_negotiation_cmd);
  install_element (BGP_NODE, &no_ipv6_neighbor_dont_capability_negotiation_cmd);
#endif /* HAVE_IPV6 */

  /* Make empty list of bgp and peer list. */
  bgp_list = list_init ();
  peer_list = list_init ();

  /* BGP multiple instance. */
  bgp_multiple_instance = 0;

  /* Init zebra. */
  zebra_init ();

  /* BGP inits. */
  bgp_attr_init ();
  bgp_debug_init ();
  bgp_dump_init ();
  bgp_route_init ();
  bgp_route_map_init ();

  /* Access list initialize. */
  access_list_init ();
  access_list_add_hook (bgp_distribute_update);
  access_list_delete_hook (bgp_distribute_update);

  /* Filter list initialize. */
  bgp_filter_init ();
  as_list_add_hook (bgp_filter_update);
  as_list_delete_hook (bgp_filter_update);

  /* Prefix list initialize.*/
  prefix_list_init ();
  prefix_list_add_hook (bgp_prefix_list_update);
  prefix_list_delete_hook (bgp_prefix_list_update);

  /* Community list initialize. */
  community_list_init ();

#ifdef HAVE_SNMP
  bgp_snmp_init ();
#endif /* HAVE_SNMP */
}
