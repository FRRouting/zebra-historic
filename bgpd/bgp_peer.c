/* BGP peer management routines.
   Copyright (C) 1996, 97 Kunihiro Ishiguro

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
 
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <sys/time.h>

#include "bgpd.h"
#include "bgp_peer.h"
#include "linklist.h"
#include "sockunion.h"
#include "vector.h"
#include "vty.h"
#include "thread.h"
#include "memory.h"

/* BGPd's all peer list. */
list peer_list;

/* Check peer's AS number and determin is this peer IBPG or EBGP */
int
peer_sort (struct peer *peer)
{
  return (peer->as == peer->bgp->as) ? BGP_PEER_IBGP : BGP_PEER_EBGP;
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

  return peer;
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

void peer_free (struct peer *peer)
{
  XFREE (MTYPE_BGP_PEER, peer);
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
    free (peer->host);

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

/* BGP neighbor configuration write. */
void
peer_config_write (struct vty *vty, list bgp_peer)
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
      if (peer_sort (peer) == BGP_PEER_EBGP && peer->ttl != 1)
	{
	  vty_out (vty, " neighbor ");
	  sockunion_vty_out (vty, peer->su);

	  if (peer->ttl == TTL_MAX)
	    vty_out (vty, " ebgp-multihop%s", VTY_NEWLINE);
	  else
	    vty_out (vty, " ebgp-multihop %d%s", peer->ttl, VTY_NEWLINE);
	}
    }
}

#define TIME_BUF 25

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

void
peer_uptime_vty (struct vty *vty, struct peer *peer)
{
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
    sprintf (timebuf, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (uptime < ONE_WEEK_SECOND)
    sprintf (timebuf, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    sprintf (timebuf, "%02dw%dd%02dh", 
	     tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);

  /* Out puts to vty. */
  vty_out (vty, "%8s", timebuf);
}
