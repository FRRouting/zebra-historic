/* Multiple view function for route server.
   Copyright (C) 1997 Kunihiro Ishiguro

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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "zebra.h"
#include "table.h"

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_peer.h"
#include "bgp_attr.h"
#include "bgp_dump.h"
#include "bgp_aspath.h"

/**/
struct route_table *bgp_static_ipv4;

/**/
#ifdef HAVE_IPV6
struct route_table *bgp_static_ipv6;
#endif /* HAVE_IPV6 */

/**/
void
filter_default (struct attr *attr, struct peer *peer)
{
  attr->med = 0;
  attr->origin = BGP_ORIGIN_IGP;
  attr->next_hop = peer->next_hop;


  if (peer->as == peer->bgp->as)
    /* IBGP connection */
    {
      /* local preference value set. */
      if (peer->def & VAL_LOCAL_PREF)
	attr->local_pref = peer->localpref;
      else if (peer->bgp->def & VAL_LOCAL_PREF)
	attr->local_pref = peer->bgp->localpref;
      else
	attr->local_pref = DEFAULT_LOCAL_PREF;

      attr->aspath = aspath_parse (NULL, 0);
    }
  else
    /* EBGP connection*/
    {
      attr->aspath = (struct aspath *) aspath_val2as (peer->bgp->as);
    }
}

#if 0
bgp_announce_static (struct prefix_ipv4 *pin, struct peer *peer)
{
  struct attr *attr;
  int nbytes;
  u_char *packet;

  attr = pin->gate.info;

  /* Set default value to attribute. */
  filter_default (attr, peer);
  
  if (attr->next_hop.s_addr == 0)
    return;

  /* Make update packet and send it to peer. */
  packet = (u_char *) bgp_make_packet (&nbytes, BGP_MSG_UPDATE, pin);
  writen (peer->fd, packet, nbytes);
  free (packet);
}

bgp_announce (struct peer *peer)
{
  radix_apply_func (bgp_static_ipv4, bgp_announce_static, peer);
}
#endif /* 0 */

DEFUN (default_attr_localpref,
       default_attr_localpref_cmd,
       "default-attr local-pref NUMBER",
       "Set default local preference value\n"
       "Set default local preference value\n"
       "Value\n")
{
  struct bgp *bgp;
  long lpref;

  bgp = (struct bgp *) vty->index;

  lpref = strtol (argv[0], NULL, 10);

  bgp->def |= VAL_LOCAL_PREF;
  bgp->localpref = lpref;

  return CMD_SUCCESS;
}

DEFUN (no_default_attr_localpref,
       no_default_attr_localpref_cmd,
       "no default-attr local-pref NUMBER",
       NO_STR
       "Unset default local preference value\n"
       "Unset default local preference value\n"
       "Value\n")
{
  struct bgp *bgp;

  bgp = (struct bgp *) vty->index;

  bgp->def &= ~DEFAULT_LOCAL_PREF;
  bgp->localpref = 0;

  return CMD_SUCCESS;
}


DEFUN (bgp_network,
       bgp_network_cmd,
       "network PREFIX",
       "Announce network setup\n"
       "Static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct prefix_ipv4 p;
  struct route_node *np;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  np = route_node_get (bgp_static_ipv4, (struct prefix *) &p);
  if (np->info)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      return CMD_WARNING;
    }
  np->info = bgp_attr_new ();

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

  bgp_attr_free (np->info);
  np->info = NULL;

  route_unlock_node (np);

  return CMD_SUCCESS;
}

int
config_write_network (struct vty *vty, struct bgp *bgp)
{
  /* radix_apply_func (bgp_static_ipv4, vty_static_dump, vty); */

  return 0;
}

void
view_init ()
{
  bgp_static_ipv4 = route_table_init ();

#ifdef HAVE_IPV6
  bgp_static_ipv6 = route_table_init ();
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &default_attr_localpref_cmd);
  install_element (BGP_NODE, &no_default_attr_localpref_cmd);
}
