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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <string.h>

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_peer.h"
#include "bgp_attr.h"
#include "bgp_dump.h"
#include "bgp_aspath.h"

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "route.h"
#include "radix.h"
#include "zebra.h"

struct radix_top *bgp_static_radix;
#ifdef HAVE_IPV6
struct radix_top *bgp_static_radix_ipv6;
#endif /* HAVE_IPV6 */

/**/
filter_default (struct attr *attr, struct peer *peer)
{
  attr->med = 0;
  attr->origin = BGP_ORIGIN_IGP;
  attr->next_hop.s_addr = peer->next_hop;


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

bgp_announce_static (struct prefix_in *pin, struct peer *peer)
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
  radix_apply_func (bgp_static_radix, bgp_announce_static, peer);
}

DEFUN (default_attr_localpref,
       default_attr_localpref_cmd,
       "default-attr local-pref NUMBER",
       "Set default local preference value.")
{
  struct bgp *bgp;
  long lpref;

  bgp = (struct bgp *) vty->index;

  lpref = strtol (argv[0], NULL, 10);

  bgp->def |= VAL_LOCAL_PREF;
  bgp->localpref = lpref;
}

DEFUN (no_default_attr_localpref,
       no_default_attr_localpref_cmd,
       "no default-attr local-pref NUMBER",
       "Unset default local preference value.")
{
  struct bgp *bgp;
  long lpref;

  bgp = (struct bgp *) vty->index;

  bgp->def &= ~DEFAULT_LOCAL_PREF;
  bgp->localpref = 0;
}


DEFUN (bgp_network,
       bgp_network_cmd,
       "network PREFIX",
       "Static network for bgp announcement.")
{
  int ret;
  struct bgp *bgp;
  struct prefix_in *pin;

  bgp = (struct bgp *) vty->index;
  pin = prefix_in_new ();

  ret = str2prefix_in (argv[0], pin);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      prefix_in_free (pin);
      return;
    }

  /* Make sure mask is applied. */
  masked_route_in (pin);
  pin->type = ZEBRA_ROUTE_BGP;
  pin->gate.info = attr_new ();

  ret = radix_lookup_rt (bgp_static_radix, (struct prefix *) pin);
  if (ret)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      prefix_in_free (pin);
      return;
    }
  radix_add (bgp_static_radix, (struct prefix *) pin);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network PREFIX",
       "Delete static network for bgp announcement.")
{
  int ret;
  struct bgp *bgp;
  struct prefix_in *pin;
  struct prefix_in *pr;

  bgp = (struct bgp *) vty->index;
  pin = prefix_in_new ();

  ret = str2prefix_in (argv[0], pin);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      prefix_in_free (pin);
      return;
    }
  masked_route_in (pin);
  pin->type = ZEBRA_ROUTE_BGP;

  ret = radix_lookup_rt (bgp_static_radix, (struct prefix *) pin);
  if (!ret)
    {
      vty_out (vty, "Can't find specified static route configuration.\r\n");
      prefix_in_free (pin);
      return;
    }
  masked_route_in (pin);
  pin->type = ZEBRA_ROUTE_BGP;

  pr = (struct prefix_in *) radix_delete (bgp_static_radix, (struct prefix *) pin);
  prefix_in_free (pin);
  attr_free (pr->gate.info);
  prefix_in_free (pr);
}

vty_static_dump (struct prefix *pr, struct vty *vty)
{
  struct prefix_in *pin = (struct prefix_in *) pr;

  vty_out (vty, " network %s/%d%s", inet_ntoa (pin->prefix), pin->mask,
	   VTY_NEWLINE);
}

config_write_network (struct vty *vty, struct bgp *bgp)
{
  radix_apply_func (bgp_static_radix, vty_static_dump, vty);
}

void
view_init ()
{
  bgp_static_radix = radix_make_rib (AF_INET);
  bgp_static_radix->sameprefix = rt_ip_sameprefix;

#ifdef HAVE_IPV6
  bgp_static_radix_ipv6 = radix_make_rib (AF_INET6);
  bgp_static_radix_ipv6->sameprefix = rt_ipv6_sameprefix;
#endif /* HAVE_IPV6 */

  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &default_attr_localpref_cmd);
  install_element (BGP_NODE, &no_default_attr_localpref_cmd);
}
