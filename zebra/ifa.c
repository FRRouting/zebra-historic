/* Address linked list routine.
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "route.h"
#include "sockunion.h"
#include "vector.h"
#include "linklist.h"
#include "if.h"
#include "ifa.h"
#include "vty.h"
#include "memory.h"
#include "zebra.h"

/* Allocate new address structure. */
struct if_addr *
ifa_new ()
{
  struct if_addr *new = XMALLOC (MTYPE_IF_ADDR, sizeof (struct if_addr));
  bzero (new, sizeof (struct if_addr));
  return new;
}

sockunion_vty_family (struct vty *vty, union sockunion *su)
{
  switch (su->sa.sa_family)
    {
    case AF_INET:
      vty_out (vty, "inet");
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      vty_out (vty, "inet6");
      break;
#endif /* HAVE_IPV6 */
    }
}

/**/
ifa_dump_vty (struct vty *vty, struct interface *ifp, struct if_addr *ifa)
{
  
  vty_out (vty, "  ");
  sockunion_vty_family (vty, &ifa->ifa_addr);
  vty_out (vty, " ");
  sockunion_vty_out (vty, &ifa->ifa_addr);
  vty_out (vty, "/%d", sockunion_masklen (&ifa->ifa_mask));

  if (ifa->ifa_addr.sa.sa_family == AF_INET)
    if (ifp->flags & IFF_BROADCAST)
      {
	vty_out (vty, " broadcast ");
	sockunion_vty_out (vty, &ifa->ifa_dest);
      }

  if (ifp->flags & IFF_POINTOPOINT)
    {
      vty_out (vty, " pointopoint ");
      sockunion_vty_out (vty, &ifa->ifa_dest);
    }
  vty_out (vty, "\r\n");
}

/* Print if_addr structure. */
void
ifa_print (unsigned long flags, struct if_addr *ifa)
{
  switch (ifa->ifa_addr.sa.sa_family) {
  case AF_INET:
    log ("  inet ");
    sockunion_log (&ifa->ifa_addr);
    sockunion_log (&ifa->ifa_mask);
    if (flags & IFF_BROADCAST)
      sockunion_log (&ifa->ifa_dest);
    log2 ("\n");
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    log ("  inet6 ");
    sockunion_log (&ifa->ifa_addr);
    log2 ("/%d\n", ip6_masklen (ifa->ifa_mask.sin6.sin6_addr));
    break;
#endif /* HAVE_IPV6 */
  default:
    break;
  }
}

/* Insert interface address route into rib. */
ifa_rib_insert (struct if_addr *ifa, struct interface *ifp)
{
  switch (ifa->ifa_addr.sa.sa_family)
    {
    case AF_INET:
      {
	struct prefix_in *pin;

	pin = prefix_in_new ();
	pin->type = ZEBRA_ROUTE_CONNECT;
	pin->prefix = ifa->ifa_addr.sin.sin_addr;
	pin->mask = ip_masklen (ifa->ifa_mask.sin.sin_addr);
	pin->gate.info = ifp;
	pin->fib = 1;

	/* We need which interface is this route belongs to. */
	rib_add_in (pin);
      }
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      {
	struct prefix_in6 *pin6;
	
	pin6 = prefix_in6_new ();
	pin6->type = ZEBRA_ROUTE_CONNECT;
	memcpy (&pin6->prefix, &ifa->ifa_addr.sin6.sin6_addr, sizeof (struct in6_addr));
	pin6->mask = ip6_masklen (ifa->ifa_mask.sin6.sin6_addr);
	pin6->gate.info = ifp;
	pin6->fib = 1;

	/* We need which interface is this route belongs to. */
	rib_add_in6 (pin6);
      }
      break;
#endif
    }
}
