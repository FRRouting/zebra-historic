/*
 * Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "client.h"

#include "zebra/zebra.h"
#include "zebra/rib.h"
#include "zebra/redistribute.h"

/* Redistribute routes. */
void
zebra_redistribute (struct zebra_client *client, int type)
{
  struct route_node *np;
  struct rib *rib;

  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (rib->type == type)
	zebra_ipv4_add (client->fd, type, (struct prefix_ipv4 *)&np->p,
			&rib->u.gate4, 0);

#ifdef HAVE_IPV6
  for (np = route_top (ipv6_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (rib->type == type)
	zebra_ipv6_add (client->fd, type, (struct prefix_ipv6 *)&np->p,
			&rib->u.gate6, 0);
#endif /* HAVE_IPV6 */
}

void
zebra_redistribute_add (int command, struct zebra_client *client, int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_CONNECT:
      if (! client->redist_connect)
	{
	  client->redist_connect = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_CONNECT);
	}
      break;
    case ZEBRA_ROUTE_STATIC:
      if (! client->redist_static)
	{
	  client->redist_static = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_STATIC);
	}
      break;
    case ZEBRA_ROUTE_RIP:
      if (! client->redist_rip)
	{
	  client->redist_rip = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_RIP);
	}
      break;
    case ZEBRA_ROUTE_RIPNG:
      if (! client->redist_ripng)
	{
	  client->redist_ripng = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_RIPNG);
	}
      break;

    case ZEBRA_ROUTE_OSPF:
      if (! client->redist_ospf)
	{
	  client->redist_ospf = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_OSPF);
	}
      break;

    case ZEBRA_ROUTE_OSPF6:
      if (! client->redist_ospf6)
	{
	  client->redist_ospf6 = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_OSPF6);
	}
      break;

    case ZEBRA_ROUTE_BGP:
      if (! client->redist_bgp)
	{
	  client->redist_bgp = 1;
	  zebra_redistribute (client, ZEBRA_ROUTE_BGP);
	}
      break;

    default:
      break;
    }
}     

void
zebra_redistribute_delete (int command, struct zebra_client *client, 
			   int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_CONNECT:
      client->redist_connect = 0;
      break;
    case ZEBRA_ROUTE_STATIC:
      client->redist_static = 0;
      break;
    case ZEBRA_ROUTE_RIP:
      client->redist_rip = 0;
      break;
    case ZEBRA_ROUTE_RIPNG:
      client->redist_ripng = 0;
      break;
    case ZEBRA_ROUTE_OSPF:
      client->redist_ospf = 0;
      break;
    case ZEBRA_ROUTE_OSPF6:
      client->redist_ospf6 = 0;
      break;
    case ZEBRA_ROUTE_BGP:
      client->redist_bgp = 0;
      break;
    }
}     
