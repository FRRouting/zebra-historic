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
#include "linklist.h"

#include "zebra/zebra.h"
#include "zebra/rib.h"
#include "zebra/redistribute.h"

int
zebra_check_addr (struct prefix *p)
{
  if (p->family == AF_INET)
    {
      u_int32_t addr;

      addr = p->u.prefix4.s_addr;
      addr = ntohl (addr);

      if (IPV4_NET127 (addr))
	return 0;
    }
#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK (&p->u.prefix6))
	return 0;
      if (IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6))
	return 0;
    }
#endif /* HAVE_IPV6 */
  return 1;
}

/* Redistribute routes. */
void
zebra_redistribute (struct zebra_client *client, int type)
{
  struct rib *rib;
  struct route_node *np;

  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (IS_RIB_FIB (rib) && rib->type == type && zebra_check_addr (&np->p))
	zebra_ipv4_add (client->fd, type, 0, (struct prefix_ipv4 *)&np->p,
			&rib->u.gate4, 0);

#ifdef HAVE_IPV6
  for (np = route_top (ipv6_rib_table); np; np = route_next (np))
    for (rib = np->info; rib; rib = rib->next)
      if (IS_RIB_FIB (rib) && rib->type == type && zebra_check_addr (&np->p))
	zebra_ipv6_add (client->fd, type, (struct prefix_ipv6 *)&np->p,
			&rib->u.gate6, 0);
#endif /* HAVE_IPV6 */
}

extern list client_list;

void
redistribute_add_ipv4 (struct route_node *np, struct rib *rib)
{
  struct zebra_client *client;
  listnode node;

  for (node = listhead (client_list); node; nextnode (node))
    {
      client = getdata (node);
      if (client->redist[rib->type])
	zebra_ipv4_add (client->fd, rib->type, 0, (struct prefix_ipv4 *)&np->p,
			&rib->u.gate4, 0);
    }
}

void
redistribute_delete_ipv4 (struct route_node *np, struct rib *rib)
{
  struct zebra_client *client;
  listnode node;

  for (node = listhead (client_list); node; nextnode (node))
    {
      client = getdata (node);
      if (client->redist[rib->type])
	zebra_ipv4_delete (client->fd, rib->type, 0, 
			   (struct prefix_ipv4 *)&np->p, &rib->u.gate4, 0);
    }
}

#ifdef HAVE_IPV6
void
redistribute_add_ipv6 (struct route_node *np, struct rib *rib)
{
  struct zebra_client *client;
  listnode node;

  for (node = listhead (client_list); node; nextnode (node))
    {
      client = getdata (node);
      if (client->redist[rib->type])
	zebra_ipv6_add (client->fd, rib->type, (struct prefix_ipv6 *)&np->p,
			&rib->u.gate6, 0);
    }
}

void
redistribute_delete_ipv6 (struct route_node *np, struct rib *rib)
{
  struct zebra_client *client;
  listnode node;

  for (node = listhead (client_list); node; nextnode (node))
    {
      client = getdata (node);
      if (client->redist[rib->type])
	zebra_ipv6_delete (client->fd, rib->type, (struct prefix_ipv6 *)&np->p,
			   &rib->u.gate6, 0);
    }
}
#endif /* HAVE_IPV6 */

void
zebra_redistribute_add (int command, struct zebra_client *client, int length)
{
  int type;

  type = stream_getc (client->ibuf);

  switch (type)
    {
    case ZEBRA_ROUTE_CONNECT:
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
      if (! client->redist[type])
	{
	  client->redist[type] = 1;
	  zebra_redistribute (client, type);
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
    case ZEBRA_ROUTE_STATIC:
    case ZEBRA_ROUTE_RIP:
    case ZEBRA_ROUTE_RIPNG:
    case ZEBRA_ROUTE_OSPF:
    case ZEBRA_ROUTE_OSPF6:
    case ZEBRA_ROUTE_BGP:
      client->redist[type] = 0;
      break;
    default:
      break;
    }
}     
