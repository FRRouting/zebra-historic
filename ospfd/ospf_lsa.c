/* OSPF Link State Advertisement
   Copyright (C) 1999 Toshiaki Takada

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

#include <zebra.h>

#include "stream.h"
#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"

/* Originate Router-LSA. */
struct ospf_lsa *
ospf_router_lsa (struct ospf_interface *oi)
{
  struct ospf *ospf;
  struct ospf_lsa *lsa;
  listnode node;
  struct stream *s;
  int flag = 0;
  u_int16_t links = 0;
  int link_type = 0;
  int length = 0;
  u_int32_t putp;

  ospf = oi->ospf;

  s = stream_new (oi->ifp->mtu);
  lsa = (struct ospf_lsa *) s->data;

  lsa->options = oi->options;
  lsa->type = OSPF_ROUTER_LSA;
  lsa->id = ospf->router_id;
  lsa->adv_router = ospf->router_id;
  lsa->ls_seqnum = htonl (ospf->ls_seqnum++);

  stream_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  /* set bit V if virtual link endpoint. */
  /* set bit E if AS boundary router. */
  /* set bit B if Area Border Router. */
  stream_putc (s, flag);
  
  /* Skip 1 octet. */
  stream_forward (s, 1);

  /* keep pointer to # links. */
  putp = s->putp;
  stream_forward (s, 2);
  length += 4;

  /* Link Information. */
  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *o;
      struct in_addr link_id, link_data;
      u_int16_t link_cost = 0;

      ifp = getdata (node);
      o = ifp->if_data;

      /* Area check. */
      if (!IPV4_ADDR_CMP (&o->area->area_id, &oi->area->area_id))
	continue;

      /* if status is Down. */
      if (o->status == ISM_Down)
	continue;

      /* is interface loopback? */

      /* Describe link. */
      switch (o->type)
	{
	case OSPF_IFTYPE_POINTOPOINT:
	  break;
	case OSPF_IFTYPE_BROADCAST:
	case OSPF_IFTYPE_NBMA:
	  if (o->status == ISM_Waiting)
	    {
	      struct in_addr mask;

	      /* Describe Type 3 Link. */
	      link_type = LSA_LINK_TYPE_STUB;
	      masklen2ip (o->address->prefixlen, &mask);
	      link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	      link_data = mask;
	      link_cost = o->output_cost;
	    }
	  else if (ospf_fully_adjacent_count (oi->nbrs))
	    {
	      /* Describe Type 2 link. */
	      link_type = LSA_LINK_TYPE_TRANSIT;
	      link_id = o->d_router;
	      link_data = o->address->u.prefix4;
	      link_cost = o->output_cost;
	    }
	  else
	    {
	      struct in_addr mask;

	      link_type = LSA_LINK_TYPE_STUB;
	      masklen2ip (o->address->prefixlen, &mask);
	      link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	      link_data = mask;
	      link_cost = o->output_cost;
	    }
	  break;
	case OSPF_IFTYPE_POINTOMULTIPOINT:
	  break;
	case OSPF_IFTYPE_VIRTUALLINK:
	  break;
	}

      stream_put_ipv4 (s, link_id.s_addr);	/* Link ID. */
      stream_put_ipv4 (s, link_data.s_addr);	/* Link Data. */
      stream_putc (s, link_type);		/* Type. */
      stream_putc (s, (u_char) 0);		/* # TOS. */
      stream_putw (s, htons (link_cost));	/* metric. */
      /* TOS based routing is not supported. */

      links++;
      length += 12;
    }

  /* Set # links. */
  stream_putw_at (s, putp, htonl (links));

  /* Set length. */
  lsa->length = htons (length);

  return lsa;
}

struct ospf_lsa *
ospf_lsa_header (struct ospf_interface *oi, u_char type)
{
  struct ospf_lsa *new;

  new = XMALLOC (MTYPE_OSPF_LSA, sizeof (struct ospf_lsa));
  bzero (new, sizeof (struct ospf_lsa));

  new->options = oi->options;
  new->type = type;

  switch (type)
    {
    case OSPF_NETWORK_LSA:
      new->id = oi->address->u.prefix4;
      break;
    case OSPF_SUMMARY_LSA_ASBR:
      new->id = ospf_top->router_id;
      break;
    }

  new->adv_router = ospf_top->router_id;
  new->ls_seqnum = ospf_top->ls_seqnum++;

  new->checksum = 0;
  new->length = 0;

  return new;
}

