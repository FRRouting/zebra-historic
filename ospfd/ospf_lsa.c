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

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"
#include "hash.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_lsdb.h"

u_int32_t
get_metric (u_char *metric)
{
  u_int32_t m;
  m = metric[0];
  m = (m << 8) + metric[1];
  m = (m << 8) + metric[2];
  return m;
}


/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX		     4102
#define LSA_CHECKSUM_OFFSET    15

u_int16_t
ospf_lsa_checksum (struct lsa_header *lsa)
{
  u_char *sp, *ep, *p, *q;
  int c0 = 0, c1 = 0;
  int x, y;
  u_int16_t length;

  lsa->checksum = 0;
  length = ntohs (lsa->length) - 2;
  sp = (char *) &lsa->options;

  for (ep = sp + length; sp < ep; sp = q)
    {
      q = sp + MODX;
      if (q > ep)
	q = ep;
      for (p = sp; p < q; p++)
	{
	  c0 += *p;
	  c1 += c0;
	}
      c0 %= 255;
      c1 %= 255;
    }

  /* r = (c1 << 8) + c0; */
  x = ((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  lsa->checksum = x + (y << 8);

  return (lsa->checksum);
}

/* Create OSPF LSA. */
struct ospf_lsa *
ospf_lsa_new ()
{
  struct ospf_lsa *new;

  new = XMALLOC (MTYPE_OSPF_LSA, sizeof (struct ospf_lsa));

  assert (new);

  bzero (new, sizeof (struct ospf_lsa));

  new->flags = 0;
  new->ts = time (NULL);
  new->originated = new->ts;
  new->v_age = OSPF_CHECK_AGE;		/* should be changed. */

  return new;
}

/* Duplicate OSPF LSA. */
struct ospf_lsa *
ospf_lsa_dup (struct ospf_lsa *lsa)
{
  struct ospf_lsa *new;

  if (lsa == NULL)
    return NULL;

  new = XMALLOC (MTYPE_OSPF_LSA, sizeof (struct ospf_lsa));

  assert (new);

  bzero (new, sizeof (struct ospf_lsa));

  new->flags = lsa->flags;
  new->ts = lsa->ts;
  new->v_age = lsa->v_age;
  new->t_age = lsa->t_age;

  new->data = ospf_lsa_data_dup (lsa->data);

  return new;
}

/* Free OSPF LSA. */
void
ospf_lsa_free (struct ospf_lsa *lsa)
{
  zlog_info ("LLLS: ospf_lsa_free lsa=%x", lsa);
  if (lsa->data != NULL)
    {
      zlog_info ("LLLD: opsf_lsa_data_free lsa->data=%x", lsa->data);
      ospf_lsa_data_free (lsa->data);
    }

  /* should be cancel thread. */

  XFREE (MTYPE_OSPF_LSA, lsa);
}

/* Create LSA data. */
struct lsa_header *
ospf_lsa_data_new (size_t size)
{
  struct lsa_header *new;

  new = (struct lsa_header *) XMALLOC (MTYPE_OSPF_LSA_DATA, size);

  assert(new);

  bzero (new, size);

  return new;
}

/* Duplicate LSA data. */
struct lsa_header *
ospf_lsa_data_dup (struct lsa_header *lsah)
{
  struct lsa_header *new;

  new = ospf_lsa_data_new (ntohs (lsah->length));
  memcpy (new, lsah, ntohs (lsah->length));

  return new;
}

/* Free LSA data. */
void
ospf_lsa_data_free (struct lsa_header *lsah)
{
  XFREE (MTYPE_OSPF_LSA_DATA, lsah);
}


/* Originate Router-LSA. */
struct ospf_lsa *
ospf_router_lsa (struct ospf_area *area)
{
  struct ospf_lsa *new, *old;
  struct lsa_header *lsah;
  struct stream *s;
  listnode node;
  u_int16_t links = 0;
  int link_type = 0;
  int length = 0;
  u_int32_t putp;
  u_int32_t seqnum;
  u_char flags;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;
  lsah->options = 0;

  /* If the area has external routing capability, set option E. */
  if (area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_ROUTER_LSA;
  lsah->id = ospf_top->router_id;
  lsah->adv_router = ospf_top->router_id;

  old = area->router_lsa_self;
  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  flags = ospf_top->flags;

  if (ospf_full_virtual_nbrs (area))
    SET_FLAG (flags, OSPF_FLAG_VIRTUAL_LINK);
  else
    UNSET_FLAG (flags, OSPF_FLAG_VIRTUAL_LINK); /* Just sanity check */

  if ((ospf_top->abr_type == OSPF_ABR_SHORTCUT) &&
      area->shortcut_configured)
    SET_FLAG (flags, OSPF_FLAG_SHORTCUT);
  else
    UNSET_FLAG (flags, OSPF_FLAG_SHORTCUT);


  stream_putc (s, flags);
  stream_putc (s, 0);
  
  /* Keep pointer to # links. */
  putp = s->putp;
  ospf_output_forward (s, 2);
  length += 4;

  /* Link Information. */
  for (node = listhead (area->iflist); node; node = nextnode (node))
    {
      struct in_addr mask;
      struct interface *ifp;
      struct ospf_interface *o;
      struct in_addr link_id, link_data;
      struct ospf_neighbor *dr, *nbr;
      u_int16_t link_cost = 0;
      struct route_node *rn;
      listnode co_node;
      struct connected *co;

      ifp = getdata (node);
      o = ifp->info;

      if (o->flag != OSPF_IF_ENABLE)
	continue;

      /* No need for area check, since we go through area->iflist
      if (o->area == NULL)
	continue;

      if (IPV4_ADDR_CMP (&o->area->area_id, &area->area_id))
	continue;
      */

      /* if status is Down. */
      if (o->status == ISM_Down)
	continue;

      /* Describe link. */
      switch (o->type)
	{
	case OSPF_IFTYPE_POINTOPOINT:
	  nbr = NULL;
	  for (rn = route_top (o->nbrs); rn; rn = route_next (rn))
	    {
	      if (rn->info == NULL)
		continue;

	      nbr = rn->info;

              if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
		 continue; /* this is myself*/
              if (nbr->status == NSM_Full) break;
	    }

	  if ( nbr && (nbr->status == NSM_Full))
	    {
	      link_type = LSA_LINK_TYPE_POINTOPOINT;
	      link_id = nbr->router_id;
	      link_data.s_addr = o->address->u.prefix4.s_addr;
	      /* For unnumbered point-to-point networks, the Link Data
		 field should specify the interface's MIB-II ifIndex
		 value. */
	      link_cost = o->output_cost;

 	      stream_put_ipv4 (s, link_id.s_addr);	/* Link ID. */
      	      stream_put_ipv4 (s, link_data.s_addr);	/* Link Data. */
              stream_putc (s, link_type);		/* Type. */
      	      stream_putc (s, (u_char) 0);		/* # TOS. */
      	      stream_putw (s, link_cost);		/* metric. */
     	      /* TOS based routing is not supported. */

             links++;
             length += 12;
	    }

	  /* Option 1 representation. It's rather legacy

	  link_type = LSA_LINK_TYPE_STUB;
	  link_id = nbr->address.u.prefix4;
	  link_data.s_addr = 0xffffffff;
	  link_cost = o->output_cost;
	  */

	  /* Option 2, we need to include link to a stub network
	     regardless of the state of the neighbor */

	  link_type = LSA_LINK_TYPE_STUB;
	  masklen2ip (o->address->prefixlen, &mask);
	  link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	  link_data = mask;
	  link_cost = o->output_cost;

	  break;
	case OSPF_IFTYPE_BROADCAST:
	case OSPF_IFTYPE_NBMA:
	  if (o->status == ISM_Waiting)
	    {
	      /* Describe Type 3 Link. */
	      link_type = LSA_LINK_TYPE_STUB;
	      masklen2ip (o->address->prefixlen, &mask);
	      link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	      link_data = mask;
	      link_cost = o->output_cost;
	      break;
	    }
	  dr = ospf_nbr_lookup_by_addr (o->nbrs, &DR (o));
	  if (dr == NULL)
	    break;
	  if ((dr->status == NSM_Full ||
	       IPV4_ADDR_SAME (&o->address->u.prefix4, &DR (o))) &&
	       ospf_nbr_count (o->nbrs, NSM_Full) > 0)
	    {
	      /* Describe Type 2 link. */
	      link_type = LSA_LINK_TYPE_TRANSIT;
	      link_id = DR (o);
	      link_data = o->address->u.prefix4;
	      link_cost = o->output_cost;
	    }
	  else
	    {
	      /* Describe type 3 link. */
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
          zlog_info ("Z: ospf_router_lsa(): type VL, state %d", o->status);
          if (o->status == ISM_PointToPoint)
	    {
	      nbr = NULL;

	      RT_ITERATOR (o->nbrs, rn)
		{
		  if (rn->info == NULL)
		    continue;
		  nbr = rn->info;

		  if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
		    continue; /* this is myself*/
		  if (nbr->status == NSM_Full) break;
		} 

	      if (nbr && (nbr->status == NSM_Full))
		{
		  link_type = LSA_LINK_TYPE_VIRTUALLINK;
		  link_id = nbr->router_id;
		  link_data.s_addr = o->address->u.prefix4.s_addr;
		  link_cost = o->output_cost;
		}
	      else
		continue;
	    }
	  break;
	}

      stream_put_ipv4 (s, link_id.s_addr);	/* Link ID. */
      stream_put_ipv4 (s, link_data.s_addr);	/* Link Data. */
      stream_putc (s, link_type);		/* Type. */
      stream_putc (s, (u_char) 0);		/* # TOS. */
      stream_putw (s, link_cost);		/* metric. */
      /* TOS based routing is not supported. */

      links++;
      length += 12;

      /* Announce secondary subnets as stub networks */

      if (o->type != OSPF_IFTYPE_VIRTUALLINK)
         LIST_ITERATOR(o->ifp->connected, co_node)
         {
           co = getdata (co_node);
           if (co == NULL)
	     continue;

           if (co->address->family != AF_INET)
	     continue;

           if (prefix_same (co->address, o->address))
	     continue;

 	   link_type = LSA_LINK_TYPE_STUB;
	   masklen2ip (co->address->prefixlen, &mask);
	   link_id.s_addr = co->address->u.prefix4.s_addr & mask.s_addr;
	   link_data = mask;
	   link_cost = o->output_cost;

           stream_put_ipv4 (s, link_id.s_addr);	/* Link ID. */
           stream_put_ipv4 (s, link_data.s_addr);	/* Link Data. */
           stream_putc (s, link_type);		/* Type. */
           stream_putc (s, (u_char) 0);		/* # TOS. */
           stream_putw (s, link_cost);		/* metric. */

           links++;
           length += 12;
           
         }
    }

  /* Set # links. */
  stream_putw_at (s, putp, links);

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  zlog_info("Z: ospf_lsa_new() in ospf_router_lsa(): %x", new);

  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  zlog_info ("Originate router-LSA sequence number 0x%x for area %s",
	     ntohl (new->data->ls_seqnum), inet_ntoa (area->area_id));

  return new;
}

/* Originate Network-LSA. */
struct ospf_lsa *
ospf_network_lsa (struct ospf_interface *oi)
{
  struct ospf *ospf;
  struct ospf_lsa *new, *old;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct route_node *rn;
  struct stream *s;
  struct ospf_neighbor *nbr;
  int length;
  u_int32_t seqnum;

  ospf = oi->ospf;

  s = stream_new (oi->ifp->mtu);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;
  lsah->options = OPTIONS (oi);

  if (oi->area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_NETWORK_LSA;
  lsah->id = DR (oi);
  lsah->adv_router = ospf->router_id;

  old = oi->network_lsa_self;
  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  masklen2ip (oi->address->prefixlen, &mask);

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if (rn->info == NULL)
	continue;
      nbr = rn->info;

      /* this is myself, include :)
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;
      */

      stream_put_ipv4 (s, nbr->router_id.s_addr);
      length += 4;
    }

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  zlog_info("Z: ospf_lsa_new() in ospf_network_lsa(): %x", new);
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  zlog_info ("Originate network-LSA sequence number 0x%x",
	     ntohl (lsah->ls_seqnum));

  return new;
}

/* Originate Summary-LSA. */
struct ospf_lsa *
ospf_summary_lsa (struct prefix_ipv4 *p, u_int32_t metric, 
		  struct ospf_area *for_area, struct ospf_lsa *old)
{
  struct ospf_lsa *new;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct stream *s;
  int length;
  char *mp;
  u_int32_t seqnum;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;

  lsah->options = 0;

  if (for_area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_SUMMARY_LSA;

  /* We should take care about host bits here */

  if (old)
     lsah->id = old->data->id;
  else
     lsah->id = ospf_get_free_id_for_prefix(SUMMARY_LSA(for_area), p,
	 			            ospf_top->router_id);


  lsah->adv_router = ospf_top->router_id;

  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  masklen2ip (p->prefixlen, &mask);

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  stream_putc (s, (u_char) 0);		/* # TOS. */
  length += 1;

  metric = htonl(metric);
  mp = (char *) &metric;
  mp++;
  stream_put(s, mp, 3);
  length += 3;

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  zlog_info("Z: ospf_lsa_new() in ospf_summary_lsa(): %x", new);
  SET_FLAG(new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  zlog_info ("Originate summary-LSA sequence number 0x%x",
	     ntohl (lsah->ls_seqnum));

  return new;
}


struct ospf_lsa *
ospf_summary_asbr_lsa (struct prefix_ipv4 *p, u_int32_t metric, 
		       struct ospf_area *for_area, struct ospf_lsa *old)
{
  struct ospf_lsa *new;
  struct lsa_header *lsah;
  struct in_addr mask;
  struct stream *s;
  int length;
  char *mp;
  u_int32_t seqnum;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;

  lsah->options = 0;

  if (for_area->external_routing == OSPF_AREA_DEFAULT)
    SET_FLAG (lsah->options, OSPF_OPTION_E);
  else
    UNSET_FLAG (lsah->options, OSPF_OPTION_E);

  lsah->type = (u_char) OSPF_SUMMARY_LSA_ASBR;

  lsah->id.s_addr = p->prefix.s_addr;

  lsah->adv_router = ospf_top->router_id;

  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  mask.s_addr = 0;

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  stream_putc (s, (u_char) 0);		/* # TOS. */
  length += 1;

  metric = htonl(metric);
  mp = (char *) &metric;
  mp++;
  stream_put(s, mp, 3);
  length += 3;

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  zlog_info("Z: ospf_lsa_new() in ospf_asbr_summary_lsa(): %x", new);
  SET_FLAG(new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  zlog_info ("Originate ASBR-summary-LSA sequence number 0x%x",
	     ntohl (lsah->ls_seqnum));

  return new;
}


/* Originate AS-external-LSA. */
struct ospf_lsa *
ospf_external_lsa (struct prefix_ipv4 *p, u_char type, u_int32_t metric,
		   u_int32_t tag, struct in_addr forward, struct ospf_lsa *old)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new;
  int length;
  u_int32_t seqnum;
  struct in_addr mask, fwd_addr;
  u_char metric_type;
  char *mp;
  struct route_node *rn;
  struct prefix nhp;
  struct ospf_route *or;
  listnode nh_node;
  struct ospf_path *path, *direct_path = NULL;
  struct ospf_interface *oi;

  s = stream_new (OSPF_MAX_LSA_SIZE);
  lsah = (struct lsa_header *) STREAM_DATA (s);

  lsah->ls_age = 0;
  lsah->options = 0;
  SET_FLAG(lsah->options, OSPF_OPTION_E);
  lsah->type = (u_char) OSPF_AS_EXTERNAL_LSA;

/*  lsah->id.s_addr = p->prefix.s_addr; */

  if (old)
     lsah->id = old->data->id;
  else
     lsah->id = ospf_get_free_id_for_prefix(ospf_top->external_lsa, p,
				            ospf_top->router_id);

  lsah->adv_router = ospf_top->router_id;

  if (old)
    {
      seqnum = ntohl (old->data->ls_seqnum) + 1;
      lsah->ls_seqnum = htonl (seqnum);
    }
  else
    lsah->ls_seqnum = htonl (OSPF_INITIAL_SEQUENCE_NUMBER);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  /* Put Network Mask. */
  masklen2ip (p->prefixlen, &mask);
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  /* Put type of external metric. */
  metric_type = 0;
  if (type == EXTERNAL_METRIC_TYPE_2)
    metric_type |= 0x80;
  stream_putc (s, metric_type);
  length += 1;

  /* Put metric. */
  metric = htonl (metric);
  mp = (char *) &metric;
  mp++;
  stream_put(s, mp, 3);
  length += 3;

  fwd_addr.s_addr = 0;

  if (forward.s_addr && ospf_top->new_table)
    {
      /* Check if the nexthop is covered by OSPF routing table */

      nhp.family = AF_INET;
      nhp.u.prefix4.s_addr = forward.s_addr;
      nhp.prefixlen = IPV4_MAX_BITLEN;
      rn = route_node_match (ospf_top->new_table, &nhp);

     if (rn)  /* Yeap, covered */
       {
	 int ok = 0;

	 zlog_info ("Z: ospf_external_lsa(): found a route to nexthop");
	 or = rn->info;
	 route_unlock_node (rn);

	 if (or->path_type == OSPF_PATH_INTRA_AREA)
	   {
	     LIST_ITERATOR (or->path, nh_node)
	       {
		 path = getdata (nh_node);
		 if (path == NULL)
		   continue;

		 if (path->nexthop.s_addr == 0)
		   {
		     direct_path = path;
		     ok = 1;
		   }
		 else
		   {
		     ok = 0;
		     zlog_info ("Z: ospf_external_lsa(): "
				"route is known as remote, not ok");
		     break;
		   }
	       }

	     if (ok)  /* Now check if we know this guy from OSPF */
	       {
		 oi = direct_path->ifp->info;
		 if (oi == NULL) 
		   ok = 0;
		 else
		   {
		     ok = ospf_nbr_lookup_by_addr (oi->nbrs, &forward) == NULL;
		     if (!ok)
		       zlog_info("Z: ospf_external_lsa(): "
				 "nexthop is known from OSPF, not OK");
		   }
	       }

	     if (ok)
	       {
		 zlog_info ("Z: ospf_external_lsa(): nexthop is ok, setting");
		 fwd_addr.s_addr = forward.s_addr;
	       }
	   }
	 else
	   zlog_info ("Z: ospf_external_lsa(): "
		      "but it's not intra-area, sorry");
       }
    }

  /* Put forwarding address. */
  stream_put_ipv4 (s, fwd_addr.s_addr);
  length += 4;
  
  /* Put route tag. */
  stream_putl (s, tag);
  length += 4;

  /* TOS. can be here for compatibility with RFC1583. */
  /* Not yet implemented. */;

  /* Set length. */
  lsah->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsah);

  /* Create OSPF LSA instance. */
  new = ospf_lsa_new ();
  zlog_info("Z: ospf_lsa_new() in ospf_external_lsa(): %x", new);
  SET_FLAG (new->flags, OSPF_LSA_SELF);

  /* Copy LSA to store. */
  new->data = ospf_lsa_data_new (length);
  memcpy (new->data, lsah, length);
  stream_free (s);

  zlog_info ("Originate AS-external-LSA sequence number 0x%x",
	     ntohl (lsah->ls_seqnum));

  return new;
}

int
ospf_router_lsa_refresh (struct thread *t)
{
  struct ospf_area *area;
  struct ospf_lsa *lsa;

  zlog_info ("K: ospf_router_lsa_refresh: Start");

  area = THREAD_ARG (t);
  area->t_router_lsa_self = NULL;

  zlog_info ("K: ospf_router_lsa_refresh: refresh router LSA start");

  lsa = ospf_router_lsa (area);
  lsa = ospf_router_lsa_install (area, lsa);
  ospf_flood_through_area (area, NULL, lsa);

  zlog_info ("K: ospf_router_lsa_refresh: refresh router LSA end");

  zlog_info ("K: ospf_router_lsa_refresh: Stop");

  return 0;
}

int
ospf_network_lsa_refresh (struct thread *t)
{
  struct ospf_interface *oi;
  struct ospf_lsa *lsa;

  zlog_info ("K: ospf_network_lsa_refresh: Start");

  oi = THREAD_ARG (t);
  oi->t_network_lsa_self = NULL;

  zlog_info ("K: ospf_network_lsa_refresh: refresh router LSA start");

  lsa = ospf_network_lsa (oi);
  lsa = ospf_network_lsa_install (oi, lsa);
  ospf_flood_through_area (oi->area, NULL, lsa);

  zlog_info ("K: ospf_network_lsa_refresh: refresh router LSA end");

  zlog_info ("K: ospf_network_lsa_refresh: Stop");

  return 0;
}


void
ospf_summary_lsa_refresh (struct ospf_lsa * lsa)
{
  struct ospf_area *area = lsa->lsdb->area;
  struct prefix_ipv4 p;
  struct summary_lsa * slsa = (struct summary_lsa *) lsa->data;

  assert (lsa);
  assert (area);

  zlog_info ("Z: ospf_summary_lsa_refresh: Start");

  p.family = AF_INET;
  p.prefix = slsa->header.id;
  p.prefixlen = ip_masklen (slsa->mask);
  apply_mask_ipv4 (&p);

  zlog_info ("Z: ospf_summary_lsa_refresh: Constructing new version");

  lsa = ospf_summary_lsa (&p, GET_METRIC (slsa->metric), area, lsa);
  lsa = ospf_summary_lsa_install (area, lsa);

  zlog_info ("Z: ospf_summary_lsa_refresh: Flooding new version");
  ospf_flood_through_area (area, NULL, lsa);
}

void
ospf_summary_lsa_asbr_refresh (struct ospf_lsa * lsa)
{
  struct ospf_area *area = lsa->lsdb->area;
  struct prefix_ipv4 p;
  struct summary_lsa * slsa = (struct summary_lsa *) lsa->data;

  assert (area);

  zlog_info ("Z: ospf_summary_lsa_asbr_refresh: Start");

  p.family = AF_INET;
  p.prefix = slsa->header.id;
  p.prefixlen = IPV4_MAX_BITLEN;

  zlog_info ("Z: ospf_summary_lsa_asbr_refresh: Constructing new version");

  lsa = ospf_summary_asbr_lsa (&p, GET_METRIC (slsa->metric), area, lsa);
  lsa = ospf_summary_asbr_lsa_install (area, lsa);

  zlog_info ("Z: ospf_summary_lsa_asbr_refresh: Flooding new version");
  ospf_flood_through_area (area, NULL, lsa);
}

void
ospf_external_lsa_refresh (struct ospf_lsa * lsa)
{
  struct prefix_ipv4 p;
  struct as_external_lsa * elsa = (struct as_external_lsa *) lsa->data;
  u_char type;



  zlog_info ("Z: ospf_external_lsa_refresh: Start");

  p.family = AF_INET;
  p.prefix = elsa->header.id;
  p.prefixlen = ip_masklen (elsa->mask);
  apply_mask_ipv4 (&p);

  if (IS_EXTERNAL_METRIC (elsa->e[0].tos))
     type = EXTERNAL_METRIC_TYPE_2;
  else
     type = EXTERNAL_METRIC_TYPE_1;

  zlog_info ("Z: ospf_external_lsa_refresh: Constructing new version");


  lsa = ospf_external_lsa (&p, type, GET_METRIC (elsa->e[0].metric),
 		           ntohl (elsa->e[0].route_tag.s_addr),
                           elsa->e[0].fwd_addr, lsa);
  lsa = ospf_external_lsa_install (lsa);
  zlog_info ("Z: ospf_external_lsa_refresh: Flooding new version");
  ospf_flood_through_as (NULL, lsa);
}




/* Install router-LSA to an area. */
struct ospf_lsa *
ospf_router_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
  struct ospf_lsa *lsa;

  /* Install new instance. */
  lsa = ospf_lsdb_add (ROUTER_LSA(area), new);

  /* Set lsdb pointer to the lsa. */
  lsa->lsdb = ROUTER_LSA (area);

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF)) 
    {
      zlog_info("setting LSA %s as router_lsa_self", inet_ntoa(lsa->data->id));
      zlog_info("the area is %s", inet_ntoa(area->area_id));

      /* Set LSRefresh timer. */
      if (area->t_router_lsa_self)
	OSPF_TIMER_OFF (area->t_router_lsa_self);

      area->t_router_lsa_self = 
	thread_add_timer (master, ospf_router_lsa_refresh,
			  area, OSPF_LS_REFRESH_TIME);
      
      /* Set self originate router lsa. */
      area->router_lsa_self = lsa;
    }

  zlog_info ("Inslall router-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install network-LSA to an area. */
struct ospf_lsa *
ospf_network_lsa_install (struct ospf_interface *oi, struct ospf_lsa *new)
{
  struct ospf_lsa *lsa;

  /* Add new LSA to lsdb. */
  lsa = ospf_lsdb_add (NETWORK_LSA (oi->area), new);

  /* Set lsdb pointer to the lsa. */
  lsa->lsdb = NETWORK_LSA (oi->area);

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

  /* We supposed that when LSA is originated by us,
     we pass the int for which it was originated.
     if LSA was received by flooding, the RECEIVED
     flag is set, so we do not link the LSA to the int
   */

  if ( CHECK_FLAG (lsa->flags, OSPF_LSA_SELF) &&
      !CHECK_FLAG (lsa->flags, OSPF_LSA_RECEIVED))
    {
      /* Set LSRefresh timer. */
      if (oi->t_network_lsa_self)
	OSPF_TIMER_OFF (oi->t_network_lsa_self);

      oi->t_network_lsa_self = 
	thread_add_timer (master, ospf_network_lsa_refresh,
			  oi, OSPF_LS_REFRESH_TIME);
      
      oi->network_lsa_self = lsa;
    }

  zlog_info ("Inslall network-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install summary-LSA to an area. */
struct ospf_lsa *
ospf_summary_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
#if 0
  struct route_node *rn;
  struct prefix p;
#endif /* 0 */
  struct ospf_lsa *lsa = NULL;

  zlog_info ("Z: ospf_summary_lsa_install(): Start");

  lsa = ospf_lsdb_add (SUMMARY_LSA (area), new);

  zlog_info ("Z: ospf_summary_lsa_install(): setting lsa->lsdb");

  lsa->lsdb = SUMMARY_LSA (area);

  zlog_info ("Z: ospf_summary_lsa_install(): Well done !");

  /* Schedule SPF calculation. */
  if (!CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
     ospf_spf_calculate_schedule ();

  zlog_info ("Z: ospf_summary_lsa_install(): SPF scheduled");

#if 0
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = lsa->data->id;

      zlog_info("Z: ospf_summary_lsa_install(): It is self-originated");
      rn = route_node_get (area->summary_lsa_self, &p);
      rn->info = lsa;
      zlog_info("Z: ospf_summary_lsa_install(): Installed into the list");
    }
#endif /* 0 */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
     ospf_refresher_register_lsa (ospf_top, lsa);
  zlog_info ("Inslall summary-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install ASBR-summary-LSA to an area. */
struct ospf_lsa *
ospf_summary_asbr_lsa_install (struct ospf_area *area, struct ospf_lsa *new)
{
#if 0
  struct route_node *rn;
  struct prefix p;
#endif /* 0 */
  struct ospf_lsa *lsa = NULL;
  
  lsa = ospf_lsdb_add (SUMMARY_LSA_ASBR (area), new);

  lsa->lsdb = SUMMARY_LSA_ASBR (area);

  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

#if 0
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = lsa->data->id;

      rn = route_node_get (area->summary_lsa_asbr_self, &p);
      rn->info = lsa;
    }
#endif /* 0 */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
     ospf_refresher_register_lsa (ospf_top, lsa);

  zlog_info ("Inslall ASBR-summary-LSA %s", inet_ntoa (lsa->data->id));

  return lsa;
}

/* Install ASBR-summary-LSA to an area. */
struct ospf_lsa *
ospf_external_lsa_install (struct ospf_lsa *new)
{
  struct ospf_lsa *lsa = NULL;
  
  zlog_info ("Z: ospf_external_lsa_install(): Start");

  zlog_info ("Z: ospf_external_lsa_install(): 1");

  lsa = ospf_lsdb_add (ospf_top->external_lsa, new);

  zlog_info ("Z: ospf_external_lsa_install(): 2");
  lsa->lsdb = ospf_top->external_lsa;
  assert (lsa->lsdb);

  zlog_info ("Z: ospf_external_lsa_install(): 3");
  /* Schedule SPF calculation. */
  ospf_spf_calculate_schedule ();

#if 0
  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    {
      zlog_info ("Z: ospf_external_lsa_install(): 4");
      ospf_lsdb_add (ospf_top->external_self, lsa);
    }
#endif /* 0 */

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
     ospf_refresher_register_lsa (ospf_top, lsa);

  zlog_info ("Z: ospf_external_lsa_install(): Stop");
  return lsa;
}

int
ospf_check_nbr_status ()
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct route_node *rn;
  struct ospf_neighbor *nbr;

  for (node = listhead (ospf_top->iflist); node; node = nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (! ospf_if_is_enable (ifp))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  nbr = rn->info;
	  if ((nbr->status == NSM_Exchange) || (nbr->status == NSM_Loading)) 
	    {
	      route_unlock_node (rn);
	      return 0;
	    }
	}
    }

  return 1;
}

int
ospf_maxage_lsa_remover (struct thread * thread)
{
  listnode node;
  listnode next;
  struct ospf_lsa *lsa;
  u_int left = 0;

  ospf_top->t_maxage = NULL;

  zlog_info ("Z: ospf_maxage_lsa_remover(): Start");

  if (ospf_check_nbr_status ())
    {
      for (node = listhead (ospf_top->maxage_lsa); node; node = next)
	{
	  lsa = getdata (node);
	  next = node->next;

	  if (lsa->ref == 0)
	    {
	      /* remove LSA from the LSDB */
	      zlog_info ("Z: ospf_maxage_lsa_remover(): "
			 "This LSA is no more referenced, removing");
	      zlog_info ("Z: ospf_maxage_lsa_remover(): removed lsa is : %s", 
                          inet_ntoa (lsa->data->id));
              if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
  	          zlog_info ("Z: ospf_maxage_lsa_remover(): This LSA is "
                             "self-orig: %s, type %d", 
                             inet_ntoa (lsa->data->id), lsa->data->type);
	      
              ospf_lsdb_delete (lsa->lsdb, lsa);
	      zlog_info ("Z: ospf_maxage_lsa_remover(): "
			 "removing entry from MaxAge list");
	      list_delete_by_val (ospf_top->maxage_lsa, lsa);
	      zlog_info ("Z: ospf_maxage_lsa_remover(): freeing LSA");

	      ospf_lsa_free (lsa);
              zlog_info("Z: ospf_lsa_free() in maxage_lsa_remover(): %x", lsa);
	    }
	  else
	    left++;
	}
    }
  else
    left = 1;

  if (left)
    {
      zlog_info ("Z: ospf_maxage_lsa_remover(): "
		 "some MaxAge LSAs are still there, rescheduling");
      OSPF_SCHEDULE_MAXAGE (ospf_top->t_maxage, ospf_maxage_lsa_remover);
    }
  return 0;
}

int
ospf_lsa_maxage_exist (struct ospf_lsa *new)
{
  listnode node;

  for (node = listhead (ospf_top->maxage_lsa); node; nextnode (node))
    if (((struct ospf_lsa *) node->data) == new)
      return 1;

  return 0;
}

void
ospf_lsa_maxage (struct ospf_lsa *lsa)
{
  /* When we saw a MaxAge LSA flooded to us,
     we put it on the list and schedule
     the MaxAge LSA remover */
  if (ospf_lsa_maxage_exist (lsa))
    {
      zlog_info ("ospf_lsa_maxage(): lsa %x already exists on maxage_lsa list",
		 lsa);
      return;
    }

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF) &&
      lsa->refresh_list) 
     ospf_refresher_unregister_lsa (lsa);

  list_add_node (ospf_top->maxage_lsa, lsa);

  zlog_info ("Z: Scheduling ospf_maxage_lsa_remover()");

  OSPF_SCHEDULE_MAXAGE (ospf_top->t_maxage, ospf_maxage_lsa_remover);
}

int
ospf_lsa_maxage_walker_remover (struct ospf_lsa *lsa, void *p_arg, int int_arg)
{
  if (LS_AGE (lsa) == OSPF_LSA_MAX_AGE)
    {
      /* Self-originated LSAs should NOT time-out
         instead, they're flushed and submitted
         to the max_age list explicitly
       */

      if (ospf_lsa_is_self_originated (lsa))
         return 0; 

      zlog_info("Z: ospf_lsa_maxage_walker_remover(): LSA %d is MaxAge",
		inet_ntoa (lsa->data->id));
      ospf_lsa_maxage (lsa);
    }

  return 0;
}

/* Periodical check of MaxAge LSA. */
int
ospf_lsa_maxage_walker (struct thread *t)
{
  listnode node;

  ospf_top->t_maxage_walker = NULL;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area;

      area = getdata (node);

      ospf_lsdb_iterator (ROUTER_LSA (area), NULL, 0,
			  ospf_lsa_maxage_walker_remover);
      ospf_lsdb_iterator (NETWORK_LSA (area), NULL, 0,
			  ospf_lsa_maxage_walker_remover);
      ospf_lsdb_iterator (SUMMARY_LSA (area), NULL, 0,
			  ospf_lsa_maxage_walker_remover);
      ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), NULL, 0,
			  ospf_lsa_maxage_walker_remover);
    }
  if (ospf_top->external_lsa)
    ospf_lsdb_iterator (ospf_top->external_lsa, NULL, 0, 
			ospf_lsa_maxage_walker_remover);

  ospf_top->t_maxage_walker = 
    thread_add_timer (master, ospf_lsa_maxage_walker, NULL,
		      OSPF_LSA_MAX_AGE_CHECK_INTERVAL);
  return 0;
}

struct ospf_lsa *
ospf_lsa_install (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  switch (lsa->data->type)
    {
    case OSPF_ROUTER_LSA:
      lsa = ospf_router_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_NETWORK_LSA:
      lsa = ospf_network_lsa_install (nbr->oi, lsa);
      break;
    case OSPF_SUMMARY_LSA:
      lsa = ospf_summary_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_SUMMARY_LSA_ASBR:
      lsa = ospf_summary_asbr_lsa_install (nbr->oi->area, lsa);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      lsa = ospf_external_lsa_install (lsa);
      break;
    default:
      break;
    }

  if ((LS_AGE (lsa) == OSPF_LSA_MAX_AGE) &&
      (! CHECK_FLAG (lsa->flags, OSPF_LSA_SELF)) )
    {
      zlog_info ("Z: ospf_lsa_install(): this LSA is MaxAge");
      ospf_lsa_maxage (lsa);
    }

  return lsa;
}

int
find_summary (struct ospf_lsa *lsa, void * v, int i)
{
  struct prefix_ipv4 *p, pr;
  struct summary_lsa *sl;

  p = (struct prefix_ipv4 *) v;
  if (p == NULL)
    return 0;

  if (lsa == NULL)
    return 0;

  /* We're looking for self-originated one */
  if (!ospf_lsa_is_self_originated (lsa))
    return 0;

  sl = (struct summary_lsa *) lsa->data;

  pr.family = AF_INET;
  pr.prefix = sl->header.id;
  pr.prefixlen = ip_masklen (sl->mask);
  apply_mask_ipv4 (&pr);

  if (prefix_same ((struct prefix*) &pr, (struct prefix*) p))
    return 1;

  return 0;
}

#if 0
struct ospf_lsa *
ospf_find_self_summary_lsa_by_prefix (struct ospf_area *area,
				      struct prefix_ipv4 *p)
{
  return ospf_lsdb_iterator (SUMMARY_LSA (area), p, 0, find_summary);
}
#endif

int
find_asbr_summary (struct ospf_lsa *lsa, void * v, int i)
{
  struct prefix_ipv4 *p;
  struct summary_lsa *sl;

  if ((p = (struct prefix_ipv4 *) v) == NULL)
    return 0;

  if (lsa == NULL)
    return 0;

  /* We're looking for self-originated one */
  if (!ospf_lsa_is_self_originated (lsa))
    return 0;

  sl = (struct summary_lsa *) lsa->data;

  if (p->prefix.s_addr == sl->header.id.s_addr)
    return 1;

  return 0;
}

#if 0
struct ospf_lsa *
ospf_find_self_summary_asbr_lsa_by_prefix (struct ospf_area *area, 
			  	           struct prefix_ipv4 *p)
{
  return ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), p, 0, find_asbr_summary);
}
#endif

int
find_external (struct ospf_lsa *lsa, void * v, int i)
{
  struct prefix_ipv4 *p, pr;
  struct as_external_lsa *el;

  if ((p = (struct prefix_ipv4 *) v) == NULL)
    return 0;

  if (lsa == NULL)
    return 0;
  /* We're looking for self-originated one */
  if (!ospf_lsa_is_self_originated (lsa))
    return 0;

  el = (struct as_external_lsa *) lsa->data;

  pr.family = AF_INET;
  pr.prefix = el->header.id;
  pr.prefixlen = ip_masklen (el->mask);
  apply_mask_ipv4 (&pr);

  if (prefix_same ((struct prefix*) &pr, (struct prefix*) p))
    return 1;

  return 0;
}

#if 0
struct ospf_lsa *
ospf_find_self_external_lsa_by_prefix (struct prefix_ipv4 *p)
{
  return ospf_lsdb_iterator (ospf_top->external_lsa, p, 0, find_external);
}
#endif

struct ospf_lsa *
ospf_lsa_lookup (struct ospf_area *area, u_int32_t type,
		 struct in_addr ls_id, struct in_addr adv_router)
{
  switch (type)
    {
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA:
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      return ospf_lsdb_lookup (area->lsa[type - 1], ls_id, adv_router);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      return ospf_lsdb_lookup (ospf_top->external_lsa, ls_id, adv_router);
      break;
    default:
      break;
    }

  return NULL;
}

struct ospf_lsa *
ospf_lsa_lookup_by_id (struct ospf_area *area, u_int32_t type, 
		       struct in_addr id)
{
  if (type != OSPF_AS_EXTERNAL_LSA)
    return ospf_lsdb_lookup_by_id (area->lsa[type-1], id);
  else
    return ospf_lsdb_lookup_by_id (ospf_top->external_lsa, id);
}


struct ospf_lsa *
ospf_lsa_lookup_by_header (struct ospf_area *area, struct lsa_header *lsa)
{
  struct ospf_lsa *match;

  match = ospf_lsa_lookup (area, lsa->type, lsa->id, lsa->adv_router);

  if (match == NULL)
    zlog_info ("ospf_lsa_lookup_by_header NO MATCH");

  return match;
}

/* return +n, l1 is more recent.
   return -n, l2 is more recent.
   return 0, l1 and l2 is identical. */
int
ospf_lsa_more_recent (struct ospf_lsa *l1, struct ospf_lsa *l2)
{
  int r;

  if (l1 == NULL && l2 == NULL)
    return 0;
  if (l1 == NULL)
    return -1;
  if (l2 == NULL)
    return 1;

  /* compare LS sequence number. */
  r = ntohl (l1->data->ls_seqnum) - ntohl (l2->data->ls_seqnum);
  if (r)
    return r;

  /* compare LS checksum. */
  r = ntohs (l1->data->checksum) - ntohs (l2->data->checksum);
  if (r)
    return r;

  /* compare LS age. */
  if (LS_AGE (l1) == OSPF_LSA_MAX_AGE &&
      LS_AGE (l2) != OSPF_LSA_MAX_AGE)
    return 1;
  else if (LS_AGE (l1) != OSPF_LSA_MAX_AGE &&
	   LS_AGE (l2) == OSPF_LSA_MAX_AGE)
    return -1;

  /* compare LS age with MaxAgeDiff. */
  if (LS_AGE (l1) - LS_AGE (l2) > OSPF_LSA_MAX_AGE_DIFF)
    return 1;
  else if (LS_AGE (l2) - LS_AGE (l1) > OSPF_LSA_MAX_AGE_DIFF)
    return -1;

  /* LSAs are identical. */
  return 0;
}

/* If two LSAs are different, return 1, otherwise return 0. */
int
ospf_lsa_different (struct ospf_lsa *l1, struct ospf_lsa *l2)
{
  char * p1, *p2;
  assert (l1);
  assert (l2);
  assert (l1->data);
  assert (l2->data);

  if (l1->data->options != l2->data->options)
    return 1;

  if ((LS_AGE (l1) == OSPF_LSA_MAX_AGE) && (LS_AGE (l2) != OSPF_LSA_MAX_AGE))
    return 1;

  if ((LS_AGE (l2) == OSPF_LSA_MAX_AGE) && (LS_AGE (l1) != OSPF_LSA_MAX_AGE))
    return 1;

  if (l1->data->length != l2->data->length)
    return 1;

  if (l1->data->length ==  0)
    return 1;

  assert (l1->data->length > OSPF_LSA_HEADER_SIZE);

  p1 = (char *) l1->data;
  p2 = (char *) l2->data;

  if (memcmp (p1 + OSPF_LSA_HEADER_SIZE, p2 + OSPF_LSA_HEADER_SIZE,
	      ntohs( l1->data->length ) - OSPF_LSA_HEADER_SIZE) != 0)
    return 1;

  return 0;
}

void
ospf_lsa_flush_self_originated (struct ospf_neighbor *nbr,
				struct ospf_lsa *self,
				struct ospf_lsa *new)
{
  u_int32_t seqnum;

  /* Adjust LS Sequence Number. */
  seqnum = ntohl (new->data->ls_seqnum) + 1;
  self->data->ls_seqnum = htonl (seqnum);

  /* Recalculate LSA checksum. */
  ospf_lsa_checksum (self->data);

  /* Reflooding LSA. */
  ospf_ls_upd_send_lsa (nbr, self, OSPF_SEND_PACKET_INDIRECT);

  zlog_info ("Flush self-originated LSA");
}

/* If there is self-originated LSA, then return 1, otherwise return 0. */
/* An interface-independent version of ospf_lsa_is_self_originated */
int 
ospf_lsa_is_self_originated (struct ospf_lsa *lsa)
{
  struct interface *ifp;
  struct ospf_interface *oi;
  listnode node, cn;
  struct connected *co;

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    return 1;

  if (lsa->data->adv_router.s_addr == ospf_top->router_id.s_addr)
    {
      SET_FLAG (lsa->flags, OSPF_LSA_SELF); /* to make it easier later */
      if (lsa->lsdb)
	lsa->lsdb->count_self++;

      return 1;
    }

  if (lsa->data->type == OSPF_ROUTER_LSA &&
      lsa->data->id.s_addr == ospf_top->router_id.s_addr)
    {
      SET_FLAG (lsa->flags, OSPF_LSA_SELF); /* to make it easier later */

      if (lsa->lsdb)
	lsa->lsdb->count_self++;

      return 1;
    }

  if (lsa->data->type == OSPF_NETWORK_LSA)
    LIST_ITERATOR (ospf_top->iflist, node)
      {
	ifp = getdata (node);
	oi  = ifp->info;

	if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	  continue;

	LIST_ITERATOR (ifp->connected, cn)
	  {
	    co = getdata (cn);
	    if (co->address->family != AF_INET)
	      continue;

	    if (IPV4_ADDR_CMP (&lsa->data->id, &co->address->u.prefix4) == 0)
	      {
		/* to make it easier later */
		SET_FLAG (lsa->flags, OSPF_LSA_SELF);
		lsa->lsdb->count_self++;
		return 1;
	      }
	  }
      }

  return 0;
}

int
count_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  int *ip = (int *) v;

  if (ip)
    (*ip)++;

  return 0;
}

int
ospf_lsa_count_table (struct ospf_lsdb *lsdb)
{
  int count = 0;

  ospf_lsdb_iterator (lsdb, &count, 0, count_lsa);

  return count;
}

int
ospf_lsa_count (struct ospf_area *area)
{
  int count = 0;

  /* Count router-LSAs. */
  count += ospf_lsa_count_table (ROUTER_LSA (area));

  /* Count network-LSAs. */
  count += ospf_lsa_count_table (NETWORK_LSA (area));

  /* Count summary-LSAs. */
  count += ospf_lsa_count_table (SUMMARY_LSA (area));

  /* Count summary-asbr-LSAs. */
  count += ospf_lsa_count_table (SUMMARY_LSA_ASBR (area));
    
  return count;
}

void
ospf_update_router_lsas ()
{
  listnode node;
  struct ospf_area * area;
  struct ospf_lsa  * lsa;
  struct in_addr new_rid;
  u_char new_flags;

  new_rid = ospf_top->router_id;
  new_flags = ospf_top->flags;

  zlog_info ("Z: ospf_update_router_lsa(): Start");
  zlog_info ("Z: ospf_update_router_lsa(): new RID: %s", inet_ntoa (new_rid));

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct router_lsa *rlsa;

      area = getdata (node);
      zlog_info ("Z: ospf_update_router_lsa(): looking at area %s",
		 inet_ntoa(area->area_id));

      if (area->router_lsa_self == NULL)
	{
	  zlog_info("Z: ospf_update_router_lsa(): "
		    "no LSA for this area, skipping");
	  continue;
	}

      rlsa = (struct router_lsa *) area->router_lsa_self->data;

      if (rlsa->header.id.s_addr == new_rid.s_addr &&
	  rlsa->flags == new_flags)
	{
	  zlog_info ("Z: ospf_update_router_lsa(): this area is ok, skipping");
	  continue;
	}

      if (rlsa->header.id.s_addr != new_rid.s_addr)
	{
	  zlog_info("Z: ospf_update_router_lsa(): "
		    "flushing the old LSA and delinking");
	  ospf_lsa_flush_area (area->router_lsa_self, area);
	  area->router_lsa_self = NULL;
	}

      zlog_info ("Z: ospf_update_router_lsa(): creating new router LSA");
      lsa = ospf_router_lsa (area);

      zlog_info ("Z: ospf_update_router_lsa(): installing new router LSA");
      lsa = ospf_router_lsa_install (area, lsa);

      zlog_info ("Z: ospf_update_router_lsa(): flooding new router LSA");
      ospf_flood_through_area (area, NULL, lsa);
    }

  zlog_info ("Z: ospf_update_router_lsa(): Stop");
}

int
ospf_update_router_lsas_timer (struct thread *t)
{
  zlog_info ("Z: ospf_update_router_lsas_timer(): Start");

  ospf_top->t_rlsa_update = 0;
  ospf_update_router_lsas();

  zlog_info ("Z: ospf_update_router_lsas_timer(): Stop");
  return 0;
}

void
ospf_schedule_update_router_lsas ()
{
  OSPF_SCHEDULE_RLSA_UPDATE (ospf_top->t_rlsa_update,
			     ospf_update_router_lsas_timer);
}


/* This function allocates LS ID for summary and ASE LSAs,
   honoring VLSMs and setting the host bits in the ID. */
struct in_addr
ospf_get_free_id_for_prefix (struct ospf_lsdb* lsdb, struct prefix_ipv4 *p,
			     struct in_addr rid)
{
  struct in_addr id, id_max, idn;
  struct in_addr mask;
  struct ospf_lsa *lsa;

  id = p->prefix;
  masklen2ip (p->prefixlen, &mask);

  id.s_addr = ntohl (id.s_addr);
  id_max.s_addr = id.s_addr + ~ntohl (mask.s_addr);

  for (; id.s_addr <= id_max.s_addr;)
    {
      idn.s_addr = htonl (id.s_addr);
      lsa = ospf_lsdb_lookup(lsdb, idn, rid);

      if (lsa == NULL) /* There's no such LSA */
	return idn;

      /* Note that we believe the calling function first tried
	 to find a self-originated LSA for the same prefix,
	 so we just set the next bit and retry */

      /* Take the next host bit combination */
      id.s_addr++;
    }

  /* We should never be here, but...:) */

  id.s_addr = 0;
  return id;
}



#define LSA_ACTION_ORIGN_RTR  1
#define LSA_ACTION_ORIGN_NET  2
#define LSA_ACTION_FLOOD_AREA 3
#define LSA_ACTION_FLOOD_AS   4
#define LSA_ACTION_FLUSH_AREA 5
#define LSA_ACTION_FLUSH_AS   6


struct lsa_action
{
  u_char action;
  struct ospf_area * area;
  struct ospf_interface *oi; 
  struct ospf_lsa  * lsa;
};


int
ospf_lsa_action (struct thread *t)
{
  struct lsa_action * data;
  struct ospf_lsa * lsa;

  data = THREAD_ARG (t);

  zlog_info ("Z: Performing scheduled LSA action: %d", data->action);

  switch (data->action)
    {
    case LSA_ACTION_ORIGN_RTR:
      lsa = ospf_router_lsa (data->area);
      lsa = ospf_router_lsa_install (data->area, lsa);
      ospf_flood_through_area (data->area, NULL, lsa);
      break;
    case LSA_ACTION_ORIGN_NET:
      lsa = ospf_network_lsa (data->oi);
      lsa = ospf_network_lsa_install (data->oi, lsa);
      ospf_flood_through_area (data->area, NULL, lsa);
      break;
    case LSA_ACTION_FLOOD_AREA:
      ospf_flood_through_area (data->area, NULL, data->lsa);
      break;
    case LSA_ACTION_FLOOD_AS:
      ospf_flood_through_as (NULL, data->lsa);
      break;
    case LSA_ACTION_FLUSH_AREA:
      ospf_lsa_flush_area (data->lsa, data->area);
      break;
    case LSA_ACTION_FLUSH_AS:
      ospf_lsa_flush_as(data->lsa);
      break;
    }

  XFREE (MTYPE_OSPF_MESSAGE, data);
  return 0;
}


void
ospf_schedule_lsa_flood_area (struct ospf_area * area, struct ospf_lsa *lsa)
{
  struct lsa_action * data;

  data = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct lsa_action));
  bzero (data, sizeof (struct lsa_action));

  data->action = LSA_ACTION_FLOOD_AREA;
  data->area = area;
  data->lsa  = lsa;

  thread_add_event (master, ospf_lsa_action, data, 0);
}


void
ospf_schedule_lsa_flush_area (struct ospf_area * area, struct ospf_lsa *lsa)
{
  struct lsa_action *data;

  data = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct lsa_action));
  bzero (data, sizeof (struct lsa_action));

  data->action = LSA_ACTION_FLUSH_AREA;
  data->area = area;
  data->lsa  = lsa;

  thread_add_event (master, ospf_lsa_action, data, 0);
}


void
ospf_schedule_router_lsa_originate (struct ospf_area * area)
{
  time_t delta;
  struct ospf_lsa *rlsa;

  rlsa = area->router_lsa_self;

  if (area->t_router_lsa_self)
    {
      zlog_info ("Z: Cancelling previously scheduled router-LSA origination");
      thread_cancel (area->t_router_lsa_self);
    }

  if (rlsa)
    {
      delta = time (NULL) - rlsa->originated;

      if (delta < OSPF_MIN_LS_INTERVAL)
	{

	  zlog_info ("Z: Delaying router-LSA origination for %d seconds", 
		     OSPF_MIN_LS_INTERVAL - delta);
	  area->t_router_lsa_self =
	    thread_add_timer (master, ospf_router_lsa_refresh, 
			      area, OSPF_MIN_LS_INTERVAL - delta);
	  return;
	}
    }

  zlog_info ("Z: Scheduling router-LSA origination right away");
  area->t_router_lsa_self =
    thread_add_event (master, ospf_router_lsa_refresh, area, 0);
}


void
ospf_schedule_network_lsa_originate (struct ospf_interface * oi)
{
  time_t delta;
  struct ospf_lsa *nlsa;

  nlsa = oi->network_lsa_self;

  if (oi->t_network_lsa_self)
    {
      zlog_info ("Z: Cancelling previously scheduled network-LSA origination");
      thread_cancel (oi->t_network_lsa_self);
    }

  if (nlsa)
    {
      delta = time (NULL) - nlsa->originated;

      if (delta < OSPF_MIN_LS_INTERVAL)
	{
	  zlog_info ("Z: Delaying network-LSA origination for %d seconds", 
		     OSPF_MIN_LS_INTERVAL - delta);
	  oi->t_network_lsa_self =
	    thread_add_timer (master, ospf_network_lsa_refresh, 
			      oi, OSPF_MIN_LS_INTERVAL - delta);
	  return;
	}
    }

  zlog_info ("Z: Scheduling network-LSA origination right away");
  oi->t_network_lsa_self =
    thread_add_event (master, ospf_network_lsa_refresh, oi, 0);
}

/* LSA Refreshment functions. */
void
ospf_lsa_refresh (struct ospf_lsa *lsa)
{
  assert (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF));

  switch (lsa->data->type)
    {
      /* Router and Network LSAs are processed differently */
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA: 
      break;

    case OSPF_SUMMARY_LSA:
      ospf_summary_lsa_refresh (lsa);
      break;

    case OSPF_SUMMARY_LSA_ASBR:
      ospf_summary_lsa_asbr_refresh (lsa);
      break;

    case OSPF_AS_EXTERNAL_LSA:
      ospf_external_lsa_refresh (lsa);
      break;
   }
}

int
ospf_lsa_refresher (struct thread *t)
{
  struct ospf *top;
  int count = 0;
  listnode node, next;
  struct ospf_lsa *lsa;

  zlog_info("Z: ospf_lsa_refresher(): Start");

  top = THREAD_ARG (t);

  if (top)
    if (top->refresh_queue)
      for (node = listhead (top->refresh_queue); node; node = next)
	{
          next = node->next;
	  lsa = getdata (node);
	  assert (lsa);

	  list_delete_by_val (top->refresh_queue, lsa);
	  assert (lsa->refresh_list == top->refresh_queue);
	  lsa->refresh_list = NULL;
	  ospf_lsa_refresh (lsa);

	  top->refresh_queue_count++;

	  if (++count == OSPF_DEF_REFRESH_PER_SLICE)
	    break;

	  if (top->refresh_queue_count >= top->refresh_queue_limit)
	    break;
	}

  count = listcount (top->refresh_queue);

  if (top->refresh_queue_count >= top->refresh_queue_limit)
    {
      top->refresh_queue_count = 0;
      if (count)
        top->t_lsa_refresher =
	  thread_add_timer (master, ospf_lsa_refresher, top,
			    top->refresh_queue_interval);
      else
        top->t_lsa_refresher = NULL;

    }
  else if (count)
    top->t_lsa_refresher = thread_add_event (master, ospf_lsa_refresher, 
					     top, 0);
  else
    top->t_lsa_refresher = NULL;

  zlog_info("Z: ospf_lsa_refresher(): Stop");
  return 0;
}

struct refresh_event
{
  struct ospf *top;
  list group;
};

int
ospf_refresh_event (struct thread *t)
{
  struct refresh_event * event;
  listnode node;
  struct ospf_lsa * lsa;

  zlog_info("Z: ospf_refresh_event(): Start");

  event = THREAD_ARG (t);

  zlog_info ("Z: ospf_refresh_event(): Copying %d LSAs to Refresh Queue",
	     listcount (event->group));

  LIST_ITERATOR (event->group, node)
    {
      lsa = getdata (node);
      assert (lsa);

      list_add_node (event->top->refresh_queue, lsa);
      lsa->refresh_list = event->top->refresh_queue;
    }

  list_delete_all (event->group); /* Free the list and list nodes */

  if (event->top->t_lsa_refresher == NULL)
    {
      zlog_info ("Z: ospf_refresh_event(): "
		 "Scheduling Refresh Queue Server right away");

      event->top->t_lsa_refresher =
	thread_add_event (master, ospf_lsa_refresher, event->top, 0);

      event->top->refresh_queue_count = 0;
    }
      
  XFREE (MTYPE_OSPF_MESSAGE, event);

  zlog_info("Z: ospf_refresh_event(): Stop");
  return 0;
}

void
ospf_refresher_flush_group (struct ospf * top)
{
  struct refresh_event * event;
  int delay;
  listnode node;
  struct ospf_lsa * lsa;

  assert (top);
 
  if (listcount (top->refresh_group))
    {
      event = XMALLOC (MTYPE_OSPF_MESSAGE, sizeof (struct refresh_event));
      assert (event);

      bzero (event, sizeof (struct refresh_event));

      event->top = top;
      event->group = top->refresh_group;

      zlog_info ("Z: refresher: group age %d", top->group_age);

      node = listhead (top->refresh_group);
      lsa = getdata (node);

      assert (lsa);

      if (top->group_age == 0 &&
	  ntohl (lsa->data->ls_seqnum) == OSPF_INITIAL_SEQUENCE_NUMBER)

        /* Randomizing the first refresh interval*/
        delay = OSPF_LS_REFRESH_SHIFT + 
	  (random () % (OSPF_LS_REFRESH_TIME - OSPF_LS_REFRESH_SHIFT));
      else
	{
	  delay = OSPF_LS_REFRESH_TIME - top->group_age;

	  if (delay < 0)
	    delay = 0;

	  delay = delay + (random () % 10) +1; /* Randomize to avoid syncing */
	}

      zlog_info ("Z: refresher: delay %d", delay);


      thread_add_timer (master, ospf_refresh_event, event, delay);

      top->refresh_group = list_init();
      assert (top->refresh_group);
    }

  top->t_refresh_group = NULL;
}

int
ospf_ref_group_checker (struct thread *t)
{
  struct ospf * top;

  zlog_info("Z: ospf_ref_group_checker(): Start");

  top = THREAD_ARG (t);

  if (top)
    {
      assert (top->refresh_group);
      ospf_refresher_flush_group (top);
    }

  zlog_info ("Z: ospf_ref_group_checker(): Stop");
  return 0;
}

void
ospf_refresher_register_lsa (struct ospf * top, struct ospf_lsa *lsa)
{
  if (lsa->refresh_list)
    return;

  if (top->t_refresh_group)
    {
      /* Not the first LSA in the group
	 Check the age and fire an event, if ages are too different */

      if (abs (top->group_age - LS_AGE (lsa)) > OSPF_REFRESH_GROUP_AGE_DIF ||
          listcount (top->refresh_group) == OSPF_REFRESH_GROUP_LIMIT)
        ospf_refresher_flush_group (top);
    }

  if (top->t_refresh_group == NULL)
    {
      zlog_info ("ospf_refresher_register_lsa(): Scheduling Checker");

      top->t_refresh_group = thread_add_timer (master, ospf_ref_group_checker, 
					       top, OSPF_REFRESH_GROUP_SLICE);
      top->group_age = LS_AGE (lsa);
    }

  list_add_node (top->refresh_group, lsa);
  lsa->refresh_list = top->refresh_group;
}

void
ospf_refresher_unregister_lsa (struct ospf_lsa *lsa)
{
  assert (lsa);

  if (lsa->data->type == OSPF_ROUTER_LSA ||
      lsa->data->type == OSPF_NETWORK_LSA)
    return; /* These LSAs are processed differently */

  assert (lsa->refresh_list);

  list_delete_by_val (lsa->refresh_list, lsa);
  lsa->refresh_list = NULL;
}


/* Show functions */
int
show_router_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  vty = (struct vty *) v;
  rl = (struct router_lsa *) lsa->data;

  vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x   %-d%s",
	   inet_ntoa (lsa->data->adv_router),
	   LS_AGE (lsa),
	   ntohl (lsa->data->ls_seqnum),
	   ntohs (lsa->data->checksum),
	   ntohs (rl->links), VTY_NEWLINE);
  return 0;
}


int
show_any_lsa (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct summary_lsa *sl;
  struct as_external_lsa *asel;
  struct vty * vty;
  struct prefix_ipv4 p;


  if (lsa == NULL)
    return 0;

  vty = (struct vty *) v;
  rl = (struct router_lsa *) lsa->data;

  vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x",
	   inet_ntoa (lsa->data->adv_router),
	   LS_AGE (lsa),
	   ntohl (lsa->data->ls_seqnum),
	   ntohs (lsa->data->checksum));

  switch (lsa->data->type){
   case OSPF_SUMMARY_LSA:

        sl = (struct summary_lsa *) lsa->data;

        p.family = AF_INET;
        p.prefix = sl->header.id;
        p.prefixlen = ip_masklen (sl->mask);
        apply_mask_ipv4 (&p);

        vty_out (vty, "   %s/%d", inet_ntoa(p.prefix), p.prefixlen);
        break;

   case OSPF_AS_EXTERNAL_LSA:

        asel = (struct as_external_lsa *) lsa->data;

        p.family = AF_INET;
        p.prefix = asel->header.id;
        p.prefixlen = ip_masklen (asel->mask);
        apply_mask_ipv4 (&p);

        if (IS_EXTERNAL_METRIC (asel->e[0].tos))
           vty_out (vty, "   E2 ");
        else
           vty_out (vty, "   E1 ");

        vty_out (vty, "%s/%d ", inet_ntoa(p.prefix), p.prefixlen);
        vty_out (vty, "[0x%X]", ntohl (asel->e[0].route_tag.s_addr));
        break;
   default: break;
  };

  vty_out (vty, VTY_NEWLINE);

  return 0;
}

void
show_ip_ospf_database_all (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area;

      area = getdata (node);

      /* Show router-LSAs. */
      if (ospf_lsa_count_table (ROUTER_LSA (area)) > 0)
	{
	  vty_out (vty, "                Router Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum Link count%s", VTY_NEWLINE);

          ospf_lsdb_iterator (ROUTER_LSA (area), vty, 0, show_router_lsa);

	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show network-LSAs. */
      if (ospf_lsa_count_table (NETWORK_LSA (area)) > 0)
	{
	  vty_out (vty, "                Net Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum%s", VTY_NEWLINE);

          ospf_lsdb_iterator (NETWORK_LSA (area), vty, 0, show_any_lsa);

	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show Summary-LSAs. */
      if (ospf_lsa_count_table (SUMMARY_LSA (area)) > 0)
	{
	  vty_out (vty, "                Summary Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum Route%s", VTY_NEWLINE);

          ospf_lsdb_iterator (SUMMARY_LSA (area), vty, 0, show_any_lsa);

	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show ASBR-Summary-LSAs. */
      if (ospf_lsa_count_table (SUMMARY_LSA_ASBR (area)) > 0)
	{
	  vty_out (vty, "                ASBR-Summary Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum%s", VTY_NEWLINE);
          ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), vty, 0, show_any_lsa);
	}
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  /* If area configuration does not exists, show nothing. */
  /*  if (list_isempty (ospf_top->areas))
      return; */

  /* show ASE-LSAs. */
  if (ospf_lsa_count_table (ospf_top->external_lsa))
    {
      vty_out (vty, "                Type-5 AS External Link States%s%s",
	       VTY_NEWLINE, VTY_NEWLINE);

      vty_out (vty, "Link ID         ADV Router      Age         "
	       "Seq#       Checksum Route%s", VTY_NEWLINE);

      if (ospf_top->external_lsa)
        ospf_lsdb_iterator (ospf_top->external_lsa, vty, 0, show_any_lsa);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

void
show_ip_ospf_database_header (struct vty *vty, struct ospf_lsa *lsa)
{
  struct router_lsa *rlsa = (struct router_lsa*) lsa->data;

  vty_out (vty, "  LS age: %d%s", LS_AGE (lsa),
	   VTY_NEWLINE);
  vty_out (vty, "  Options: %d%s", lsa->data->options,
	   VTY_NEWLINE);
  if (lsa->data->type == OSPF_ROUTER_LSA)
    {
      vty_out (vty, "  Flags: 0x%x" , rlsa->flags);

      if (rlsa->flags)
	{
	  vty_out (vty, " :");
	  if (IS_ROUTER_LSA_BORDER (rlsa))
	    vty_out (vty, " ABR");
	  if (IS_ROUTER_LSA_EXTERNAL (rlsa))
	    vty_out (vty, " ASBR");
	  if (IS_ROUTER_LSA_VIRTUAL (rlsa))
	    vty_out (vty, " VL-endpoint");
	  if (IS_ROUTER_LSA_SHORTCUT (rlsa))
	    vty_out (vty, " Shortcut");
	}
    }

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "  LS Type: %s%s",
	   LOOKUP (ospf_lsa_type_msg, lsa->data->type),
	   VTY_NEWLINE);
  vty_out (vty, "  Link State ID: %s %s%s", inet_ntoa (lsa->data->id),
	   LOOKUP (ospf_link_state_id_type_msg, lsa->data->type),
	   VTY_NEWLINE);
  vty_out (vty, "  Advertising Router: %s%s",
	   inet_ntoa (lsa->data->adv_router),
	   VTY_NEWLINE);
  vty_out (vty, "  LS Seq Number: %08x%s", ntohl (lsa->data->ls_seqnum),
	   VTY_NEWLINE);
  vty_out (vty, "  Checksum: 0x%04x%s", ntohs(lsa->data->checksum),
	   VTY_NEWLINE);
  vty_out (vty, "  Length: %d%s", ntohs (lsa->data->length),
	   VTY_NEWLINE);
}

int
show_network_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  struct network_lsa *nl;
  int length, i;
  struct vty * vty;

  if (lsa == NULL)
     return 0;

  vty = (struct vty*) v;
  nl = (struct network_lsa *) lsa->data;

  show_ip_ospf_database_header (vty, lsa);

  vty_out (vty, "  Network Mask: /%d%s", ip_masklen (nl->mask), VTY_NEWLINE);

  length = ntohs (lsa->data->length) - OSPF_LSA_HEADER_SIZE - 4;

  for (i = 0; length > 0; i++, length -= 4)
    vty_out (vty, "        Attached Router: %s%s",
	     inet_ntoa (nl->routers[i]), VTY_NEWLINE);

  vty_out (vty, "%s", VTY_NEWLINE);

  return 0;
}


void
show_ip_ospf_database_network (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                Net Link States (Area %s)%s%s",
	       inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      ospf_lsdb_iterator (NETWORK_LSA (area), vty, 0, show_network_lsa_detail);
      vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
    }
}

void
show_ip_ospf_database_router_links (struct vty *vty,
				    struct router_lsa *rl)
{
  int len, i;

  len = ntohs (rl->header.length) - 4;
  for (i = 0; i < ntohs (rl->links) && len > 0; len -= 12, i++)
    {
      switch (rl->link[i].type)
	{
	case LSA_LINK_TYPE_POINTOPOINT:
	  vty_out (vty, "    Link connected to: another Router (point-to-point)%s",
		   VTY_NEWLINE);
	  vty_out (vty, "     (Link ID) Neighboring Router ID: %s%s",
		   inet_ntoa (rl->link[i].link_id),
		   VTY_NEWLINE);
	  vty_out (vty, "     (Link Data) Router Interface address: %s%s",
		   inet_ntoa (rl->link[i].link_data),
		   VTY_NEWLINE);
	  vty_out (vty, "      Number of TOS metrics: 0%s", VTY_NEWLINE);
	  vty_out (vty, "       TOS 0 Metric: %d%s",
		   ntohs (rl->link[i].metric),
		   VTY_NEWLINE);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  break;
	case LSA_LINK_TYPE_TRANSIT:
	  vty_out (vty, "    Link connected to: a Transit Network%s", VTY_NEWLINE);
	  vty_out (vty, "     (Link ID) Desianated Router address: %s%s",
		   inet_ntoa (rl->link[i].link_id),
		   VTY_NEWLINE);
	  vty_out (vty, "     (Link Data) Router Interface address: %s%s",
		   inet_ntoa (rl->link[i].link_data),
		   VTY_NEWLINE);
	  vty_out (vty, "      Number of TOS metrics: 0%s", VTY_NEWLINE);
	  vty_out (vty, "       TOS 0 Metric: %d%s",
		   ntohs (rl->link[i].metric),
		   VTY_NEWLINE);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  break;
	case LSA_LINK_TYPE_STUB:
	  vty_out (vty, "    Link connected to: Stub Network%s", VTY_NEWLINE);
	  vty_out (vty, "     (Link ID) Network/subnet number: %s%s",
		   inet_ntoa (rl->link[i].link_id),
		   VTY_NEWLINE);
	  vty_out (vty, "     (Link Data) Network Mask: %s%s",
		   inet_ntoa (rl->link[i].link_data),
		   VTY_NEWLINE);
	  vty_out (vty, "      Number of TOS metric: 0%s", VTY_NEWLINE);
	  vty_out (vty, "       TOS 0 Metric: %d%s",
		   ntohs (rl->link[i].metric),
		   VTY_NEWLINE);
	  vty_out (vty, "%s", VTY_NEWLINE);

	  break;

	case LSA_LINK_TYPE_VIRTUALLINK:
	  vty_out (vty, "    Link connected to: a Virtual Link%s", VTY_NEWLINE);
	  vty_out (vty, "     (Link ID) Neighboring Router ID: %s%s",
		   inet_ntoa (rl->link[i].link_id),
		   VTY_NEWLINE);
	  vty_out (vty, "     (Link Data) Router Interface address: %s%s",
		   inet_ntoa (rl->link[i].link_data),
		   VTY_NEWLINE);
	  vty_out (vty, "      Number of TOS metrics: 0%s", VTY_NEWLINE);
	  vty_out (vty, "       TOS 0 Metric: %d%s",
		   ntohs (rl->link[i].metric),
		   VTY_NEWLINE);
	  vty_out (vty, "%s", VTY_NEWLINE);
	  break;
	}
    }
}

int
show_router_lsa_detail (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct vty *vty;

  if (lsa == NULL)
    return 0;

  vty = (struct vty*) v;
  rl = (struct router_lsa *) lsa->data;

  show_ip_ospf_database_header (vty, lsa);
	  
  vty_out (vty, "   Number of Links: %d%s%s", ntohs (rl->links),
	   VTY_NEWLINE, VTY_NEWLINE);

  show_ip_ospf_database_router_links (vty, rl);

  return 0;

}

void
show_ip_ospf_database_router (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);
      
      vty_out (vty, "%s                Router Link States (Area %s)%s%s",
	       VTY_NEWLINE, inet_ntoa (area->area_id),
	       VTY_NEWLINE, VTY_NEWLINE);

      ospf_lsdb_iterator (ROUTER_LSA (area), vty, 0, show_router_lsa_detail);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_summary_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  struct summary_lsa *sl;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  vty = (struct vty*) v;
  sl = (struct summary_lsa *) lsa->data;

  show_ip_ospf_database_header (vty, lsa);

  vty_out (vty, "  Network Mask: /%d%s", ip_masklen (sl->mask), VTY_NEWLINE);
  vty_out (vty, "        TOS: 0  Metric: %d%s", GET_METRIC (sl->metric),
	   VTY_NEWLINE);

  return 0;

}

void
show_ip_ospf_database_summary (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                Summary Link States (Area %s)%s%s",
	       inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      ospf_lsdb_iterator (SUMMARY_LSA (area), vty, 0, show_summary_lsa_detail);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_summary_asbr_lsa_detail (struct ospf_lsa *lsa, void *v, int i_arg)
{
  struct summary_lsa *sl;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  vty = (struct vty *) v;
  sl = (struct summary_lsa *) lsa->data;

  show_ip_ospf_database_header (vty, lsa);

  vty_out (vty, "  Network Mask: /%d%s", ip_masklen (sl->mask),
	   VTY_NEWLINE);
  vty_out (vty, "        TOS: 0  Metric: %d%s", GET_METRIC (sl->metric),
	   VTY_NEWLINE);

  return 0;
}

void
show_ip_ospf_database_summary_asbr (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);

      vty_out (vty, "                ASBR-Summary Link States (Area %s)%s%s",
	       inet_ntoa (area->area_id), VTY_NEWLINE, VTY_NEWLINE);

      ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area), vty, 0,
			  show_summary_lsa_detail);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

int
show_as_external_lsa_detail (struct ospf_lsa *lsa, void *v, int i)
{
  struct as_external_lsa *al;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  vty = (struct vty *) v;
  al = (struct as_external_lsa *) lsa->data;

  show_ip_ospf_database_header (vty, lsa);

  vty_out (vty, "  Network Mask: /%d%s", ip_masklen (al->mask), VTY_NEWLINE);
  vty_out (vty, "        Metric Type: %s%s",
	   IS_EXTERNAL_METRIC (al->e[0].tos) ?
	   "2 (Larger than any link state path)" : "1", VTY_NEWLINE);
  vty_out (vty, "        TOS: 0%s", VTY_NEWLINE);
  vty_out (vty, "        Metric: %d%s",
	   GET_METRIC (al->e[0].metric), VTY_NEWLINE);
  vty_out (vty, "        Forward Address: %s%s",
	   inet_ntoa (al->e[0].fwd_addr), VTY_NEWLINE);

  vty_out (vty, "        External Route Tag: %d%s%s", al->e[0].route_tag,
	   VTY_NEWLINE, VTY_NEWLINE);

  return 0;
}

void
show_ip_ospf_database_external (struct vty *vty)
{
  vty_out (vty, "                Type-5 AS External Link States%s%s",
	   VTY_NEWLINE, VTY_NEWLINE);

  ospf_lsdb_iterator (ospf_top->external_lsa, vty, 0,
		      show_as_external_lsa_detail);

  vty_out (vty, "%s", VTY_NEWLINE);
}

int
show_router_lsa_self (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  if (!ospf_lsa_is_self_originated(lsa))
    return 0;

  vty = (struct vty *) v;
  rl = (struct router_lsa *) lsa->data;

  vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x   %-d%s",
	   inet_ntoa (lsa->data->adv_router),
	   LS_AGE (lsa),
	   ntohl (lsa->data->ls_seqnum),
	   ntohs (lsa->data->checksum),
	   ntohs (rl->links),
	   VTY_NEWLINE);
  return 0;
}

int
show_any_lsa_self (struct ospf_lsa *lsa, void *v, int i)
{
  struct router_lsa *rl;
  struct vty * vty;

  if (lsa == NULL)
    return 0;

  if (!ospf_lsa_is_self_originated (lsa))
    return 0;

  vty = (struct vty *) v;
  rl = (struct router_lsa *) lsa->data;

  vty_out (vty, "%-15s ", inet_ntoa (lsa->data->id));
  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x%s",
	   inet_ntoa (lsa->data->adv_router), LS_AGE (lsa),
	   ntohl (lsa->data->ls_seqnum), ntohs (lsa->data->checksum),
	   VTY_NEWLINE);

 return 0;
}

void
show_ip_ospf_database_self_originate (struct vty *vty)
{
  listnode node;

  LIST_ITERATOR (ospf_top->areas, node)
    {
      struct ospf_area *area;

      if ((area = getdata (node)) == NULL)
	continue;

      /* Show self-originated router-LSA. */
      if (ROUTER_LSA (area)->count_self)
	{
	  vty_out (vty, "                Router Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);

	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum Link count%s", VTY_NEWLINE);

	  ospf_lsdb_iterator (ROUTER_LSA (area), vty, 0, show_router_lsa_self);
	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show self-originated network-LSA. */
      if (NETWORK_LSA (area)->count_self)
	{
	  vty_out (vty, "                Net Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum%s", VTY_NEWLINE);

	  ospf_lsdb_iterator (NETWORK_LSA (area), vty, 0, show_any_lsa_self);
	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show self-originated summary-LSA. */
      if (SUMMARY_LSA (area)->count_self)
	{
	  vty_out (vty, "                Summary Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE,
		   VTY_NEWLINE);
	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum%s", VTY_NEWLINE);

	  ospf_lsdb_iterator (SUMMARY_LSA (area), vty, 0, show_any_lsa_self);
	  vty_out (vty, "%s", VTY_NEWLINE);
	}

      /* Show self-originated ASBR-summary-LSA. */
      if (SUMMARY_LSA_ASBR (area)->count_self)
	{
	  vty_out (vty, "                ASBR-Summary Link States (Area %s)%s%s",
		   inet_ntoa (area->area_id),
		   VTY_NEWLINE, VTY_NEWLINE);

	  vty_out (vty, "Link ID         ADV Router      Age         "
		   "Seq#       Checksum%s", VTY_NEWLINE);
	  ospf_lsdb_iterator (SUMMARY_LSA_ASBR (area),
			      vty, 0, show_any_lsa_self);
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
    }

  /* Show self-originated AS-external-LSA. */
  if (ospf_top->external_lsa->count_self)
    {
      vty_out (vty, "                Type-5 AS External Link States%s%s",
	       VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, "Link ID         ADV Router      Age         "
	       "Seq#       Checksum%s", VTY_NEWLINE);
      ospf_lsdb_iterator (ospf_top->external_lsa, vty, 0, show_any_lsa_self);
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}


void
show_ip_ospf_database_maxage (struct vty *vty)
{
  listnode node;
  struct ospf_lsa *lsa;

  vty_out (vty, "%s                MaxAge Link States:%s%s",
	   VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  LIST_ITERATOR (ospf_top->maxage_lsa, node) 
    {
      if ((lsa = getdata (node)) == NULL)
	continue;

      vty_out (vty, "LS type: %d%s", lsa->data->type, VTY_NEWLINE);
      vty_out (vty, "LS ID: %s%s", inet_ntoa(lsa->data->id), VTY_NEWLINE);
      vty_out (vty, "LS Adv Rtr: %s%s", inet_ntoa(lsa->data->adv_router),
	       VTY_NEWLINE);
      vty_out (vty, "LS Reference counter: %d%s", lsa->ref, VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

DEFUN (show_ip_ospf_database,
       show_ip_ospf_database_cmd,
       "show ip ospf database",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n")
{
  if (ospf_top == NULL)
    return CMD_SUCCESS;

  vty_out (vty, "%s       OSPF Router with ID (%s)%s%s", VTY_NEWLINE,
	   inet_ntoa (ospf_top->router_id), VTY_NEWLINE, VTY_NEWLINE);

  /* Show all LSA. */
  if (argc == 0)
    show_ip_ospf_database_all (vty);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "a", 1) == 0)
	show_ip_ospf_database_summary_asbr (vty);
      else if (strncmp (argv[0], "e", 1) == 0)
	show_ip_ospf_database_external (vty);
      else if (strncmp (argv[0], "m", 1) == 0)
	show_ip_ospf_database_maxage (vty);
      else if (strncmp (argv[0], "n", 1) == 0)
	show_ip_ospf_database_network (vty);
      else if (strncmp (argv[0], "r", 1) == 0)
	show_ip_ospf_database_router (vty);
      else if (strncmp (argv[0], "se", 2) == 0)
	show_ip_ospf_database_self_originate (vty);
      else if (strncmp (argv[0], "su", 2) == 0)
	show_ip_ospf_database_summary (vty);
      else
	return CMD_WARNING;
    }

  return CMD_SUCCESS;
}
       
ALIAS (show_ip_ospf_database,
       show_ip_ospf_database_type_cmd,
       "show ip ospf database (asbr-summary|external|max-age|network|router|self-originate|summary)",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "LSAs in MaxAge list\n"
       "Network link states\n"
       "Router link states\n"
       "Self-originated link states\n"
       "Network summary link states\n")

DEFUN (show_ip_ospf_refresher,
       show_ip_ospf_refresher_cmd,
       "show ip ospf refresher",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "LSA Refresher process info\n")
{
  listnode node;
  struct ospf_lsa * lsa;
  u_char buf1[INET_ADDRSTRLEN];
  u_char buf2[INET_ADDRSTRLEN];

  if (ospf_top == NULL)
    return CMD_SUCCESS;

  if (listcount (ospf_top->refresh_queue) == 0)
    {
      vty_out (vty, " LSA refresh queue is empty%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  vty_out (vty, " LSA Refresher is active. Queue :%s", VTY_NEWLINE);
  LIST_ITERATOR (ospf_top->refresh_queue, node)
    {
      lsa = getdata (node);
      assert (lsa);

      bzero (&buf1, INET_ADDRSTRLEN);
      bzero (&buf2, INET_ADDRSTRLEN);
      strncpy (buf1, inet_ntoa (lsa->data->id), INET_ADDRSTRLEN);
      strncpy (buf2, inet_ntoa (lsa->data->adv_router), INET_ADDRSTRLEN);

      vty_out (vty, " LSA Type: %d, LSID: %s, AdvRtr: %s, Age: %d, Seq: %X%s",
	       lsa->data->type, buf1, buf2, LS_AGE(lsa), 
	       ntohs (lsa->data->ls_seqnum), VTY_NEWLINE);
    }

  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

/* Install LSA related commands. */
void
ospf_lsa_init ()
{
  install_element (VIEW_NODE, &show_ip_ospf_database_type_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_database_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_refresher_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_type_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_refresher_cmd);
}
