/* OSPF Sending and Receiving OSPF Packets
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

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"

/* Packet Type String. */
char *ospf_packet_type_str[] =
{
  NULL,
  "Hello",
  "Database Description",
  "Link State Request",
  "Link State Update",
  "Link State Acknowledgment",
};

extern int in_cksum (void *ptr, int nbytes);

/* debug flag. */
extern unsigned long ospf_debug_packet;


/* forward output pointer. */
void
ospf_output_forward (struct stream *s, int size)
{
  s->putp += size;
}


int
ospf_write (struct ospf_interface *oi, struct ospf_neighbor *nbr)
{
  struct ospf_header *ospfh;
  int length, fd;
  struct in_addr dst;
  struct stream *s;
  struct sockaddr_in sa;

  fd = oi->fd;
  s = oi->obuf;

  length = OSPF_OUTPUT_LENGTH (s);
  ospfh = (struct ospf_header *) STREAM_DATA (s);

  /* Select Address. */
  switch (oi->type)
    {
    case OSPF_IFTYPE_POINTOPOINT:
      dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
      break;
    case OSPF_IFTYPE_BROADCAST:
      if (ospfh->type == OSPF_MSG_HELLO)
	dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
      else if (ospfh->type == OSPF_MSG_LS_UPD ||
	       ospfh->type == OSPF_MSG_LS_ACK)
	dst.s_addr = htonl (OSPF_ALLDROUTERS);
      else if (nbr)
	dst = nbr->address.u.prefix4;
    default:
      if (nbr)
	dst = nbr->address.u.prefix4;
      break;
    }

  sa.sin_family = AF_INET;
  sa.sin_port = htons (0);
  sa.sin_addr = dst;

  sendto (fd, STREAM_DATA (oi->obuf), length, 0,
	  (struct sockaddr *) &sa, sizeof (sa));

  stream_free (oi->obuf);
  oi->obuf = NULL;

  zlog (NULL, LOG_INFO, "OSPF %s sent to [%s].",
	ospf_packet_type_str[ospfh->type],
	inet_ntoa (dst));

  return 0;
}

void
ospf_make_header (int type, struct ospf_interface *oi,
		  struct ospf_header *ospfh)
{
  ospfh->version = (u_char) OSPF_VERSION;
  ospfh->type = (u_char) type;

  ospfh->router_id = ospf_top->router_id;

  ospfh->checksum = 0;
  ospfh->area_id = oi->area->area_id;
  ospfh->auth_type = htons (oi->area->auth_type);

  ospf_output_forward (oi->obuf, OSPF_HEADER_SIZE);
}

/* OSPF Hello message read. */
void
ospf_hello (struct ip *iph, struct ospf_header *ospfh,
	    struct ospf_interface *oi, int size)
{
  struct ospf_hello *hello;
  struct ospf_neighbor *nbr;
  struct route_node *rn;
  struct prefix p, key;

  zlog (NULL, LOG_INFO, "OSPF Hello received from [%s]",
	inet_ntoa (ospfh->router_id));

  /* increment statistics. */
  oi->hello_in++;

  hello = (struct ospf_hello *) STREAM_PNT (oi->ibuf);

  /* get neighbor prefix. */
  p.family = AF_INET;
  p.prefixlen = ip_masklen (hello->network_mask);
  p.u.prefix4 = iph->ip_src;

  /* compare network mask. */
  /* checking is ignored for Point-to-Point and Virtual link. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    if (oi->address->prefixlen != p.prefixlen)
      {
	zlog (NULL, LOG_WARNING, "neighbor [%s] NetworkMask mismatch.",
	      inet_ntoa (ospfh->router_id));
	return;
      }

  /* compare Hello Interval. */
  if (oi->v_hello != ntohs (hello->hello_interval))
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] HelloInterval mismatch.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare Router Dead Interval. */
  if (oi->v_wait != ntohl (hello->dead_interval))
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] RouterDeadInterval mismatch.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare options. */
  if (oi->options != hello->options)
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] Options mismacth.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = 32;
  key.u.prefix4 = ospfh->router_id;

  /* if Hello is myself, silently discard. */
  if (!IPV4_ADDR_CMP (&ospfh->router_id, &ospf_top->router_id))
    return;

  rn = route_node_get (oi->nbrs, &key);
  if (rn->info)
    {
      route_unlock_node (rn);
      nbr = rn->info;
    }
  else
    {
      /* Create new OSPF Neighbor structure. */
      nbr = ospf_nbr_new (oi);
      nbr->status = NSM_Down;
      nbr->host = strdup (inet_ntoa (iph->ip_src));
      nbr->router_id = ospfh->router_id;
      nbr->address = p;

      rn->info = nbr;

      zlog (NULL, LOG_INFO, "OSPF NSM[%s] start.",
	    inet_ntoa (nbr->router_id));
    }

  /* set neighbor information. */
  nbr->priority = hello->priority;
  nbr->options = hello->options;
  nbr->d_router = hello->d_router;
  nbr->bd_router = hello->bd_router;

  /* Add event to thread. */
  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_HelloReceived);

  if (ospf_nbr_bidirectional (&ospf_top->router_id, hello->neighbors,
			      size - OSPF_HELLO_MIN_SIZE))
    OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
  else
    {
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_OneWayReceived);
      return;
    }

  /* Neighbor priority check. */
  if (nbr->priority >= 0 && nbr->priority != hello->priority)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* if neighbor itself is DR or no BDR exists,
     cause event BackupSeen */
  if (!IPV4_ADDR_CMP (&ospfh->router_id, &hello->d_router))
    if (hello->bd_router.s_addr == 0 && oi->status == ISM_Waiting)
      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((!IPV4_ADDR_CMP (&ospfh->router_id, &hello->d_router) &&
       IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router)) ||
      (IPV4_ADDR_CMP (&ospfh->router_id, &hello->d_router) &&
       !IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* neighbor itself declares BDR. */
  if (!IPV4_ADDR_CMP (&ospfh->router_id, &hello->bd_router) &&
      oi->status == ISM_Waiting)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((!IPV4_ADDR_CMP (&ospfh->router_id, &hello->bd_router) &&
       IPV4_ADDR_CMP (&nbr->router_id, &nbr->bd_router)) ||
      (IPV4_ADDR_CMP (&ospfh->router_id, &hello->bd_router) &&
       !IPV4_ADDR_CMP (&nbr->router_id, &nbr->bd_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);
}

void
ospf_make_hello (struct ospf_interface *oi)
{
  struct ospf_hello *hello;
  struct ospf_neighbor *nbr;
  struct route_node *node;

  /* prepare Hello body. */
  hello = (struct ospf_hello *) OSPF_OUTPUT_PNT (oi->obuf);
  
  /* set netmask of interface. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    masklen2ip (oi->address->prefixlen, &hello->network_mask);

  hello->hello_interval = htons (oi->v_hello);
  hello->options = oi->options;
  hello->priority = oi->priority;
  hello->dead_interval = htonl (oi->v_wait);
  hello->d_router = oi->d_router;
  hello->bd_router = oi->bd_router;

  ospf_output_forward (oi->obuf, OSPF_HELLO_MIN_SIZE);

  /* Add neighbor seen. */
  for (node = route_top (oi->nbrs); node; node = route_next (node))
    {
      if (node->info == NULL)
	continue;

      nbr = node->info;

      /* ignore 0.0.0.0 node. */
      if (nbr->router_id.s_addr == 0)
	continue;

      /* this is myself for DR election. */
      if (!IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id))
	continue;

      stream_put_ipv4 (oi->obuf, nbr->address.u.prefix4.s_addr);
    }

}

/* Process rest of DD packet */
void
ospf_db_desc_proc (struct ospf_interface *oi, struct ospf_neighbor *nbr,
		   struct ospf_db_desc *dd, u_int16_t size)
{
  struct ospf_lsa *lsa, *find, *new;

  stream_forward (oi->ibuf, OSPF_DB_DESC_MIN_SIZE);
  for (size -= OSPF_DB_DESC_MIN_SIZE; size > 0; size -= OSPF_LSA_HEADER_SIZE) 
    {
      lsa = (struct ospf_lsa *) STREAM_PNT (oi->ibuf);

      /* Unknown LS type. */
      if (lsa->type < OSPF_MIN_LSA || lsa->type > OSPF_MAX_LSA)
	{
	  zlog (NULL, LOG_WARNING, "OSPF DD Unknown LS type %d.", lsa->type);
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  continue;
	}
      /* */
      if (lsa->type == OSPF_AS_EXTERNAL_LSA)
	{
	  /* Check Neighbor's External Routing Capability. */
	}

      /* Lookup received LSA, then add LS request list. */
      find = ospf_lsa_lookup_by_header (oi->area, lsa);
      if (find == NULL)
	{
	  new = XMALLOC (MTYPE_OSPF_LSA, ntohs (lsa->length));
	  bcopy (lsa, new, ntohs (lsa->length));
	  list_add_node (nbr->ls_request, new);
	}
      else if (ospf_lsa_more_recent (find, lsa) < 0)
	{
	  new = XMALLOC (MTYPE_OSPF_LSA, ntohs (lsa->length));
	  bcopy (lsa, new, ntohs (lsa->length));
	  list_add_node (nbr->ls_request, new);
	}
      else
	{
	  /* Received LSA is not recent. */
	  zlog (NULL, LOG_INFO, "LSA received is not recent.");
	  continue;
	}
      stream_forward (oi->ibuf, OSPF_LSA_HEADER_SIZE);
    }

  /* Master */
  if (IS_SET_DD_MS (nbr->dd_flags))
    {
      nbr->dd_seqnum++;
      /* Entire DD packet sent. */
      if (!IS_SET_DD_M (dd->flags) && !IS_SET_DD_M (nbr->dd_flags))
	OSPF_NSM_EVENT_EXECUTE (nbr, NSM_ExchangeDone);
      else
	/* Send new DD packet. */
	OSPF_NSM_WRITE_ON (nbr->t_write, ospf_db_desc_send, oi->fd);
    }
  /* Slave */
  else
    {
      nbr->dd_seqnum = ntohl (dd->dd_seqnum);

      if (!IS_SET_DD_M (dd->flags))
	OSPF_NSM_EVENT_EXECUTE (nbr, NSM_ExchangeDone);

      /* Send DD pakcet in reply. */
      OSPF_NSM_WRITE_ON (nbr->t_write, ospf_db_desc_send, oi->fd);
    }

  /* Save received neighbor values. */
  nbr->last_flags = dd->flags;
  nbr->last_options = dd->options;
  nbr->last_dd_seqnum = dd->dd_seqnum;
}

void
ospf_db_desc (struct ip *iph, struct ospf_header *ospfh,
	      struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_db_desc *dd;
  struct ospf_neighbor *nbr;
  int dup_flag = 0;
  u_int32_t dd_seqnum;

  zlog (NULL, LOG_INFO, "OSPF Database Description received from [%s]",
	inet_ntoa (ospfh->router_id));

  /* increment statistics. */
  oi->db_desc_in++;

  dd = (struct ospf_db_desc *) STREAM_PNT (oi->ibuf);
  /*
  stream_forward (oi->ibuf, OSPF_DB_DESC_MIN_SIZE);
  */

  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog (NULL, LOG_WARNING, "OSPF DD: Unknown Neighbor %s",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* Is DD duplicated? */
  if (dd->options == nbr->last_options &&
      dd->flags == nbr->last_flags &&
      ntohl (dd->dd_seqnum) == nbr->last_dd_seqnum)
    dup_flag = 1;

  /* check MTU. */
  if (dd->mtu > oi->ifp->mtu)
    {
      zlog (NULL, LOG_WARNING, "OSPF DD: MTU is larger than [%s]'s MTU",
	    oi->ifp->name);
      return;
    }

  dd_seqnum = ntohl (dd->dd_seqnum);

  /* Process DD packet by neighbor status. */
  switch (nbr->status)
    {
    case NSM_Down:
    case NSM_Attempt:
      zlog (NULL, LOG_WARNING, "OSPF DD packet discarded.");
      break;
    case NSM_Init:
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
      if (nbr->status == NSM_ExStart)
	goto ExStart;
      break;
    case NSM_TwoWay:
      zlog (NULL, LOG_WARNING, "OSPF DD packet discarded.");
      break;
    case NSM_ExStart:
    ExStart:
      /* Slave. */
      if (IS_SET_DD_MS (dd->flags) && IS_SET_DD_M (dd->flags) &&
	  IS_SET_DD_I  (dd->flags) && size == OSPF_DB_DESC_MIN_SIZE &&
	  IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) > 0)
	{
	  nbr->dd_seqnum = dd_seqnum;
	  nbr->dd_flags &= ~(OSPF_DD_FLAG_MS|OSPF_DD_FLAG_I); /* Reset I/MS */
	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);
	  OSPF_NSM_WRITE_ON (nbr->t_write, ospf_db_desc_send, oi->fd);

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (oi, nbr, dd, size);
	}
      /* Master. */
      else if (!IS_SET_DD_MS (dd->flags) && !IS_SET_DD_I (dd->flags) &&
	       dd_seqnum == nbr->dd_seqnum &&
	       IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) < 0)
	{
	  nbr->dd_flags &= ~OSPF_DD_FLAG_I;
	  /*	  nbr->dd_init = OSPF_DD_EXCHANGING; */
	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (oi, nbr, dd, size);
	}
      else
	zlog (NULL, LOG_WARNING, "OSPF DD packet discarded.");
      break;
    case NSM_Exchange:
      if (dup_flag)
	if (IS_SET_DD_MS (nbr->dd_flags))
	  zlog (NULL, LOG_WARNING, "OSPF DD Master: packet duplicated.");
	else
	  zlog (NULL, LOG_WARNING, "OSPF DD Slave: packet duplicated.");
      /* cause the slave to retransmit the last Database Description. */
      else
	{
	  /* Master/Slave mismatch */
	  if (IS_SET_DD_MS (dd->flags) == IS_SET_DD_MS (nbr->dd_flags))
	    {
	      zlog (NULL, LOG_WARNING, "OSPF DD MS-bit mismatch.");
	      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	      return;
	    }
	  /* Initialize bit is set. */
	  else if (IS_SET_DD_I (dd->flags))
	    {
	      zlog (NULL, LOG_WARNING, "OSPF DD I-bit set.");
	      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	      return;
	    }
	  else if (dd->options != nbr->last_options)
	    {
	      zlog (NULL, LOG_WARNING, "OSPF DD options mismatch.");
	      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	      return;
	    }
	  else if ((IS_SET_DD_MS (nbr->dd_flags) &&
		    dd_seqnum != nbr->dd_seqnum) ||
		   (!IS_SET_DD_MS (nbr->dd_flags) &&
		    dd_seqnum != nbr->dd_seqnum + 1))
	    {
	      zlog (NULL, LOG_WARNING, "OSPF DD sequence number mismatch.");
	      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	      return;
	    }
	}
      /*      nbr->dd_init = OSPF_DD_EXCHANGING; */

      /* continue processing rest of packet. */
      ospf_db_desc_proc (oi, nbr, dd, size);
      break;
    case NSM_Loading:
    case NSM_Full:
      if (dup_flag)
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master should discard duplicate DD packet. */
	    zlog (NULL, LOG_INFO, "OSPF DD packet discarded.");
	  else
	    /* Resent last sent DD packet. */
	    ;
	  return;
	}
      else
	{
	  /*	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch); */
	  return;
	}
      break;
    default:
      zlog (NULL, LOG_WARNING, "OSPF DD illegal status.");
      break;
    }
}

void
ospf_make_db_desc (struct ospf_interface *oi, struct ospf_neighbor *nbr)
{
  struct ospf_db_desc *dd;
  listnode node;
  struct ospf_lsa *lsa;
  
  /* Prepare DD body. */
  dd = (struct ospf_db_desc *) OSPF_OUTPUT_PNT (oi->obuf);

  /* Set Interface MTU. */
  if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
    dd->mtu = htons (oi->ifp->mtu);
  else
    dd->mtu = 0;

  /* Set Options. */
  dd->options = oi->options;

  /* Set Flags. */
  dd->flags = nbr->dd_flags;

  /* Set DD Sequence Number. */
  dd->dd_seqnum = htonl (nbr->dd_seqnum);

  ospf_output_forward (oi->obuf, OSPF_DB_DESC_MIN_SIZE);

  /*
  if (nbr->dd_init != OSPF_DD_EXCHANGING)
    return;
  */

  if (list_isempty (nbr->db_summary))
    return;

  /* Describe LSA Header from Database Summary List. */
  for (node = listhead (nbr->db_summary); node; nextnode (node))
    {
      lsa = (struct ospf_lsa *) getdata (node);
      stream_memcpy (oi->obuf, lsa, OSPF_LSA_HEADER_SIZE);
    }

  nbr->dd_flags &= ~OSPF_DD_FLAG_M;
}

void
ospf_ls_req (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;
  struct ospf_lsa *find;

  zlog (NULL, LOG_INFO, "OSPF Link State Request received [%s]",
	inet_ntoa (ospfh->router_id));

  /* increment statistics. */
  oi->ls_req_in++;

  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog (NULL, LOG_WARNING, "OSPF LS Request: Unknown Neighbor %s",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  if (nbr->status != NSM_Exchange &&
      nbr->status != NSM_Loading &&
      nbr->status != NSM_Full)
    {
      zlog (NULL, LOG_WARNING, "Link State Request discarded.");
      return;
    }

  for (; size > 0; size -= 12)
    {
      ls_type = stream_getl (oi->ibuf);
      ls_id.s_addr = stream_get_ipv4 (oi->ibuf);
      adv_router.s_addr = stream_get_ipv4 (oi->ibuf);

      find = ospf_lsa_lookup (oi->area, ls_type, ls_id, adv_router);
      if (find == NULL)
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);

      OSPF_NSM_WRITE_ON (nbr->t_write, ospf_ls_upd_send, oi->fd);
    }
}

void
ospf_make_ls_req (struct ospf_interface *oi, struct ospf_neighbor *nbr)
{
  struct ospf_lsa *lsa;
  listnode node;

  for (node = listhead (nbr->ls_request); node; nextnode (node))
    {
      lsa = (struct ospf_lsa *) getdata (node);

      stream_putl (oi->obuf, lsa->type);
      stream_put_ipv4 (oi->obuf, lsa->id.s_addr);
      stream_put_ipv4 (oi->obuf, lsa->adv_router.s_addr);
    }
}

void
ospf_ls_upd (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_lsa *lsa;
  u_int32_t count;

  zlog (NULL, LOG_INFO, "OSPF Link State Update received [%s]",
	inet_ntoa (ospfh->router_id));

  /* increment statistics. */
  oi->ls_upd_in++;

  count = stream_getl (oi->ibuf);
  size -= 4;

  while (size > 0)
    {
      u_int16_t s1, s2;
      u_int32_t length;

      lsa = (struct ospf_lsa *) STREAM_PNT (oi->ibuf);

      length = ntohs (lsa->length);

      /* Check LSA. */
      s1 = lsa->checksum;
      ospf_lsa_checksum (lsa);
      s2 = lsa->checksum;
      if (s1 != s2)
	{
	  zlog (NULL, LOG_WARNING, "LSA Checksum Error.");
	  stream_forward (oi->ibuf, length);
	  size -= length;
	  continue;
	}

      if (lsa->ls_age == OSPF_LSA_MAX_AGE &&
	  ospf_lsa_count (oi->area) == 0 &&
	  (ospf_nbr_count (oi->nbrs, NSM_Exchange) + 
	   ospf_nbr_count (oi->nbrs, NSM_Loading)) == 0)
	{
	  /* Response Link State Acknowledgment. */
	  /* Discard LSA. */	  
	  zlog (NULL, LOG_WARNING, "LSA discarded.");
	  stream_forward (oi->ibuf, length);
	  size -= length;
	  continue;
	}

      /*
zlog (NULL, LOG_INFO, "*** OSPFd checksum 0x%04x", r);
zlog (NULL, LOG_INFO, "*** lsa->checksum = 0x%x", ntohs (lsa->checksum));
      */
      switch (lsa->type)
	{
	case OSPF_ROUTER_LSA:
	  break;
	case OSPF_NETWORK_LSA:
	  break;
	case OSPF_SUMMARY_LSA:
	  break;
	case OSPF_SUMMARY_LSA_ASBR:
	  break;
	case OSPF_AS_EXTERNAL_LSA:
	  /* If area is conifugured as stub, then drop the LSA. */
	  break;
	default:
	  zlog (NULL, LOG_WARNING, "LSA Unknown type. ");
	  break;
	}

      stream_forward (oi->ibuf, length);
      size -= length;
    }
}

void
ospf_make_ls_upd (struct ospf_interface *oi, struct ospf_neighbor *nbr)
{
  struct ospf_lsa *lsa;
  struct ospf_area *area;
  struct route_node *rn;
  int count = 0;
  u_int32_t count_p;

  area = oi->area;

  count_p = stream_get_putp (oi->obuf);
  ospf_output_forward (oi->obuf, 4);

  for (rn = route_top (area->router_lsa); rn; rn = route_next (rn))
    {
      if (rn->info == NULL)
	continue;

      lsa = (struct ospf_lsa *) rn->info;

      stream_memcpy (oi->obuf, lsa, ntohs (lsa->length));
      count++;
    }

  stream_putl_at (oi->obuf, count_p, count);
}

void
ospf_ls_ack (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  /* increment statistics. */
  oi->ls_ack_in++;

  zlog (NULL, LOG_INFO, "OSPF Link State Acknowledgement received [%s]",
	inet_ntoa (ospfh->router_id));
}

void
ospf_make_ls_ack ()
{

}

int
ospf_recv_packet (struct ospf_interface *oi)
{
  int ret;

  ret = recvfrom (oi->fd, STREAM_DATA (oi->ibuf), STREAM_SIZE (oi->ibuf),
		  0, NULL, 0);

  return ret;
}

int
ospf_check_area_id (struct ospf_interface *oi, struct in_addr ip_src,
		    struct in_addr area_id)
{
  struct in_addr mask, me, him;

  if (! IPV4_ADDR_CMP (&oi->area->area_id, &area_id))
    {
      masklen2ip (oi->address->prefixlen, &mask);

      if (oi->type == OSPF_IFTYPE_POINTOPOINT)
	return 1;

      me.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
      him.s_addr = ip_src.s_addr & mask.s_addr;

      if (! IPV4_ADDR_CMP (&me, &him))
	return 1;
      else
	return 0;
    }
  else if (area_id.s_addr == htonl (OSPF_AREA_BACKBONE))
    {
      /* must be border router. */
    }

  return 0;
}

int
ospf_check_auth (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  int ret = 0;

  switch (ntohs (ospfh->auth_type))
    {
    case OSPF_AUTH_NULL:
      ret = 1;
      break;
    case OSPF_AUTH_SIMPLE:
      if (!memcmp (oi->auth_data, ospfh->auth_data, OSPF_AUTH_SIZE))
	ret = 1;
      else
	ret = 0;
      break;
    case OSPF_AUTH_CRYPTOGRAPHIC:
      ret = 1;
      break;
    default:
      ret = 0;
      break;
    }

  return ret;
}

int
ospf_check_sum (struct ospf_header *ospfh)
{
  u_int32_t ret;
  u_int16_t sum;
  int in_cksum (void *ptr, int nbytes);

  /* clear auth_data for checksum. */
  bzero (ospfh->auth_data, OSPF_AUTH_SIZE);

  /* keep checksum and clear. */
  sum = ospfh->checksum;
  bzero (&ospfh->checksum, sizeof (u_int16_t));

  /* calculate checksum. */
  ret = in_cksum (ospfh, ntohs (ospfh->length));

  if (ret != sum)
    return 0;

  return 1;
}

/* OSPF Header verification. */
int
ospf_verify_header (struct ospf_interface *oi,
		    struct ip *iph, struct ospf_header *ospfh)
{
  /* check version. */
  if (ospfh->version != OSPF_VERSION)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read version number mismatch.", oi->ifp->name);
      return -1;
    }

  /* check Area ID. */
  if (! ospf_check_area_id (oi, iph->ip_src, ospfh->area_id))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read invalid Area ID.", oi->ifp->name);
      return -1;
    }

  /* check authentication. */
  if (oi->area->auth_type != ntohs (ospfh->auth_type))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read authentication type mismatch.",
	    oi->ifp->name);
      return -1;
    }

  if (! ospf_check_auth (oi, ospfh))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read authentication failed.", oi->ifp->name);
      return -1;
    }

  /* if check sum is invalid, packet is discarded. */
  if (! ospf_check_sum (ospfh))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet checksum error", oi->ifp->name);
      return -1;
    }

  return 0;
}

/* Starting point of packet process function. */
int
ospf_read (struct thread *thread)
{
  int ret;
  struct ospf_interface *oi;
  struct ip *iph;
  struct ospf_header *ospfh;
  u_int16_t ip_len, length;

  /* first of all get interface pointer. */
  oi = THREAD_ARG (thread);
  oi->t_read = NULL;

  /* Clear input buffer. */
  stream_reset (oi->ibuf);
  iph = (struct ip *) STREAM_DATA (oi->ibuf);

  /* read OSPF packet. */
  ret = ospf_recv_packet (oi);
  if (ret < 0)
    return ret;

  /* prepare for next packet. */
  OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);

  /* IP Header dump. */
  /*
  if (ospf_debug_packet & OSPF_DEBUG_RECV)
    ospf_ip_header_dump (oi->ibuf);
  */

  /* get total ip length. */
#ifdef GNU_LINUX
  ip_len = ntohs (iph->ip_len);
#else /* GNU_LINUX */
  ip_len = iph->ip_len;
#endif /* GNU_LINUX */

  /* Packet size check. */
  if (ip_len > oi->ifp->mtu)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet buffer over flow", oi->ifp->name);
      return 0;
    }

  /* my packet should be discarded silently. */
  if (!IPV4_ADDR_CMP (&iph->ip_src, &oi->address->u.prefix4))
      return 0;

  /* Adjust size to message length. */
  stream_forward (oi->ibuf, iph->ip_hl * 4);

  /* get ospf packet header. */
  ospfh = (struct ospf_header *) STREAM_PNT (oi->ibuf);
  if (ospf_debug_packet & OSPF_DEBUG_RECV)
    ospf_packet_dump (oi->ibuf);
  stream_forward (oi->ibuf, OSPF_HEADER_SIZE);

  /* some header verification. */
  ret = ospf_verify_header (oi, iph, ospfh);
  if (ret < 0)
    return ret;

  /* Adjust size to message length. */
  length = ntohs (ospfh->length) - OSPF_HEADER_SIZE;

  /* Read rest of the packet and call each sort of packet routine. */
  switch (ospfh->type)
    {
    case OSPF_MSG_HELLO:
      ospf_hello (iph, ospfh, oi, length);
      break;
    case OSPF_MSG_DB_DESC:
      ospf_db_desc (iph, ospfh, oi, length);
      break;
    case OSPF_MSG_LS_REQ:
      ospf_ls_req (iph, ospfh, oi, length);
      break;
    case OSPF_MSG_LS_UPD:
      ospf_ls_upd (iph, ospfh, oi, length);
      break;
    case OSPF_MSG_LS_ACK:
      ospf_ls_ack (iph, ospfh, oi, length);
      break;
    default:
      zlog (NULL, LOG_WARNING,
	    "interface %s: OSPF packet header type %d is illegal",
	    oi->ifp->name, ospfh->type);
      break;
    }

  return 0;
}

/* Make Authentication Data. */
int
ospf_make_auth (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  switch (oi->area->auth_type)
    {
    case OSPF_AUTH_NULL:
      bzero (ospfh->auth_data, sizeof (ospfh->auth_data));
      break;
    case OSPF_AUTH_SIMPLE:
      memcpy (ospfh->auth_data, oi->auth_data, OSPF_AUTH_SIZE);
      break;
    case OSPF_AUTH_CRYPTOGRAPHIC:
      /* not yet implemented. */
      bzero (ospfh->auth_data, sizeof (ospfh->auth_data));
      break;
    default:
      bzero (ospfh->auth_data, sizeof (ospfh->auth_data));
      break;
    }

  return 0;
}

/* Sending All type of OSPF message. */
int
ospf_hello_send (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_header *ospfh;
  int fd, length;

  oi = THREAD_ARG (thread);
  oi->obuf = stream_new (oi->ifp->mtu);

  ospfh = (struct ospf_header *) STREAM_PNT (oi->obuf);

  fd = THREAD_FD (thread);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_HELLO, oi, ospfh);

  /* Prepare OSPF Hello body. */
  ospf_make_hello (oi);

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);

  /* Debug sending packet. */
  if (ospf_debug_packet & OSPF_DEBUG_SEND)
    ospf_packet_dump (oi->obuf);

  /* Write OSPF messsage now. */
  ospf_write (oi, NULL);

  /* Cancel write thread. */
  oi->t_write = NULL;

  return 0;
}

int
ospf_db_desc_send (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_header *ospfh;
  int fd, length;

  nbr = THREAD_ARG (thread);
  nbr->t_write = NULL;

  oi = nbr->oi;
  oi->obuf = stream_new (oi->ifp->mtu);

  ospfh = (struct ospf_header *) STREAM_PNT (oi->obuf);

  fd = THREAD_FD (thread);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_DB_DESC, oi, ospfh);

  /* Prepare OSPF Database Description body. */
  ospf_make_db_desc (oi, nbr);

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);

  /* Debug sending packet. */
  if (ospf_debug_packet & OSPF_DEBUG_SEND)
    ospf_packet_dump (oi->obuf);

  /* Write OSPF messsage now. */
  ospf_write (oi, nbr);

  /* nbr sent entire DD. */
  /*  nbr->dd_flags &= ~OSPF_DD_FLAG_M; */

  /* Cancel write thread. */
  nbr->t_write = NULL;

  return 0;
}

int
ospf_ls_req_send (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_header *ospfh;
  int fd, length;

  nbr = THREAD_ARG (thread);
  nbr->t_write = NULL;

  oi = nbr->oi;
  oi->obuf = stream_new (oi->ifp->mtu);

  ospfh = (struct ospf_header *) STREAM_PNT (oi->obuf);

  fd = THREAD_FD (thread);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_REQ, oi, ospfh);

  /* Prepare OSPF Link State Request body. */
  ospf_make_ls_req (oi, nbr);

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);

  /* Debug sending packet. */
  if (ospf_debug_packet & OSPF_DEBUG_SEND)
    ospf_packet_dump (oi->obuf);

  /* Write OSPF messsage now. */
  ospf_write (oi, nbr);

  /* Cancel write thread. */
  nbr->t_write = NULL;

  return 0;
}

int
ospf_ls_upd_send (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_header *ospfh;
  int fd, length;

  nbr = THREAD_ARG (thread);
  nbr->t_write = NULL;

  oi = nbr->oi;
  oi->obuf = stream_new (oi->ifp->mtu);

  ospfh = (struct ospf_header *) STREAM_PNT (oi->obuf);

  fd = THREAD_FD (thread);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_UPD, oi, ospfh);

  /* Prepare OSPF Link State Update body. */
  ospf_make_ls_upd (oi, nbr);

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);

  /* Debug sending packet. */
  if (ospf_debug_packet & OSPF_DEBUG_SEND)
    ospf_packet_dump (oi->obuf);

  /* Write OSPF messsage now. */
  ospf_write (oi, nbr);

  /* Cancel write thread. */
  nbr->t_write = NULL;

  return 0;
}

int
ospf_ls_ack_send (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_header *ospfh;
  struct stream *s;
  int fd, length;

  nbr = THREAD_ARG (thread);
  nbr->t_write = NULL;

  oi = nbr->oi;
  oi->obuf = stream_new (oi->ifp->mtu);
  s = oi->obuf;
  ospfh = (struct ospf_header *) STREAM_PNT (oi->obuf);

  fd = THREAD_FD (thread);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_ACK, oi, ospfh);

  /* Prepare OSPF Link State Acknowledgment body. */
  ospf_make_ls_ack (oi, nbr);

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);

  /* Debug sending packet. */
  if (ospf_debug_packet & OSPF_DEBUG_SEND)
    ospf_packet_dump (oi->obuf);

  /* Write OSPF messsage now. */
  ospf_write (oi, nbr);

  /* Cancel write thread. */
  nbr->t_write = NULL;

  return 0;
}

