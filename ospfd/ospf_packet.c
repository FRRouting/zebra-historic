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
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
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
extern unsigned long ospf_debug_packet[];


/* forward output pointer. */
void
ospf_output_forward (struct stream *s, int size)
{
  s->putp += size;
}

struct ospf_packet *
ospf_packet_new (size_t size)
{
  struct ospf_packet *new;

  new = XMALLOC (MTYPE_OSPF_PACKET, sizeof (struct ospf_packet));
  bzero (new, sizeof (struct ospf_packet));

  new->s = stream_new (size);

  return new;
}

void
ospf_packet_free (struct ospf_packet *op)
{
  if (op->s)
    stream_free (op->s);

  XFREE (MTYPE_OSPF_PACKET, op);

  op = NULL;
}

struct ospf_fifo *
ospf_fifo_new ()
{
  struct ospf_fifo *new;

  new = XMALLOC (MTYPE_OSPF_FIFO, sizeof (struct ospf_fifo));
  bzero (new, sizeof (struct ospf_fifo));

  return new;
}

/* Add new packet to fifo. */
void
ospf_fifo_push (struct ospf_fifo *fifo, struct ospf_packet *op)
{
  if (fifo->tail)
    fifo->tail->next = op;
  else
    fifo->head = op;

  fifo->tail = op;

  fifo->count++;
}

/* Delete first packet from fifo. */
struct ospf_packet *
ospf_fifo_pop (struct ospf_fifo *fifo)
{
  struct ospf_packet *op;

  op = fifo->head;

  if (op)
    {
      fifo->head = op->next;

      if (fifo->head == NULL)
	fifo->tail = NULL;

      fifo->count--;
    }

  return op;
}

/* Return first fifo entry. */
struct ospf_packet *
ospf_fifo_head (struct ospf_fifo *fifo)
{
  return fifo->head;
}

void
ospf_fifo_flush (struct ospf_fifo *fifo)
{
  struct ospf_packet *op;
  struct ospf_packet *next;

  for (op = fifo->head; op; op = next)
    {
      next = op->next;
      ospf_packet_free (op);
    }
  fifo->head = fifo->tail = NULL;
  fifo->count = 0;
}

void
ospf_fifo_free (struct ospf_fifo *fifo)
{
  ospf_fifo_flush (fifo);

  XFREE (MTYPE_OSPF_FIFO, fifo);
}

#if 0
void
ospf_fifo_debug (struct ospf_fifo *fifo)
{
  int i = 0;
  struct ospf_packet *op;

  printf ("OSPF fifo count %ld\n", fifo->count);

  for (op = fifo->head; op; op = op->next)
    {
      printf (" fifo %d: stream: size %d putp %ld getp %ld\n", i, op->s->size,
	      op->s->getp, op->s->putp);
      i++;
    }
}
#endif

void
ospf_packet_add (struct ospf_interface *oi, struct ospf_packet *op)
{
  /* Add packet to end of queue. */
  ospf_fifo_push (oi->obuf, op);

  /* Debug of packet fifo*/
  /* ospf_fifo_debug (oi->obuf); */
}

void
ospf_packet_delete (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  
  op = ospf_fifo_pop (oi->obuf);

  if (op)
    ospf_packet_free (op);
}

struct stream *
ospf_stream_dup (struct stream *s)
{
  struct stream *new;

  new = stream_new (stream_get_endp (s));

  new->endp = s->endp;
  new->putp = s->putp;
  new->getp = s->getp;

  memcpy (new->data, s->data, stream_get_endp (s));

  return new;
}

struct ospf_packet *
ospf_packet_dup (struct ospf_packet *op)
{
  struct ospf_packet *new;

  new = ospf_packet_new (op->length);

  new->s = ospf_stream_dup (op->s);
  new->dst = op->dst;
  new->length = op->length;

  return new;
}


int
ospf_ls_req_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;
  struct ospf_interface *oi;

  nbr = THREAD_ARG (thread);
  nbr->t_ls_req = NULL;

  oi = nbr->oi;

  /* Send Link State Request. */
  ospf_ls_req_send (nbr);

  /* Set LS Request retransmission timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);

  return 0;
}


int
ospf_write (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  struct sockaddr_in sa;
  u_char type;

  oi = THREAD_ARG (thread);
  oi->t_write = NULL;

  /* Get one packet from queue. */
  op = ospf_fifo_head (oi->obuf);
  assert (op);
  assert (op->length >= OSPF_HEADER_SIZE);

  sa.sin_family = AF_INET;
  sa.sin_port = htons (0);
  sa.sin_addr = op->dst;

  /* Now send packet. */
  sendto (oi->fd, STREAM_DATA (op->s), op->length, 0,
	  (struct sockaddr *) &sa, sizeof (sa));

  /* Retrieve OSPF pakcet type. */
  stream_set_getp (op->s, 1);
  type = stream_getc (op->s);

  /* Show debug sending packet. */
  if (ospf_debug_packet[type - 1] & OSPF_DEBUG_SEND)
    {
      if (ospf_debug_packet[type - 1] & OSPF_DEBUG_DETAIL)
	{
	  stream_set_getp (op->s, 0);
	  ospf_packet_dump (op->s);
	}

      zlog_info ("OSPF %s sent to [%s].",
		 ospf_packet_type_str[type], inet_ntoa (op->dst));
    }

  /* Now delete packet from queue. */
  ospf_packet_delete (oi);

  /* If packets still remain in queue, call write thread. */
  if (ospf_fifo_head (oi->obuf))
    OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  return 0;
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

  /* increment statistics. */
  oi->hello_in++;

  hello = (struct ospf_hello *) STREAM_PNT (oi->ibuf);

  /* if Hello is myself, silently discard. */
  if (IPV4_ADDR_SAME (&ospfh->router_id, &ospf_top->router_id))
    return;

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
	zlog_warn ("neighbor [%s] NetworkMask mismatch.",
		   inet_ntoa (ospfh->router_id));
	return;
      }

  /* compare Hello Interval. */
  if (oi->v_hello != ntohs (hello->hello_interval))
    {
      zlog_warn ("neighbor [%s] HelloInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare Router Dead Interval. */
  if (oi->v_wait != ntohl (hello->dead_interval))
    {
      zlog_warn ("neighbor [%s] RouterDeadInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare options. */
  if (oi->options != hello->options)
    {
      zlog_warn ("neighbor [%s] Options mismacth.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = 32;
  key.u.prefix4 = ospfh->router_id;

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

      zlog_info ("OSPF NSM[%s] start.", inet_ntoa (nbr->router_id));
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
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router))
    if (hello->bd_router.s_addr == 0 && oi->status == ISM_Waiting)
      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_SAME (&nbr->router_id, &nbr->d_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* neighbor itself declares BDR. */
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router) &&
      oi->status == ISM_Waiting)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_CMP (&nbr->router_id, &nbr->bd_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_SAME (&nbr->router_id, &nbr->bd_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);
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
	  zlog_warn ("OSPF DD Unknown LS type %d.", lsa->type);
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
      if (ospf_lsa_more_recent (find, lsa) < 0)
	{
	  new = XMALLOC (MTYPE_OSPF_LSA, ntohs (lsa->length));
	  bcopy (lsa, new, ntohs (lsa->length));
	  list_add_node (nbr->ls_request, new);
	}
      else
	{
	  /* Received LSA is not recent. */
	  zlog_info ("LSA received is not recent.");
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
	ospf_db_desc_send (nbr);
    }
  /* Slave */
  else
    {
      nbr->dd_seqnum = ntohl (dd->dd_seqnum);

      if (!IS_SET_DD_M (dd->flags))
	OSPF_NSM_EVENT_EXECUTE (nbr, NSM_ExchangeDone);

      /* Send DD pakcet in reply. */
      ospf_db_desc_send (nbr);
    }

  /* Save received neighbor values. */
  nbr->last_recv.flags = dd->flags;
  nbr->last_recv.options = dd->options;
  nbr->last_recv.dd_seqnum = ntohl (dd->dd_seqnum);
}

int
ospf_db_desc_is_dup (struct ospf_db_desc *dd, struct ospf_neighbor *nbr)
{
  /* Is DD duplicated? */
  if (dd->options == nbr->last_recv.options &&
      dd->flags == nbr->last_recv.flags &&
      dd->dd_seqnum == htonl (nbr->last_recv.dd_seqnum))
    return 1;

  return 0;
}

void
ospf_db_desc (struct ip *iph, struct ospf_header *ospfh,
	      struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_db_desc *dd;
  struct ospf_neighbor *nbr;

  /* increment statistics. */
  oi->db_desc_in++;

  dd = (struct ospf_db_desc *) STREAM_PNT (oi->ibuf);

  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog_warn ("OSPF DD: Unknown Neighbor %s", inet_ntoa (ospfh->router_id));
      return;
    }

  /* check MTU. */
  if (ntohs (dd->mtu) > oi->ifp->mtu)
    {
      zlog_warn ("OSPF DD: MTU is larger than [%s]'s MTU", oi->ifp->name);
      return;
    }

  /* Process DD packet by neighbor status. */
  switch (nbr->status)
    {
    case NSM_Down:
    case NSM_Attempt:
      zlog_warn ("OSPF DD packet discarded.");
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
	  nbr->dd_seqnum = ntohl (dd->dd_seqnum);
	  nbr->dd_flags &= ~(OSPF_DD_FLAG_MS|OSPF_DD_FLAG_I); /* Reset I/MS */
	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);
	  ospf_db_desc_send (nbr);

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (oi, nbr, dd, size);
	}
      /* Master. */
      else if (!IS_SET_DD_MS (dd->flags) && !IS_SET_DD_I (dd->flags) &&
	       ntohl (dd->dd_seqnum) == nbr->dd_seqnum &&
	       IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) < 0)
	{
	  nbr->dd_flags &= ~OSPF_DD_FLAG_I;
	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (oi, nbr, dd, size);
	}
      else
	zlog (NULL, LOG_WARNING, "OSPF DD packet discarded.");
      break;
    case NSM_Exchange:
      if (ospf_db_desc_is_dup (dd, nbr))
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master: discard duplicated DD packet. */
	    zlog (NULL, LOG_WARNING, "OSPF DD Master: packet duplicated.");
	  else
	    /* Slave: cause to retransmit the last Database Description. */
	    {
	      zlog (NULL, LOG_WARNING, "OSPF DD Slave: packet duplicated.");
	      ospf_db_desc_resend (nbr);
	    }
	  break;
	}
      /* Otherwise DD packet should be checked. */

      /* Master/Slave mismatch */
      if (IS_SET_DD_MS (dd->flags) == IS_SET_DD_MS (nbr->dd_flags))
	{
	  zlog (NULL, LOG_WARNING, "OSPF DD MS-bit mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Initialize bit is set. */
      if (IS_SET_DD_I (dd->flags))
	{
	  zlog (NULL, LOG_WARNING, "OSPF DD I-bit set.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}
      /* */
      if (dd->options != nbr->last_recv.options)
	{
	  zlog (NULL, LOG_WARNING, "OSPF DD options mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}
      /* */
      if ((IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum) ||
	  (!IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum + 1))
	{
	  zlog (NULL, LOG_WARNING, "OSPF DD sequence number mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* continue processing rest of packet. */
      ospf_db_desc_proc (oi, nbr, dd, size);
      break;
    case NSM_Loading:
    case NSM_Full:
      if (ospf_db_desc_is_dup (dd, nbr))
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master should discard duplicate DD packet. */
	    zlog (NULL, LOG_INFO, "OSPF DD packet discarded.");
	  else
	    /* Resend last DD packet. */
	    ospf_db_desc_resend (nbr);
	  break;
	}

      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
      break;
    default:
      zlog (NULL, LOG_WARNING, "OSPF DD illegal status.");
      break;
    }
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
  list update;

  /* increment statistics. */
  oi->ls_req_in++;

  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog_warn ("OSPF LS Request: Unknown Neighbor %s.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Neighbor State should be Exchange or later. */
  if (nbr->status != NSM_Exchange &&
      nbr->status != NSM_Loading &&
      nbr->status != NSM_Full)
    {
      zlog_warn ("Link State Request discarded.");
      return;
    }

  /* Make update list. */
  update = list_init ();
  while (size > 0)
    {
      ls_type = stream_getl (oi->ibuf);
      ls_id.s_addr = stream_get_ipv4 (oi->ibuf);
      adv_router.s_addr = stream_get_ipv4 (oi->ibuf);

      find = ospf_lsa_lookup (oi->area, ls_type, ls_id, adv_router);
      if (find == NULL)
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);

      list_add_node (update, find);
      size -= 12;
    }

  /* Now send LSAs requested. */
  ospf_ls_upd_send (nbr, update);
}

void
ospf_ls_upd (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  u_int16_t count, length;

  /* increment statistics. */
  oi->ls_upd_in++;

  count = stream_getl (oi->ibuf);

  /* Check neighbor. */
  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog_warn ("OSPF LS Update: Unknown Neighbor %s",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Process LSAs. */
  for (size -= 4; size > 0 && count > 0;
       size -= length, stream_forward (oi->ibuf, length), count--)
    {
      struct ospf_lsa *lsa, *find, *new;
      listnode node;
      u_int16_t sum;

      lsa = (struct ospf_lsa *) STREAM_PNT (oi->ibuf);

      length = ntohs (lsa->length);

      /* (1) Check LSA checksum. */
      sum = lsa->checksum;
      if (sum != ospf_lsa_checksum (lsa))
	{
	  zlog_warn ("LSA Checksum Error.");
	  continue;
	}

      /* (2) Unknown LS type, then ignore it. */
      if (lsa->type < OSPF_MIN_LSA || lsa->type > OSPF_MAX_LSA)
	{
	  zlog_warn ("OSPF LS Update Unknown LS type %d", lsa->type);
	  continue;
	}

      /* (3) Check external routing capability. */

      /* (4) */
      if (lsa->ls_age == OSPF_LSA_MAX_AGE &&
	  ospf_lsa_count (oi->area) == 0 &&
	  (ospf_nbr_count (oi->nbrs, NSM_Exchange) + 
	   ospf_nbr_count (oi->nbrs, NSM_Loading)) == 0)
	{
	  /* a) Response Link State Acknowledgment. */
	  /* b) Discard LSA. */	  
	  zlog_warn ("LSA discarded.");
	  continue;
	}

      /* (5) */
      find = ospf_lsa_lookup_by_header (oi->area, lsa);
      if (ospf_lsa_more_recent (find, lsa) < 0)
	{
	  /* (a) */
	  /* (b) */
	  /* (c) */
	  /* (d) */
	  /* (e) */
	  /* (f) */
	}

      /* (6) */
      /* (7) */
      {
	/* (a) */
	/* (b) */
      }
      /* (8) */

      switch (lsa->type)
	{
	case OSPF_ROUTER_LSA:
	  new = XMALLOC (MTYPE_OSPF_LSA, length);
	  memcpy (new, lsa, length);
	  ospf_add_router_lsa (oi->area, new);
	  ospf_ls_ack_send_direct (nbr, new);
	  break;
	case OSPF_NETWORK_LSA:
	  new = XMALLOC (MTYPE_OSPF_LSA, length);
	  memcpy (new, lsa, length);
	  ospf_add_network_lsa (oi->area, new);
	  ospf_ls_ack_send_direct (nbr, new);
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

      /* Remove LSA header from Link State Request list. */
      node = ospf_lsa_lookup_from_list (nbr->ls_request, lsa->type,
					 lsa->id, lsa->adv_router);
      list_delete_node (nbr->ls_request, node);
    }

  /* If Link State Request List is empty, generate NSM Event LoadingDone. */
  if (list_isempty (nbr->ls_request))
    OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_LoadingDone);
}

void
ospf_ls_ack (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  struct ospf_lsa *lsa;

  /* increment statistics. */
  oi->ls_ack_in++;

  nbr = ospf_nbr_lookup_by_router_id (oi->nbrs, &ospfh->router_id);
  if (nbr == NULL)
    {
      zlog (NULL, LOG_WARNING, "OSPF LS Request: Unknown Neighbor %s.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  if (nbr->status < NSM_Exchange)
    {
      zlog (NULL, LOG_WARNING, "OSPF LS Request: discarded.");
      return;
    }

  while (size > 0)
    {
      lsa = (struct ospf_lsa *) STREAM_PNT (oi->ibuf);
      size--;
    }
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

  if (IPV4_ADDR_SAME (&oi->area->area_id, &area_id))
    {
      masklen2ip (oi->address->prefixlen, &mask);

      if (oi->type == OSPF_IFTYPE_POINTOPOINT)
	return 1;

      me.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
      him.s_addr = ip_src.s_addr & mask.s_addr;

      if (IPV4_ADDR_SAME (&me, &him))
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
	    "interface %s: ospf_read packet checksum error %s",
	    oi->ifp->name, inet_ntoa (ospfh->router_id));
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
  if (IPV4_ADDR_SAME (&iph->ip_src, &oi->address->u.prefix4))
      return 0;

  /* Adjust size to message length. */
  stream_forward (oi->ibuf, iph->ip_hl * 4);

  /* get ospf packet header. */
  ospfh = (struct ospf_header *) STREAM_PNT (oi->ibuf);

  /* Show debug receiving packet. */
  if (ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_RECV)
    {
      if (ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL)
	ospf_packet_dump (oi->ibuf);

      zlog_info ("OSPF %s received from [%s]",
		 ospf_packet_type_str[ospfh->type],
		 inet_ntoa (ospfh->router_id));
    }

  /* some header verification. */
  ret = ospf_verify_header (oi, iph, ospfh);
  if (ret < 0)
    return ret;

  stream_forward (oi->ibuf, OSPF_HEADER_SIZE);

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


void
ospf_make_header (int type, struct ospf_interface *oi, struct stream *s)
{
  struct ospf_header *ospfh;

  ospfh = (struct ospf_header *) STREAM_DATA (s);

  ospfh->version = (u_char) OSPF_VERSION;
  ospfh->type = (u_char) type;

  ospfh->router_id = ospf_top->router_id;

  ospfh->checksum = 0;
  ospfh->area_id = oi->area->area_id;
  ospfh->auth_type = htons (oi->area->auth_type);
  bzero (ospfh->auth_data, OSPF_AUTH_SIZE);

  ospf_output_forward (s, OSPF_HEADER_SIZE);
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

void
ospf_fill_header (struct ospf_interface *oi,
		  struct stream *s, u_int16_t length)
{
  struct ospf_header *ospfh;

  ospfh = (struct ospf_header *) STREAM_DATA (s);

  /* Fill length. */
  ospfh->length = htons (length);

  /* Calculate checksum. */
  ospfh->checksum = in_cksum (ospfh, length);

  /* Add Authentication Data. */
  ospf_make_auth (oi, ospfh);
}

int
ospf_make_hello (struct ospf_interface *oi, struct stream *s)
{
  struct ospf_neighbor *nbr;
  struct route_node *node;
  u_int16_t length = OSPF_HELLO_MIN_SIZE;
  struct in_addr mask;

  /* Set netmask of interface. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    masklen2ip (oi->address->prefixlen, &mask);
  else
    bzero ((char *) &mask, sizeof (struct in_addr));
  stream_put_ipv4 (s, mask.s_addr);

  /* Set Hello Interval. */
  stream_putw (s, oi->v_hello);

  /* Set Options. */
  stream_putc (s, oi->options);

  /* Set Router Priority. */
  stream_putc (s, oi->priority);

  /* Set Router Dead Interval. */
  stream_putl (s, oi->v_wait);

  /* Set Designated Router. */
  stream_put_ipv4 (s, oi->d_router.s_addr);

  /* Set Backup Designated Router. */
  stream_put_ipv4 (s, oi->bd_router.s_addr);

  /* Add neighbor seen. */
  for (node = route_top (oi->nbrs); node; node = route_next (node))
    {
      if (node->info == NULL)
	continue;

      nbr = (struct ospf_neighbor *) node->info;

      /* ignore 0.0.0.0 node. */
      if (nbr->router_id.s_addr == 0)
	continue;

      /* this is myself for DR election. */
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;

      stream_put_ipv4 (s, nbr->router_id.s_addr);
      length += 4;
    }

  return length;
}

int
ospf_make_db_desc (struct ospf_interface *oi, struct ospf_neighbor *nbr,
		   struct stream *s)
{
  struct ospf_lsa *lsa;
  list rm_list;
  listnode node;
  u_int16_t length = OSPF_DB_DESC_MIN_SIZE;
  unsigned long pp;
  
  /* Set Interface MTU. */
  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    stream_putw (s, 0);
  else
    stream_putw (s, oi->ifp->mtu);

  /* Set Options. */
  stream_putc (s, oi->options);

  /* Keep pointer to flags. */
  pp = stream_get_putp (s);
  stream_putc (s, nbr->dd_flags);

  /* Set DD Sequence Number. */
  stream_putl (s, nbr->dd_seqnum);

  if (list_isempty (nbr->db_summary))
    return length;

  rm_list = list_init ();

  /* Describe LSA Header from Database Summary List. */
  for (node = listhead (nbr->db_summary); node; nextnode (node))
    {
      /* DD packet overflows interface MTU. */
      if (length + OSPF_LSA_HEADER_SIZE > oi->ifp->mtu)
	break;

      /* Append LSA header to the packet. */
      lsa = (struct ospf_lsa *) getdata (node);
      stream_memcpy (s, lsa, OSPF_LSA_HEADER_SIZE);
      length += OSPF_LSA_HEADER_SIZE;

      /* Add remove list from DB summary list. */
      list_add_node (rm_list, lsa);
    }

  /* Remove LSA header from DB summary list. */
  for (node = listhead (rm_list); node; nextnode (node))
    {
      lsa = (struct ospf_lsa *) getdata (node);
      list_delete_by_val (nbr->db_summary, lsa);
    }

  list_delete_all (rm_list);

  /* There is no LSAs to describe, then set M-bit off. */
  if (nbr->status >= NSM_Exchange && list_isempty (nbr->db_summary))
    {
      nbr->dd_flags &= ~OSPF_DD_FLAG_M;
      /* set DD flags again */
      stream_set_putp (s, pp);
      stream_putc (s, nbr->dd_flags);
    }

  return length;
}

int
ospf_make_ls_req (struct ospf_neighbor *nbr, struct stream *s)
{
  struct ospf_interface *oi;
  struct ospf_lsa *lsa;
  listnode node;
  u_int16_t length = OSPF_LS_REQ_MIN_SIZE;

  oi = nbr->oi;

  for (node = listhead (nbr->ls_request); node; nextnode (node))
    {
      /* LS Request packet overflows interface MTU. */
      if (length + 12 > oi->ifp->mtu)
	break;

      lsa = (struct ospf_lsa *) getdata (node);

      stream_putl (s, lsa->type);
      stream_put_ipv4 (s, lsa->id.s_addr);
      stream_put_ipv4 (s, lsa->adv_router.s_addr);

      length += 12;
    }

  return length;
}

int
ospf_make_ls_upd (struct ospf_interface *oi, list update, struct stream *s)
{
  struct ospf_lsa *lsa;
  listnode node;
  u_int16_t length = OSPF_LS_UPD_MIN_SIZE;

  stream_putl (s, listcount (update));

  for (node = listhead (update); node; nextnode (node))
    {
      lsa = getdata (node);
      assert (lsa);

      stream_memcpy (s, lsa, ntohs (lsa->length));

      length += ntohs (lsa->length);
    }

  return length;
}

int
ospf_make_ls_ack (struct ospf_interface *oi, struct ospf_lsa *lsa,
		  struct stream *s)
{
  u_int16_t length = OSPF_LS_ACK_MIN_SIZE;

  stream_memcpy (s, lsa, OSPF_LSA_HEADER_SIZE);
  length += OSPF_LSA_HEADER_SIZE;

  return length;
}


/* Send OSPF Hello. */
void
ospf_hello_send (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_HELLO, oi, op->s);

  /* Prepare OSPF Hello body. */
  length += ospf_make_hello (oi, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send OSPF Database Description. */
void
ospf_db_desc_send (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_DB_DESC, oi, op->s);

  /* Prepare OSPF Database Description body. */
  length += ospf_make_db_desc (oi, nbr, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  /* Remove old DD packet, then copy new one and keep in neighbor structure. */
  if (nbr->last_send)
    ospf_packet_free (nbr->last_send);
  nbr->last_send = ospf_packet_dup (op);
}

/* Re-send Database Description. */
void
ospf_db_desc_resend (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;

  oi = nbr->oi;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, ospf_packet_dup (nbr->last_send));

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send Link State Request. */
void
ospf_ls_req_send (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_REQ, oi, op->s);

  /* Prepare OSPF Link State Request body. */
  length += ospf_make_ls_req (nbr, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  /* Add Link State Request Retransmission Timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_req, ospf_ls_req_timer, nbr->v_ls_req);
}

/* Send Link State Update. */
void
ospf_ls_upd_send (struct ospf_neighbor *nbr, list update)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_UPD, oi, op->s);

  {
    listnode node;
    struct ospf_lsa *lsa;
    for (node = listhead (update); node; nextnode (node))
      {
	lsa = (struct ospf_lsa *) getdata (node);
	ospf_lsa_header_dump (lsa);
      }
  }

  /* Prepare OSPF Link State Update body. */
  length += ospf_make_ls_upd (oi, update, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  if (oi->status == ISM_DR || oi->status == ISM_Backup)
    op->dst.s_addr = htonl (OSPF_ALLSPFROUTERS);
  else
    op->dst.s_addr = htonl (OSPF_ALLDROUTERS);

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

/* Send Link State Acknowledgment directly. */
void
ospf_ls_ack_send_direct (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_ACK, oi, op->s);

  /* Prepare OSPF Link State Acknowledgment body. */
  length += ospf_make_ls_ack (oi, lsa, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  op->dst = nbr->address.u.prefix4;

  /* Add packet to the interface output queue. */
  ospf_packet_add (oi, op);

  /* Hook thread to write packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
}

