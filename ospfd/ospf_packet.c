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
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"

/* Packet Type String. */
char *ospf_packet_type_str[] =
{
  "unknown",
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
ospf_ls_upd_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;
  list update;
  listnode node;

  update = list_init ();

  nbr = THREAD_ARG (thread);
  nbr->t_ls_upd = NULL;

  /* Send Link State Update. */
  if (listcount (nbr->ls_retransmit) > 0)
    {
      for (node = listhead (nbr->ls_retransmit); node; nextnode (node))
	list_add_node (update, node->data);

zlog_info ("CCC in ospf_ls_upd_timer");
      ospf_ls_upd_send (nbr, update, OSPF_SEND_PACKET_DIRECT);
    }

  /* Set LS Update retransmission timer. */
  OSPF_NSM_TIMER_ON (nbr->t_ls_upd, ospf_ls_upd_timer, nbr->v_ls_upd);

  list_free (update);

  return 0;
}

int
ospf_ls_ack_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_ls_ack = NULL;

  /* Send Link State Acknowledgment. */
  if (listcount (oi->ls_ack) > 0)
    ospf_ls_ack_send_delayed (oi);

  /* Set LS Ack timer. */
  OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);

  return 0;
}


int
ospf_write (struct thread *thread)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  struct sockaddr_in sa_src, sa_dst;
  u_char type;
  int sock, ret;

  oi = THREAD_ARG (thread);
  oi->t_write = NULL;

  /* Open outgoing socket. */
  sock = ospf_serv_sock (oi->ifp, AF_INET);
  if (sock < 0)
    {
      zlog_warn ("ospf_write: interface %s can't create raw socket",
		 oi->ifp->name);
      return -1;
    }

  /* Get one packet from queue. */
  op = ospf_fifo_head (oi->obuf);
  assert (op);
  assert (op->length >= OSPF_HEADER_SIZE);

  /* Select outgoing interface by destination address. */
  if (op->dst.s_addr == htonl (OSPF_ALLSPFROUTERS) ||
      op->dst.s_addr == htonl (OSPF_ALLDROUTERS))
    ospf_if_ipmulticast (sock, oi->address);
  else
    {
      bzero (&sa_src, sizeof (sa_src));
      sa_src.sin_family = AF_INET;
      sa_src.sin_addr = oi->address->u.prefix4;
      sa_src.sin_port = htons (0);

      ret = bind (sock, (struct sockaddr *) &sa_src, sizeof (sa_src));
      if (ret < 0)
	{
	  zlog_warn ("*** bind error");
	  return 0;
	}
    }

  bzero (&sa_dst, sizeof (sa_dst));
  sa_dst.sin_family = AF_INET;
  sa_dst.sin_addr = op->dst;
  sa_dst.sin_port = htons (0);

  /* Now send packet. */
  sendto (sock, STREAM_DATA (op->s), op->length, 0,
	  (struct sockaddr *) &sa_dst, sizeof (sa_dst));

  /* Immediately close socket. */
  close (sock);

  /* Retrieve OSPF pakcet type. */
  stream_set_getp (op->s, 1);
  type = stream_getc (op->s);

  /* Show debug sending packet. */
  if (ospf_debug_packet[type - 1] & OSPF_DEBUG_SEND)
    {
      if (ospf_debug_packet[type - 1] & OSPF_DEBUG_DETAIL)
	{
	  zlog_info ("------------------------------"
		     "-----------------------------");
	  stream_set_getp (op->s, 0);
	  ospf_packet_dump (op->s);
	}

      zlog_info ("OSPF %s sent to [%s] via [%s].",
		 ospf_packet_type_str[type], inet_ntoa (op->dst),
		 oi->ifp->name);

      if (ospf_debug_packet[type - 1] & OSPF_DEBUG_DETAIL)
	zlog_info ("------------------------------"
		   "-----------------------------");
    }

  /* Now delete packet from queue. */
  ospf_packet_delete (oi);

  /* If packets still remain in queue, call write thread. */
  if (ospf_fifo_head (oi->obuf))
    OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);

  return 0;
}

/* OSPF Hello message read -- RFC2328 Section 10.5. */
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

  /* Compare network mask. */
  /* Checking is ignored for Point-to-Point and Virtual link. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    if (oi->address->prefixlen != p.prefixlen)
      {
	zlog_warn ("neighbor [%s] NetworkMask mismatch.",
		   inet_ntoa (ospfh->router_id));
	return;
      }

  /* Compare Hello Interval. */
  if (oi->v_hello != ntohs (hello->hello_interval))
    {
      zlog_warn ("neighbor [%s] HelloInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Compare Router Dead Interval. */
  if (oi->v_wait != ntohl (hello->dead_interval))
    {
      zlog_warn ("neighbor [%s] RouterDeadInterval mismatch.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Compare options. */
  if (OPTIONS (oi) != hello->options)
    {
      zlog_warn ("neighbor [%s] Options mismacth.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = IPV4_MAX_BITLEN;
  key.u.prefix4 = iph->ip_src;

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

  /* Add event to thread. */
  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_HelloReceived);

  if (ospf_nbr_bidirectional (&ospf_top->router_id, hello->neighbors,
			      size - OSPF_HELLO_MIN_SIZE))
    OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
  else
    {
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_OneWayReceived);
      /* Set neighbor information. */
      nbr->priority = hello->priority;
      nbr->options = hello->options;
      nbr->d_router = hello->d_router;
      nbr->bd_router = hello->bd_router;
      return;
    }

  /* If neighbor itself declares DR and no BDR exists,
     cause event BackupSeen */
  if (IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router))
    if (hello->bd_router.s_addr == 0 && oi->status == ISM_Waiting)
      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* neighbor itself declares BDR. */
  if (oi->status == ISM_Waiting &&
      IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_BackupSeen);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_CMP (&nbr->address.u.prefix4, &nbr->d_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->d_router) &&
       IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->d_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* had not previously. */
  if ((IPV4_ADDR_SAME (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_CMP (&nbr->address.u.prefix4, &nbr->bd_router)) ||
      (IPV4_ADDR_CMP (&nbr->address.u.prefix4, &hello->bd_router) &&
       IPV4_ADDR_SAME (&nbr->address.u.prefix4, &nbr->bd_router)))
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* Neighbor priority check. */
  if (nbr->priority >= 0 && nbr->priority != hello->priority)
    OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  /* Set neighbor information. */
  nbr->priority = hello->priority;
  nbr->options = hello->options;
  nbr->d_router = hello->d_router;
  nbr->bd_router = hello->bd_router;
}

void
ospf_db_desc_save_current (struct ospf_neighbor *nbr,
			   struct ospf_db_desc *dd)
{
  nbr->last_recv.flags = dd->flags;
  nbr->last_recv.options = dd->options;
  nbr->last_recv.dd_seqnum = ntohl (dd->dd_seqnum);
}

/* Process rest of DD packet */
void
ospf_db_desc_proc (struct ospf_interface *oi, struct ospf_neighbor *nbr,
		   struct ospf_db_desc *dd, u_int16_t size)
{
  struct lsa_header *lsah, *new;
  struct ospf_lsa *find;

  stream_forward (oi->ibuf, OSPF_DB_DESC_MIN_SIZE);
  for (size -= OSPF_DB_DESC_MIN_SIZE; size > 0; size -= OSPF_LSA_HEADER_SIZE) 
    {
      lsah = (struct lsa_header *) STREAM_PNT (oi->ibuf);
      stream_forward (oi->ibuf, OSPF_LSA_HEADER_SIZE);

      /* Unknown LS type. */
      if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA)
	{
	  zlog_warn ("OSPF DD: Unknown LS type %d.", lsah->type);
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  continue;
	}

      /* */
      if (lsah->type == OSPF_AS_EXTERNAL_LSA)
	{
	  /* Check Neighbor's External Routing Capability. */
	}

      /* Lookup received LSA, then add LS request list. */
      find = ospf_lsa_lookup_by_header (oi->area, lsah);
      if (!find || ospf_lsa_more_recent (find->data, lsah) < 0)
	{
	  new = ospf_lsa_data_new (OSPF_LSA_HEADER_SIZE);
	  memcpy (new, lsah, OSPF_LSA_HEADER_SIZE);
	  list_add_node (nbr->ls_request, new);
	}
      else
	{
	  /* Received LSA is not recent. */
	  zlog_info ("OSPF DD: LSA received is not recent.");
	  continue;
	}
    }

  /* Cancel DD retransmission timer before send new DD. */
  OSPF_NSM_TIMER_OFF (nbr->t_db_desc);

  /* Master */
  if (IS_SET_DD_MS (nbr->dd_flags))
    {
      nbr->dd_seqnum++;
      /* Entire DD packet sent. */
      if (!IS_SET_DD_M (dd->flags) && !IS_SET_DD_M (nbr->dd_flags))
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_ExchangeDone);
      else
	/* Send new DD packet. */
	ospf_db_desc_send (nbr);
    }
  /* Slave */
  else
    {
      nbr->dd_seqnum = ntohl (dd->dd_seqnum);

      if (!IS_SET_DD_M (dd->flags))
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_ExchangeDone);

      /* Send DD pakcet in reply. */
      ospf_db_desc_send (nbr);
    }

  /* Save received neighbor values from DD. */
  ospf_db_desc_save_current (nbr, dd);
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

/* OSPF Database Description message read -- RFC2328 Section 10.6. */
void
ospf_db_desc (struct ip *iph, struct ospf_header *ospfh,
	      struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_db_desc *dd;
  struct ospf_neighbor *nbr;

  /* increment statistics. */
  oi->db_desc_in++;

  dd = (struct ospf_db_desc *) STREAM_PNT (oi->ibuf);

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
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
  REDO_DD_PROCESS:
  switch (nbr->status)
    {
    case NSM_Down:
    case NSM_Attempt:
      zlog_warn ("OSPF DD: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      break;
    case NSM_Init:
      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_TwoWayReceived);
      if (nbr->status == NSM_ExStart)
	goto REDO_DD_PROCESS;
      break;
    case NSM_TwoWay:
      zlog_warn ("OSPF DD: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      break;
    case NSM_ExStart:
      /* Slave. */
      if ((IS_SET_DD_ALL (dd->flags) == dd->flags) &&
	  size == OSPF_DB_DESC_MIN_SIZE &&
	  IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id) > 0)
	{
	  nbr->dd_seqnum = ntohl (dd->dd_seqnum);
	  nbr->dd_flags &= ~(OSPF_DD_FLAG_MS|OSPF_DD_FLAG_I); /* Reset I/MS */

	  OSPF_NSM_EVENT_EXECUTE (nbr, NSM_NegotiationDone);
	  zlog_warn ("OSPF DD: Negotiation done (Slave).");

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
	  zlog_warn ("OSPF DD: Negotiation done (Master).");

	  /* continue processing rest of packet. */
	  ospf_db_desc_proc (oi, nbr, dd, size);
	}
      else
	zlog_warn ("OSPF DD: Negotiation fails, packet discarded.");
      break;
    case NSM_Exchange:
      if (ospf_db_desc_is_dup (dd, nbr))
	{
	  if (IS_SET_DD_MS (nbr->dd_flags))
	    /* Master: discard duplicated DD packet. */
	    zlog_warn ("OSPF DD [Master]: packet duplicated.");
	  else
	    /* Slave: cause to retransmit the last Database Description. */
	    {
	      zlog_warn ("OSPF DD [Slave]: packet duplicated.");
	      ospf_db_desc_resend (nbr);
	    }
	  break;
	}

      /* Otherwise DD packet should be checked. */
      /* Check Master/Slave bit mismatch */
      if (IS_SET_DD_MS (dd->flags) != IS_SET_DD_MS (nbr->last_recv.flags))
	{
	  zlog_warn ("OSPF DD: MS-bit mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  zlog_info ("dd->flags=%d, nbr->dd_flags=%d",
		     dd->flags, nbr->dd_flags);
	  break;
	}

      /* Check initialize bit is set. */
      if (IS_SET_DD_I (dd->flags))
	{
	  zlog_warn ("OSPF DD: I-bit set.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Check DD Options. */
      if (dd->options != nbr->last_recv.options)
	{
	  zlog_warn ("OSPF DD: options mismatch.");
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  break;
	}

      /* Check DD sequence number. */
      if ((IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum) ||
	  (!IS_SET_DD_MS (nbr->dd_flags) &&
	   ntohl (dd->dd_seqnum) != nbr->dd_seqnum + 1))
	{
	  zlog_warn ("OSPF DD: sequence number mismatch.");
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
	    zlog_warn ("OSPF DD: DD is dup, packet discarded.");
	  else
	    /* Resend last DD packet. */
	    ospf_db_desc_resend (nbr);
	  break;
	}

      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
      break;
    default:
      zlog_warn ("OSPF DD: NSM illegal status.");
      break;
    }
}

/* OSPF Link State Request Read -- RFC2328 Section 10.7. */
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

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
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
      zlog_warn ("Link State Request: Neighbor state is %s, packet discarded.",
		 LOOKUP (ospf_nsm_status_msg, nbr->status));
      return;
    }

  /* Make update list. */
  update = list_init ();
  while (size > 0)
    {
      ls_type = stream_getl (oi->ibuf);
      ls_id.s_addr = stream_get_ipv4 (oi->ibuf);
      adv_router.s_addr = stream_get_ipv4 (oi->ibuf);

      find = ospf_lsa_lookup (oi->area, ls_type, ls_id);
      if (find == NULL)
	OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);

      list_add_node (update, find);
      size -= 12;
    }

  /* Now send LSAs requested. */
  ospf_ls_upd_send (nbr, update, OSPF_SEND_PACKET_INDIRECT);

  list_free (update);
}

/* Get the list of LSAs from Link State Update packet.
   And process some validation -- Section 13. (1)-(3). */
list
ospf_ls_upd_list_lsa (struct ospf_interface *oi, size_t size)
{
  u_int16_t count, sum;
  u_int32_t length;
  struct lsa_header *lsah;
  struct ospf_lsa *lsa;
  list lsas;

  lsas = list_init ();

  count = stream_getl (oi->ibuf);
  size -= 4;

  for (; size > 0 && count > 0;
       size -= length, stream_forward (oi->ibuf, length), count--)
    {
      lsah = (struct lsa_header *) STREAM_PNT (oi->ibuf);
      length = ntohs (lsah->length);

      if (length > size)
	{
	  zlog_warn ("OSPF LS Update: LSA length exceeds packet size.");
	  break;
	}

      /* Validate the LSA's LS checksum. */
      sum = lsah->checksum;
      if (sum != ospf_lsa_checksum (lsah))
	{
	  zlog_warn ("OSPF LS Update: LSA checksum error.");
	  continue;
	}

      /* Examine the LSA's LS type. */
      if (lsah->type < OSPF_MIN_LSA || lsah->type >= OSPF_MAX_LSA)
	{
	  zlog_warn ("OSPF LS Update: Unknown LS type %d", lsah->type);
	  continue;
	}

      /* If this is an AS-external-LSA, and the area has been configured
	 as  a stub area, discard the LSA. */
      if (lsah->type == OSPF_AS_EXTERNAL_LSA)
	{
	  ; /* If the area is configured as stub are, discard this LSA. */ 
	}

      /* Create OSPF LSA instance. */
      lsa = ospf_lsa_new ();
      lsa->data = ospf_lsa_data_new (length);
      memcpy (lsa->data, lsah, length);

      list_add_node (lsas, lsa);
    }

  return lsas;
}

/* OSPF LSA flooding -- RFC2328 Section 13.3. */
void
ospf_lsa_flooding_select_if (struct ospf_neighbor *inbr,
			     struct ospf_lsa *lsa)
{
  listnode n1, n2;

  for (n1 = listhead (ospf_top->iflist); n1; nextnode (n1))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct ospf_neighbor *onbr;
      struct route_node *rn;
      int flag;

      ifp = getdata (n1);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      /* If LS type is AS-external-LSA, ... */
      if (!OSPF_AREA_SAME (&inbr->oi->area, &oi->area))
	continue;

      /* Remember if new LSA is flooded out back. */
      flag = 0;

      /* Each of the neighbors attached to this interface are examined,
	 to determine whether they must receive the new LSA.  The following
	 steps are executed for each neighbor: */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  onbr = rn->info;

	  /* If the neighbor is in a lesser state than Exchange, it
	     does not participate in flooding, and the next neighbor
	     should be examined. */
	  if (onbr->status < NSM_Exchange)
	    continue;

	  /* If the adjacency is not yet full (neighbor state is
	     Exchange or Loading), examine the Link state request
	     list associated with this adjacency.  If there is an
	     instance of the new LSA on the list, it indicates that
	     the neighboring router has an instance of the LSA
	     already.  Compare the new LSA to the neighbor's copy: */
	  if (onbr->status < NSM_Full)
	    {
	      n2 = ospf_lsa_data_lookup_from_list (onbr->ls_request,
						   lsa->data->type,
						   lsa->data->id,
						   lsa->data->adv_router);
	      if (n2 != NULL)
		{
		  int ret;

		  ret = ospf_lsa_more_recent (n2->data, lsa->data);
		  /* The new LSA is less recent. */
		  if (ret > 0)
		    continue;
		  /* The two copies are the same instance, then delete
		     the LSA from the Link state request list. */
		  else if (ret == 0)
		    {
		      ospf_lsa_data_free (n2->data);
		      list_delete_node (onbr->ls_request, n2);
		      continue;
		    }
		  /* The new LSA is more recent.  Delete the LSA
		     from the Link state request list. */
		  else
		    {
		      ospf_lsa_data_free (n2->data);
		      list_delete_node (onbr->ls_request, n2);
		    }
		}
	    }

	  /* If the new LSA was received from this neighbor,
	     examine the next neighbor. */
 zlog_info ("VVV inbr->router_id=%s", inet_ntoa (inbr->router_id));
 zlog_info ("VVV onbr->router_id=%s", inet_ntoa (onbr->router_id));
	  if (IPV4_ADDR_SAME (&inbr->router_id, &onbr->router_id))
	    continue;

	  /* Add the new LSA to the Link state retransmission list
	     for the adjacency. The LSA will be retransmitted
	     at intervals until an acknowledgment is seen from
	     the neighbor. */
	  list_add_node (onbr->ls_retransmit, lsa);
	  flag = 1;
	}

      /* LSA is more recent than database copy, but was not flooded
         back out receiving interface. */
zlog_info ("AAA flag=%d", flag);
zlog_info ("AAA oi->status=%d", oi->status);
zlog_info ("AAA inbr->d_router=%s", inet_ntoa (inbr->d_router));
      if (flag == 0)
	if (oi->status != ISM_Backup || NBR_IS_DR (inbr))
	  list_add_node (oi->ls_ack, ospf_lsa_dup (lsa));

      /* If in the previous step, the LSA was NOT added to any of
	 the Link state retransmission lists, there is no need to
	 flood the LSA out the interface. */

      /* If the new LSA was received on this interface, and it was
	 received from either the Designated Router or the Backup
	 Designated Router, chances are that all the neighbors have
	 received the LSA already. */
      if (inbr->oi == oi)
	{
	  if (NBR_IS_DR (inbr) || NBR_IS_BDR (inbr))
	    continue;
	}

      /* If the new LSA was received on this interface, and the
	 interface state is Backup, examine the next interface.  The
	 Designated Router will do the flooding on this interface.
	 However, if the Designated Router fails the router will
	 end up retransmitting the updates. */
	else if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi)))
	  continue;

      /* The LSA must be flooded out the interface. Send a Link State
	 Update packet (including the new LSA as contents) out the
	 interface.  The LSA's LS age must be incremented by InfTransDelay
	 (which	must be	> 0) when it is copied into the outgoing Link
	 State Update packet (until the LS age field reaches the maximum
	 value of MaxAge). */
    }
}

/* Remove the current database copy from all neighbors'
   Link state retransmission lists. */
void
ospf_lsa_remove_from_ls_retransmit (struct ospf_lsa *current)
{
  listnode n1, n2;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct route_node *rn;

  for (n1 = listhead (ospf_top->iflist); n1; nextnode (n1))
    {
      ifp = getdata (n1);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if (!rn->info)
	    continue;

	  nbr = rn->info;
	  n2 = ospf_lsa_lookup_from_list (nbr->ls_retransmit,
					  current->data->type,
					  current->data->id,
					  current->data->adv_router);
	  if (n2 != NULL)
	    {
	      struct ospf_lsa *l;

	      l = getdata (n2);

	      list_delete_node (nbr->ls_retransmit, n2);
	    }
	}
    }
}  

void
ospf_lsa_flush_self_originated (struct ospf_neighbor *nbr,
				struct ospf_lsa *self,
				struct ospf_lsa *new)
{
  u_int32_t seqnum;
  list update;

  /* Adjust LS Sequence Number. */
  seqnum = ntohl (new->data->ls_seqnum) + 1;
  self->data->ls_seqnum = htonl (seqnum);

  /* Recalculate LSA checksum. */
  ospf_lsa_checksum (self->data);

  /* Reflooding LSA. */
  update = list_init ();
  list_add_node (update, self);
  ospf_ls_upd_send (nbr, update, OSPF_SEND_PACKET_INDIRECT);
  list_free (update);

  zlog_info ("Flush self-originated LSA");
}

/* OSPF LSA flooding -- RFC2328 Section 13.(5). */
int
ospf_lsa_flooding (struct ospf_neighbor *nbr, struct ospf_lsa *current,
		   struct ospf_lsa *new)
{
  struct ospf_interface *oi;
  struct ospf_lsa *self;
  time_t ts;

  oi = nbr->oi;

  /* Get current time. */
  ts = time (NULL);

  /* If there is already a database copy, and if the
     database copy was received via flooding and installed less
     than MinLSArrival seconds ago, discard the new LSA
     (without acknowledging it). */
  if (current && (ts - current->ts) < OSPF_MIN_LS_INTERVAL)
    return -1;

  /* Flood the new LSA out some subset of the router's interfaces.
     In some cases (e.g., the state of the receiving interface is
     DR and the LSA was received from a router other than the
     Backup DR) the LSA will be flooded back out the receiving
     interface. */
  ospf_lsa_flooding_select_if (nbr, new);

  /* Remove the current database copy from all neighbors'
     Link state retransmission lists. */
  if (current)
    ospf_lsa_remove_from_ls_retransmit (current);

  /* Install the new LSA in the link state database
     (replacing the current database copy).  This may cause the
     routing table calculation to be scheduled.  In addition,
     timestamp the new LSA with the current time.  The flooding
     procedure cannot overwrite the newly installed LSA until
     MinLSArrival seconds have elapsed. */  
  if (!current || ospf_lsa_different (current->data, new->data))
    ospf_spf_calculate_schedule ();

  ospf_lsa_install (nbr, new);

  /* Acknowledge the receipt of the LSA by sending a Link State
     Acknowledgment packet back out the receiving interface. */
  /* ospf_ls_ack_send (nbr, new); */

  /* If this new LSA indicates that it was originated by the
     receiving router itself, the router must take special action,
     either updating the LSA or in some cases flushing it from
     the routing domain. */
  self = ospf_lsa_is_self_originated (oi, new);
  if (self != NULL)
    ospf_lsa_flush_self_originated (nbr, self, new);

  return 0;
}

/* OSPF Link State Update message read -- RFC2328 Section 13. */
void
ospf_ls_upd (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  list lsas, update;
  listnode n1;

  /* increment statistics. */
  oi->ls_upd_in++;

  /* Check neighbor. */
  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("OSPF LS Update: Unknown Neighbor %s",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Check neighbor status. */
  if (nbr->status < NSM_Exchange)
    {
      zlog_warn ("OSPF LS Update: Neighbor[%s] state is lesser than Exchange",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  /* Get list of LSAs from Link State Update packet. */
  lsas = ospf_ls_upd_list_lsa (oi, size);

  /* Process each LSA received. */
  for (n1 = listhead (lsas); n1; nextnode (n1))
    {
      struct ospf_lsa *lsa, *current;
      listnode node;
      int ret = 1;

      lsa = getdata (n1);

      /* Find the LSA in the current database. */
      current = ospf_lsa_lookup_by_header (oi->area, lsa->data);
      /* If the LSA's LS age is equal to MaxAge, and there is currently
	 no instance of the LSA in the router's link state database,
	 and none of router's neighbors are in states Exchange or Loading,
	 then take the following actions. */
      if (lsa->data->ls_age == OSPF_LSA_MAX_AGE && !current &&
	  (ospf_nbr_count (oi->nbrs, NSM_Exchange) + 
	   ospf_nbr_count (oi->nbrs, NSM_Loading)) == 0)
	{
	  /* Response Link State Acknowledgment. */
	  ospf_ls_ack_send (nbr, lsa);

	  /* Discard LSA. */	  
	  zlog_warn ("OSPF LS Update: LS age is equal to MaxAge.");
	  continue;
	}

      /* Find the instance of this LSA that is currently contained
	 in the router's link state database.  If there is no
	 database copy, or the received LSA is more recent than
	 the database copy the following steps must be performed. */

      if (current == NULL ||
	  (ret = ospf_lsa_more_recent (current->data, lsa->data)) < 0)
	{
	  /* Actual flooding procedure. */
	  ospf_lsa_flooding (nbr, current, lsa);
	  continue;
	}

      /* If there is an instance of the LSA on the sending
	 neighbor's Link state request list, an error has occurred in the
	 Database Exchange process.  In this case, restart the Database
	 Exchange process by generating the neighbor event BadLSReq for
	 the sending neighbor and stop processing the Link State Update
	 packet. */
      if (ospf_lsa_data_lookup_from_list (nbr->ls_request, lsa->data->type,
					  lsa->data->id, lsa->data->adv_router))
	{
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_BadLSReq);
	  zlog_warn ("LSA instance exists on Link state request list");

	  /* Clean list of LSAs. */
	  list_delete_all (lsas);
	  return;
	}
      /* If the received LSA is the same instance as the database copy
	 (i.e., neither one is more recent) the following two steps
	 should be performed: */
      if (ret == 0)
	{
	  /* If the LSA is listed in the Link state retransmission list
	     for the receiving adjacency, the router itself is expecting
	     an acknowledgment for this LSA.  The router should treat the
	     received LSA as an acknowledgment by removing the LSA from
	     the Link state retransmission list.  This is termed an
	     "implied acknowledgment". */
	  node = ospf_lsa_lookup_from_list (nbr->ls_retransmit,
					    lsa->data->type,
					    lsa->data->id,
					    lsa->data->adv_router);
	  if (node != NULL)
	    {
	      list_delete_node (nbr->ls_retransmit, node);
	      /* Delayed acknowledgment sent if advertisement received
		 from Designated Router, otherwise do nothing. */
	      if (oi->status == ISM_Backup)
		if (NBR_IS_DR (nbr))
		  list_add_node (oi->ls_ack, ospf_lsa_dup (lsa));
	    }
	  else
	    /* Acknowledge the receipt of the LSA by sending a
	       Link State Acknowledgment packet back out the receiving
	       interface. */
	    ospf_ls_ack_send (nbr, lsa);
	}

      /* The database copy is more recent.  If the database copy
	 has LS age equal to MaxAge and LS sequence number equal to
	 MaxSequenceNumber, simply discard the received LSA without
	 acknowledging it. (In this case, the LSA's LS sequence number is
	 wrapping, and the MaxSequenceNumber LSA must be completely
	 flushed before any new LSA instance can be introduced). */
      else if (current->data->ls_age == OSPF_LSA_MAX_AGE &&
	       current->data->ls_seqnum == htonl (OSPF_MAX_SEQUENCE_NUMBER))
	ospf_lsa_free (lsa);

      /* Otherwise, as long as the database copy has not been sent in a
	 Link State Update within the last MinLSArrival seconds, send the
	 database copy back to the sending neighbor, encapsulated within
	 a Link State Update Packet. The Link State Update Packet should
	 be sent directly to the neighbor. In so doing, do not put the
	 database copy of the LSA on the neighbor's link state
	 retransmission list, and do not acknowledge the received (less
	 recent) LSA instance. */
      else
	{
	  /* MinLSArrival Check should be performed. */

	  update = list_init ();
	  list_add_node (update, current);
zlog_info ("CCC in ospf_ls_upd");
	  ospf_ls_upd_send (nbr, update, OSPF_SEND_PACKET_DIRECT);
	  list_free (update);
	}

      /* Remove LSA header from Link State Request list. */
      node = ospf_lsa_data_lookup_from_list (nbr->ls_request, lsa->data->type,
					lsa->data->id, lsa->data->adv_router);

      if (node != NULL)
	{
	  ospf_lsa_data_free (node->data);
	  list_delete_node (nbr->ls_request, node);
	}
    }
  
  /* If Link State Request List is empty, generate NSM Event LoadingDone. */
  if (list_isempty (nbr->ls_request))
    OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_LoadingDone);

  list_delete_all (lsas);
}

/* OSPF Link State Acknowledgment message read -- RFC2328 Section 13.7. */
void
ospf_ls_ack (struct ip *iph, struct ospf_header *ospfh,
	     struct ospf_interface *oi, u_int16_t size)
{
  struct ospf_neighbor *nbr;
  struct lsa_header *lsah;
  listnode node;

  /* increment statistics. */
  oi->ls_ack_in++;

  nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &iph->ip_src);
  if (nbr == NULL)
    {
      zlog_warn ("OSPF LS Acknowledgment: Unknown Neighbor %s.",
		 inet_ntoa (ospfh->router_id));
      return;
    }

  if (nbr->status < NSM_Exchange)
    {
      zlog_warn ("OSPF LS Acknowledgment: State is lesser than Exchange.");
      return;
    }

  while (size > 0)
    {
      lsah = (struct lsa_header *) STREAM_PNT (oi->ibuf);
      size -= OSPF_LSA_HEADER_SIZE;
      stream_forward (oi->ibuf, OSPF_LSA_HEADER_SIZE);

      node = ospf_lsa_lookup_from_list (nbr->ls_retransmit,
					lsah->type,
					lsah->id,
					lsah->adv_router);
zlog_info ("BBB nbr->router_id=%s", inet_ntoa (nbr->router_id));
zlog_info ("BBB nbr->ls_retransmit=%d", listcount (nbr->ls_retransmit));
zlog_info ("BBB lsah->type=%d", lsah->type);
zlog_info ("BBB lsah->id=%s", inet_ntoa (lsah->id));
zlog_info ("BBB lsah->adv_router=%s", inet_ntoa (lsah->adv_router));
      if (node != NULL)
{
  struct ospf_lsa *lsa;

  lsa = node->data;

	list_delete_node (nbr->ls_retransmit, node);
zlog_info ("BBB lsa->data->type=%d", lsa->data->type);
zlog_info ("BBB lsa->data->id=%s", inet_ntoa (lsa->data->id));
zlog_info ("BBB lsa->data->adv_router=%s", inet_ntoa (lsa->data->adv_router));

}
      else
	continue;
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
ospf_check_area_id (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  if (OSPF_AREA_SAME (&oi->area, &ospfh))
    return 1;
  else if (ospfh->area_id.s_addr == htonl (OSPF_AREA_BACKBONE))
    {
      /* must be border router. */
    }

  return 0;
}

/* Unbound socket will accept any Raw IP packets if proto is matched.
   To prevent it, compare src IP address and i/f address with masking
   i/f network mask. */
int
ospf_check_network_mask (struct ospf_interface *oi, struct in_addr ip_src)
{
  struct in_addr mask, me, him;

  if (oi->type == OSPF_IFTYPE_POINTOPOINT)
    return 1;

  masklen2ip (oi->address->prefixlen, &mask);

  me.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
  him.s_addr = ip_src.s_addr & mask.s_addr;

 if (IPV4_ADDR_SAME (&me, &him))
   return 1;
 else
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
      zlog_warn ("interface %s: ospf_read version number mismatch.",
		 oi->ifp->name);
      return -1;
    }

  /* Check Area ID. */
  if (!ospf_check_area_id (oi, ospfh))
    {
      zlog_warn ("interface %s: ospf_read invalid Area ID %s.",
		 oi->ifp->name, inet_ntoa (ospfh->area_id));
      return -1;
    }

  /* Check network mask. */
  /* Silently discarded. */
  if (! ospf_check_network_mask (oi, iph->ip_src))
    {
      /*
      zlog_warn ("interface %s: ospf_read network address is not same [%s]",
		 oi->ifp->name, inet_ntoa (iph->ip_src));
      */
      return -1;
    }

  /* Check authentication. */
  if (oi->area->auth_type != ntohs (ospfh->auth_type))
    {
      zlog_warn ("interface %s: ospf_read authentication type mismatch.",
		 oi->ifp->name);
      return -1;
    }

  if (! ospf_check_auth (oi, ospfh))
    {
      zlog_warn ("interface %s: ospf_read authentication failed.",
		 oi->ifp->name);
      return -1;
    }

  /* if check sum is invalid, packet is discarded. */
  if (! ospf_check_sum (ospfh))
    {
      zlog_warn ("interface %s: ospf_read packet checksum error %s",
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

  /* Self-originated packet should be discarded silently. */
  if (IPV4_ADDR_SAME (&iph->ip_src, &oi->address->u.prefix4))
      return 0;

  /* Adjust size to message length. */
  stream_forward (oi->ibuf, iph->ip_hl * 4);

  /* Get ospf packet header. */
  ospfh = (struct ospf_header *) STREAM_PNT (oi->ibuf);

  /* Show debug receiving packet. */
  if (ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_RECV)
    {
      if (ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL)
	{
	  zlog_info ("------------------------------"
		     "-----------------------------");
	  ospf_packet_dump (oi->ibuf);
	}

      zlog_info ("OSPF %s received from [%s] via [%s]",
		 ospf_packet_type_str[ospfh->type],
		 inet_ntoa (ospfh->router_id),
		 oi->ifp->name);

      if (ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL)
	  zlog_info ("------------------------------"
		     "-----------------------------");
    }

  /* Some header verification. */
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
  unsigned long p;
  int flag = 0;

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
  stream_putc (s, OPTIONS (oi));

  /* Set Router Priority. */
  stream_putc (s, PRIORITY (oi));

  /* Set Router Dead Interval. */
  stream_putl (s, oi->v_wait);

  /* Set Designated Router. */
  stream_put_ipv4 (s, DR (oi).s_addr);

  p = s->putp;

  /* Set Backup Designated Router. */
  stream_put_ipv4 (s, BDR (oi).s_addr);

  /* Add neighbor seen. */
  for (node = route_top (oi->nbrs); node; node = route_next (node))
    {
      if (node->info == NULL)
	continue;

      nbr = (struct ospf_neighbor *) node->info;

      /* ignore 0.0.0.0 node. */
      if (nbr->router_id.s_addr == 0)
	continue;

      /* ignore Down neighbor. */
      if (nbr->status == NSM_Down)
	continue;

      /* this is myself for DR election. */
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;

      /* Check neighbor is sane? */
      if (nbr->d_router.s_addr != 0 &&
	  IPV4_ADDR_SAME (&nbr->d_router, &oi->address->u.prefix4) &&
	  IPV4_ADDR_SAME (&nbr->bd_router, &oi->address->u.prefix4))
	flag = 1;

      stream_put_ipv4 (s, nbr->router_id.s_addr);
      length += 4;
    }

  /* Let neighbor generate BackupSeen. */
  if (flag == 1)
    {
      stream_set_putp (s, p);
      stream_put_ipv4 (s, 0);
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
  stream_putc (s, OPTIONS (oi));

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
      struct lsa_header *lsah;
      u_int16_t ls_age;

      /* DD packet overflows interface MTU. */
      if (length + OSPF_LSA_HEADER_SIZE > oi->ifp->mtu)
	break;

      /* Append LSA header to the packet. */
      lsa = (struct ospf_lsa *) getdata (node);

      /* Keep pointer to LS age. */
      lsah = (struct lsa_header *) (STREAM_DATA (s) + stream_get_putp (s));

      /* Proceed stream pointer. */
      stream_put (s, lsa->data, OSPF_LSA_HEADER_SIZE);
      length += OSPF_LSA_HEADER_SIZE;

      /* Set LS age. */
      ls_age = ntohs (lsa->data->ls_age) + (time (NULL) - lsa->ts);
      lsah->ls_age = htons (ls_age);

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
  struct lsa_header *lsah;
  listnode node;
  u_int16_t length = OSPF_LS_REQ_MIN_SIZE;

  oi = nbr->oi;

  for (node = listhead (nbr->ls_request); node; nextnode (node))
    {
      /* LS Request packet overflows interface MTU. */
      if (length + 12 > oi->ifp->mtu)
	break;

      lsah = (struct lsa_header *) getdata (node);

      stream_putl (s, lsah->type);
      stream_put_ipv4 (s, lsah->id.s_addr);
      stream_put_ipv4 (s, lsah->adv_router.s_addr);

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
      struct lsa_header *lsah;
      u_int16_t ls_age;

      lsa = getdata (node);
      assert (lsa);
      assert (lsa->data);

      /* Check packet size. */
      if (length + ntohs (lsa->data->length) > oi->ifp->mtu)
	break;

      /* Keep pointer to LS age. */
      lsah = (struct lsa_header *) (STREAM_DATA (s) + stream_get_putp (s));

      /* Put LSA to Link State Request. */
      stream_put (s, lsa->data, ntohs (lsa->data->length));

      /* Set LS age. */
      ls_age = ntohs (lsa->data->ls_age) + (time (NULL) - lsa->ts);
      lsah->ls_age = htons (ls_age);

      length += ntohs (lsa->data->length);
    }

  return length;
}

int
ospf_make_ls_ack (struct ospf_interface *oi, struct ospf_lsa *d_lsa,
		  struct stream *s)
{
  list rm_list;
  listnode node;
  u_int16_t length = OSPF_LS_ACK_MIN_SIZE;
  struct ospf_lsa *lsa;

  /* Direct Ack. */
  if (d_lsa)
    {
      stream_put (s, d_lsa->data, OSPF_LSA_HEADER_SIZE);
      length += OSPF_LSA_HEADER_SIZE;
    }
  /* Delayed Ack. */
  else
    {
      rm_list = list_init ();

      for (node = listhead (oi->ls_ack); node; nextnode (node))
	{
	  lsa = getdata (node);
	  assert (lsa);

	  if (length + OSPF_LSA_HEADER_SIZE > oi->ifp->mtu)
	    break;

	  stream_put (s, lsa->data, OSPF_LSA_HEADER_SIZE);
	  length += OSPF_LSA_HEADER_SIZE;

	  list_add_node (rm_list, lsa);
	}

      /* Remove LSA from LS-Ack list. */
      for (node = listhead (rm_list); node; nextnode (node))
	{
	  lsa = (struct ospf_lsa *) getdata (node);

	  ospf_lsa_free (lsa);
	  list_delete_by_val (oi->ls_ack, lsa);
	}

      list_delete_all (rm_list);
    }

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
  if (length == OSPF_HEADER_SIZE)
    {
      ospf_packet_free (op);
      return;
    }

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
ospf_ls_upd_send (struct ospf_neighbor *nbr, list update, int flag)
{
  struct ospf_interface *oi;
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;
  /*  listnode node;
      struct ospf_lsa *lsa; */

  oi = nbr->oi;
  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_UPD, oi, op->s);

  /* Prepare OSPF Link State Update body. */
  length += ospf_make_ls_upd (oi, update, op->s);

  /* Fill OSPF header. */
  ospf_fill_header (oi, op->s, length);

  /* Set packet length. */
  op->length = length;

  /* Decide destination address. */
  if (flag == OSPF_SEND_PACKET_DIRECT)
    op->dst = nbr->address.u.prefix4;
  else if (oi->status == ISM_DR || oi->status == ISM_Backup)
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
ospf_ls_ack_send (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
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

/* Send Link State Acknowledgment delayed. */
void
ospf_ls_ack_send_delayed (struct ospf_interface *oi)
{
  struct ospf_packet *op;
  u_int16_t length = OSPF_HEADER_SIZE;

  op = ospf_packet_new (oi->ifp->mtu);

  /* Prepare OSPF common header. */
  ospf_make_header (OSPF_MSG_LS_ACK, oi, op->s);

  /* Prepare OSPF Link State Acknowledgment body. */
  length += ospf_make_ls_ack (oi, NULL, op->s);

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

void
ospf_ls_retransmit (struct ospf_interface *ospfi, struct ospf_lsa *lsa)
{
  listnode n1, n2;
  struct route_node *rn;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;

  for (n1 = listhead (ospf_top->iflist); n1; nextnode (n1))
    {
      ifp = getdata (n1);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      if (!OSPF_AREA_SAME (&ospfi->area, &oi->area))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  nbr = rn->info;

	  if (nbr->status != NSM_Full)
	    continue;

	  n2 = ospf_lsa_lookup_from_list (nbr->ls_retransmit,
					  lsa->data->type,
					  lsa->data->id,
					  lsa->data->adv_router);
	  if (n2)
	    list_delete_node (nbr->ls_retransmit, n2);

	  list_add_node (nbr->ls_retransmit, lsa);
	}
    }
}

