/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospfd.h"

int
proc_hello2 (struct sockaddr *src, struct iovec *iov, struct interface *iface)
{
  struct ospf_msghdr *ospfhp;
  struct hello2 *hellop;
  u_short retoff = 0;
  struct network *netp;
  struct neighbor *nbp;
  prefixlen_t prefix;
  listnode i;
  rtr_id_t *rtr_idp;
  int twoway = 0;
  int rtr_pri_changed = 0;
  int nbchange = 0;

  ospfhp = (struct ospf_msghdr *)(iov[0].iov_base);
  hellop = (struct hello2 *)(iov[1].iov_base);

  /* Make fields host byte-order */
  hellop->hello_interval = ntohs (hellop->hello_interval);
  hellop->router_dead_interval = ntohl (hellop->router_dead_interval);

  /* Netmask check */
  prefix = mask2prefix ((void *)&hellop->netmask, 4);
  for (i = listhead (iface->networks); i; nextnode (i))
    {
      netp = getdata (i);
      if (IN6_IS_ADDR_V4MAPPED (&netp->address))
	{
	  if (prefix + 96 == netp->prefixlen)
	    goto maskok;
	}
    }
  log_warn ("Netmask Mismatch.\n");
  return -1;

maskok:
  retoff += sizeof (hellop->netmask);

  /* HelloInterval check */
  if (hellop->hello_interval != iface->hello_interval)
    {
      log_warn ("HelloInterval mismatch.\n");
      return -1;
    }
  retoff += sizeof (hellop->hello_interval);

  /* Option check */
  if (V2HELLO_IS_EBITSET (hellop->opt))
    {
      if (!iface->area->external_routing_capability)
        {
          log_warn ("E bit mismatch.\n");
          return -1;
        }
    }
  else
    {
      if (iface->area->external_routing_capability)
        {
          log_warn ("E bit mismatch.\n");
          return -1;
        }
    }
  retoff += sizeof (hellop->opt);

  retoff += sizeof (hellop->rtr_pri);

  /* RouterDeadInterval check */
  if (hellop->router_dead_interval != iface->rtr_dead_interval)
    {
      log_warn ("RouterDeadInterval mismatch.\n");
      return -1;
    }
  retoff += sizeof (hellop->router_dead_interval);

#ifdef DEBUG_HELLO
  {
    char dr[16], bdr[16], nb1[16], nb2[16], nb3[16];

    log ("HELLO: mask[%#x] HelloInt[%d] Pri[%d] RtrDeadInt[%d]\n",
	 ntohl (hellop->netmask.s_addr),
	 hellop->hello_interval, hellop->rtr_pri,
	 hellop->router_dead_interval);
    bcopy (inet_ntoa (*(struct in_addr *)&hellop->dr), dr, sizeof (dr));
    bcopy (inet_ntoa (*(struct in_addr *)&hellop->bdr), bdr, sizeof (bdr));
    bcopy (inet_ntoa (*(struct in_addr *)(hellop + 1)), nb1, sizeof (nb1));
    bcopy (inet_ntoa (*(((struct in_addr *)(hellop + 1)) + 1)), nb2, sizeof (nb2));
    bcopy (inet_ntoa (*(((struct in_addr *)(hellop + 1)) + 2)), nb3, sizeof (nb3));
    log ("HELLO: DR[%s] BDR[%s]\n", dr, bdr);
    log ("HELLO: [%s, %s, %s...]\n\n", nb1, nb2, nb3);
  }
#endif

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
  if (nbp == NULL)
    {
      nbp = make_neighbor (ospfhp->router_id, iface);
      nbp->ifid = ((struct sockaddr_in *)src)->sin_addr.s_addr;
      nbp->prevdr = nbp->dr = hellop->dr;
      nbp->prevbdr = nbp->bdr = hellop->bdr;
      nbp->rtr_pri = hellop->rtr_pri;
    }

  /* Neighbor data field set equal to this packet */
  if (nbp->rtr_pri != hellop->rtr_pri)
    {
      nbp->rtr_pri = hellop->rtr_pri;
      rtr_pri_changed++;
    }

  /* XXX remember dr field of Hello is RouterID if version 3
     while it is Interface ID if version 2 */
  if (nbp->dr != hellop->dr)
    {
      nbp->prevdr = nbp->dr;
      nbp->dr = hellop->dr;
      nbchange++;
    }
  retoff += sizeof (hellop->dr);

  if (nbp->bdr != hellop->bdr)
    {
      nbp->prevbdr = nbp->bdr;
      nbp->bdr = hellop->bdr;
      nbchange++;
    }
  retoff += sizeof (hellop->bdr);

  /* Look up my RouterID */
  for (rtr_idp = (rtr_id_t *)((char *)hellop + sizeof (struct hello2));
       retoff < ntohs (ospfhp->len) - OSPFV2HDRLEN; rtr_idp++)
    {
      if (IS_ROUTER_ID_EQUAL (*rtr_idp, iface->area->ospf->router_id))
	twoway++;
      retoff += sizeof (*rtr_idp);
    }

  /* Execute Events */
  /* Neighbor State Machine */
  thread_add_event (master, hello_received, nbp, 0);
  if (twoway)
    thread_add_event (master, twoway_received, nbp, 0);
  else
    {
      thread_add_event (master, oneway_received, nbp, 0);
    }

  /* Interface State Machine */
  if (rtr_pri_changed)
    thread_add_event (master, neighbor_change, iface, 0);

  if (nbp->dr == ((struct sockaddr_in *)src)->sin_addr.s_addr && nbp->bdr == 0
      && iface->state == IFS_WAITING)
    thread_add_event (master, backup_seen, iface, 0);
  else if (nbp->bdr == ((struct sockaddr_in *)src)->sin_addr.s_addr
      && iface->state == IFS_WAITING)
    thread_add_event (master, backup_seen, iface, 0);
  else
    {
      if (nbchange)
	{
	  if (nbp->dr == ((struct sockaddr_in *)src)->sin_addr.s_addr ||
	      nbp->prevdr == ((struct sockaddr_in *)src)->sin_addr.s_addr)
	    thread_add_event (master, neighbor_change, iface, 0);
	  else if (nbp->bdr == ((struct sockaddr_in *)src)->sin_addr.s_addr ||
	      nbp->prevbdr == ((struct sockaddr_in *)src)->sin_addr.s_addr)
	    thread_add_event (master, neighbor_change, iface, 0);
	}
    }

  return retoff;
}


int
proc_hello3 (struct sockaddr *src, struct iovec *iov, struct interface *iface)
{
  struct hello3 *hellop;
  struct ospf_msghdr *ospfhp;
  u_short retoff = 0;
  struct neighbor *nbp;
  prefixlen_t prefix;
  listnode i;
  rtr_id_t *rtr_idp;
  int twoway = 0;
  int rtr_pri_changed = 0;
  int nbchange = 0;

  ospfhp = (struct ospf_msghdr *)(iov[0].iov_base);
  hellop = (struct hello3 *)(iov[1].iov_base);

  /* Make fields host byte-order */
  hellop->hello_interval = ntohs (hellop->hello_interval);
  hellop->router_dead_interval = ntohs (hellop->router_dead_interval);

  /* these will be used later. */
  retoff += sizeof (hellop->interface_id);
  retoff += sizeof (hellop->rtr_pri);

  /* Option check */
  if (V3_IS_EBIT_SET (hellop->options))
    {
      if (!iface->area->external_routing_capability)
        {
          log_warn ("E bit mismatch.\n");
          return -1;
        }
    }
  else
    {
      if (iface->area->external_routing_capability)
        {
          log_warn ("E bit mismatch.\n");
          return -1;
        }
    }
  retoff += sizeof (hellop->options);

  /* HelloInterval check */
  if (hellop->hello_interval != iface->hello_interval)
    {
      log_warn ("HelloInterval mismatch.\n");
      return -1;
    }
  retoff += sizeof (hellop->hello_interval);

  /* RouterDeadInterval check */
  if (hellop->router_dead_interval != iface->rtr_dead_interval)
    {
      log_warn ("RouterDeadInterval mismatch.\n");
      return -1;
    }
  retoff += sizeof (hellop->router_dead_interval);

#ifdef DEBUG_HELLO
  {
    char dr[16], bdr[16], nb1[16], nb2[16], nb3[16];

    log ("HELLO: InterfaceID[%#x] HelloInt[%d] Pri[%d]\n",
	 ntohl (hellop->interface_id),
	 hellop->hello_interval, hellop->rtr_pri);
    bcopy (inet_ntoa (hellop->dr), dr, sizeof (dr));
    bcopy (inet_ntoa (hellop->bdr), bdr, sizeof (bdr));
    bcopy (inet_ntoa (*((struct in_addr *)(hellop + 1))), nb1, sizeof (nb1));
    bcopy (inet_ntoa (*((struct in_addr *)(hellop + 1) + 1)), nb2, sizeof (nb2));
    bcopy (inet_ntoa (*((struct in_addr *)(hellop + 1) + 2)), nb3, sizeof (nb3));
    log ("HELLO: RtrDeadInt[%d] DR[%s] BDR[%s]\n", hellop->router_dead_interval,
	 dr, bdr);
    log ("HELLO: seen[%s, %s, %s...]\n", nb1, nb2, nb3);
  }
#endif

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
  /* What happen if neighbor changed only his ipaddr?? */
  /* This daemon don't support this. */
  if (nbp == NULL)
    {
      nbp = make_neighbor (ospfhp->router_id, iface);
      nbp->ifid = hellop->interface_id;
      nbp->prevdr = nbp->dr = id_val (hellop->dr);
      nbp->prevbdr = nbp->bdr = id_val (hellop->bdr);
      nbp->rtr_pri = hellop->rtr_pri;
      bcopy (&((struct sockaddr_in6 *)src)->sin6_addr, &nbp->ipaddr,
	     sizeof (struct in6_addr));
    }

  if (!IN6_ARE_ADDR_EQUAL (&((struct sockaddr_in6 *)src)->sin6_addr,
			   &nbp->ipaddr))
    {
      char ntopbuf[32];
      log_warn ("!!! Neighbor %s have changed his ipaddr !!!\n",
		inet_ntop (src->sa_family, &((struct sockaddr_in6 *)src)->sin6_addr,
			   ntopbuf, sizeof (ntopbuf)));
      bcopy (&((struct sockaddr_in6 *)src)->sin6_addr, &nbp->ipaddr,
	     sizeof (struct in6_addr));
    }

  /* Neighbor data field set equal to this packet */
  if (nbp->rtr_pri != hellop->rtr_pri)
    {
      nbp->rtr_pri = hellop->rtr_pri;
      rtr_pri_changed++;
    }

  /* XXX remember dr field of Hello is RouterID if version 3
     while it is Interface ID if version 2 */
  if (nbp->dr != id_val (hellop->dr))
    {
      nbp->prevdr = nbp->dr;
      nbp->dr = id_val (hellop->dr);
      nbchange++;
    }
  retoff += sizeof (hellop->dr);

  if (nbp->bdr != id_val (hellop->bdr))
    {
      nbp->prevbdr = nbp->bdr;
      nbp->bdr = id_val (hellop->bdr);
      nbchange++;
    }
  retoff += sizeof (hellop->bdr);

  /* Look up my RouterID */
  for (rtr_idp = (rtr_id_t *)((char *)hellop + sizeof (struct hello3));
       retoff < ntohs (ospfhp->len) - OSPFV3HDRLEN; rtr_idp++)
    {
      if (IS_ROUTER_ID_EQUAL (*rtr_idp, iface->area->ospf->router_id))
	twoway++;
      retoff += sizeof (*rtr_idp);
    }

  /* Execute Events */
  /* Neighbor State Machine */
  thread_add_event (master, hello_received, nbp, 0);
  if (twoway)
    thread_add_event (master, twoway_received, nbp, 0);
  else
    {
      thread_add_event (master, oneway_received, nbp, 0);
    }

  /* Interface State Machine */
  if (rtr_pri_changed)
    thread_add_event (master, neighbor_change, iface, 0);

  if (nbp->dr == id_val (nbp->rtr_id) && nbp->bdr == 0
      && iface->state == IFS_WAITING)
    thread_add_event (master, backup_seen, iface, 0);
  else if (nbp->bdr == id_val (nbp->rtr_id)
      && iface->state == IFS_WAITING)
    thread_add_event (master, backup_seen, iface, 0);
  else
    {
      if (nbchange)
	{
	  if (nbp->dr == id_val (nbp->rtr_id) ||
	      nbp->prevdr == id_val (nbp->rtr_id))
	    thread_add_event (master, neighbor_change, iface, 0);
	  else if (nbp->bdr == id_val (nbp->rtr_id) ||
	      nbp->prevbdr == id_val (nbp->rtr_id))
	    thread_add_event (master, neighbor_change, iface, 0);
	}
    }

  return retoff;
}

int
proc_database_description (struct sockaddr *src, struct iovec *iov,
			   struct interface *iface)
{
  struct ospf_msghdr *ospfhp;
  struct neighbor *nbp;
  struct database_description *ddp;
  struct thread t;
  struct iovec *lsalist;

  ospfhp = (struct ospf_msghdr *)iov[0].iov_base;
  ddp = (struct database_description *)iov[1].iov_base;
  lsalist = &iov[2];

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
#if 0
  assert (nbp);
#else
  if (nbp == (struct neighbor *)NULL)
    return -1;
#endif

  /* XXX Interface MTU */

#ifdef DEBUG_DATABASE_DESCRIPTION
  {
    char *optp, opt[4], *bitsp, bits[4];

    bzero (opt, sizeof (opt));
    optp = opt;
    bzero (bits, sizeof (bits));
    bitsp = bits;

    if (V3_IS_EBIT_SET (ddp->options))
      {
	*optp++ = 'E';
      }

    if (DD_IS_IBIT_SET (ddp->bits))
      *bitsp++ = 'I';
    if (DD_IS_MBIT_SET (ddp->bits))
      *bitsp++ = 'M';
    if (DD_IS_MSBIT_SET(ddp->bits))
      *bitsp++ = 'm';
    else
      *bitsp++ = 's';

    log ("DD: Options[%s] InterfaceMTU[%lu] Bits[%s]\n",
	 opt, ntohs (ddp->interface_mtu), bits);
    log ("DD: SequenceNumber[%lu]\n", ntohl (ddp->sequence_number));
  }
#endif

 retry:
  switch (nbp->state)
    {
    case NBS_DOWN:
    case NBS_ATTEMPT:
      return 0;

    case NBS_INIT:
#ifdef DEBUG_DATABASE_DESCRIPTION
      log ("DD: !!!! Recv in NBS_INIT\n");
#endif
      thread_add_event (master, twoway_received, nbp, 0);
      while (thread_fetch (master, &t))
	{
	  thread_call (&t);
	  if (t.func == twoway_received && t.arg == nbp)
	    {
#ifdef DEBUG_DATABASE_DESCRIPTION
	      log ("DD: !!!! Broken in NBS_INIT\n");
#endif
	      break;
	    }
	}
      thread_fetch (master, &t);
      thread_call (&t);
      goto retry;
      break;

    case NBS_TWOWAY:
#ifdef DEBUG_DATABASE_DESCRIPTION
      log ("DD: Ignored: State 2-Way\n");
#endif
      return 0;

    case NBS_EXSTART:
      if (DD_IS_MSBIT_SET (ddp->bits) &&
	  DD_IS_MBIT_SET (ddp->bits) &&
	  DD_IS_IBIT_SET (ddp->bits) &&
	  !lsalist->iov_base &&
	  id_val (nbp->rtr_id) > id_val (iface->area->ospf->router_id))
	{
	  /* I am Slave */
	  DD_MSBIT_CLEAR (nbp->dd_bits);
	  DD_IBIT_CLEAR (nbp->dd_bits);
	  nbp->dd_sequence_number = ntohl (ddp->sequence_number);
	}
      else if (!DD_IS_MSBIT_SET (ddp->bits) &&
	       !DD_IS_IBIT_SET (ddp->bits) &&
	       ntohl (ddp->sequence_number) == nbp->dd_sequence_number &&
	       id_val (nbp->rtr_id) < id_val (iface->area->ospf->router_id))
	{
	  /* I am Master */
	  nbp->dd_sequence_number++;
	}
      else
	{
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Ignored: Negotiation Failed\n");
#endif
	  return 0;
	}

      prepare_neighbor_lsdb (nbp);
      thread_add_event (master, negotiation_done, nbp, 0);
      bcopy (ddp->options, nbp->nboptions, sizeof (nbp->nboptions));
      break;

    case NBS_EXCHANGE:
      /* Check if duplicate */
      if (bcmp (ddp->options, nbp->last_dd.options, sizeof (nbp->last_dd.options)) == 0
	  && ddp->bits == nbp->last_dd.bits
	  && ntohl (ddp->sequence_number) == nbp->last_dd.sequence_number)
	{
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Duplicate Packet\n");
#endif
	  if (DD_IS_MSBIT_SET (nbp->dd_bits))
	    {
	      return 0;
	    }
	  else
	    {
	      thread_add_event (master, send_database_description, nbp, 0);
	      return 0;
	    }
	}

      if (DD_IS_IBIT_SET (ddp->bits))
	{
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Initialize bit set in state Exchange\n");
#endif
	  thread_add_event (master, seqnumber_mismatch, nbp, 0);
	  return 0;
	}

      if (bcmp (ddp->options, nbp->nboptions, sizeof (nbp->nboptions)) != 0)
	{
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Option field have changed\n");
#endif
	  thread_add_event (master, seqnumber_mismatch, nbp, 0);
	  return 0;
	}

      if (DD_IS_MSBIT_SET (nbp->dd_bits))
	{
	  /* Master */
	  if (DD_IS_MSBIT_SET (ddp->bits))
	    {
#ifdef DEBUG_DATABASE_DESCRIPTION
	      log ("DD: Master/Slave bit Mismatch\n");
#endif
	      thread_add_event (master, seqnumber_mismatch, nbp, 0);
	      return 0;
	    }

	  if (ntohl (ddp->sequence_number) != nbp->dd_sequence_number)
	    {
#ifdef DEBUG_DATABASE_DESCRIPTION
	      log ("DD: Sequence Number Mismatch from Slave\n");
	      log ("DD: recv[%lu] have[%lu]\n",
		   ntohl (ddp->sequence_number),
		   nbp->dd_sequence_number);
#endif
	      thread_add_event (master, seqnumber_mismatch, nbp, 0);
	      return 0;
	    }
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Response to SequenceNumber[%lu]\n", nbp->dd_sequence_number);
#endif
	  nbp->dd_sequence_number++;
	}
      else
	{
	  /* Slave */
	  if (!DD_IS_MSBIT_SET (ddp->bits))
	    {
#ifdef DEBUG_DATABASE_DESCRIPTION
	      log ("DD: Master/Slave bit Mismatch\n");
#endif
	      thread_add_event (master, seqnumber_mismatch, nbp, 0);
	      return 0;
	    }

	  if (ntohl (ddp->sequence_number) != nbp->dd_sequence_number + 1)
	    {
#ifdef DEBUG_DATABASE_DESCRIPTION
	      log ("DD: Sequence Number Mismatch from Master\n");
	      log ("DD: recv[%lu] have[%lu]\n",
		   ntohl (ddp->sequence_number),
		   nbp->dd_sequence_number);
#endif
	      thread_add_event (master, seqnumber_mismatch, nbp, 0);
	      return 0;
	    }

#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Incremented by Master: SeqNum[%lu->%lu]\n",
	       nbp->dd_sequence_number, ntohl (ddp->sequence_number));
#endif

	  nbp->dd_sequence_number = ntohl (ddp->sequence_number);
	}
      break;

    case NBS_LOADING:
    case NBS_FULL:

      /* Check if duplicate */
      if (bcmp (ddp->options, nbp->last_dd.options, sizeof (nbp->last_dd.options)) == 0
	  && ddp->bits == nbp->last_dd.bits
	  && ntohl (ddp->sequence_number) == nbp->last_dd.sequence_number)
	{
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: Duplicate Packet\n");
#endif
	  if (DD_IS_MSBIT_SET (nbp->dd_bits))
	    {
	      return 0;
	    }
	  else
	    {
	      thread_add_event (master, send_database_description, nbp, 0);
	      return 0;
	    }
	}

#ifdef DEBUG_DATABASE_DESCRIPTION
      log ("DD: Not Duplicate Packet in State %s\n", nbs_name[nbp->state]);
#endif
      thread_add_event (master, seqnumber_mismatch, nbp, 0);
      return 0;

    default:
      log ("BROKEN STATE!! Neighbor %s, State[%s]\n", inet_ntoa (nbp->rtr_id),
	   nbs_name[nbp->state]);
      return 0;
    }

  if (lsalist[0].iov_base && check_neighbor_lsdb (lsalist, nbp) < 0)
    {
      /* one possible situation to come here is to find as-external
	 lsa found when this area is stub */
#ifdef DEBUG_DATABASE_DESCRIPTION
	  log ("DD: check_neighbor_lsdb() < 0\n");
#endif
      thread_add_event (master, seqnumber_mismatch, nbp, 0);
      return 0;
    }

  /* only valid packet in Exchange and ExStart state will come here */

  /* Master decides whether to make event ExchangeDone on reception
     Slave decides this on sending */
  if (DD_IS_MSBIT_SET (nbp->dd_bits) &&
      !DD_IS_MBIT_SET (ddp->bits) &&
      !DD_IS_MBIT_SET (nbp->dd_bits))
    {
      /* This is Master. */
      thread_add_event (master, exchange_done, nbp, 0);
      if (nbp->send_dd)
	{
	  thread_cancel (nbp->send_dd);
	  nbp->send_dd = (struct thread *)NULL;
	}
      return 0;
    }

  proceed_summarylist (nbp);   /* I(nitialize) bit may be changed */

  if (!DD_IS_MSBIT_SET (nbp->dd_bits) &&
      !DD_IS_MBIT_SET (ddp->bits) &&
      !DD_IS_MBIT_SET (nbp->dd_bits))
    {
      /* This is Slave. */
      thread_add_event (master, exchange_done, nbp, 0);
      if (nbp->send_dd)
	{
	  thread_cancel (nbp->send_dd);
	  nbp->send_dd = (struct thread *)NULL;
	}
      /* Not return, Slave must response to Master */
    }

  if (nbp->send_dd)
    {
      thread_cancel (nbp->send_dd);
      nbp->send_dd = (struct thread *)NULL;
    }
  thread_add_event (master, send_database_description, nbp, 0);

  /* Save Last Received DD */
  bcopy (ddp->options, nbp->last_dd.options, sizeof (nbp->last_dd.options));
  nbp->last_dd.bits = ddp->bits;
  nbp->last_dd.sequence_number = ntohl (ddp->sequence_number);

  return 1;
}

int
proc_linkstate_request (struct sockaddr *src, struct iovec *iov,
			struct interface *iface)
{
  struct ospf_msghdr *ospfhp;
  struct neighbor *nbp;
  int i, lsanum = 0;
  struct linkstate_request *lsreq;
  struct lsa_internal *lsip;
  struct iovec response[MAXIOVLIST];
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;

  iov_clear (response, MAXIOVLIST);
  ospfhp = (struct ospf_msghdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
#if 0
  assert (nbp);
#else
  if (nbp == (struct neighbor *)NULL)
    return -1;
#endif

  if (nbp->state < NBS_EXCHANGE)
    {
      log ("LSREQ: Ignored from %s\n", inet_ntoa (nbp->rtr_id));
      return -1;
    }

  if (iov_count (iov) == 1)
    {
      log ("LSREQ: Null Request.\n");
    }

  for (i = 1; iov[i].iov_base; i++)
    {
      lsreq = (struct linkstate_request *)iov[i].iov_base;

#ifdef DEBUG_LINKSTATE_REQUEST
      {
	log ("LSREQ: %s\n", print_lsahdr ((struct lsa_hdr *)lsreq));
      }
#endif
      lsip = lsa_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
			 lsreq->lsreq_advrtr, nbp->interface->area, nbp->interface);
      if (!lsip)
	{
	  /* XXX BadLSReq */
	  log ("Requested not found[%s] : BadLSReq\n",
	       print_lsahdr((struct lsa_hdr *)lsreq));
	  thread_add_event (master, bad_lsreq, nbp, 0);
	  return;
	}

      attach_lsa_to_iov (lsip, response);
      lsanum++;
    }

  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      dst.sin6_len = sizeof (struct sockaddr_in6);
      dst.sin6_family = AF_INET6;
      dst.sin6_addr.s6_addr32[0] = nbp->ipaddr.s6_addr32[0];
      dst.sin6_addr.s6_addr32[1] = nbp->ipaddr.s6_addr32[1];
      dst.sin6_addr.s6_addr32[2] = nbp->ipaddr.s6_addr32[2];
      dst.sin6_addr.s6_addr32[3] = nbp->ipaddr.s6_addr32[3];
      dst.sin6_scope_id = if_nametoindex (nbp->interface->ifname);

      lsupdate = (struct linkstate_update *)
	iov_prepend (MTYPE_OSPF_MESSAGE, response, sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf_send (MSGT_LINKSTATE_UPDATE, response, (struct sockaddr *)&dst,
		 nbp->interface);
      iov_free (MTYPE_OSPF_MESSAGE, response, 0, 1);
    }

  return 0;
}

int
proc_linkstate_update (struct sockaddr *src, struct iovec *iov,
		       struct interface *iface)
{
  struct ospf_msghdr *ospfhp;
  struct neighbor *nbp;
  int i, lsanum;
  struct linkstate_update *lsupdate;
  struct lsa_internal *lsip, **p;
  struct lsa_hdr *lshp, *lsa;
  struct iovec directack[MAXIOVLIST];
  struct sockaddr_in6 dst;

  ospfhp = (struct ospf_msghdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
#if 0
  assert (nbp);
#else
  if (nbp == (struct neighbor *)NULL)
    return -1;
#endif

  bzero (nbp->direct_ack, sizeof (struct lsa_internal *) * MAXLSDBSIZE);

  if (nbp->state < NBS_EXCHANGE)
    {
      log ("LSUPDATE: Ignored from %s\n", inet_ntoa (nbp->rtr_id));
      return -1;
    }

  lsupdate = (struct linkstate_update *)iov[1].iov_base;
  lsanum = ntohl (lsupdate->lsupdate_num);
#ifdef DEBUG_LINKSTATE_UPDATE
  log ("LSUPDATE: # LSAs[%d]\n", lsanum);
#endif

  for (lshp = (struct lsa_hdr *)iov[2].iov_base; lsanum; lsanum--)
    {
#ifdef DEBUG_LINKSTATE_UPDATE
      {
	log ("LSUPDATE: %s\n", print_lsahdr (lshp));
      }
#endif

      lsa_receive (lshp, nbp);
      lshp = LSA_NEXT (lshp);
    }

  /* Direct acknowledgement */
  iov_clear (directack, MAXIOVLIST);

  for (p = nbp->direct_ack; *p; p++)
    {
#ifdef DEBUG_OSPF
      log ("[%s] To DIRECT ACK\n", print_lsahdr ((*p)->lsh));
#endif
      attach_lsa_hdr_to_iov (*p, directack);
      (*p)->lsh->lsh_age =
	htons (calc_lsa_age_external (*p) + nbp->interface->inf_trans_delay);
    }

  if (iov_count (directack))
    {
      dst.sin6_len = sizeof (struct sockaddr_in6);
      dst.sin6_family = AF_INET6;
      dst.sin6_addr.s6_addr32[0] = nbp->ipaddr.s6_addr32[0];
      dst.sin6_addr.s6_addr32[1] = nbp->ipaddr.s6_addr32[1];
      dst.sin6_addr.s6_addr32[2] = nbp->ipaddr.s6_addr32[2];
      dst.sin6_addr.s6_addr32[3] = nbp->ipaddr.s6_addr32[3];
      dst.sin6_scope_id = if_nametoindex (nbp->interface->ifname);
      ospf_send (MSGT_LINKSTATE_ACK, directack, (struct sockaddr *)&dst, iface);
    }
#ifdef DEBUG_OSPF
  else
    log ("Nothing to Direct ACK\n");
#endif

  bzero (nbp->direct_ack, sizeof (struct lsa_internal *) * MAXLSDBSIZE);

  return 0;
}

int
proc_linkstate_ack (struct sockaddr *src, struct iovec *iov,
		    struct interface *iface)
{
  struct lsa_hdr *lsh;
  struct lsa_internal *p, *lsi, *q;
  struct neighbor *nbp;
  struct ospf_msghdr *ospfhp;
  int i, j;
  listnode m, n;

  ospfhp = (struct ospf_msghdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbp = nb_lookup_by_nb_id (ospfhp->router_id, iface->nb_list);
#if 0
  assert (nbp);
#else
  if (nbp == (struct neighbor *)NULL)
    return -1;
#endif

  if (nbp->state < NBS_EXCHANGE)
    {
      log ("LSACK: Ignored from %s\n", inet_ntoa (nbp->rtr_id));
      return -1;
    }

  for (i = 1; iov[i].iov_base; i++)
    {
      lsh = (struct lsa_hdr *)iov[i].iov_base;
      lsi = make_lsa_hdr_internal (lsh, nbp);

#ifdef DEBUG_OSPF
      log ("LSACK: %s\n", print_lsahdr (lsh));
#endif

      p = lsa_lookup (lsh->lsh_type, lsh->lsh_id, lsh->lsh_advrtr,
		      nbp->interface->area, nbp->interface);
      if (p)
	{
	  for (n = listhead (nbp->retranslist); n; nextnode (n))
	    {
	      q = (struct lsa_internal *)getdata (n);
	      if (p == q)
		{
#if 0
		  if (which_is_more_recent (p, lsi) != 0)
		    {
#ifdef DEBUG_OSPF
		      log ("RFC said to log!!\n");
#endif
		      /* XXX break; */
		    }

#else
		  if (p->lsh->lsh_seqnum != lsi->lsh->lsh_seqnum)
		    {
#ifdef DEBUG_OSPF
		      log ("RFC said to log!!\n");
#endif
		      /* XXX break; */
		    }
#endif

#ifdef DEBUG_OSPF
		  {
		    char tmp[32];
		    strncpy (tmp, inet_ntoa (nbp->rtr_id), sizeof (tmp));
		    log ("LSACK: Deleted %s from retranslist on %s\n",
			 print_lsahdr (p->lsh), tmp);
		  }
#endif
		  list_delete_by_val (nbp->retranslist, p);
		  break;
		}
	    }
	}
      free_lsa (lsi->lsh);
      free_lsa_internal_hdr (lsi);
    }

  return 0;
}

int
auth_ok (u_short autype, char *auth_data1, char *auth_data2)
{
  int i;

  if (autype != AUTYPE_SIMPLE_PASSWD)
    return 0;

  for (i = 0; i < 8; i++)
    if (auth_data1[i] != auth_data2[i])
      return 0;

  return 1;
}


int
proc_ospf (struct iovec *iov, struct interface *iface)
{
  u_short retoff = 0;
  char auth_data[8];
  int retval;
  struct ospf_msghdr *ospfhp;

  ospfhp = (struct ospf_msghdr *)(iov[0].iov_base);

  if (!iface)
    {
      log ("BUG! Received Interface Not Found in proc_ospf\n");
      return -1;
    }

#ifdef DEBUG_OSPF
      {
	char rtr_id[64];
	strncpy (rtr_id, inet_ntoa (ospfhp->router_id), sizeof (rtr_id));
	log ("OSPFv%d from %s, RouterID[%s] AreaID[%s]\n",
	     ospfhp->version, iface->ifname,
	     rtr_id, inet_ntoa (ospfhp->area_id));
      }
#endif

  if (ospfhp->version != iface->area->ospf->version)
    {
      ospfstat.ospfs_vermismatch++;
      log_warn ("Version(%d) mismatch between i/f and packet.\n", ospfhp->version);
      return -1;
    }

  retoff += sizeof (ospfhp->version);
  retoff += sizeof (ospfhp->type);
  retoff += sizeof (ospfhp->len);

  /* Router ID */
  retoff += sizeof (ospfhp->router_id);

  /* Area ID check */
  if (iface && ospfhp->area_id.s_addr != iface->area->area_id.s_addr)
    if (ospfhp->area_id.s_addr == 0)
      log ("vertual link?\n");
    else
      {
        ospfstat.ospfs_areamismatch++;
        log ("Can't find Area, drop.\n");
        return -1;
      }
  retoff += sizeof (ospfhp->area_id);

  /* Checksum */
  if (ospfhp->version == 2)
    {
      bcopy (ospfhp->v2auth_data, auth_data, sizeof (auth_data));
      bzero (ospfhp->v2auth_data, sizeof (ospfhp->v2auth_data));
      if (in_cksum (ospfhp, ntohs(ospfhp->len)))
	{
	  ospfstat.ospfs_badsum++;
	  log_warn ("Checksum Error.\n");
	  return -1;
	}
    }
  else if (ospfhp->version == OSPF_V3)
    {
      /* XXX */
    }
  else
    {
      log ("Unknown version in proc_ospf\n");
      return -1;
    }
  retoff += sizeof (ospfhp->cksum);

  /* Authentication and Instance ID check */
  if (iface->area->ospf->version == 3)
    {
      if (iface->area->ospf->instance_id != ospfhp->v3instance_id)
        {
          log_warn ("Instance ID[%d] mismatch on %s[%d].\n",
                     ospfhp->v3instance_id, iface->ifname,
                     iface->area->ospf->instance_id);
          return -1;
        }
      retoff += sizeof (ospfhp->v3instance_id);
    }
  else if (iface->autype != ntohs (ospfhp->v2autype))
    {
      ospfstat.ospfs_authfail++;
      log ("%s from %s: Authentication Failed\n",
	   mesg_name[ospfhp->type],
	   inet_ntoa (ospfhp->router_id));
      return -1;
    }
  else if (!auth_ok (iface->autype, iface->auth_data, auth_data))
    {
      ospfstat.ospfs_authfail++;
      log ("%s from %s: Authentication Failed\n",
	   mesg_name[ospfhp->type],
	   inet_ntoa (ospfhp->router_id));
      return -1;
    }

  if (ospfhp->version == OSPF_V3)
    retoff = OSPFV3HDRLEN;
  else
    retoff = OSPFV2HDRLEN;	/* XXX */

  return retoff;
}


int
make_ospfhdr (u_int8_t msgtype, struct iovec *iov, struct interface *iface)
{
  struct ospf_msghdr *ospfhp;
  int i;
  char *p;

  switch (iface->area->ospf->version)
    {
    case OSPF_V2:
      ospfhp = (struct ospf_msghdr *)iov_prepend (MTYPE_OSPF_MESSAGE, iov, OSPFV2HDRLEN);
      if (!ospfhp)
	{
	  log ("make_ospfhdr() failed\n");
	  return ;
	}
      ospfhp->v2autype = htons (iface->autype);
      break;
    case OSPF_V3:
      ospfhp = (struct ospf_msghdr *)iov_prepend (MTYPE_OSPF_MESSAGE, iov, OSPFV3HDRLEN);
      if (!ospfhp)
	{
	  log ("make_ospfhdr() failed\n");
	  return ;
	}
      ospfhp->v3instance_id = iface->area->ospf->instance_id;
      break;
    default:
      log ("Unknown OSPF version in make_ospfhdr()\n");
      return -1;
    }

  ospfhp->version = iface->area->ospf->version;
  ospfhp->type = msgtype;
  id_val (ospfhp->router_id) = id_val (iface->area->ospf->router_id);
  id_val (ospfhp->area_id) = id_val (iface->area->area_id);

  /* Length, Checksum */
  ospfhp->len = htons (iov_totallen (iov));
  if (iface->area->ospf->version == OSPF_V2)
    {
      char cksumbuf[MAXOSPFMESSAGELEN];
      p = cksumbuf;
      for (i = 0; i < iov_count (iov); i++)
	{
	  bcopy (iov[i].iov_base, p, iov[i].iov_len);
	  p += iov[i].iov_len;
	}
      ospfhp->cksum = in_cksum (cksumbuf, p - cksumbuf);
      bcopy (iface->auth_data, ospfhp->v2auth_data, sizeof (ospfhp->v2auth_data));
    }
  return 0;
}

int
make_hello2 (struct iovec *iov, struct sockaddr *dst,
	     struct interface *iface, int *msgend)
{
  struct neighbor *nbp;
  struct network *netp;
  listnode n;
  struct hello2 *hellop;
  struct sockaddr_in *sin;

  sin = (struct sockaddr_in *)dst;
  sin->sin_len = sizeof (struct sockaddr_in);
  sin->sin_family = AF_INET;
  inet_pton (AF_INET, ALLSPFROUTERS, &sin->sin_addr);

  *msgend = iov_count (iov) + 1;
  hellop = (struct hello2 *)iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct hello2));
  if (!hellop)
    {
      log ("iov_append() failed\n");
      return -1;
    }

  for (n = listhead (iface->networks); n; nextnode (n))
    {
      netp = getdata (n);
      if (!IN6_IS_ADDR_V4MAPPED (&netp->address))
	{
	  netp = NULL;
	  continue;
	}
      else
	break;
    }
  if (!netp)
    {
      log_warn ("No address, Can't make HELLO for %s\n", iface->ifname);
      return -1;
    }

  prefix2mask (netp->prefixlen - 96,
	       (void *)&hellop->netmask, 4);
  hellop->hello_interval = htons (iface->hello_interval);
  hellop->rtr_pri = iface->rtr_pri;
  if (iface->area->external_routing_capability)
    EBITSET (hellop->opt);
  hellop->router_dead_interval = htonl (iface->rtr_dead_interval);
  hellop->dr = id_val (iface->dr);
  hellop->bdr = id_val (iface->bdr);

  for (n = listhead (iface->nb_list); n; nextnode (n))
    {
      nbp = getdata (n);
      if (nbp->state < NBS_INIT)
	continue;
      iov_attach_last (iov, &nbp->rtr_id, sizeof (rtr_id_t));
    }
  return 0;
}

int
make_hello3 (struct iovec *iov, struct sockaddr *dst,
	     struct interface *iface)
{
  int i;
  listnode n;
  struct hello3 *hellop;
  struct neighbor *nbp;
  struct sockaddr_in6 *sin6;

  sin6 = (struct sockaddr_in6 *)dst;
  sin6->sin6_len = sizeof (struct sockaddr_in6);
  sin6->sin6_family = AF_INET6;
  inet_pton (AF_INET6, ALLSPFROUTERS6, &sin6->sin6_addr);
  sin6->sin6_scope_id = if_nametoindex (iface->ifname);

  hellop = (struct hello3 *)iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct hello3));
  if (!hellop)
    {
      log ("iov_append() failed\n");
      return -1;
    }

  hellop->interface_id = iface->ifid;
  hellop->rtr_pri = iface->rtr_pri;
  bcopy (iface->area->options, hellop->options, sizeof (hellop->options));
  hellop->hello_interval = htons ((short)iface->hello_interval);
  hellop->router_dead_interval = htons ((short)iface->rtr_dead_interval);
  id_val (hellop->dr) = id_val (iface->dr);
  id_val (hellop->bdr) = id_val (iface->bdr);

  for (n = listhead (iface->nb_list); n; nextnode (n))
    {
      nbp = getdata (n);
      if (nbp->state < NBS_INIT)
	continue;
      iov_attach_last (iov, &nbp->rtr_id, sizeof (rtr_id_t));
    }
  return 0;
}

int
make_database_description (struct iovec *iov, struct sockaddr *dst,
			   struct neighbor *nbp)
{
  struct database_description *ddp;
  struct timeval tv;
  int i;
  struct sockaddr_in6 *sin6;
  listnode n;

  sin6 = (struct sockaddr_in6 *)dst;
  sin6->sin6_len = sizeof (struct sockaddr_in6);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_addr.s6_addr32[0] = nbp->ipaddr.s6_addr32[0];
  sin6->sin6_addr.s6_addr32[1] = nbp->ipaddr.s6_addr32[1];
  sin6->sin6_addr.s6_addr32[2] = nbp->ipaddr.s6_addr32[2];
  sin6->sin6_addr.s6_addr32[3] = nbp->ipaddr.s6_addr32[3];
  sin6->sin6_scope_id = if_nametoindex (nbp->interface->ifname);

  ddp = (struct database_description *)
    iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct database_description));
  if (!ddp)
    {
      log ("iov_append() failed\n");
      return -1;
    }

  bcopy (nbp->interface->area->options, ddp->options, sizeof (ddp->options));
  ddp->interface_mtu = htons (DEFAULT_INTERFACE_MTU);
  ddp->bits = nbp->dd_bits;

  if (DD_IS_IBIT_SET (ddp->bits))
    {
      if (gettimeofday (&tv, (struct timezone *)NULL) < 0)
	{
	  log ("gettimeofday() failed in send_database_description: %s\n",
	       strerror (errno));
	  return -1;
	}
      nbp->dd_sequence_number = tv.tv_sec;
#ifdef DEBUG_DATABASE_DESCRIPTION
      log ("Neighbor[%s] SequenceNumber newly set [%lu]\n",
	   inet_ntoa (nbp->rtr_id), nbp->dd_sequence_number);
#endif
    }
  ddp->sequence_number = htonl (nbp->dd_sequence_number);

  if (!DD_IS_IBIT_SET (nbp->dd_bits))
    {
      for (n = listhead (nbp->dd_retrans); n; nextnode (n))
	attach_lsa_hdr_to_iov ((struct lsa_internal *)getdata (n), iov);
    }

  return 0;
}

int
make_linkstate_request (struct iovec *iov, struct sockaddr *dst,
			struct neighbor *nbp)
{
  struct linkstate_request *lsreq;
  int i;
  struct sockaddr_in6 *sin6;
  listnode n,m;
  struct lsa_internal *lsi;

  sin6 = (struct sockaddr_in6 *)dst;
  sin6->sin6_len = sizeof (struct sockaddr_in6);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_addr.s6_addr32[0] = nbp->ipaddr.s6_addr32[0];
  sin6->sin6_addr.s6_addr32[1] = nbp->ipaddr.s6_addr32[1];
  sin6->sin6_addr.s6_addr32[2] = nbp->ipaddr.s6_addr32[2];
  sin6->sin6_addr.s6_addr32[3] = nbp->ipaddr.s6_addr32[3];
  sin6->sin6_scope_id = if_nametoindex (nbp->interface->ifname);

  if (listcount (nbp->requestlist) == 0)
    {
      log ("LSREQ: empty requestlist of Neighbor[%s]\n",
	   inet_ntoa (nbp->rtr_id));
      return -1;
    }

  for (n = listhead (nbp->requestlist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      assert (lsi->lsh);
      lsreq = (struct linkstate_request *)iov_append
	(MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_request));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsi->lsh->lsh_type;
      lsreq->lsreq_id = lsi->lsh->lsh_id;
      lsreq->lsreq_advrtr = lsi->lsh->lsh_advrtr;
      if (iov_totallen (iov) >= DEFAULT_INTERFACE_MTU - OSPFV3HDRLEN)
	break;
    }
  return 0;
}

/* Send Neighbor's Retransmit list */
int
make_linkstate_update (struct iovec *iov, struct sockaddr *dst,
		       struct neighbor *nbp)
{
  struct linkstate_update *lsupdate;
  int i, lsanum;
  struct sockaddr_in6 *sin6;
  listnode n, m;
  struct lsa_internal *lsi;

  sin6 = (struct sockaddr_in6 *)dst;
  sin6->sin6_len = sizeof (struct sockaddr_in6);
  sin6->sin6_family = AF_INET6;
  /* Destination address may be changed later. */
  sin6->sin6_addr.s6_addr32[0] = nbp->ipaddr.s6_addr32[0];
  sin6->sin6_addr.s6_addr32[1] = nbp->ipaddr.s6_addr32[1];
  sin6->sin6_addr.s6_addr32[2] = nbp->ipaddr.s6_addr32[2];
  sin6->sin6_addr.s6_addr32[3] = nbp->ipaddr.s6_addr32[3];
  sin6->sin6_scope_id = if_nametoindex (nbp->interface->ifname);

  /* This is NOT response to LS request. schedule retransmitting. */
  /* count number of LSA */
  lsanum = listcount (nbp->retranslist);
  if (!lsanum)
    return -1;   /* Nothing to retransmit. */

  lsupdate = (struct linkstate_update *)
    iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
  assert (lsupdate);
  lsupdate->lsupdate_num = htonl (lsanum);

  i = 1;
  for (n = listhead (nbp->retranslist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      if (iov_totallen (iov) >= DEFAULT_INTERFACE_MTU - OSPFV3HDRLEN)
	break;
      attach_lsa_to_iov (lsi, iov);
#ifdef DEBUG_OSPF
      log ("[%s] to Retransmit (%d/%d)\n", print_lsahdr (lsi->lsh),
	   i, lsanum);
#endif
      i++;
    }

  return 0;
}

