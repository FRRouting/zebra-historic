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

#include "ospf6d.h"

int
proc_hello (struct sockaddr_in6 *src, struct iovec *iov,
            struct ospf6_if *ospf6_if)
{
  struct hello *hello;
  struct ospf6_hdr *ospf6_hdr;
  struct neighbor *nbr = NULL;
  rtr_id_t *rtr_idp = NULL;
  int seenrtrnum = 0;
  int twoway = 0;
  int rtr_pri_change = 0;
  int drchange = 0, bdrchange = 0;
  int schedule_backupseen = 0, schedule_nbchange = 0;
  int i;

  ospf6_hdr = (struct ospf6_hdr *)(iov[0].iov_base);
  hello = (struct hello *)(iov[1].iov_base);

  /* check how many router-id has been attached */
  seenrtrnum = (ntohs (ospf6_hdr->len) - sizeof (struct ospf6_hdr)
               - sizeof (struct hello)) / sizeof (rtr_id_t);

#ifdef DEBUG_HELLO
  {
#define MAXSEENNBR 16
    char dr[16], bdr[16], nb[MAXSEENNBR][16];
    inet_ntop (AF_INET, &hello->dr, dr, sizeof (dr));
    inet_ntop (AF_INET, &hello->bdr, bdr, sizeof (bdr));
    zvlog_debug ("HELLO: Interface ID[%#x]", ntohl (hello->interface_id));
    zvlog_debug ("HELLO: Rtr Pri[%#x], Options[Not yet]", hello->rtr_pri);
    zvlog_debug ("HELLO: Hello Int[%d], RtrDeadInt[%d]",
                 ntohs (hello->hello_interval),
                 ntohs (hello->router_dead_interval));
    zvlog_debug ("HELLO: DR [%s], BDR[%s]\n", dr, bdr);
    rtr_idp = (rtr_id_t *)(hello + 1);
    for (i = 0; i < seenrtrnum && i < MAXSEENNBR; i++)
      {
        inet_ntop (AF_INET, rtr_idp, nb[i], sizeof (nb[i]));
        zvlog_debug ("HELLO: Seen [%s]", nb[i]);
        rtr_idp++;
      }
  }
#endif

  /* Option check */
  if (V3OPT_ISSET (hello->options, V3OPT_E) ^
      V3OPT_ISSET (ospf6_if->area->options, V3OPT_E))
    {
      o6log.packet ("process Hello: E bit mismatch.");
      return 0;
    }

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != ospf6_if->hello_interval)
    {
      o6log.packet ("process Hello: HelloInterval mismatch.");
      return 0;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval) != ospf6_if->rtr_dead_interval)
    {
      o6log.packet ("process Hello: RouterDeadInterval mismatch.");
      return 0;
    }

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    {
      nbr = make_neighbor (ospf6_hdr->router_id, ospf6_if);
      nbr->ifid = ntohl (hello->interface_id);
      nbr->prevdr = nbr->dr = hello->dr;
      nbr->prevbdr = nbr->bdr = hello->bdr;
      nbr->rtr_pri = hello->rtr_pri;
      memcpy (&nbr->hisaddr, src, sizeof (struct sockaddr_in6));
    }

  if (!IN6_ARE_ADDR_EQUAL (&src->sin6_addr, &nbr->hisaddr.sin6_addr))
    {
      char ntopbuf[32];
      o6log.packet ("*** Neighbor %s have changed his address!",
                    inet_ntop (src->sin6_family, &src->sin6_addr,
                    ntopbuf, sizeof (ntopbuf)));
      memcpy (&nbr->hisaddr, src, sizeof (struct sockaddr_in6));
    }

  /* Neighbor data field set equal to this packet */
  if (nbr->rtr_pri != hello->rtr_pri)
    {
      nbr->rtr_pri = hello->rtr_pri;
      rtr_pri_change++;
    }

  if (nbr->dr != hello->dr)
    {
      nbr->prevdr = nbr->dr;
      nbr->dr = hello->dr;
      drchange++;
    }

  if (nbr->bdr != hello->bdr)
    {
      nbr->prevbdr = nbr->bdr;
      nbr->bdr = hello->bdr;
      bdrchange++;
    }

  /* Look up my RouterID */
  rtr_idp = (rtr_id_t *)(hello + 1);
  for (i = 0; i < seenrtrnum; i++)
    {
      if (*rtr_idp == ospf6_if->area->ospf6->router_id)
        twoway++;
      rtr_idp++;
    }

  /* Execute or Schedule Events */
  /* Neighbor State Machine */
  thread_execute (master, hello_received, nbr, 0);
  if (twoway)
    thread_execute (master, twoway_received, nbr, 0);
  else
    {
      thread_execute (master, oneway_received, nbr, 0);
      return 0;
    }

  /* Interface State Machine */
  if (rtr_pri_change)
    schedule_nbchange++;

  if (hello->dr == nbr->rtr_id && hello->bdr == 0
      && ospf6_if->state == IFS_WAITING)
    schedule_backupseen++;
  else if ((drchange && nbr->prevdr == nbr->rtr_id) ||
           (drchange && nbr->dr == nbr->rtr_id))
    schedule_nbchange++;

  if (hello->bdr == nbr->rtr_id && ospf6_if->state == IFS_WAITING)
    schedule_backupseen++;
  else if ((bdrchange && nbr->prevbdr == nbr->rtr_id) ||
           (bdrchange && nbr->bdr == nbr->rtr_id))
    schedule_nbchange++;

  if (schedule_backupseen)
    thread_add_event (master, backup_seen, ospf6_if, 0);

  if (schedule_nbchange)
    thread_add_event (master, neighbor_change, ospf6_if, 0);

  return 0;
}


int
proc_database_description (struct sockaddr_in6 *src, struct iovec *iov,
                           struct ospf6_if *ospf6_if)
{
  struct ospf6_hdr *ospf6_hdr;
  struct neighbor *nbr;
  struct database_description *ddp;
  struct iovec *lsalist;

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;
  ddp = (struct database_description *)iov[1].iov_base;
  lsalist = &iov[2];

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0; /* reject */

#ifdef DEBUG_DATABASE_DESCRIPTION
  {
    char *bitsp, bits[4];
    memset (bits, 0, sizeof (bits));
    bitsp = bits;
    if (DD_IS_IBIT_SET (ddp->bits))
      *bitsp++ = 'I';
    if (DD_IS_MBIT_SET (ddp->bits))
      *bitsp++ = 'M';
    if (DD_IS_MSBIT_SET(ddp->bits))
      *bitsp++ = 'm';
    else
      *bitsp++ = 's';
    zvlog_debug ("DD: Options[Not Yet]");
    zvlog_debug ("DD: InterfaceMTU[%lu] Bits[%s]",
                 ntohs (ddp->interface_mtu), bits);
    zvlog_debug ("DD: SequenceNumber[%lu]",
                 ntohl (ddp->sequence_number));
  }
#endif

  /* XXX reject by invalid Interface MTU */

  switch (nbr->state)
    {
    case NBS_DOWN:
    case NBS_ATTEMPT:
    case NBS_TWOWAY:
      return 0;     /* reject */

    case NBS_INIT:
      thread_execute (master, twoway_received, nbr, 0);
      if (nbr->state != NBS_EXSTART)
        return 0;
   /* else fall through to ExStart */

    case NBS_EXSTART:
      if (DD_IS_MSBIT_SET (ddp->bits) && DD_IS_MBIT_SET (ddp->bits) &&
          DD_IS_IBIT_SET (ddp->bits) && !lsalist->iov_base &&
          nbr->rtr_id > ospf6_if->area->ospf6->router_id)
        {
          /* I am Slave */
          DD_MSBIT_CLEAR (nbr->dd_bits);
          DD_IBIT_CLEAR (nbr->dd_bits);
          nbr->dd_seqnum = ntohl (ddp->sequence_number);
        }
      else if (!DD_IS_MSBIT_SET (ddp->bits) && !DD_IS_IBIT_SET (ddp->bits) &&
           ntohl (ddp->sequence_number) == nbr->dd_seqnum &&
           nbr->rtr_id < ospf6_if->area->ospf6->router_id)
        {
           /* I am Master, do nothing  */
        }
      else
        {
          zvlog_info ("Negotiation with %s Failed", nbr->str);
          return 0;
        }

      prepare_neighbor_lsdb (nbr);
      thread_add_event (master, negotiation_done, nbr, 0);
      break;

    case NBS_EXCHANGE:
      /* Check if duplicate */
      if (!memcmp (ddp, &nbr->last_dd, sizeof (struct database_description)))
        {
          zvlog_info ("Duplicate DatabaseDescription from %s", nbr->str);
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))    /* Slave */
            thread_add_event (master, send_database_description, nbr, 0);
          return 0;
        }

      if (!(DD_IS_MSBIT_SET (nbr->dd_bits) ^ DD_IS_MSBIT_SET (ddp->bits)))
        {
          zvlog_info ("MSBIT mismatch from %s", nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if (DD_IS_IBIT_SET (ddp->bits))
        {
          zvlog_info ("Initialize bit set from %s in state Exchange",
                      nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if (memcmp (ddp->options, nbr->last_dd.options, sizeof (ddp->options)))
        {
          o6log.packet ("Option field have changed in DD from %s",
                        nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if ((DD_IS_MSBIT_SET (nbr->dd_bits) &&
           ntohl (ddp->sequence_number) != nbr->dd_seqnum) ||
          (!DD_IS_MSBIT_SET (nbr->dd_bits) && 
           ntohl (ddp->sequence_number) != nbr->dd_seqnum + 1))
        {
          o6log.packet ("Sequence Number Mismatch from %s", nbr->str);
          o6log.packet ("recv[%lu] have[%lu]",
                        ntohl (ddp->sequence_number),
                        nbr->dd_seqnum);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }
      break;

    case NBS_LOADING:
    case NBS_FULL:
      /* Check if duplicate */
      if (!memcmp (ddp, &nbr->last_dd, sizeof (struct database_description)))
        {
          o6log.packet ("Duplicate Packet from %s in Full,Loading",
                        nbr->str);
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))
            thread_add_event (master, send_database_description, nbr, 0);
        }
      else
        {
          o6log.packet ("Not Duplicate Packet from %s in State %s",
                        nbr->str, nbs_name[nbr->state]);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
        }
      return 0;

    default:
      assert (0);
    }

  if (lsalist[0].iov_base && check_neighbor_lsdb (lsalist, nbr) < 0)
    {
      /* one possible situation to come here is to find as-external
      lsa found when this area is stub */
      o6log.packet ("AS-External found where stub area from %s in State %s",
                    nbr->str, nbs_name[nbr->state]);
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      return 0;
    }

  /* only valid packet in Exchange and ExStart state will come here */

  /* Master decides whether to make event ExchangeDone on reception
     while Slave decides this on sending */
  if (DD_IS_MSBIT_SET (nbr->dd_bits))
    {
      /* This is Master. */
      nbr->dd_seqnum++;
      if (!DD_IS_MBIT_SET (ddp->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
        {
          thread_add_event (master, exchange_done, nbr, 0);
          if (nbr->send_dd)
            {
              thread_cancel (nbr->send_dd);
              nbr->send_dd = (struct thread *)NULL;
            }
          return 0; /* Prevent from sending another illegal DD */
        }
      proceed_summarylist (nbr);   /* DD bits may be changed */
    }
  else
    {
      /* This is Slave. */
      nbr->dd_seqnum = ntohl (ddp->sequence_number);
      proceed_summarylist (nbr);   /* DD bits may be changed */
      if (!DD_IS_MBIT_SET (ddp->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
        thread_add_event (master, exchange_done, nbr, 0);
    }

  /* Save Last Received DD */
  memcpy (&nbr->last_dd, ddp, sizeof (struct database_description));

  /* Schedule new thread for sending DD */
  if (nbr->send_dd)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = (struct thread *)NULL;
    }
  thread_add_event (master, send_database_description, nbr, 0);

  return 0;
}

int
proc_linkstate_request (struct sockaddr_in6 *src, struct iovec *iov,
                        struct ospf6_if *ospf6_if)
{
  struct ospf6_hdr *ospf6_hdr;
  struct neighbor *nbr;
  int i, lsanum = 0;
  struct linkstate_request *lsreq = NULL;
  struct ospf6_lsa *lsa;
  struct iovec response[MAXIOVLIST];
  struct linkstate_update *lsupdate;
  void *scope;

  iov_clear (response, MAXIOVLIST);
  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      o6log.packet ("LSREQ: Ignored from %s", nbr->str);
      return 0;
    }

  if (iov_count (iov) == 1)
    o6log.packet ("LSREQ: Null Request from %s", nbr->str);

  for (i = 1; iov[i].iov_base; i++)
    {
      lsreq = (struct linkstate_request *)iov[i].iov_base;

#ifdef DEBUG_LINKSTATE_REQUEST
      o6log.packet ("LSREQ from %s: %s", nbr->str,
                   print_lsahdr ((struct ospf6_lsa_hdr *)lsreq));
#endif

      /* get scope from request type */
      switch (ospf6_lsa_get_scope_type (lsreq->lsreq_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_if;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_if->area;
            break;
          case SCOPE_AS:
          case SCOPE_RESERVED:
          default:
            o6log.packet ("unsupported type request, ignore");
            return 0;
        }

      /* find instance of database copy */
      lsa = ospf6_lsdb_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                               lsreq->lsreq_advrtr, scope);
      if (!lsa)
        {
          o6log.packet ("requested %s from %s not found, BadLSReq",
                        print_lsreq (lsreq),
                        nbr->str);
          thread_add_event (master, bad_lsreq, nbr, 0);
          return 0;
        }

      o6log.packet ("LSUpdate(response): %s", print_lsahdr (lsa->lsa_hdr));
      attach_lsa_to_iov (lsa, response);
      lsanum++;
    }

  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      lsupdate = (struct linkstate_update *)
                 iov_prepend (MTYPE_OSPF6_MESSAGE, response,
                              sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf6_send (MSGT_LINKSTATE_UPDATE, response,
                 (struct sockaddr *)&nbr->hisaddr, nbr->ospf6_if);
      iov_free (MTYPE_OSPF6_MESSAGE, response, 0, 1);
    }

  return 0;
}

int
proc_linkstate_update (struct sockaddr_in6 *src, struct iovec *iov,
                       struct ospf6_if *ospf6_if)
{
  struct ospf6_hdr *ospf6_hdr;
  struct neighbor *nbr;
  int    lsanum;
  struct linkstate_update *lsupdate;
  struct ospf6_lsa_hdr *lsh;

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      o6log.packet ("LSUpdate: ignored from %s", nbr->str);
      return 0;
    }

  lsupdate = (struct linkstate_update *)iov[1].iov_base;
  lsanum = ntohl (lsupdate->lsupdate_num);
  o6log.packet ("LSUpdate: # LSAs[%d] from %s", lsanum, nbr->str);

  for (lsh = (struct ospf6_lsa_hdr *)iov[2].iov_base; lsanum; lsanum--)
    {
      o6log.packet ("LSUpdate: %s", print_lsahdr (lsh));

      lsa_receive (lsh, nbr);
      lsh = LSA_NEXT (lsh);
    }

  iov_free_all (MTYPE_OSPF6_LSA, iov);

  return 0;
}

int
proc_linkstate_ack (struct sockaddr_in6 *src, struct iovec *iov,
                    struct ospf6_if *ospf6_if)
{
  struct ospf6_lsa_hdr *lsh;
  struct ospf6_lsa *p, *lsa;
  struct neighbor *nbr;
  struct ospf6_hdr *ospf6_hdr = NULL;
  int i;
  void *scope;

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      o6log.packet ("LSAck: ignored from %s", nbr->str);
      return 0;
    }

  for (i = 1; iov[i].iov_base; i++)
    {
      lsh = (struct ospf6_lsa_hdr *)iov[i].iov_base;
      lsa = make_ospf6_lsa (lsh);
      lsa->from = nbr;
      switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_if;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_if->area;
            break;
          case SCOPE_AS:
          case SCOPE_RESERVED:
          default:
            o6log.packet ("unsupported scope acknowledge, ignore");
            ospf6_lsa_unlock (lsa);
            continue;
        }

      o6log.packet ("acknowledge %s from %s", print_lsahdr (lsh), nbr->str);

      p = ospf6_lsdb_lookup (lsh->lsh_type, lsh->lsh_id,
                             lsh->lsh_advrtr, scope);
      if (!p)
        {
          o6log.packet ("there's no database copy");
          ospf6_lsa_unlock (lsa);
          continue;
        }

      if (!ospf6_lookup_retrans (p, nbr))
        {
          o6log.packet ("acknowledgement not in retranslist %s",
                        print_lsahdr (p->lsa_hdr));
          ospf6_lsa_unlock (lsa);
          continue;
        }

      if (which_is_more_recent (lsa, p) == 0)
        {
          ospf6_remove_retrans (p, nbr);
        }
      else
        {
          /* Log the questionable acknowledgment,
             and examine the next one. */
          o6log.packet ("questionable acknowledgement");
          ospf6_lsa_unlock (lsa);
          continue;
        }

      ospf6_lsa_unlock (lsa);
    }

  return 0;
}

int
proc_ospf6_hdr (struct iovec *iov, struct ospf6_if *ospf6_if)
{
  struct ospf6_hdr *ospf6_hdr;

  assert (ospf6_if);
  ospf6_hdr = (struct ospf6_hdr *)(iov[0].iov_base);

  if (ospf6_hdr->version != ospf6_if->area->ospf6->version)
    {
      o6log.packet ("version mismatch between i/f and packet(%d)",
                    ospf6_hdr->version);
      return 0;
    }

  /* Area ID check */
  if (ospf6_hdr->area_id != ospf6_if->area->area_id)
    {
      if (ospf6_hdr->area_id == 0)
        {
          o6log.packet ("virtual link, not yet");
          return 0;
        }
      else
        {
          char area_id[16];
          inet_ntop (AF_INET, &ospf6_hdr->area_id,
                     area_id, sizeof (area_id));
          o6log.packet ("Can't find Area %s", area_id);
          return 0;
        }
    }

  /* Checksum */
  /* XXX */

  /* Instance ID check */
  if (ospf6_if->area->ospf6->instance_id != ospf6_hdr->instance_id)
    {
      o6log.packet ("instance id[%d] mismatch with %d on %s",
                    ospf6_hdr->instance_id,
                    ospf6_if->area->ospf6->instance_id,
                    ospf6_if->interface->name);
      return -1;
    }

  return 0;
}

int
make_ospf6_hdr (msgtype_t msgtype, struct iovec *iov,
                struct ospf6_if *ospf6_if)
{
  struct ospf6_hdr *ospf6_hdr;

  ospf6_hdr = (struct ospf6_hdr *)
         iov_prepend (MTYPE_OSPF_MESSAGE, iov, sizeof (struct ospf6_hdr));
  if (!ospf6_hdr)
    {
      zlog (NULL, LOG_ERR, "iov_prepend() err in make_ospf6_hdr ()");
      return -1;
    }

  ospf6_hdr->instance_id = ospf6_if->area->ospf6->instance_id;
  ospf6_hdr->version = OSPF_V3;
  ospf6_hdr->type = msgtype;
  ospf6_hdr->router_id = ospf6_if->area->ospf6->router_id;
  ospf6_hdr->area_id = ospf6_if->area->area_id;

  /* Length */
  ospf6_hdr->len = htons (iov_totallen (iov));

  return 0;
}

int
make_hello (struct iovec *iov, struct sockaddr_in6 *dst,
            struct ospf6_if *ospf6_if)
{
  listnode n;
  struct hello *hello;
  struct neighbor *nbr;

  dst->sin6_family = AF_INET6;
  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst->sin6_addr);
#ifdef SIN6_LEN
  dst->sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
  dst->sin6_scope_id = if_nametoindex (ospf6_if->interface->name);
#endif /* HAVE_SIN6_SCOPE_ID */

  hello = (struct hello *) iov_append (MTYPE_OSPF6_MESSAGE,
                                       iov, sizeof (struct hello));
  if (!hello)
    {
      o6log.packet ("iov_append() failed in make_hello ()");
      return -1;
    }

  hello->interface_id = htonl (ospf6_if->ifid);
  hello->rtr_pri = ospf6_if->rtr_pri;
  memcpy (hello->options, ospf6_if->area->options, sizeof (hello->options));
  hello->hello_interval = htons (ospf6_if->hello_interval);
  hello->router_dead_interval = htons (ospf6_if->rtr_dead_interval);
  hello->dr = ospf6_if->dr;
  hello->bdr = ospf6_if->bdr;

  for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state < NBS_INIT)
        continue;
      iov_attach_last (iov, &nbr->rtr_id, sizeof (rtr_id_t));
    }
  return 0;
}

int
make_database_description (struct iovec *iov, struct sockaddr_in6 *dst,
                           struct neighbor *nbr)
{
  struct database_description *dd;
  struct timeval tv;
  listnode n;
  struct ospf6_lsa *p;

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  dd = (struct database_description *)
       iov_append (MTYPE_OSPF6_MESSAGE, iov,
                   sizeof (struct database_description));
  if (!dd)
    {
      zvlog_err ("iov_append() failed in make_database_description ()");
      return -1;
    }

  memcpy (dd->options, nbr->ospf6_if->area->options, sizeof (dd->options));
  dd->interface_mtu = htons (DEFAULT_INTERFACE_MTU);
  dd->bits = nbr->dd_bits;

  if (DD_IS_IBIT_SET (dd->bits))
    {
      if (gettimeofday (&tv, (struct timezone *)NULL) < 0)
        {
          o6log.packet ("gettimeofday() failed in"
                        " make_database_description (): %s",
                        strerror (errno));
          tv.tv_sec = 1;
        }
      nbr->dd_seqnum = tv.tv_sec;
      o6log.packet ("neighbor[%s] sequence number newly set [%lu]",
                    nbr->str, nbr->dd_seqnum);
    }

  dd->sequence_number = htonl (nbr->dd_seqnum);

  if (!DD_IS_IBIT_SET (nbr->dd_bits))
    {
      for (n = listhead (nbr->dd_retrans); n; nextnode (n))
        {
          p = (struct ospf6_lsa *) getdata (n);
          attach_lsa_hdr_to_iov (p, iov);
          o6log.packet ("DD: %s", print_lsahdr (p->lsa_hdr));
        }
    }

  return 0;
}

int
make_linkstate_request (struct iovec *iov, struct sockaddr_in6 *dst,
                        struct neighbor *nbr)
{
  struct linkstate_request *lsreq;
  listnode n;
  struct ospf6_lsa *lsa;

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  /* XXX, invalid access to request list */
  if (list_isempty (nbr->requestlist))
    {
      o6log.packet ("LSReq: empty requestlist of neighbor[%s]",
                    nbr->str);
      return -1;
    }

  /* xxx, invalid access to requestlist */
  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      assert (lsa->lsa_hdr);
      lsreq = (struct linkstate_request *) iov_append
              (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct linkstate_request));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsa->lsa_hdr->lsh_type;
      lsreq->lsreq_id = lsa->lsa_hdr->lsh_id;
      lsreq->lsreq_advrtr = lsa->lsa_hdr->lsh_advrtr;
      o6log.packet ("LSReq: %s", print_lsreq (lsreq));
      if (iov_totallen (iov) >= DEFAULT_INTERFACE_MTU
                                - sizeof (struct ospf6_hdr))
        break;
    }
  return 0;
}

int
make_linkstate_update (struct iovec *iov, struct sockaddr_in6 *dst,
                       struct neighbor *nbr)
{
  struct linkstate_update *lsupdate;
  int i, lsanum;
  listnode n;
  struct ospf6_lsa *lsa;

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  /* count number of LSA */
  lsanum = listcount (nbr->retranslist);
  if (!lsanum)
    return -1;   /* Nothing to retransmit. */

  lsupdate = (struct linkstate_update *) iov_append
             (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
  if (!lsupdate)
    {
      o6log.packet ("iov_append () failed in make_linkstate_update");
      return -1;
    }
  lsupdate->lsupdate_num = htonl (lsanum);

  /* XXX, invalid access to retranslist */
  i = 1;
  for (n = listhead (nbr->retranslist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (iov_totallen (iov) >= DEFAULT_INTERFACE_MTU
                                - sizeof (struct ospf6_hdr))
        break;
      attach_lsa_to_iov (lsa, iov);
      o6log.packet ("LSUpdate: %s (%d/%d)",
                    print_lsahdr (lsa->lsa_hdr), i, lsanum);
      i++;
    }

  return 0;
}


/* new */


static void
ospf6_message_put_lsa_hdr (struct iovec *iov, struct ospf6_lsa_hdr *lsa_hdr)
{
  iov_attach_first (iov, lsa_hdr, sizeof (struct ospf6_lsa_hdr));
  return;
}

struct ospf6_lsa_hdr *
ospf6_message_get_lsa_hdr (struct iovec *iov)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  lsa_hdr = (struct ospf6_lsa_hdr *) iov_detach_first (iov);
  return lsa_hdr;
}

static void
ospf6_message_put_lsa (struct iovec *iov, struct ospf6_lsa_hdr *lsa_hdr)
{
  iov_attach_first (iov, lsa_hdr, ntohs (lsa_hdr->lsh_len));
  return;
}

/* make piece of LSA from current processing pointer */
static struct ospf6_lsa_hdr *
ospf6_message_get_lsa (struct iovec *iov, struct ospf6_lsa_hdr *current)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  lsa_hdr = make_ospf6_lsa_data (current, ntohs (current->lsh_len));
  return lsa_hdr;
}


/* used only when failed to allocate buffer for receive */
static void
ospf6_message_lsa_hdr_clear_buffer (struct iovec *iov)
{
  iov_free_all (MTYPE_OSPF6_LSA, iov);
  return;
}

/* allocate space for ospf6_lsa_hdr */
static int
ospf6_message_lsa_hdr_set_buffer (struct iovec *iov, size_t len)
{
  int i, lsa_hdr_num;

  /* assert len is multiple of ospf6_lsa_hdr size */
  assert (len % sizeof (struct ospf6_lsa_hdr) == 0);

  /* count LSA header number and make space for each of them */
  lsa_hdr_num = len / sizeof (struct ospf6_lsa_hdr);
  for (i = 0; i < lsa_hdr_num; i++)
    {
      if (!iov_prepend (MTYPE_OSPF6_LSA, iov,
                        sizeof (struct ospf6_lsa_hdr)))
        {
          ospf6_message_lsa_hdr_clear_buffer (iov);
          return -1;
        }
    }
  return 0;
}

/* free temporary space after LSAs are cut in pieces */
static void
ospf6_message_lsa_clear_buffer (struct iovec *iov)
{
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
  return;
}

/* allocate space for catch LSAs. this space is used temporary
   until LSAs are cut in pieces */
static int
ospf6_message_lsa_set_buffer (struct iovec *iov, size_t len)
{
  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, len))
    return -1;
  return 0;
}

/* used only when failed to receive packet */
static void
ospf6_message_clear_buffer (unsigned char msgtype, struct iovec *iov)
{
  switch (msgtype)
    {
      case MSGT_HELLO:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case MSGT_DATABASE_DESCRIPTION:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      case MSGT_LINKSTATE_REQUEST:
        iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case MSGT_LINKSTATE_UPDATE:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_clear_buffer (iov);
        break;

      case MSGT_LINKSTATE_ACK:
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      default:
        return;
    }
  assert (iov_count (iov) == 0);
  return;
}

/* if failed, return -1. in this case, free all buffer */
static int
ospf6_message_set_buffer (unsigned char msgtype, unsigned short msglen,
                          struct iovec *iov)
{
  unsigned short left;

  /* substract ospf6_hdr size from left space to allocate */
  left = msglen - sizeof (struct ospf6_hdr);

  switch (msgtype)
    {
      case MSGT_HELLO:
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, left))
          return -1;
        break;

      case MSGT_DATABASE_DESCRIPTION:
        left -= sizeof (struct database_description);
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct database_description)))
          {
            ospf6_message_lsa_hdr_clear_buffer (iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_REQUEST:
        assert (left % sizeof (struct linkstate_request) == 0);
        while (left)
          {
            if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                              sizeof (struct linkstate_request)))
              {
                iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
                return -1;
              }
            left -= sizeof (struct linkstate_request);
          }
        break;

      case MSGT_LINKSTATE_UPDATE:
        left -= sizeof (struct linkstate_update);
        if (ospf6_message_lsa_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct linkstate_update)))
          {
            ospf6_message_lsa_clear_buffer (iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_ACK:
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        break;

      default:
        return -1;
    }

  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_hdr)))
    {
      ospf6_message_clear_buffer (msgtype, iov);
      return -1;
    }

  return 0;
}

int
ospf6_opt_is_mismatch (unsigned char opt, char *options1, char *options2)
{
  return (V3OPT_ISSET (options1, opt) ^ V3OPT_ISSET (options2, opt));
}


static void
ospf6_process_hello (struct iovec *iov, struct ospf6_if *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct hello *hello;
  char *my_options;
  char changes = 0;
#define CHANGE_RTRPRI (1 << 0)
#define CHANGE_DR     (1 << 1)
#define CHANGE_BDR    (1 << 2)
  int twoway = 0, backupseen = 0, nbchange = 0;
  unsigned long *router_id_ptr, my_router_id;
  int i, seenrtrnum = 0, router_id_space = 0;
  struct neighbor *nbr = NULL;
  char dr_str[16], bdr_str[16];

  /* assert interface */
  assert (o6if);

  /* set hello pointer */
  hello = (struct hello *) iov[0].iov_base;

  /* dump hello */
  inet_ntop (AF_INET, &hello->dr, dr_str, sizeof (dr_str));
  inet_ntop (AF_INET, &hello->bdr, bdr_str, sizeof (bdr_str));
  o6log.packet ("receive Hello: ifid:%lu rtrpri:%d opt:xxx helloint: %hu"
                " rtrdeadint: %hu dr:%s bdr:%s",
                ntohl (hello->interface_id), hello->rtr_pri,
                ntohs (hello->hello_interval),
                ntohs (hello->router_dead_interval), dr_str, bdr_str);

  /* HelloInterval check */
  if (ntohs (hello->hello_interval)
      != o6if->hello_interval)
    {
      o6log.packet ("HelloInterval mismatch with %s", nbr->str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval)
      != o6if->rtr_dead_interval)
    {
      o6log.packet ("RouterDeadInterval mismatch with %s", nbr->str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* check options */
  /* Ebit */
  my_options = o6if->area->options;
  if (ospf6_opt_is_mismatch (V3OPT_E, hello->options, my_options))
    {
      o6log.packet ("Ebit mismatch with %s", nbr->str);
      ospf6_message_clear_buffer (MSGT_HELLO, iov);
      return;
    }

  /* find neighbor. if cannot be found, create */
  nbr = nbr_lookup (router_id, o6if->area->ospf6);
  if (!nbr)
    {
      nbr = make_neighbor (router_id, o6if);
      nbr->ifid = ntohl (hello->interface_id);
      nbr->prevdr = nbr->dr = hello->dr;
      nbr->prevbdr = nbr->bdr = hello->bdr;
      nbr->rtr_pri = hello->rtr_pri;
      memcpy (&nbr->hisaddr, src, sizeof (struct sockaddr_in6));
    }

  /* RouterPriority set */
  if (nbr->rtr_pri != hello->rtr_pri)
    {
      nbr->rtr_pri = hello->rtr_pri;
      o6log.packet ("RouterPriority changed");
      changes |= CHANGE_RTRPRI;
    }

  /* DR set */
  if (nbr->dr != hello->dr)
    {
      /* save previous dr, set current */
      nbr->prevdr = nbr->dr;
      nbr->dr = hello->dr;
      o6log.packet ("%s declare %s as DR", nbr->str, inet4str (nbr->dr));
      changes |= CHANGE_DR;
    }

  /* BDR set */
  if (nbr->bdr != hello->bdr)
    {
      /* save previous bdr, set current */
      nbr->prevbdr = nbr->bdr;
      nbr->bdr = hello->bdr;
      o6log.packet ("%s declare %s as BDR", nbr->str, inet4str (nbr->bdr));
      changes |= CHANGE_BDR;
    }

  /* TwoWay check */
  router_id_space = iov[0].iov_len - sizeof (struct hello);
  assert (router_id_space % sizeof (unsigned long) == 0);
  seenrtrnum = router_id_space / sizeof (unsigned long);
  my_router_id = nbr->ospf6_if->area->ospf6->router_id;
  router_id_ptr = (unsigned long *) (hello + 1);
  for (i = 0; i < seenrtrnum; i++)
    {
      if (*router_id_ptr == my_router_id)
        twoway++;
      router_id_ptr++;
    }

  /* execute neighbor events */
  thread_execute (master, hello_received, nbr, 0);
  if (twoway)
    thread_execute (master, twoway_received, nbr, 0);
  else
    thread_execute (master, oneway_received, nbr, 0);

  /* BackupSeen check */
  if (nbr->ospf6_if->state == IFS_WAITING)
    {
      if (hello->dr == hello->bdr == nbr->rtr_id)
        assert (0);
      else if (hello->bdr == nbr->rtr_id)
        backupseen++;
      else if (hello->dr == nbr->rtr_id && hello->bdr == 0)
        backupseen++;
    }

  /* NeighborChange check */
  if (changes & CHANGE_RTRPRI)
    nbchange++;
  if (changes & CHANGE_DR)
    if (nbr->prevdr == nbr->rtr_id || nbr->dr == nbr->rtr_id)
      nbchange++;
  if (changes & CHANGE_BDR)
    if (nbr->prevbdr == nbr->rtr_id || nbr->bdr == nbr->rtr_id)
      nbchange++;

  /* schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, nbr->ospf6_if, 0);
  if (nbchange)
    thread_add_event (master, neighbor_change, nbr->ospf6_if, 0);

  /* free hello space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

/* assume size of buf is bigger than 4 */
static void
ospf6_dbdesc_bit_str (unsigned char dbdesc_bit, char *buf)
{
  char *p = buf;

  /* Initialize bit */
  if (DD_IS_IBIT_SET (dbdesc_bit))
    *p++ = 'I';
  /* More bit */
  if (DD_IS_MBIT_SET (dbdesc_bit))
    *p++ = 'M';
  /* Master/Slave bit */
  if (DD_IS_MSBIT_SET (dbdesc_bit))
    *p++ = 'm';
  else
    *p++ = 's';
  *p = '\0';
  return;
}

static int
ospf6_dbdesc_is_master (struct neighbor *nbr, struct ospf6_if *o6if)
{
  if (nbr->rtr_id == o6if->area->ospf6->router_id)
    {
      o6log.packet ("***neighbor router id is the same of mine");
      return -1;
    }
  else if (nbr->rtr_id > o6if->area->ospf6->router_id)
    return 0;
  return 1;
}

static void
ospf6_process_dbdesc_master (struct iovec *iov, struct neighbor *nbr)
{
  struct database_description *dbdesc;

  /* set database description pointer */
  dbdesc = (struct database_description *) iov[0].iov_base;

  switch (nbr->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
        return;

      case NBS_INIT:
        thread_execute (master, twoway_received, nbr, 0);
        if (nbr->state != NBS_EXSTART)
          {
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (!DD_IS_MSBIT_SET (dbdesc->bits) &&
            !DD_IS_IBIT_SET (dbdesc->bits) &&
            ntohl (dbdesc->sequence_number) == nbr->dd_seqnum)
          {
            prepare_neighbor_lsdb (nbr);
            if (nbr->send_dd)
              {
                thread_cancel (nbr->send_dd);
                nbr->send_dd = (struct thread *)NULL;
              }
            thread_add_event (master, negotiation_done, nbr, 0);
          }
        else
          {
            o6log.packet ("negotiation failed");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct database_description)))
          {
            o6log.packet ("duplicate dbdesc, drop");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DD_IS_IBIT_SET (dbdesc->bits))
          {
            o6log.packet ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        if (DD_IS_MSBIT_SET (dbdesc->bits))
          {
            o6log.packet ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, nbr->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            o6log.packet ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->sequence_number) != nbr->dd_seqnum)
          {
            o6log.packet ("dbdesc seqnumber mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct database_description)))
          {
            o6log.packet ("duplicate dbdesc, drop");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        else
          {
            o6log.packet ("not duplicate dbdesc in state %s",
                          nbs_name[nbr->state]);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  if (check_neighbor_lsdb (iov, nbr) < 0)
    {
      /* one possible situation to come here is to find as-external
      lsa found when this area is stub */
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      iov_free_all (MTYPE_OSPF6_LSA, iov);
      return;
    }

  /* increment dbdesc seqnum */
  nbr->dd_seqnum++;

  /* more bit check */
  if (!DD_IS_MBIT_SET (dbdesc->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
    {
      thread_add_event (master, exchange_done, nbr, 0);
      if (nbr->send_dd)
        {
          thread_cancel (nbr->send_dd);
          nbr->send_dd = (struct thread *)NULL;
        }
    }
  else
    {
      /* proceed summary LSA to transmit, set more bit */
      proceed_summarylist (nbr);

      /* cancel retransmit and schedule new dbdesc to send */
      if (nbr->send_dd)
        thread_cancel (nbr->send_dd);
      thread_add_event (master, send_database_description, nbr, 0);
    }

  /* save last received dbdesc , and free */
  memcpy (&nbr->last_dd, dbdesc, sizeof (struct database_description));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  return;
}

static void
ospf6_process_dbdesc_slave (struct iovec *iov, struct neighbor *nbr)
{
  struct database_description *dbdesc;

  /* set database description pointer */
  dbdesc = (struct database_description *) iov[0].iov_base;

  switch (nbr->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
        return;
      case NBS_INIT:
        thread_execute (master, twoway_received, nbr, 0);
        if (nbr->state != NBS_EXSTART)
          {
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DD_IS_IBIT_SET (dbdesc->bits) &&
            DD_IS_MBIT_SET (dbdesc->bits) &&
            DD_IS_MSBIT_SET (dbdesc->bits) &&
            iov_count (iov) == 1)
          {
            /* Master/Slave bit set to slave */
            DD_MSBIT_CLEAR (nbr->dd_bits);
            /* Initialize bit clear */
            DD_IBIT_CLEAR (nbr->dd_bits);
            /* sequence number set to master's */
            nbr->dd_seqnum = ntohl (dbdesc->sequence_number);
            prepare_neighbor_lsdb (nbr);
            if (nbr->send_dd)
              {
                thread_cancel (nbr->send_dd);
                nbr->send_dd = (struct thread *)NULL;
              }
            thread_add_event (master, negotiation_done, nbr, 0);
          }
        else
          {
            o6log.packet ("negotiation failed");
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct database_description)))
          {
            o6log.packet ("duplicate dbdesc, retransmit dbdesc");
            if (nbr->send_dd)
              {
                thread_cancel (nbr->send_dd);
                nbr->send_dd = (struct thread *)NULL;
              }
            thread_add_event (master, send_database_description, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DD_IS_IBIT_SET (dbdesc->bits))
          {
            o6log.packet ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        if (!DD_IS_MSBIT_SET (dbdesc->bits))
          {
            o6log.packet ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, nbr->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            o6log.packet ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->sequence_number) != nbr->dd_seqnum + 1)
          {
            o6log.packet ("dbdesc seqnumber mismatch");
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc cause slave to retransmit */
        if (!memcmp (dbdesc, &nbr->last_dd,
                     sizeof (struct database_description)))
          {
            o6log.packet ("duplicate dbdesc, retransmit");
            if (nbr->send_dd)
              {
                thread_cancel (nbr->send_dd);
                nbr->send_dd = (struct thread *)NULL;
              }
            thread_add_event (master, send_database_description, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        else
          {
            o6log.packet ("not duplicate dbdesc in state %s",
                          nbs_name[nbr->state]);
            thread_add_event (master, seqnumber_mismatch, nbr, 0);
            ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  if (check_neighbor_lsdb (iov, nbr) < 0)
    {
      /* one possible situation to come here is to find as-external
      lsa found when this area is stub */
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      iov_free_all (MTYPE_OSPF6_LSA, iov);
      return;
    }

  /* set dbdesc seqnum to master's */
  nbr->dd_seqnum = ntohl (dbdesc->sequence_number);

  /* proceed summary LSA to transmit, set more bit */
  proceed_summarylist (nbr);

  /* more bit check */
  if (!DD_IS_MBIT_SET (dbdesc->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
    {
      thread_add_event (master, exchange_done, nbr, 0);
    }
  thread_add_event (master, send_database_description, nbr, 0);

  /* save last received dbdesc , and free */
  memcpy (&nbr->last_dd, dbdesc, sizeof (struct database_description));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
  return;
}

static void
ospf6_process_dbdesc (struct iovec *iov, struct ospf6_if *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct database_description *dbdesc;
  char dbdesc_bit_str[4];
  int Im_master = 0;

  /* assert interface */
  assert (o6if);

  /* set database description pointer */
  dbdesc = (struct database_description *) iov[0].iov_base;

  /* dump database description */
  ospf6_dbdesc_bit_str (dbdesc->bits, dbdesc_bit_str);
  o6log.packet ("DbDesc: opt:xxx ifmtu:%hu bit:%s seqnum:%lu",
                ntohs (dbdesc->interface_mtu), dbdesc_bit_str,
                ntohl (dbdesc->sequence_number));

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if->area->ospf6);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
      o6log.packet ("neighbor not found, reject");
      return;
    }

  /* interface mtu check */
    /* xxx */

  /* check am I master */
  Im_master = ospf6_dbdesc_is_master (nbr, o6if);
  if (Im_master < 0)
    {
      ospf6_message_clear_buffer (MSGT_DATABASE_DESCRIPTION, iov);
      return; /* can't decide which is master, return */
    }

  if (Im_master)
    ospf6_process_dbdesc_master (iov, nbr);
  else
    ospf6_process_dbdesc_slave (iov, nbr);

  return;
}

static void
ospf6_process_lsreq (struct iovec *iov, struct ospf6_if *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct linkstate_request *lsreq;
  struct iovec response[MAXIOVLIST];
  struct ospf6_lsa *lsa;
  void *scope;
  unsigned long lsanum = 0;
  struct linkstate_update *lsupdate;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if->area->ospf6);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
      o6log.packet ("neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
      o6log.packet ("neighbor state less than Exchange, reject");
      return;
    }

  /* clear buffer for response LSUpdate packet */
  iov_clear (response, MAXIOVLIST);

  /* process each request */
  lsreq = (struct linkstate_request *) iov_detach_first (iov);
  while (lsreq)
    {
      o6log.packet (" requested: %s", print_lsreq (lsreq));

      /* get scope from request type */
      switch (ospf6_lsa_get_scope_type (lsreq->lsreq_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_if;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_if->area;
            break;
          case SCOPE_AS:
          case SCOPE_RESERVED:
          default:
            o6log.packet ("unsupported type requested, ignore");
            XFREE (MTYPE_OSPF6_MESSAGE, lsreq);
            lsreq = (struct linkstate_request *) iov_detach_first (iov);
            continue;
        }

      /* find instance of database copy */
      lsa = ospf6_lsdb_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                               lsreq->lsreq_advrtr, scope);
      if (!lsa)
        {
          o6log.packet ("requested %s not found, BadLSReq",
                        print_lsreq (lsreq));
          thread_add_event (master, bad_lsreq, nbr, 0);
          XFREE (MTYPE_OSPF6_MESSAGE, lsreq);
          ospf6_message_clear_buffer (MSGT_LINKSTATE_REQUEST, iov);
          return;
        }

      o6log.packet ("LSUpdate(response): %s", print_lsahdr (lsa->lsa_hdr));
      attach_lsa_to_iov (lsa, response);
      lsanum++;
      lsreq = (struct linkstate_request *) iov_detach_first (iov);
    }

  /* send response LSUpdate to this request */
  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      lsupdate = (struct linkstate_update *)
                 iov_prepend (MTYPE_OSPF6_MESSAGE, response,
                              sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf6_send (MSGT_LINKSTATE_UPDATE, response,
                 (struct sockaddr *)&nbr->hisaddr, nbr->ospf6_if);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, response);
      iov_clear (iov, MAXIOVLIST);
    }

  return;
}

static void
ospf6_process_lsupdate (struct iovec *iov, struct ospf6_if *o6if,
                        struct sockaddr_in6 *src, unsigned long router_id)
{
  struct linkstate_update *lsupdate;
  struct neighbor *nbr;
  unsigned long lsanum;
  struct ospf6_lsa_hdr *lsa_hdr;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if->area->ospf6);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_UPDATE, iov);
      o6log.packet ("neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_UPDATE, iov);
      o6log.packet ("neighbor state less than Exchange, reject");
      return;
    }

  /* set linkstate update pointer */
  lsupdate = (struct linkstate_update *) iov[0].iov_base;

  /* save linkstate update info */
  lsanum = ntohl (lsupdate->lsupdate_num);

  /* decapsulation */
  lsupdate = (struct linkstate_update *) NULL;
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  /* dump message and process LSAs */
  o6log.packet ("LSUpdate: %lu LSAs", lsanum);
  for (lsa_hdr = (struct ospf6_lsa_hdr *) iov[0].iov_base;
       lsanum; lsanum--)
    {
      lsa_receive (lsa_hdr, nbr);
      lsa_hdr = LSA_NEXT (lsa_hdr);
    }

  /* free LSA space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

static void
ospf6_process_lsack (struct iovec *iov, struct ospf6_if *o6if,
                     struct sockaddr_in6 *src, unsigned long router_id)
{
  struct neighbor *nbr;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct ospf6_lsa *lsa, *copy;
  void *scope;

  /* assert interface */
  assert (o6if);

  /* find neighbor. if cannot be found, reject this message */
  nbr = nbr_lookup (router_id, o6if->area->ospf6);
  if (!nbr)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_ACK, iov);
      o6log.packet ("neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (MSGT_LINKSTATE_ACK, iov);
      o6log.packet ("neighbor state less than Exchange, reject");
      return;
    }

  /* process each LSA header */
  while (iov[0].iov_base)
    {
      /* make each LSA header treated as LSA */
      lsa_hdr = (struct ospf6_lsa_hdr *) iov[0].iov_base;
      lsa = make_ospf6_lsa (lsa_hdr);
      lsa->from = nbr;

      /* detach from message */
      iov_detach_first (iov);

      /* set scope for this LSA */
      switch (ospf6_lsa_get_scope_type (lsa_hdr->lsh_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_if;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_if->area;
            break;
          case SCOPE_AS:
          case SCOPE_RESERVED:
          default:
            o6log.packet ("unsupported scope acknowledge, ignore");
            ospf6_lsa_unlock (lsa);
            continue;
        }

      /* dump acknowledged LSA */
      o6log.packet ("acknowledge %s", print_lsahdr (lsa_hdr));

      /* find database copy */
      copy = ospf6_lsdb_lookup (lsa_hdr->lsh_type, lsa_hdr->lsh_id,
                                lsa_hdr->lsh_advrtr, scope);

      /* if no database copy */
      if (!copy)
        {
          o6log.packet ("no database copy, ignore");
          ospf6_lsa_unlock (lsa);
          continue;
        }

      /* if not on his retrans list */
      if (!ospf6_lookup_retrans (copy, nbr))
        {
          o6log.packet ("not on %s's retranslist, ignore",
                        nbr->str);
          ospf6_lsa_unlock (lsa);
          continue;
        }

      /* if the same instance, remove from retrans list.
         else, log and ignore */
      if (which_is_more_recent (lsa, copy) == 0)
        ospf6_remove_retrans (copy, nbr);
      else
        {
          /* Log the questionable acknowledgement,
             and examine the next one. */
          o6log.packet ("questionable acknowledgement");
        }

      /* release temporary LSA from Ack message */
      ospf6_lsa_unlock (lsa);
    }

  return;
}

/* process ospf6 protocol header. then, call next process function
   for each message type */
static void 
ospf6_message_process (struct iovec *iov, struct ospf6_if *o6if,
                       struct sockaddr_in6 *src)
{
  struct ospf6_hdr *ospf6_hdr = NULL;
  char rtr_id_str[16], area_id_str[16];
  unsigned char type;
  unsigned long router_id;

  assert (iov);
  assert (o6if);
  assert (src);

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_hdr = (struct ospf6_hdr *) iov[0].iov_base;

  /* dump ospf6 header */
  inet_ntop (AF_INET, &ospf6_hdr->router_id, rtr_id_str, sizeof (rtr_id_str));
  inet_ntop (AF_INET, &ospf6_hdr->area_id, area_id_str, sizeof (area_id_str));
  o6log.packet("receive ospfv%d type:%d len:%hu"
               " rtrid:%s areaid:%s instance:%d",
               ospf6_hdr->version, ospf6_hdr->type, ntohs (ospf6_hdr->len),
               rtr_id_str, area_id_str, ospf6_hdr->instance_id);

  /* version check */
  if (ospf6_hdr->version != OSPF_V3)
    {
      o6log.packet ("version mismatch, drop");
      return;
    }

  /* area id check */
  if (ospf6_hdr->area_id != o6if->area->area_id)
    {
      if (ospf6_hdr->area_id == 0)
        {
          o6log.packet ("virtual link not yet, drop");
          return;
        }

      o6log.packet ("area id mismatch, drop");
      return;
    }

  /* checksum */
    /* XXX */

  /* instance id check */
  if (ospf6_hdr->instance_id != o6if->instance_id)
    {
      o6log.packet ("instance id mismatch, drop");
      return;
    }

  /* save message type and router id */
  type = ospf6_hdr->type;
  router_id = ospf6_hdr->router_id;

  /* trim ospf6_hdr */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  /* futher process */
  switch (type)
    {
      case MSGT_HELLO:
        ospf6_process_hello (iov, o6if, src, router_id);
        break;
      case MSGT_DATABASE_DESCRIPTION:
        ospf6_process_dbdesc (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_REQUEST:
        ospf6_process_lsreq (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_UPDATE:
        ospf6_process_lsupdate (iov, o6if, src, router_id);
        break;
      case MSGT_LINKSTATE_ACK:
        ospf6_process_lsack (iov, o6if, src, router_id);
        break;
      default:
        o6log.packet ("unknown message type, drop");
        ospf6_message_clear_buffer (type, iov);
        break;
    }

  /* check for memory leak */
  assert (iov_count (iov) == 0);

  return;
}

/* peek only ospf6_hdr to get message type, message len,
   received interface and sending neighbor */
static void
ospf6_peek_hdr (int sockfd, struct msghdr *rmsghdrp,
                unsigned char *msgtype, unsigned short *msglen,
                struct ospf6_if **o6if)
{
  struct ospf6_hdr *ospf6_hdr = NULL;
  struct sockaddr_in6 *src = NULL;
  struct in6_pktinfo *pktinfo = NULL;
  struct interface *ifp;
  unsigned long router_id;

  /* set default to fail */
  *msgtype = MSGT_NONE;
  *msglen = 0;
  *o6if = NULL;

  /* set pointer to get ifindex and source ip address */
  pktinfo = (struct in6_pktinfo *)
    (CMSG_DATA ((struct cmsghdr *)rmsghdrp->msg_control));
  src = (struct sockaddr_in6 *)rmsghdrp->msg_name;

  /* prepare buffer for ospf6 header */
  iov_prepend (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov,
               sizeof (struct ospf6_hdr));
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* peek ospf6 header */
  if (recvmsg (sockfd, rmsghdrp, MSG_PEEK) < 0)
    {
      o6log.packet ("can't peek ospf6_hdr: %s", strerror (errno));
      return;
    }

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_hdr = (struct ospf6_hdr *) rmsghdrp->msg_iov[0].iov_base;

  /* set message type and len */
  *msgtype = ospf6_hdr->type;
  *msglen = ntohs (ospf6_hdr->len);

  /* save router id */
  router_id = ospf6_hdr->router_id;

  /* clear buffer for ospf6 header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov);
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* find received ospf6 interface */
  ifp = if_lookup_by_index (pktinfo->ipi6_ifindex);
  if (!ifp || !ifp->if_data)
    return;
  *o6if = (struct ospf6_if *)ifp->if_data;
  if (!(*o6if)->area)
    {
      o6log.packet ("received interface %s not attached to area",
                    ifp->name);
      return;
    }

  return;
}

/* failed before allocate buffer, before really read packet. */
static void
ospf6_receive_fail (int sockfd, struct msghdr *rmsghdrp)
{
  assert (iov_count (rmsghdrp->msg_iov) == 0);

  /* prepare buffer for ospf6 packet */
  iov_prepend (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov,
               sizeof (struct ospf6_hdr));
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* read ospf6 packet to drop */
  recvmsg (sockfd, rmsghdrp, 0);

  /* clear buffer for ospf6 packet */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, rmsghdrp->msg_iov);
  rmsghdrp->msg_iovlen = iov_count (rmsghdrp->msg_iov);

  /* add thread next read */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  return;
}


int
ospf6_receive (struct thread *thread)
{
  struct iovec iov[MAXIOVLIST];
  int sockfd;
  struct msghdr rmsghdr;
  struct cmsghdr *rcmsgp = NULL;
  u_char cmsgbuf[CMSG_SPACE (sizeof (struct in6_pktinfo))];
  union {
    struct sockaddr sa;
    char data[sizeof (struct sockaddr_in6)];
  } unsa;
  struct sockaddr_in6 *src;
  unsigned char msgtype = MSGT_NONE;
  unsigned short msglen = 0;
  struct ospf6_if *o6if = NULL;

  /* get socket */
  sockfd = THREAD_FD (thread);

  /* clear buffers */
  iov_clear (iov, MAXIOVLIST);
  memset (&rmsghdr, 0, sizeof (struct msghdr));
  memset (&cmsgbuf, 0, sizeof (cmsgbuf));
  memset (&unsa.data, 0, sizeof (unsa.data));

  /* ancillary data set up */
  rcmsgp = (struct cmsghdr *)&cmsgbuf;
  rcmsgp->cmsg_level = IPPROTO_IPV6;
  rcmsgp->cmsg_type = IPV6_PKTINFO;
  rcmsgp->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

  /* set union pointer */
  src = (struct sockaddr_in6 *)&unsa.sa;

  /* msghdr for receive set up */
  rmsghdr.msg_name = (caddr_t) src;
  rmsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  rmsghdr.msg_iov = iov;
  rmsghdr.msg_iovlen = iov_count (iov); /* will be update later */
  rmsghdr.msg_control = (caddr_t) rcmsgp;
  rmsghdr.msg_controllen = sizeof (cmsgbuf);

  /* peek ospf6_hdr to get message type, sending neighbor
     and  received ospf6 interface */
  ospf6_peek_hdr (sockfd, &rmsghdr, &msgtype, &msglen, &o6if);
  if (msgtype == MSGT_NONE || msglen == 0 || o6if == NULL)
    {
      o6log.packet ("ospf6_hdr peek failed, drop");
      ospf6_receive_fail (sockfd, &rmsghdr);
      return -1;
    }

  /* prepare buffer for each type */
  if (ospf6_message_set_buffer (msgtype, msglen, iov) < 0)
    {
      o6log.packet ("set buffer failed, drop %s len %hu",
                    mesg_name[msgtype], msglen);
      ospf6_receive_fail (sockfd, &rmsghdr);
      return -1;
    }

  /* update iovlen */
  rmsghdr.msg_iovlen = iov_count (iov);

  /* receive message */
  if (recvmsg (sockfd, &rmsghdr, 0) != msglen)
    {
      o6log.packet ("recvmsg () failed: %s", strerror (errno));
      /* add thread next read */
      thread_add_read (master, ospf6_receive, NULL, sockfd);
      /* clear buffer for ospf6_hdr */
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      /* clear buffer for each message type */
      ospf6_message_clear_buffer (msgtype, iov);
      return -1;
    }

  /* process message received */
  ospf6_message_process (iov, o6if, src);

  /* add thread next read */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  return 0;
}

