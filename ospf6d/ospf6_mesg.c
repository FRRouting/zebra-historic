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
      zlog (NULL, LOG_WARNING, "Proc HELLO: E bit mismatch.");
      return 0;
    }

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != ospf6_if->hello_interval)
    {
      zlog (NULL, LOG_WARNING,"Proc HELLO: HelloInterval mismatch.");
      return 0;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval) != ospf6_if->rtr_dead_interval)
    {
      zlog (NULL, LOG_WARNING,"Proc Hello: RouterDeadInterval mismatch.");
      return 0;
    }

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (nbr == NULL)
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
      zvlog_warn ("*** Neighbor %s have changed his address!",
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
          zvlog_info ("Option field have changed in DD from %s",
                      nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if ((DD_IS_MSBIT_SET (nbr->dd_bits) &&
           ntohl (ddp->sequence_number) != nbr->dd_seqnum) ||
          (!DD_IS_MSBIT_SET (nbr->dd_bits) && 
           ntohl (ddp->sequence_number) != nbr->dd_seqnum + 1))
        {
          zvlog_warn ("Sequence Number Mismatch from %s", nbr->str);
          zvlog_warn ("recv[%lu] have[%lu]",
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
          zlog (NULL, LOG_WARNING,"Duplicate Packet from %s in Full,Loading", nbr->str);
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))
            thread_add_event (master, send_database_description, nbr, 0);
        }
      else
        {
          zlog (NULL, LOG_WARNING,"Not Duplicate Packet from %s in State %s",
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
      zvlog_warn ("AS-External found where stub area from %s in State %s",
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
  struct linkstate_request *lsreq;
  struct lsa_internal *lsip;
  struct iovec response[MAXIOVLIST];
  struct linkstate_update *lsupdate;

  iov_clear (response, MAXIOVLIST);
  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      zvlog_warn ("LSREQ: Ignored from %s", nbr->str);
      return 0;
    }

  if (iov_count (iov) == 1)
    zvlog_warn ("LSREQ: Null Request from %s", nbr->str);

  for (i = 1; iov[i].iov_base; i++)
    {
      lsreq = (struct linkstate_request *)iov[i].iov_base;

#ifdef DEBUG_LINKSTATE_REQUEST
      zvlog_debug ("LSREQ from %s: %s", nbr->str,
                   print_lsahdr ((struct lsa_hdr *)lsreq));
#endif
      lsip = lsa_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                         lsreq->lsreq_advrtr, nbr->ospf6_if->area,
                         nbr->ospf6_if);
      if (!lsip)
        {
          zvlog_warn ("Requested[%s] from %s not found, BadLSReq",
                      print_lsahdr((struct lsa_hdr *)lsreq), nbr->str);
          thread_add_event (master, bad_lsreq, nbr, 0);
          return 0;
        }

      zvlog_debug ("LSUPDATE(response): %s", print_lsahdr (lsip->lsh));
      attach_lsa_to_iov (lsip, response);
      lsanum++;
    }

  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      lsupdate = (struct linkstate_update *)
                 iov_prepend (MTYPE_OSPF_MESSAGE, response,
                              sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf6_send (MSGT_LINKSTATE_UPDATE, response,
                 (struct sockaddr *)&nbr->hisaddr, nbr->ospf6_if);
      iov_free (MTYPE_OSPF_MESSAGE, response, 0, 1);
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
  struct lsa_hdr *lsh;

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      zlog (NULL, LOG_WARNING,"LSUPDATE: Ignored from %s", nbr->str);
      return 0;
    }

  lsupdate = (struct linkstate_update *)iov[1].iov_base;
  lsanum = ntohl (lsupdate->lsupdate_num);
  zvlog_debug ("LSUPDATE: # LSAs[%d] from %s", lsanum, nbr->str);

  for (lsh = (struct lsa_hdr *)iov[2].iov_base; lsanum; lsanum--)
    {
      zvlog_debug ("LSUPDATE: %s", print_lsahdr (lsh));

      lsa_receive (lsh, nbr);
      lsh = LSA_NEXT (lsh);
    }

  return 0;
}

int
proc_linkstate_ack (struct sockaddr_in6 *src, struct iovec *iov,
                    struct ospf6_if *ospf6_if)
{
  struct lsa_hdr *lsh;
  struct lsa_internal *p, *lsi;
  struct neighbor *nbr;
  struct ospf6_hdr *ospf6_hdr = NULL;
  int i;
  listnode n;

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      zvlog_debug ("LSACK: Ignored from %s", nbr->str);
      return 0;
    }

  for (i = 1; iov[i].iov_base; i++)
    {
      lsh = (struct lsa_hdr *)iov[i].iov_base;
      lsi = make_lsa_hdr_internal (lsh, nbr);

      o6log.dbex ("acknowledge %s from %s", print_lsahdr (lsh), nbr->str);

      p = lsa_lookup (lsh->lsh_type, lsh->lsh_id, lsh->lsh_advrtr,
                      nbr->ospf6_if->area, nbr->ospf6_if);
      if (!p)
        continue;
      n = list_lookup_node (nbr->retranslist, p);
      if (!n)
        continue;
      if (which_is_more_recent (p, lsi) == 0)
        {
          detach_lsa_from_retranslist (p, nbr);
        }
      else
        {
          o6log.dbex ("RFC said to log!!");
#if 1
          continue;
#else
          detach_lsa_from_retranslist (p, nbr);
#endif
        }
      free_lsa (lsi->lsh);
      free_lsa_internal_hdr (lsi);
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
      zvlog_info ("Version mismatch between i/f and packet(%d)",
                  ospf6_hdr->version);
      return 0;
    }

  /* Area ID check */
  if (ospf6_hdr->area_id != ospf6_if->area->area_id)
    {
      if (ospf6_hdr->area_id == 0)
        {
          zvlog_notice ("Virtual link, not yet");
          return 0;
        }
      else
        {
          char area_id[16];
          inet_ntop (AF_INET, &ospf6_hdr->area_id,
                     area_id, sizeof (area_id));
          zvlog_info ("Can't find Area %s", area_id);
          return 0;
        }
    }

  /* Checksum */
  /* XXX */

  /* Instance ID check */
  if (ospf6_if->area->ospf6->instance_id != ospf6_hdr->instance_id)
    {
      zvlog_info ("Instance ID[%d] mismatch with %d on %s",
                  ospf6_hdr->instance_id, ospf6_if->interface->name,
                  ospf6_if->area->ospf6->instance_id);
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

  hello = (struct hello *)iov_append (MTYPE_OSPF_MESSAGE,
                                      iov, sizeof (struct hello));
  if (!hello)
    {
      zlog (NULL, LOG_ERR, "iov_append () failed in make_hello ()");
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

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  dd = (struct database_description *)
       iov_append (MTYPE_OSPF_MESSAGE, iov,
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
          zvlog_warn ("gettimeofday() failed in"
                      " make_database_description (): %s",
                      strerror (errno));
          tv.tv_sec = 1;
        }
      nbr->dd_seqnum = tv.tv_sec;
      zvlog_debug ("Neighbor[%s] SequenceNumber newly set [%lu]",
                    nbr->str, nbr->dd_seqnum);
    }

  dd->sequence_number = htonl (nbr->dd_seqnum);

  if (!DD_IS_IBIT_SET (nbr->dd_bits))
    {
      struct lsa_internal *p;
      for (n = listhead (nbr->dd_retrans); n; nextnode (n))
        {
          p = (struct lsa_internal *) getdata (n);
          attach_lsa_hdr_to_iov (p, iov);
          zvlog_debug ("DD: %s", print_lsahdr (p->lsh));
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
  struct lsa_internal *lsi;

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  if (list_isempty (nbr->requestlist))
    {
      zvlog_warn ("LSREQ: empty requestlist of Neighbor[%s]",
                  nbr->str);
      return -1;
    }

  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      assert (lsi->lsh);
      lsreq = (struct linkstate_request *) iov_append
              (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_request));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsi->lsh->lsh_type;
      lsreq->lsreq_id = lsi->lsh->lsh_id;
      lsreq->lsreq_advrtr = lsi->lsh->lsh_advrtr;
      zvlog_debug ("LSREQ: %s",
                   print_lsahdr ((struct lsa_hdr *)lsreq));
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
  struct lsa_internal *lsi;

  memcpy (dst, &nbr->hisaddr, sizeof (struct sockaddr_in6));

  /* count number of LSA */
  lsanum = listcount (nbr->retranslist);
  if (!lsanum)
    return -1;   /* Nothing to retransmit. */

  lsupdate = (struct linkstate_update *) iov_append
             (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
  if (!lsupdate)
    {
      zlog (NULL, LOG_ERR, "iov_append () failed in make_linkstate_update");
      return -1;
    }
  lsupdate->lsupdate_num = htonl (lsanum);

  i = 1;
  for (n = listhead (nbr->retranslist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      if (iov_totallen (iov) >= DEFAULT_INTERFACE_MTU
                                - sizeof (struct ospf6_hdr))
        break;
      attach_lsa_to_iov (lsi, iov);
      zvlog_debug ("LSUPDATE: %s (%d/%d)", print_lsahdr (lsi->lsh),
                   i, lsanum);
      i++;
    }

  return 0;
}

