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
  seenrtrnum = (ospf6_hdr->len - sizeof (struct ospf6_hdr)
               - sizeof (struct hello)) / sizeof (rtr_id_t);

#ifdef DEBUG_HELLO
  {
#define MAXSEENNBR 16
    char dr[16], bdr[16], nb[MAXSEENNBR][16];
    inet_ntop (AF_INET, &hello->dr, dr, sizeof (dr));
    inet_ntop (AF_INET, &hello->bdr, bdr, sizeof (bdr));
    ospf6_debug ("HELLO: Interface ID[%#x]\n", ntohl (hello->interface_id));
    ospf6_debug ("HELLO: Rtr Pri[%#x], Options[Not yet]\n", hello->rtr_pri);
    ospf6_debug ("HELLO: Hello Int[%d], RtrDeadInt[%d]\n",
                 ntohs (hello->hello_interval),
                 ntohs (hello->router_dead_interval));
    ospf6_debug ("HELLO: DR [%s], BDR[%s]\n", dr, bdr);
    rtr_idp = (rtr_id_t *)(hello + 1);
    for (i = 0; i < seenrtrnum && i < MAXSEENNBR; i++)
      {
        inet_ntop (AF_INET, rtr_idp, nb[i], sizeof (nb[i]));
        ospf6_debug ("HELLO: Seen [%s]\n", nb[i]);
        rtr_idp++;
      }
  }
#endif

  /* Option check */
  if (V3OPT_ISSET (hello->options, V3OPT_E) ^
      V3OPT_ISSET (ospf6_if->area->options, V3OPT_E))
    {
      ospf6_warn ("Proc HELLO: E bit mismatch.\n");
      return 0;
    }

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != ospf6_if->hello_interval)
    {
      ospf6_warn ("Proc HELLO: HelloInterval mismatch.\n");
      return 0;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval) != ospf6_if->rtr_dead_interval)
    {
      ospf6_warn ("Proc Hello: RouterDeadInterval mismatch.\n");
      return 0;
    }

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (nbr == NULL)
    {
      nbr = make_neighbor (ospf6_hdr->router_id, ospf6_if);
      nbr->ifid = hello->interface_id;
      nbr->prevdr = nbr->dr = hello->dr;
      nbr->prevbdr = nbr->bdr = hello->bdr;
      nbr->rtr_pri = hello->rtr_pri;
      memcpy (&nbr->hisaddr, src, sizeof (struct sockaddr_in6));
    }

  if (!IN6_ARE_ADDR_EQUAL (&src->sin6_addr, &nbr->hisaddr->sin6_addr))
    {
      char ntopbuf[32];
      ospf6_warn ("*** Neighbor %s have changed his address!\n",
                  inet_ntop (src->sa_family, &src->sin6_addr,
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

  if (schedule_neighbor_change)
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
    ospf6_debug ("DD: Options[Not Yet]\n");
    ospf6_debug ("DD: InterfaceMTU[%lu] Bits[%s]\n",
                 ntohs (ddp->interface_mtu), bits);
    ospf6_debug ("DD: SequenceNumber[%lu]\n",
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
          nbr->dd_sequence_number = ntohl (ddp->sequence_number);
        }
      else if (!DD_IS_MSBIT_SET (ddp->bits) && !DD_IS_IBIT_SET (ddp->bits) &&
           ntohl (ddp->sequence_number) == nbr->dd_sequence_number &&
           nbr->rtr_id < ospf6_if->area->ospf6->router_id)
        {
           /* I am Master, do nothing  */
        }
      else
        {
          ospf6_info ("Negotiation with %s Failed\n", nbr->str);
          return 0;
        }

      prepare_neighbor_lsdb (nbr);
      thread_add_event (master, negotiation_done, nbr, 0);
      memcpy (nbr->options, ddp->options, sizeof (nbr->options));
      break;

    case NBS_EXCHANGE:
      /* Check if duplicate */
      if (!memcmp (ddp, &nbr->last_dd, sizeof (struct database_description))
        {
          ospf6_info ("Duplicate DatabaseDescription from %s\n", nbr->str);
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))    /* Slave */
            thread_add_event (master, send_database_description, nbr, 0);
          return 0;
        }

      if (!(DD_IS_MSBIT_SET (nbr->dd_bits) ^ DD_IS_MSBIT_SET (ddp->bits)))
        {
          ospf6_info ("MSBIT mismatch from %s\n", nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0
        }

      if (DD_IS_IBIT_SET (ddp->bits))
        {
          ospf6_info ("Initialize bit set from %s in state Exchange\n",
                      nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if (memcmp (ddp->options, nbr->last_dd->options,
                  sizeof (nbr->nboptions)) != 0)
        {
          ospf6_info ("Option field have changed in DD from %s\n"
                      nbr->str);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }

      if ((DD_IS_MSBIT_SET (nbr->dd_bits) &&
           ntohl (ddp->sequence_number) != nbr->dd_sequence_number) ||
          (!DD_IS_MSBIT_SET (nbr->dd_bits) && 
           ntohl (ddp->sequence_number) != nbr->dd_sequence_number + 1))
        {
          ospf6_warn ("Sequence Number Mismatch from %s\n", nbr->str);
          ospf6_warn ("recv[%lu] have[%lu]\n",
                      ntohl (ddp->sequence_number),
                      nbr->dd_sequence_number);
          thread_add_event (master, seqnumber_mismatch, nbr, 0);
          return 0;
        }
      break;

    case NBS_LOADING:
    case NBS_FULL:
      /* Check if duplicate */
      if (!memcmp (ddp, &nbr->last_dd, sizeof (struct database_description)))
        {
          ospf6_warn ("Duplicate Packet from %s in Full,Loading\n", nbr->str);
          if (!DD_IS_MSBIT_SET (nbr->dd_bits))
            thread_add_event (master, send_database_description, nbr, 0);
        }
      else
        {
          ospf6_warn ("Not Duplicate Packet from %s in State %s\n",
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
      ospf6_warn ("AS-External found where stub area from %s in State %s\n",
                  nbr->str, nbs_name[nbr->state]);
      thread_add_event (master, seqnumber_mismatch, nbr, 0);
      return 0;
    }

  /* only valid packet in Exchange and ExStart state will come here */

  /* Master decides whether to make event ExchangeDone on reception
     Slave decides this on sending */
  if (DD_IS_MSBIT_SET (nbr->dd_bits))
    {
      /* This is Master. */
      nbr->dd_sequence_number++;
      if (!DD_IS_MBIT_SET (ddp->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
        {
          thread_add_event (master, exchange_done, nbr, 0);
        }
      proceed_summarylist (nbr);   /* DD bits may be changed */
    }
  else
    {
      /* This is Slave. */
      nbr->dd_sequence_number = ntohl (ddp->sequence_number);
      proceed_summarylist (nbr);   /* DD bits may be changed */
      if (!DD_IS_MBIT_SET (ddp->bits) && !DD_IS_MBIT_SET (nbr->dd_bits))
        {
          thread_add_event (master, exchange_done, nbr, 0);
          thread_add_event (master, send_database_description, nbr, 0);
        }
    }

  /* Save Last Received DD */
  memcpy (&nbr->last_dd, ddp, sizeof (struct database_description));

  /* Schedule new thread for sending DD */
  if (nbr->send_dd)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = (struct thread *)NULL;
    }
  if (DD_IS_MBIT_SET (nbr->dd_bits))
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
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;

  iov_clear (response, MAXIOVLIST);
  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_warn ("LSREQ: Ignored from %s\n", nbr->str);
      return 0;
    }

  if (iov_count (iov) == 1)
    ospf6_warn ("LSREQ: Null Request from %s\n", nbr->str);

  for (i = 1; iov[i].iov_base; i++)
    {
      lsreq = (struct linkstate_request *)iov[i].iov_base;

#ifdef DEBUG_LINKSTATE_REQUEST
      ospf6_debug ("LSREQ from %s: %s\n", nbr->str,
                   print_lsahdr ((struct lsa_hdr *)lsreq));
#endif
      lsip = lsa_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                         lsreq->lsreq_advrtr, nbr->ospf6_if->area,
                         nbr->ospf6_if);
      if (!lsip)
        {
          ospf6_warn ("Requested[%s] from %s not found, BadLSReq\n",
                      print_lsahdr((struct lsa_hdr *)lsreq), nbr->str);
          thread_add_event (master, bad_lsreq, nbp, 0);
          return 0;
        }

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

      ospf_send (MSGT_LINKSTATE_UPDATE, response,
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
  int i, lsanum;
  struct linkstate_update *lsupdate;
  struct lsa_internal *lsip, **p;
  struct lsa_hdr *lshp, *lsa;
  struct iovec directack[MAXIOVLIST];

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;

  /* Find Corresponding Neighbor data structure */
  nbr = nbr_lookup (ospf6_hdr->router_id, ospf6_if->area->ospf6);
  if (!nbr)
    return 0;

  list_delete_all_node (nbr->direct_ack);

  if (nbr->state < NBS_EXCHANGE)
    {
      ospf6_warn ("LSUPDATE: Ignored from %s\n", nbr->str);
      return 0;
    }
/* XXXXXXXXXXXXXXXXXXXX */

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
    retoff = OSPFV2HDRLEN;    /* XXX */

  return retoff;
}


int
make_ospf6_hdr (u_int8_t msgtype, struct iovec *iov, struct interface *iface)
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
make_hello (struct iovec *iov, struct sockaddr *dst,
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
  lsanum = listcount (nbr->retranslist);
  if (!lsanum)
    return -1;   /* Nothing to retransmit. */

  lsupdate = (struct linkstate_update *)
    iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
  assert (lsupdate);
  lsupdate->lsupdate_num = htonl (lsanum);

  i = 1;
  for (n = listhead (nbr->retranslist); n; nextnode (n))
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

