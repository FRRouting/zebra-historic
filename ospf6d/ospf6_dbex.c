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

/* prepare for dd exchange */
void
prepare_neighbor_lsdb (struct neighbor *nbr)
{
  listnode n;
  list l;
  void *scope;
  struct ospf6_lsa *lsa;

  assert (nbr);

  /* log */
  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("  Making summary list for %s", nbr->str);

  /* clear summary list of neighbor */
  ospf6_remove_summary_all (nbr);

  /* malloc temporary_list */
  l = list_init ();

  /* add as scope LSAs to summarylist */
  scope = (void *) nbr->ospf6_if->area->ospf6;

    /* add AS-external-LSAs */
  ospf6_lsdb_collect_type (l, htons (LST_AS_EXTERNAL_LSA), scope);
  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_age_current (lsa) == MAXAGE)
        ospf6_add_retrans (lsa, nbr);
      else
        ospf6_add_summary (lsa, nbr);
    }
  list_delete_all_node (l);

  /* add area scope LSAs to summarylist */
  scope = (void *) nbr->ospf6_if->area;

    /* add Router-LSAs */
  ospf6_lsdb_collect_type (l, htons (LST_ROUTER_LSA), scope);
  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_age_current (lsa) == MAXAGE)
        ospf6_add_retrans (lsa, nbr);
      else
        ospf6_add_summary (lsa, nbr);
    }
  list_delete_all_node (l);

    /* add Network-LSAs */
  ospf6_lsdb_collect_type (l, htons (LST_NETWORK_LSA), scope);
  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_age_current (lsa) == MAXAGE)
        ospf6_add_retrans (lsa, nbr);
      else
        ospf6_add_summary (lsa, nbr);
    }
  list_delete_all_node (l);

    /* add Intra-Area-Prefix-LSAs */
  ospf6_lsdb_collect_type (l, htons (LST_INTRA_AREA_PREFIX_LSA), scope);
  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_age_current (lsa) == MAXAGE)
        ospf6_add_retrans (lsa, nbr);
      else
        ospf6_add_summary (lsa, nbr);
    }
  list_delete_all_node (l);

  /* add interface scope LSAs to summarylist */
  scope = (void *) nbr->ospf6_if;

    /* add Link-LSAs */
  ospf6_lsdb_collect_type (l, htons (LST_LINK_LSA), scope);
  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_age_current (lsa) == MAXAGE)
        ospf6_add_retrans (lsa, nbr);
      else
        ospf6_add_summary (lsa, nbr);
    }

  /* free temporary list */
  list_delete_all (l);

  return;
}

/* check validity and put lsa in reqestlist if needed.
   XXX, this function should return -1 if stub area and 
   if as-external-lsa contained. this is not yet */
int
check_neighbor_lsdb (struct iovec *iov, struct neighbor *nbr)
{
  struct ospf6_lsa *have, *received;
  struct ospf6_lsa_hdr *lsh;
  void *scope;
  char buf[128];

  have = received = (struct ospf6_lsa *)NULL;

  /* for each LSA listed in DD */
  while (iov_count (iov))
    {
      lsh = ospf6_message_get_lsa_hdr (iov);

      /* log */
      if (IS_OSPF6_DUMP_DBDESC)
        {
          ospf6_lsa_hdr_str (lsh, buf, sizeof (buf));
          zlog_info ("  %s", buf);
        }

      /* make lsa structure for this LSA */
      received = make_ospf6_lsa_summary (lsh);

      /* set scope */
      switch (ospf6_lsa_get_scope_type (received->lsa_hdr->lsh_type))
        {
          case SCOPE_LINKLOCAL:
            scope = (void *) nbr->ospf6_if;
            break;
          case SCOPE_AREA:
            scope = (void *) nbr->ospf6_if->area;
            break;
          case SCOPE_AS:
            scope = (void *) nbr->ospf6_if->area->ospf6;
            break;
          case SCOPE_RESERVED:
          default:
            zlog_warn ("unsupported scope, check DD failed");
            return -1;
        }
      received->scope = scope;

      /* set sending neighbor */
      received->from = nbr;

      /* if already have newer database copy, check next LSA */
      have = ospf6_lsdb_lookup (lsh->lsh_type, lsh->lsh_id,
                                lsh->lsh_advrtr, received->scope);
      if (!have)
        {
          /* if we don't have database copy, add request */
          ospf6_add_request (received, nbr);
        }
      else if (have)
        {
          /* if database copy is less recent, add request */
          if (ospf6_lsa_check_recent (received, have) < 0)
            ospf6_add_request (received, nbr);
        }

      /* decrement reference counter of lsa.
         if above ospf6_add_request() really add to request list,
         there should be another reference, so bellow unlock
         don't really free this lsa. otherwise, do free */
      ospf6_lsa_unlock (received);
    }
  return 0;
}

void
proceed_summarylist (struct neighbor *nbr)
{
  int size;
  struct ospf6_lsa *lsa;
  listnode n;

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("  Proceed %s's summary list", nbr->str);

  /* clear DD packet to retransmit */
  for (n = listhead (nbr->dd_retrans); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_summary (lsa, nbr);
    }
  list_delete_all_node (nbr->dd_retrans);

  /* DD packet size must be less than InterfaceMTU.
     prepare size of packet before attaching LSA header. */
  size = sizeof (struct ospf6_hdr) + sizeof (struct database_description);

  /* XXX, invalid method to access summarylist */
  for (n = listhead (nbr->summarylist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (DEFAULT_INTERFACE_MTU - size <= sizeof (struct ospf6_lsa_hdr))
        break;
      list_add_node (nbr->dd_retrans, lsa);
      size += sizeof (struct ospf6_lsa_hdr);
    }

  /* clear More bit of DD */
  if (list_isempty (nbr->summarylist))
    {
      DD_MBIT_CLEAR (nbr->dd_bits);
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("  No more DbDesc to send to %s", nbr->str);
    }

  return;
}

/* Direct acknowledgement */
void
direct_acknowledge (struct ospf6_lsa *lsa)
{
  struct iovec directack[MAXIOVLIST];

  assert (lsa && lsa->from);

  /* clear pointers to fragments of packet for direct acknowledgement */
  iov_clear (directack, MAXIOVLIST);

  /* set pointer of LSA to send */
  attach_lsa_hdr_to_iov (lsa, directack);

  /* age update and add InfTransDelay */
  ospf6_age_update_to_send (lsa, lsa->from->ospf6_if);

  /* send unicast packet to neighbor's ipaddress */
  ospf6_send (MSGT_LINKSTATE_ACK, directack,
              (struct sockaddr *)&lsa->from->hisaddr, lsa->from->ospf6_if);

  return;
}

/* Delayed  acknowledgement */
void
delayed_acknowledge (struct ospf6_lsa *lsa)
{
  struct ospf6_if *o6if = NULL;

  o6if = lsa->from->ospf6_if;
  assert (o6if);

  /* attach delayed acknowledge list */
  ospf6_add_delayed_ack (lsa, o6if);

  /* if not yet, schedule delayed acknowledge RxmtInterval later */
    /* timers should be *less than* RxmtInterval
       or needless retrans will ensue */
  if (o6if->send_ack == (struct thread *)NULL)
    o6if->send_ack = thread_add_timer (master, send_linkstate_ack,
                                        o6if, o6if->rxmt_interval - 1);

  return;
}

/* RFC2328 section 13 */
void
lsa_receive (struct ospf6_lsa_hdr *lsh, struct neighbor *from)
{
  struct ospf6_lsa *received, *have;
  struct neighbor *nbr;
  struct timeval now;
  listnode n;
  int ismore_recent, acktype;
  void *scope;
  char lsh_str[128];

  received = have = (struct ospf6_lsa *)NULL;
  ismore_recent = -1;
  recent_reason = "no instance";

  ospf6_lsa_hdr_str (lsh, lsh_str, sizeof (lsh_str));
  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("LSA: Receive %s age:%hu", lsh_str, ntohs (lsh->lsh_age));

  /* make lsa structure for received lsa */
  received = make_ospf6_lsa (lsh);
  received->lsa_hdr = make_ospf6_lsa_data (lsh, ntohs (lsh->lsh_len));
  /* set scope */
  switch (ospf6_lsa_get_scope_type (received->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        scope = (void *) from->ospf6_if;
        break;
      case SCOPE_AREA:
        scope = (void *) from->ospf6_if->area;
        break;
      case SCOPE_AS:
        scope = (void *) from->ospf6_if->area->ospf6;
        break;
      case SCOPE_RESERVED:
      default:
        zlog_warn ("unsupported scope, lsa_receive() failed");
        /* always unlock before return after make_ospf6_lsa() */
        ospf6_lsa_unlock (received);
        return;
    }
  received->scope = scope;
  /* set sending neighbor */
  received->from = from;

  /* (1) XXX, LSA Checksum */

  /* (2) XXX, should be relaxed */
  switch (ntohs (lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
      case LST_NETWORK_LSA:
      case LST_LINK_LSA:
      case LST_INTRA_AREA_PREFIX_LSA:
      case LST_AS_EXTERNAL_LSA:
        break;
      case LST_INTER_AREA_PREFIX_LSA:
      case LST_INTER_AREA_ROUTER_LSA:
      default:
        zlog_warn ("Unsupported LSA Type: %#x, Ignore",
                   ntohs (lsh->lsh_type));
        ospf6_lsa_unlock (received);
        return;
    }

  /* (3) XXX, Ebit Missmatch: AS-External-LSA */

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_age_current (received) == MAXAGE)
    {
      zlog_info ("  MaxAge LSA...");

      if (!ospf6_lsdb_lookup (lsh->lsh_type, lsh->lsh_id,
                              lsh->lsh_advrtr, received->scope))
        {
          if (!count_nbr_in_state (NBS_EXCHANGE,
                                   received->from->ospf6_if->area) &&
              !count_nbr_in_state (NBS_LOADING,
                                  received->from->ospf6_if->area))
            {
              /* log */
              if (IS_OSPF6_DUMP_DBEX)
                zlog_info ("  MaxAge, no database copy, and "
                           "no neighbor in Exchange or Loading");
              /* a) Acknowledge back to neighbor (13.5) */
                /* Direct Acknowledgement */
              direct_acknowledge (received);

              /* b) Discard */
              ospf6_lsa_unlock (received);
              return;
            }
        }
    }

  /* (5) */
  /* lookup the same database copy in lsdb */
  have = ospf6_lsdb_lookup (lsh->lsh_type, lsh->lsh_id,
                            lsh->lsh_advrtr, received->scope);

  /* if no database copy or received is more recent */
  if (!have || (ismore_recent = ospf6_lsa_check_recent (received, have)) < 0) 
    {
      /* in case we have no database copy */
      ismore_recent = -1;

      /* (a) MinLSArrival check */
      gettimeofday (&now, (struct timezone *)NULL);
      if (have && now.tv_sec - have->installed <= MIN_LS_ARRIVAL)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Arrived less than MinLSArrival(1sec), drop");

          /* this will do free this lsa */
          ospf6_lsa_unlock (received);
          return;   /* examin next lsa */
        }

      /* (b) immediately flood */
      ospf6_lsa_flood (received);

      /* (c) remove database copy from all neighbor's retranslist */
      if (have)
        {
          for (n = listhead (have->retrans_nbr); n;
               n = listhead (have->retrans_nbr))
            {
              nbr = (struct neighbor *)getdata (n);
              ospf6_remove_retrans (have, nbr);
            }
          assert (list_isempty (have->retrans_nbr));
        }

      /* (d), installing lsdb, which may cause routing
              table calculation (replacing database copy) */
        /* XXX, retrans list was processed above. what about
           summary list? */
      ospf6_lsdb_install (received);

      /* (e) possibly acknowledge */
      acktype = ack_type (received, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: direct");
          direct_acknowledge (received);
        }
      else if (acktype == DELAYED_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: delayed");
          delayed_acknowledge (received);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: none");
        }

      /* (f) */
      /* Self Originated LSA, section 13.4 */
      if (is_self_originated (received) && have && ismore_recent < 0)
        {
          /* we're going to make new lsa or to flush this LSA. */
          ospf6_lsa_unlock (received);
          if (reconstruct_lsa (received) == NULL)
            ospf6_premature_aging (received);
          return;
        }
    }
  else if (ospf6_lookup_request (received, received->from))
    /* (6) if there is instance on sending neighbor's request list */
    {
      /* if no database copy, should go above state (5) */
      assert (have);

      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("  database copy exists, received is not newer,"
                   " and is on his requestlist -> BadLSReq");

      /* BadLSReq */
      thread_add_event (master, bad_lsreq, from, 0);

      /* always unlock before return */
      ospf6_lsa_unlock (received);
      return;
    }
  else if (ismore_recent == 0) /* (7) if neither is more recent */
    {
      ospf6_lsa_set_flag (received, OSPF6_LSA_DUPLICATE);

      /* (a) if on retranslist, Treat this LSA as an Ack: Implied Ack */
      if (ospf6_lookup_retrans (received, from))
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Implied Ack");

          ospf6_remove_retrans (have, from);

          /* note occurrence of implied ack */
          ospf6_lsa_set_flag (received, OSPF6_LSA_IMPLIEDACK);
        }

      /* (b) possibly acknowledge */
      acktype = ack_type (received, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: direct");
          direct_acknowledge (received);
        }
      else if (acktype == DELAYED_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: delayed");
          delayed_acknowledge (received);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("  Aknowledge: none");
        }
    }
  else /* (8) previous database copy is more recent */
    {
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("already have newer copy");

      /* XXX, Seqnumber Wrapping */

      /* XXX, Send database copy of this LSA to this neighbor */
      {
        struct iovec iov[8];
        struct linkstate_update *update;
        struct sockaddr_in6 dst;

        assert (have);
        memcpy (&dst, &received->from->hisaddr,
                sizeof (struct sockaddr_in6));
        iov_clear (iov, 8);
        update = (struct linkstate_update *) iov_append
             (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct linkstate_update));
        if (!update)
          {
            zlog_warn ("  *** iov_append() failed in send back");
            ospf6_lsa_unlock (received);
            return;
          }
        update->lsupdate_num = ntohl (1);
        ospf6_age_update_to_send (have, received->from->ospf6_if);
        attach_lsa_to_iov (have, iov);
        ospf6_send (MSGT_LINKSTATE_UPDATE, iov, (struct sockaddr *)&dst,
                    received->from->ospf6_if);
        iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);

        if (IS_OSPF6_DUMP_DBEX)
          zlog_info ("  send database copy back to neighbor");
      }
    }
  ospf6_lsa_unlock (received);
  return;
}

/* RFC2328: Table 19: Sending link state acknowledgements. */
  /* XXX, I don't remember why No Ack, when MaxAge, no instance and
     no neighbor ExChange or Loading. and more, the circumstance should
     be processed at lsa_receive() */
int 
ack_type (struct ospf6_lsa *newp, int ismore_recent)
{
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  listnode n, m;

  assert (newp->from && newp->from->ospf6_if);
  ospf6_if = newp->from->ospf6_if;

  if (ospf6_lsa_test_flag (newp, OSPF6_LSA_FLOODBACK))
    return NO_ACK;
  else if (ismore_recent < 0
           && !(ospf6_lsa_test_flag (newp, OSPF6_LSA_FLOODBACK)))
    {
      if (ospf6_if->state == IFS_BDR)
        {
          if (ospf6_if->dr == newp->from->rtr_id)
            return DELAYED_ACK;
          else
            return NO_ACK;
        }
      else
        return DELAYED_ACK;
    }
  else if (ospf6_lsa_test_flag (newp, OSPF6_LSA_DUPLICATE)
           && ospf6_lsa_test_flag (newp, OSPF6_LSA_IMPLIEDACK))
    {
      if (ospf6_if->state == IFS_BDR)
        {
          if (ospf6_if->dr == newp->from->rtr_id)
            return DELAYED_ACK;
          else
            return NO_ACK;
        }
      else
        return NO_ACK;
    }
  else if (ospf6_lsa_test_flag (newp, OSPF6_LSA_DUPLICATE) &&
           !(ospf6_lsa_test_flag (newp, OSPF6_LSA_IMPLIEDACK)))
    {
      return DIRECT_ACK;
    }
  else if (ospf6_age_current (newp) == MAXAGE)
    {
      if (!ospf6_lsdb_lookup (newp->lsa_hdr->lsh_type, newp->lsa_hdr->lsh_id,
                              newp->lsa_hdr->lsh_advrtr, newp->scope))
        {
          /* no current instance in lsdb */

          for (n = listhead (newp->from->ospf6_if->area->ospf6_if_list);
               n; nextnode (n))
            {
              ospf6_if = (struct ospf6_if *) getdata (n);
              for (m = listhead (ospf6_if->nbr_list);
                   m;
                   nextnode (m))
                {
                  nbr = (struct neighbor *) getdata (m);
                  if (nbr->state == NBS_EXCHANGE || nbr->state == NBS_LOADING)
                    return NO_ACK;
                }
            }
          return DIRECT_ACK;
        }
    }
  
  return NO_ACK;
}

void
ospf6_lsa_flood_interface (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  struct neighbor *nbr = (struct neighbor *)NULL;
  int ismore_recent, addretrans = 0;
  listnode n;
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;
  struct iovec iov[MAXIOVLIST];
  struct ospf6_lsa *req;

  /* (1) for each neighbor */
  for (n = listhead (o6if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);

      /* (a) */
      if (nbr->state < NBS_EXCHANGE)
        continue;  /* examin next neighbor */

      /* (b) */
      if (nbr->state == NBS_EXCHANGE
          || nbr->state == NBS_LOADING)
        {
          req = ospf6_lookup_request (lsa, nbr);
          if (req)
            {
              ismore_recent = ospf6_lsa_check_recent (lsa, req);
              if (ismore_recent > 0)
                {
                  o6log.dbex ("requesting is newer on %s (%s)",
                              nbr->str, recent_reason);
                  continue; /* examin next neighbor */
                }
              else if (ismore_recent == 0)
                {
                  o6log.dbex ("the same instance,delete from"
                              " %s requestlist", nbr->str);
                  ospf6_remove_request (req, nbr);
                  continue; /* examin next neighbor */
                }
              else /* ismore_recent < 0(the new LSA is more recent) */
                {
                  o6log.dbex ("flooding is newer(%s), delete from"
                              " %s requestlist", recent_reason, nbr->str);
                  ospf6_remove_request (req, nbr);
                }
            }
        }

      /* (c) */
      if (lsa->from == nbr)
        continue; /* examin next neighbor */

      /* (d) add retranslist */
      ospf6_add_retrans (lsa, nbr);
      addretrans++;
      if (nbr->send_update == (struct thread *) NULL)
        nbr->send_update = thread_add_timer (master, send_linkstate_update,
                                             nbr, nbr->ospf6_if->rxmt_interval);
    }

  /* (2) */
  if (addretrans == 0)
    {
      o6log.dbex ("don't flood interface %s",
                  o6if->interface->name);
      return; /* examin next interface */
    }
  else if (lsa->from && lsa->from->ospf6_if == o6if)
    {
      o6log.dbex ("flooding %s is floodback",
                  o6if->interface->name);
      /* note occurence of floodback */
      ospf6_lsa_set_flag (lsa, OSPF6_LSA_FLOODBACK);
    }
  else
    o6log.dbex ("flood %s", o6if->interface->name);

  /* (3) */
  if (lsa->from && lsa->from->ospf6_if == o6if)
    {
      /* if from DR or BDR, don't need to flood this interface */
      if (lsa->from->rtr_id == lsa->from->ospf6_if->dr ||
          lsa->from->rtr_id == lsa->from->ospf6_if->bdr)
        return; /* examin next interface */
    }

  /* (4) if I'm BDR, DR will flood this interface */
  if (lsa->from && lsa->from->ospf6_if == o6if
      && o6if->state == IFS_BDR)
    return; /* examin next interface */

  /* (5) send LinkState Update */
  iov_clear (iov, MAXIOVLIST);

    /* set age */
  ospf6_age_update_to_send (lsa, o6if);

    /* attach whole lsa */
  attach_lsa_to_iov (lsa, iov);

    /* prepare destination infomation */
  dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  dst.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
  dst.sin6_scope_id = if_nametoindex (nbr->ospf6_if->interface->name);
#endif /* HAVE_SIN6_SCOPE_ID */
  if (if_is_broadcast (o6if->interface))
    {
      switch (o6if->state)
        {
        case IFS_DR:
        case IFS_BDR:
          inet_pton (AF_INET6, ALLSPFROUTERS6, &dst.sin6_addr);
          break;
        default:
          inet_pton (AF_INET6, ALLDROUTERS6, &dst.sin6_addr);
          break;
        }
    }
  else
    {
      /* XXX NBMA not yet */
      inet_pton (AF_INET6, ALLSPFROUTERS6, &dst.sin6_addr);
    }

    /* make LinkState Update header */
  lsupdate = (struct linkstate_update *)
    iov_prepend (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct linkstate_update));
  assert (lsupdate);
  lsupdate->lsupdate_num = htonl (1);

  ospf6_message_send (MSGT_LSUPDATE, iov, &dst.sin6_addr,
                      o6if->interface->ifindex);
  iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);

  return;
}

/* RFC2328 section 13.3 */
void
ospf6_lsa_flood_area (struct ospf6_lsa *lsa, struct area *area)
{
  listnode n;
  struct ospf6_if *ospf6_if;

  assert (lsa && lsa->lsa_hdr && area);
  o6log.dbex ("flooding %s in area %s", print_lsahdr (lsa->lsa_hdr),
              area->str);

  /* for each eligible ospf_ifs */
  for (n = listhead (area->ospf6_if_list); n; nextnode (n))
    {
      ospf6_if = (struct ospf6_if *)getdata (n);
      ospf6_lsa_flood_interface (lsa, ospf6_if);
    }

  return;
}

void
ospf6_lsa_flood_as (struct ospf6_lsa *lsa, struct ospf6 *ospf6)
{
  listnode n;
  struct area *area;

  assert (lsa && lsa->lsa_hdr && ospf6);
  o6log.dbex ("flooding %s in AS", print_lsahdr (lsa->lsa_hdr));

  /* for each attached area */
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);
      ospf6_lsa_flood_area (lsa, area);
    }

  return;
}

/* flood ospf6_lsa within appropriate scope */
void
ospf6_lsa_flood (struct ospf6_lsa *lsa)
{
  unsigned short scope_type;
  struct area *area;
  struct ospf6_if *o6if;
  struct ospf6 *ospf6;

  scope_type = ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type);
  switch (scope_type)
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) lsa->scope;
        assert (o6if);
        ospf6_lsa_flood_interface (lsa, o6if);
        return;

      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        assert (area);
        ospf6_lsa_flood_area (lsa, area);
        return;

      case SCOPE_AS:
        ospf6 = (struct ospf6 *) lsa->scope;
        assert (ospf6);
        ospf6_lsa_flood_as (lsa, ospf6);
        return;

      case SCOPE_RESERVED:
      default:
        o6log.dbex ("unsupported scope, can't flood");
        break;
    }
  return;
}


