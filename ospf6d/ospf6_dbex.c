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

/* lookup delayed acknowledge list of ospf6_interface */
struct ospf6_lsa *
ospf6_lookup_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (listnode_lookup (o6i->lsa_delayed_ack, lsa))
    {
#ifndef NDEBUG
      if (! listnode_lookup (lsa->delayed_ack_if, o6i))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add to delayed acknowledge list of ospf6_interface */
void
ospf6_add_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (ospf6_lookup_delayed_ack (lsa, o6i))
    return;

  listnode_add (o6i->lsa_delayed_ack, lsa);
  listnode_add (lsa->delayed_ack_if, o6i);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked to be send in delayed acknowledgement to interface %s: %s (%#x lock:%d)",
               o6i->interface->name, lsa->str, lsa, lsa->lock);
#endif
}

/* remove from delayed acknowledge list of ospf6_interface */
void
ospf6_remove_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (!ospf6_lookup_delayed_ack (lsa, o6i))
    return;

  listnode_delete (o6i->lsa_delayed_ack, lsa);
  listnode_delete (lsa->delayed_ack_if, o6i);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from being send in delayed acknowledgement to interface %s: %s (%#x lock:%d)",
               o6i->interface->name, lsa->str, lsa, lsa->lock);
#endif
}

void
ospf6_lsa_delayed_ack_remove_all (struct ospf6_lsa *lsa)
{
  listnode i;
  struct ospf6_interface *o6i;

  while (listcount (lsa->delayed_ack_if))
    {
      i = listhead (lsa->delayed_ack_if);
      o6i = (struct ospf6_interface *) getdata (i);
      ospf6_remove_delayed_ack (lsa, o6i);
    }
}




/* prepare for dd exchange */
void
ospf6_dbex_prepare_summary (struct ospf6_neighbor *o6n)
{
  listnode n;
  struct ospf6_lsa *lsa;

  assert (o6n);

  /* clear summary list of neighbor */
  ospf6_neighbor_summary_remove_all (o6n);

  /* add AS-scoped LSAs */
  for (n = listhead (o6n->ospf6_interface->area->ospf6->lsdb);
       n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_lsa_is_maxage (lsa))
        ospf6_neighbor_retrans_add (lsa, o6n);
      else
        ospf6_neighbor_summary_add (lsa, o6n);
    }

  /* add Area-scoped LSAs */
  for (n = listhead (o6n->ospf6_interface->area->lsdb);
       n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_lsa_is_maxage (lsa))
        ospf6_neighbor_retrans_add (lsa, o6n);
      else
        ospf6_neighbor_summary_add (lsa, o6n);
    }

  /* add Linklocal-scoped LSAs */
  for (n = listhead (o6n->ospf6_interface->lsdb);
       n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      /* MaxAge LSA are added to retrans list, instead of summary list.
         (RFC2328, section 14) */
      if (ospf6_lsa_is_maxage (lsa))
        ospf6_neighbor_retrans_add (lsa, o6n);
      else
        ospf6_neighbor_summary_add (lsa, o6n);
    }
}

/* check validity and put lsa in reqestlist if needed. */
/* returns -1 if SeqNumMismatch required. */
int
ospf6_dbex_check_dbdesc_lsa_header (struct ospf6_lsa_header *lsa_header,
                                    struct ospf6_neighbor *from)
{
  struct ospf6_lsa *received = NULL;
  struct ospf6_lsa *have = NULL;

  received = ospf6_lsa_summary_create (lsa_header);
  ospf6_lsa_lock (received);

  /* warn if unknown */
  if (! ospf6_lsa_is_known_type (lsa_header))
    zlog_warn ("DBEX: [%s%%%s] receive DbDesc unknown: %#x",
               from->str, from->ospf6_interface->interface->name,
               ntohs (lsa_header->type));

  /* case when received is AS-External though neighbor belongs stub area */
  if (lsa_header->type == htons (OSPF6_LSA_TYPE_AS_EXTERNAL) &&
      ospf6_area_is_stub (from->ospf6_interface->area))
    {
      zlog_err ("DBEX: [%s%%%s] receive DbDesc E-bit mismatch: %s",
                 from->str, from->ospf6_interface->interface->name,
                 received->str);
      ospf6_lsa_unlock (received);
      return -1;
    }

  /* if already have newer database copy, check next LSA */
  have = ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                            lsa_header->advrtr);
  if (! have)
    {

      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: [%s%%%s] request %s",
                   from->str, from->ospf6_interface->interface->name,
                   received->str);
      /* if we don't have database copy, add request */
      ospf6_neighbor_request_add (received, from);
    }
  else if (have)
    {
      /* if database copy is less recent, add request */
      if (ospf6_lsa_check_recent (received, have) < 0)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: [%s%%%s] request %s (newer)",
                       from->str, from->ospf6_interface->interface->name,
                       received->str);
          ospf6_neighbor_request_add (received, from);
        }
    }

  /* decrement reference counter of lsa.
     if above ospf6_add_request() really add to request list,
     there should be another reference, so bellow unlock
     don't really free this lsa. otherwise, do free */
  ospf6_lsa_unlock (received);

  return 0;
}

/* Direct acknowledgement */
static void
ospf6_dbex_acknowledge_direct (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  struct iovec directack[MAXIOVLIST];
  assert (lsa);

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("DBEX: [%s%%%s] direct ack %s ",
               o6n->str, o6n->ospf6_interface->interface->name,
               lsa->str);

  /* clear pointers to fragments of packet for direct acknowledgement */
  iov_clear (directack, MAXIOVLIST);

  /* set pointer of LSA to send */
  attach_lsa_hdr_to_iov (lsa, directack);

  /* age update and add InfTransDelay */
  ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);

  /* send unicast packet to neighbor's ipaddress */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, directack, &o6n->hisaddr,
                      o6n->ospf6_interface->if_id);
}

/* Delayed  acknowledgement */
void
ospf6_dbex_acknowledge_delayed (struct ospf6_lsa *lsa,
                                struct ospf6_interface *o6i)
{
  assert (o6i);

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("DBEX: [%s] delayed ack %s",
               o6i->interface->name,
               lsa->str);

  /* attach delayed acknowledge list */
  ospf6_add_delayed_ack (lsa, o6i);

  /* if not yet, schedule delayed acknowledge RxmtInterval later */
    /* timers should be *less than* RxmtInterval
       or needless retrans will ensue */
  if (o6i->thread_send_lsack_delayed == (struct thread *) NULL)
    o6i->thread_send_lsack_delayed
      = thread_add_timer (master, ospf6_send_lsack_delayed,
                          o6i, o6i->rxmt_interval - 1);

  return;
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading */
/* returns 1 if match this case, else returns 0 */
static int
ospf6_dbex_is_maxage_to_be_dropped (struct ospf6_lsa *received,
                                    struct ospf6_neighbor *from)
{
  struct ospf6_lsa_header *lsa_header;

  lsa_header = (struct ospf6_lsa_header *) received->lsa_hdr;

  if (! ospf6_lsa_is_maxage (received))
    return 0;

  if (ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                         lsa_header->advrtr) != NULL)
    return 0;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
    {
      if (ospf6_interface_count_neighbor_in_state (NBS_EXCHANGE,
            from->ospf6_interface))
        return 0;
      if (ospf6_interface_count_neighbor_in_state (NBS_LOADING,
            from->ospf6_interface))
        return 0;
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
    {
      if (ospf6_area_count_neighbor_in_state (NBS_EXCHANGE,
            from->ospf6_interface->area))
        return 0;
      if (ospf6_area_count_neighbor_in_state (NBS_LOADING,
            from->ospf6_interface->area))
        return 0;
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
    {
      if (ospf6_top_count_neighbor_in_state (NBS_EXCHANGE,
            from->ospf6_interface->area->ospf6))
        return 0;
      if (ospf6_top_count_neighbor_in_state (NBS_LOADING,
            from->ospf6_interface->area->ospf6))
        return 0;
    }

  return 1;
}

/* RFC2328 section 13 */
void
ospf6_dbex_receive_lsa (struct ospf6_lsa_header *lsa_header,
                        struct ospf6_neighbor *from)
{
  struct ospf6_lsa *received, *have;
  struct ospf6_neighbor *nbr;
  struct timeval now;
  listnode n;
  int ismore_recent, acktype;
  unsigned short cksum;

  received = have = (struct ospf6_lsa *)NULL;
  ismore_recent = -1;
  recent_reason = "no instance";

  /* make lsa structure for received lsa */
  received = ospf6_lsa_create (lsa_header);
  ospf6_lsa_lock (received);

  /* set LSA scope */
  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (htons (lsa_header->type)))
    received->scope = from->ospf6_interface;
  else if (OSPF6_LSA_IS_SCOPE_AREA (htons (lsa_header->type)))
    received->scope = from->ospf6_interface->area;
  else if (OSPF6_LSA_IS_SCOPE_AS (htons (lsa_header->type)))
    received->scope = from->ospf6_interface->area->ospf6;

  /* (1) LSA Checksum */
  cksum = ntohs (lsa_header->checksum);
  if (ntohs (ospf6_lsa_checksum (lsa_header)) != cksum)
    {
      zlog_warn ("DBEX: [%s%%%s] receive LSA cksum wrong: %s"
                 " checksum %#hx should be %#hx",
                 from->str, from->ospf6_interface->interface->name,
                 received->str, cksum, ntohs (ospf6_lsa_checksum (lsa_header)));
    }

  /* (2) warn if unknown */
  if (! ospf6_lsa_is_known_type (lsa_header))
    zlog_warn ("DBEX: [%s%%%s] receive DbDesc unknown: %#x",
               from->str, from->ospf6_interface->interface->name,
               ntohs (lsa_header->type));

  /* (3) Ebit Missmatch: AS-External-LSA */
  if (lsa_header->type == htons (OSPF6_LSA_TYPE_AS_EXTERNAL) &&
      ospf6_area_is_stub (from->ospf6_interface->area))
    {
      zlog_err ("DBEX: [%s%%%s] receive LSA E-bit mismatch: %s",
                 from->str, from->ospf6_interface->interface->name,
                 received->str);
      ospf6_lsa_unlock (received);
      return;
    }

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_dbex_is_maxage_to_be_dropped (received, from))
    {
      /* log */
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: [%s%%%s] received MaxAge LSA to be dropped: %s",
                   from->str, from->ospf6_interface->interface->name,
                   received->str);

      /* a) Acknowledge back to neighbor (13.5) */
        /* Direct Acknowledgement */
      ospf6_dbex_acknowledge_direct (received, from);

      /* b) Discard */
      ospf6_lsa_unlock (received);
      return;
    }

  /* (5) */
  /* lookup the same database copy in lsdb */
  have = ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                            lsa_header->advrtr);

  /* if no database copy or received is more recent */
  if (!have || (ismore_recent = ospf6_lsa_check_recent (received, have)) < 0) 
    {
      /* in case we have no database copy */
      ismore_recent = -1;

      /* (a) MinLSArrival check */
      gettimeofday (&now, (struct timezone *)NULL);
      if (have && now.tv_sec - have->installed <= OSPF6_MIN_LS_ARRIVAL)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: [%s%%%s] received LSA too soon: %s",
                       from->str, from->ospf6_interface->interface->name,
                       received->str);

          /* this will do free this lsa */
          ospf6_lsa_unlock (received);
          return;   /* examin next lsa */
        }

      /* (b) immediately flood */
      ospf6_dbex_flood (received, from);

      /* (c) remove database copy from all neighbor's retranslist */
      if (have)
        {
          while (listcount (have->retrans_nbr))
            {
              n = listhead (have->retrans_nbr);
              nbr = (struct ospf6_neighbor *) getdata (n);
              ospf6_neighbor_retrans_remove (have, nbr);
            }
          assert (list_isempty (have->retrans_nbr));
        }

      /* (d), installing lsdb, which may cause routing
              table calculation (replacing database copy) */
      ospf6_lsdb_install (received);

      /* (e) possibly acknowledge */
      acktype = ack_type (received, ismore_recent, from);
      if (acktype == DIRECT_ACK)
        {
          ospf6_dbex_acknowledge_direct (received, from);
        }
      else if (acktype == DELAYED_ACK)
        {
          ospf6_dbex_acknowledge_delayed (received, from->ospf6_interface);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: [%s%%%s] don't ack %s",
                       from->str, from->ospf6_interface->interface->name,
                       received->str);
        }

      /* (f) */
      /* Self Originated LSA, section 13.4 */
      if (received->lsa_hdr->lsh_advrtr == ospf6->router_id
          && have && ismore_recent < 0)
        {
          /* we're going to make new lsa or to flush this LSA. */
          /* "received" lsa is already installed in LSDB by now.
             So there's two lock in "received" LSA; LSDB's lock and
             this function(ospf6_dbex_receive_lsa)'s lock.
             The latter is not needed already.
             ospf6_lsa_reoriginate() will try to remove "received" LSA,
             and asserts that the "received" LSA's lock is 1
             to make sure the LSA is not referenced by any other than LSDB.
             This will be happen when ospf6_lsdb_remove() really removes
             this "received" LSA; then, the lock this function have done
             will become a problem. That's why ospf6_lsa_unlock() appears
             first bellow. */
          ospf6_lsa_unlock (received);
          ospf6_lsa_reoriginate (received);
          return;
        }
    }
  else if (ospf6_neighbor_request_lookup (received, from))
    /* (6) if there is instance on sending neighbor's request list */
    {
      /* if no database copy, should go above state (5) */
      assert (have);

      zlog_warn ("DBEX: [%s%%%s] received LSA %s is not newer,"
                 " and is on his requestlist: Generate BadLSReq",
                 from->str, from->ospf6_interface->interface->name,
                 received->str);

      /* BadLSReq */
      thread_add_event (master, bad_lsreq, from, 0);

      ospf6_lsa_unlock (received);
      return;
    }
  else if (ismore_recent == 0) /* (7) if neither is more recent */
    {
      received->flags |= OSPF6_LSA_DUPLICATE;

      /* (a) if on retranslist, Treat this LSA as an Ack: Implied Ack */
      if (ospf6_neighbor_retrans_lookup (received, from))
        {
          ospf6_neighbor_retrans_remove (have, from);

          /* note occurrence of implied ack */
          received->flags |= OSPF6_LSA_IMPLIEDACK;
        }

      /* (b) possibly acknowledge */
      acktype = ack_type (received, ismore_recent, from);
      if (acktype == DIRECT_ACK)
        {
          ospf6_dbex_acknowledge_direct (received, from);
        }
      else if (acktype == DELAYED_ACK)
        {
          ospf6_dbex_acknowledge_delayed (received, from->ospf6_interface);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: [%s%%%s] will no ack %s",
                       from->str, from->ospf6_interface->interface->name,
                       received->str);
        }
    }
  else /* (8) previous database copy is more recent */
    {
      /* XXX, Seqnumber Wrapping */

      /* XXX, Send database copy of this LSA to this neighbor */
      {
        struct iovec iov[8];
        struct ospf6_lsupdate *update;
        struct sockaddr_in6 dst;

        assert (have);
        dst.sin6_family = AF_INET6;
        memcpy (&dst.sin6_addr, &from->hisaddr, sizeof (struct in6_addr));
        iov_clear (iov, 8);
        update = (struct ospf6_lsupdate *) iov_append
             (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_lsupdate));
        if (!update)
          {
            zlog_err ("DBEX: iov_append() failed in send back");
            ospf6_lsa_unlock (received);
            return;
          }
        update->lsupdate_num = ntohl (1);
        ospf6_lsa_age_update_to_send (have, from->ospf6_interface->transdelay);
        attach_lsa_to_iov (have, iov);
        ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, iov, &dst.sin6_addr,
                            from->ospf6_interface->if_id);
        iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);

        if (IS_OSPF6_DUMP_DBEX)
          zlog_info ("DBEX: [%s%%%s] send DB copy back %s",
                     from->str, from->ospf6_interface->interface->name,
                     received->str);
      }
    }
  ospf6_lsa_unlock (received);
  return;
}

/* RFC2328: Table 19: Sending link state acknowledgements. */
int 
ack_type (struct ospf6_lsa *newp, int ismore_recent,
          struct ospf6_neighbor *from)
{
  struct ospf6_interface *ospf6_interface;
  struct ospf6_neighbor *nbr;
  listnode n, m;

  assert (from && from->ospf6_interface);
  ospf6_interface = from->ospf6_interface;

  if (newp->flags & OSPF6_LSA_FLOODBACK)
    {
      return NO_ACK;
    }
  else if (ismore_recent < 0
           && !(newp->flags & OSPF6_LSA_FLOODBACK))
    {
      if (ospf6_interface->state == IFS_BDR)
        {
          if (ospf6_interface->dr == from->router_id)
            {
              return DELAYED_ACK;
            }
          else
            {
              return NO_ACK;
            }
        }
      else
        {
          return DELAYED_ACK;
        }
    }
  else if ((newp->flags & OSPF6_LSA_DUPLICATE)
           && (newp->flags & OSPF6_LSA_IMPLIEDACK))
    {
      if (ospf6_interface->state == IFS_BDR)
        {
          if (ospf6_interface->dr == from->router_id)
            {
              return DELAYED_ACK;
            }
          else
            {
              return NO_ACK;
            }
        }
      else
        {
          return NO_ACK;
        }
    }
  else if ((newp->flags & OSPF6_LSA_DUPLICATE) &&
           !(newp->flags & OSPF6_LSA_IMPLIEDACK))
    {
      return DIRECT_ACK;
    }
  else if (ospf6_lsa_is_maxage (newp))
    {
      if (!ospf6_lsdb_lookup (newp->lsa_hdr->lsh_type,
                              newp->lsa_hdr->lsh_id,
                              newp->lsa_hdr->lsh_advrtr))
        {
          for (n = listhead (from->ospf6_interface->area->if_list);
               n; nextnode (n))
            {
              ospf6_interface = (struct ospf6_interface *) getdata (n);
              for (m = listhead (ospf6_interface->neighbor_list);
                   m; nextnode (m))
                {
                  nbr = (struct ospf6_neighbor *) getdata (m);
                  if (nbr->state == NBS_EXCHANGE || nbr->state == NBS_LOADING)
                    {
                      return NO_ACK;
                    }
                }
            }
          return DIRECT_ACK;
        }
    }
 
  return NO_ACK;
}

static void
ospf6_dbex_flood_linklocal (struct ospf6_lsa *lsa, struct ospf6_interface *o6i,
                            struct ospf6_neighbor *from)
{
  struct ospf6_neighbor *o6n = (struct ospf6_neighbor *) NULL;
  int ismore_recent, addretrans = 0;
  listnode n;
  struct sockaddr_in6 dst;
  struct ospf6_lsupdate *lsupdate;
  struct iovec iov[MAXIOVLIST];
  struct ospf6_lsa *req;

  /* (1) for each neighbor */
  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);

      /* (a) */
      if (o6n->state < NBS_EXCHANGE)
        continue;  /* examin next neighbor */

      /* (b) */
      if (o6n->state == NBS_EXCHANGE
          || o6n->state == NBS_LOADING)
        {
          req = ospf6_neighbor_request_lookup (lsa, o6n);
          if (req)
            {
              ismore_recent = ospf6_lsa_check_recent (lsa, req);
              if (ismore_recent > 0)
                {
                  continue; /* examin next neighbor */
                }
              else if (ismore_recent == 0)
                {
                  ospf6_neighbor_request_remove (req, o6n);
                  continue; /* examin next neighbor */
                }
              else /* ismore_recent < 0 (the new LSA is more recent) */
                {
                  ospf6_neighbor_request_remove (req, o6n);
                }
            }
        }

      /* (c) */
      if (from && from->router_id == o6n->router_id)
        continue; /* examin next neighbor */

      /* (d) add retranslist */
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: schedule flooding [%s%%%s]: %s",
                   o6n->str, o6n->ospf6_interface->interface->name,
                   lsa->str);
      ospf6_neighbor_retrans_add (lsa, o6n);
      addretrans++;
      if (o6n->send_update == (struct thread *) NULL)
        o6n->send_update =
          thread_add_timer (master, ospf6_send_lsupdate_retrans, o6n,
                            o6n->ospf6_interface->rxmt_interval);
    }

  /* (2) */
  if (addretrans == 0)
    {
      return; /* examin next interface */
    }
  else if (from && from->ospf6_interface == o6i)
    {
      /* note occurence of floodback */
      lsa->flags |= OSPF6_LSA_FLOODBACK;
    }

  /* (3) */
  if (from && from->ospf6_interface == o6i)
    {
      /* if from DR or BDR, don't need to flood this interface */
      if (from->router_id == from->ospf6_interface->dr ||
          from->router_id == from->ospf6_interface->bdr)
        return; /* examin next interface */
    }

  /* (4) if I'm BDR, DR will flood this interface */
  if (from && from->ospf6_interface == o6i
      && o6i->state == IFS_BDR)
    return; /* examin next interface */

  /* (5) send LinkState Update */
  iov_clear (iov, MAXIOVLIST);

    /* set age */
  ospf6_lsa_age_update_to_send (lsa, o6i->transdelay);

    /* attach whole lsa */
  attach_lsa_to_iov (lsa, iov);

    /* prepare destination infomation */
  dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  dst.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
  dst.sin6_scope_id = if_nametoindex (o6n->ospf6_interface->interface->name);
#endif /* HAVE_SIN6_SCOPE_ID */
  if (if_is_broadcast (o6i->interface))
    {
      switch (o6i->state)
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
  lsupdate = (struct ospf6_lsupdate *)
    iov_prepend (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_lsupdate));
  assert (lsupdate);
  lsupdate->lsupdate_num = htonl (1);

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, iov, &dst.sin6_addr,
                      o6i->interface->ifindex);
  iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);

  return;
}

/* RFC2328 section 13.3 */
static void
ospf6_dbex_flood_area (struct ospf6_lsa *lsa, struct ospf6_area *area,
                       struct ospf6_neighbor *from)
{
  listnode n;
  struct ospf6_interface *ospf6_interface;

  assert (lsa && lsa->lsa_hdr && area);

  /* for each eligible ospf_ifs */
  for (n = listhead (area->if_list); n; nextnode (n))
    {
      ospf6_interface = (struct ospf6_interface *) getdata (n);
      ospf6_dbex_flood_linklocal (lsa, ospf6_interface, from);
    }
}

static void
ospf6_dbex_flood_as (struct ospf6_lsa *lsa, struct ospf6 *ospf6,
                     struct ospf6_neighbor *from)
{
  listnode n;
  struct ospf6_area *o6a;

  assert (lsa && lsa->lsa_hdr && ospf6);

  /* for each attached area */
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      o6a = (struct ospf6_area *) getdata (n);
      ospf6_dbex_flood_area (lsa, o6a, from);
    }
}

/* flood ospf6_lsa within appropriate scope */
void
ospf6_dbex_flood (struct ospf6_lsa *lsa, struct ospf6_neighbor *from)
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6 *o6;
  struct ospf6_lsa_header *lsa_header;

  lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
    {
      o6i = (struct ospf6_interface *) lsa->scope;
      assert (o6i);

      ospf6_dbex_flood_linklocal (lsa, o6i, from);
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
    {
      o6a = (struct ospf6_area *) lsa->scope;
      assert (o6a);

      ospf6_dbex_flood_area (lsa, o6a, from);
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
    {
      o6 = (struct ospf6 *) lsa->scope;
      assert (o6);

      ospf6_dbex_flood_as (lsa, o6, from);
    }
  else
    {
      zlog_warn ("DBEX: Can't Flood %s: scope unknown", lsa->str);
    }
}


