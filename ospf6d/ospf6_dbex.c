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
int
prepare_neighbor_lsdb (struct neighbor *nbr)
{
  int i, type;
  struct area *area;
  struct lsa_internal *lsi;
  listnode n;

  assert (nbr);

  o6log.dbex ("prepare summarylist for %s", nbr->str);

  list_cleared_of_lsa (nbr);

  area = nbr->ospf6_if->area;
  assert (area);

  for (type = 0; type < AREALSTYPESIZE; type++)
    {
      for (i = 0; i < HASHVAL; i++)
        {
          for (n = listhead (area->lsdb[type][i]); n; nextnode (n))
            {
              lsi = (struct lsa_internal *) getdata (n);
              o6log.dbex ("attache %s", print_lsahdr (lsi->lsh));
              list_add_node (nbr->summarylist, lsi);
            }
        }
    }

  for (n = listhead (nbr->ospf6_if->linklocal_lsa); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      o6log.dbex ("attache %s", print_lsahdr (lsi->lsh));
      list_add_node (nbr->summarylist, lsi);
    }

  return 0;
}

/* check validity and put lsa in reqestlist if needed.
   this function should return -1 if stub area and 
   if as-external-lsa contained. this is not yet */
int
check_neighbor_lsdb (struct iovec *iov, struct neighbor *nbr)
{
  int i;
  struct lsa_internal *have, *received;
  struct lsa_hdr *lsh;

  have = received = (struct lsa_internal *)NULL;

  if (!iov->iov_base)
    return 0;

  o6log.dbex ("check DD from %s", nbr->str);

  for (i = 0; iov[i].iov_base; i++)
    {
      lsh = (struct lsa_hdr *)iov[i].iov_base;
      o6log.dbex ("checking %s", print_lsahdr (lsh));

      if (!lsatype_ok (lsh))
        assert (0);

      if (received)
        {
          lsa_expire_cancel (received);
          lsa_refresh_cancel (received);
          free_lsa (received->lsh);
          free_lsa_internal_hdr (received);
        }
      received = make_lsa_hdr_internal (lsh, nbr);
      have = lsa_lookup (lsh->lsh_type, lsh->lsh_id,
                         lsh->lsh_advrtr, nbr->ospf6_if->area,
                         nbr->ospf6_if);
      if (have)
        {
          if (which_is_more_recent (received, have) >= 0)
            continue;
        }

      /* Search this in case already in Requestlist */
      if (lslist_lookup (received, nbr->requestlist))
        {
          o6log.dbex ("%s already attached to his requestlist",
                       print_lsahdr (received->lsh));
          continue;
        }

        /* the LSA we have just received is newer.
           attach requestlist. */
        list_add_node (nbr->requestlist, received);
        o6log.dbex ("attache %s to his requestlist",
                    print_lsahdr (received->lsh));
        received = (struct lsa_internal *)NULL;
    }
  return 0;
}

int
proceed_summarylist (struct neighbor *nbr)
{
  int size;
  struct lsa_internal *p;
  listnode n;

  list_delete_all_node (nbr->dd_retrans);

  size = sizeof (struct ospf6_hdr) + sizeof (struct database_description);
  for (n = listhead(nbr->summarylist); n; nextnode (n))
    {
      p = (struct lsa_internal *)getdata (n);
      if (DEFAULT_INTERFACE_MTU - size <= sizeof (struct lsa_hdr))
        break;
      list_add_node (nbr->dd_retrans, p);
      list_delete_by_val (nbr->summarylist, p);
      size += sizeof (struct lsa_hdr);
    }

  o6log.dbex ("proceed summarylist of %s", nbr->str);

  if (list_isempty (nbr->summarylist))
    {
      DD_MBIT_CLEAR (nbr->dd_bits);
      o6log.dbex ("mbit for %s clear", nbr->str);
    }

  return 0;
}

void
direct_acknowledge (struct lsa_internal *lsi)
{
  struct iovec directack[MAXIOVLIST];

  /* Direct acknowledgement */
  iov_clear (directack, MAXIOVLIST);

  o6log.dbex ("direct acknowledge to %s for %s",
              lsi->from->str, print_lsahdr (lsi->lsh));

  attach_lsa_hdr_to_iov (lsi, directack);
  lsi->lsh->lsh_age = htons (calc_lsa_age_external (lsi)
                             + lsi->from->ospf6_if->inf_trans_delay);
  ospf6_send (MSGT_LINKSTATE_ACK, directack,
              (struct sockaddr *)&lsi->from->hisaddr, lsi->from->ospf6_if);
  return;
}

void
delayed_acknowledge (struct lsa_internal *lsi)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = lsi->from->ospf6_if;
  assert (ospf6_if);

  o6log.dbex ("schedule delayed acknowledge to %s for %s",
              ospf6_if->interface->name, print_lsahdr (lsi->lsh));

  list_add_node (ospf6_if->delayed_ack, lsi);

  if (ospf6_if->send_ack == (struct thread *)NULL)
    ospf6_if->send_ack = thread_add_timer (master, send_linkstate_ack,
                                           ospf6_if,
                                           ospf6_if->rxmt_interval);

  return;
}

/* RFC2328 section 13 */
int
lsa_receive (struct lsa_hdr *lsh, struct neighbor *from)
{
  struct lsa_internal *newp, *oldp, *lsi;
  struct neighbor *nbr;
  struct timeval now;
  listnode n;
  int onrequest, ismore_recent, onretrans, acknowledge, acktype;

  newp = oldp = (struct lsa_internal *)NULL;
  ismore_recent = 1;
  acknowledge = 0;

  o6log.dbex ("receive %s", print_lsahdr (lsh));

  /* (1) */
  /* XXX LSA Checksum */

  /* (2) */
  switch (ntohs (lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
    case LST_LINK_LSA:
    case LST_INTRA_AREA_PREFIX_LSA:
      break;
    case LST_INTER_AREA_PREFIX_LSA:
    case LST_INTER_AREA_ROUTER_LSA:
    case LST_AS_EXTERNAL_LSA:
    default:
      o6log.dbex ("Unsupported LSA Type: %#x, Ignore",
                  ntohs (lsh->lsh_type));
      return -1;
    }

  /* (3) */
  /* XXX, Ebit Missmatch: AS-External-LSA */

  /* (4) */
  /* XXX, if MaxAge LSA and if we have no instance */

  gettimeofday (&now, (struct timezone *)NULL);
  newp = make_lsa_internal (lsh, from);
  oldp = lsa_lookup (lsh->lsh_type, lsh->lsh_id, lsh->lsh_advrtr,
                     from->ospf6_if->area, from->ospf6_if);

  /* for later use by (6) and (7) */
  /* check sending neighbor's LS request list */
  onrequest = 0;
  for (n = listhead (from->requestlist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *)getdata (n);
      assert (lsi->lsh);
      if (lsa_issame (newp->lsh, lsi->lsh))
        onrequest++;
    }
  /* check sending neighbor's LS retrans list */
  if (oldp)
    {
      n = list_lookup_node (oldp->retransing_nbr, from);
      if (n)
        onretrans = 1;
      else
        onretrans = 0;

      if (newp->lsh->lsh_seqnum == oldp->lsh->lsh_seqnum)
        acknowledge |= DUPLICATE;
    }

  /* (5) */
  if (!oldp || (ismore_recent = which_is_more_recent (newp, oldp)) < 0) 
    {
      o6log.dbex ("received is newer");

      /* (a) */
      if (oldp && now.tv_sec - oldp->installed <= MIN_LS_ARRIVAL)
        {
          o6log.dbex ("lsa arrived less than MinLSArrival.");
          lsa_delete (newp);
          return -1;
        }

      /* (b) */
      acknowledge |= lsa_flood (newp);

      /* (c) */
      if (oldp)
        {
          for (n = listhead (oldp->retransing_nbr); n; nextnode (n))
            {
              nbr = (struct neighbor *)getdata (n);
              detach_lsa_from_retranslist (oldp, nbr);
            }
          assert (list_isempty (oldp->retransing_nbr));
        }

      /* (d), which may cause routing table calculation */
      lsa_install (newp);

      /* (e) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          o6log.dbex ("%s aknowledge: direct", print_lsahdr (newp->lsh));
          list_add_node (from->direct_ack, newp);
        }
      else if (acktype == DELAYED_ACK)
        {
          o6log.dbex ("%s aknowledge: delayed", print_lsahdr (newp->lsh));
          delayed_acknowledge (newp);
        }
      else
        o6log.dbex ("%s aknowledge: none", print_lsahdr (newp->lsh));

      /* (f) */
      /* Self Originated LSA, section 13.4 */
      if (is_self_originated (newp) && oldp &&
          which_is_more_recent (newp, oldp) < 0)
        {
          update_ls_seqnum (newp);
          construct_lsa (newp);
          /* XXX prematuer aging */
        }
    }
  else if (onrequest) /* (6) */
    {
      /* BadLSReq */
      o6log.dbex ("received is not newer,"
                  " and %s is on his requestlist -> BadLSReq",
                  print_lsahdr (newp->lsh));
      lsa_delete (newp);
      thread_add_event (master, bad_lsreq, from, 0);
      return 0;
    }
  else if (ismore_recent == 0) /* (7) */
    {
      o6log.dbex ("received and had is the same instance");
      /* XXXXXX does this cause memory leak? where to release newp */
      o6log.pointer ("care about freeing %#x", newp);

      /* (a) if on retranslist, Treat this LSA as an Ack: Implied Ack */
      if (lslist_lookup (newp, from->retranslist))
        {
          assert (acknowledge & DUPLICATE);
          o6log.dbex ("treat %s as implied ack", print_lsahdr (newp->lsh));
          detach_lsa_from_retranslist (oldp, from);
          acknowledge |= IMPLIEDACK;
        }

      /* (b) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          o6log.dbex ("%s aknowledge: direct", print_lsahdr (newp->lsh));
          direct_acknowledge (newp);
        }
      else if (acktype == DELAYED_ACK)
        {
          o6log.dbex ("%s aknowledge: delayed", print_lsahdr (newp->lsh));
          delayed_acknowledge (newp);
        }
      else
        o6log.dbex ("%s aknowledge: none", print_lsahdr (newp->lsh));
    }
  else /* (8) previous database copy is more recent */
    {
      o6log.dbex ("already have newer copy");

      /* XXX, Seqnumber Wrapping */

      /* XXX, Send database copy of this LSA to this neighbor */
      assert (oldp);
      list_add_node (from->direct_ack, oldp);
      o6log.dbex ("send database copy back to neighbor");
      lsa_delete (newp);
    }
  return 0;
}

/* if we should resoponse to this LSA as direct acknowledgement,
   return 1, otherwise (delayed acknowledgement) return 0 */
/* RFC2328: Table 19: Sending link state acknowledgements. */
int 
ack_type (struct lsa_internal *newp, int acknowledge, int ismore_recent)
{
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  listnode n, m;

  assert (newp->from && newp->from->ospf6_if);
  ospf6_if = newp->from->ospf6_if;

  if (acknowledge & FLOODBACK)
    return NO_ACK;
  else if (ismore_recent < 0 && !(acknowledge & FLOODBACK))
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
  else if (acknowledge & DUPLICATE && acknowledge & IMPLIEDACK)
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
  else if (acknowledge & DUPLICATE && !(acknowledge & IMPLIEDACK))
    {
      return DIRECT_ACK;
    }
  else if (calc_lsa_age_external (newp) == MAXAGE)
    {
      if (lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
                      newp->lsh->lsh_advrtr, newp->area, newp->ospf6_if)
          == (struct lsa_internal *)NULL)
        {
          for (n = listhead (newp->area->ospf6_if_list);
               n;
               nextnode (n))
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

/* RFC2328 section 13.3 */
int
lsa_flood (struct lsa_internal *newp)
{
  struct neighbor *nbr = (struct neighbor *)NULL;
  listnode n, m;
  struct ospf6_if *ospf6_if;
  int ismore_recent, addretrans;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;
  int retval = 0;
  struct lsa_internal *lsi = (struct lsa_internal *)NULL;
  list eligible_ifacelist;

  assert (newp && newp->lsh && newp->area);

  o6log.dbex ("flooding %s", print_lsahdr (newp->lsh));

  eligible_ifacelist = list_init ();
  switch (GET_LSASCOPE (newp->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      list_add_node (eligible_ifacelist, newp->ospf6_if);
      break;
    case SCOPE_AREA:
      for (n = listhead (newp->area->ospf6_if_list); n; nextnode (n))
        list_add_node (eligible_ifacelist, getdata (n));
      break;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      zvlog_debug ("Not Reached!?");
      break;
    }

  /* for each eligible ospf_ifs */
  for (n = listhead (eligible_ifacelist);
       n;
       nextnode (n))
    {
      ospf6_if = (struct ospf6_if *)getdata (n);
      addretrans = 0;

      /* (1) for each neighbor */
      for (m = listhead (ospf6_if->nbr_list); m; nextnode (m))
        {
          nbr = (struct neighbor *) getdata (m);

          /* (a) */
          if (nbr->state < NBS_EXCHANGE)
            continue;  /* examin next neighbor */

          /* (b) */
          if (nbr->state == NBS_EXCHANGE
              || nbr->state == NBS_LOADING)
            {
              lsi = lslist_lookup (newp, nbr->requestlist);
              if (lsi)
                {
                  ismore_recent = which_is_more_recent (newp, lsi);
                  if (ismore_recent > 0)
                    {
                      o6log.dbex ("requesting is newer on %s",
                                  nbr->str);
                      continue; /* examin next neighbor */
                    }
                  else if (ismore_recent == 0)
                    {
                      o6log.dbex ("the same instance,delete from"
                                  " %s requestlist", nbr->str);
                      lsa_delete (lsi);
                      list_delete_by_val (nbr->requestlist, lsi);
                      continue; /* examin next neighbor */
                    }
                  else /* ismore_recent < 0(the new LSA is more recent) */
                    {
                      o6log.dbex ("flooding is newer,delete from"
                                  " %s requestlist",
                                  nbr->str);
                      lsa_delete (lsi);
                      list_delete_by_val (nbr->requestlist, lsi);
                    }
                }
            }

          /* (c) */
          if (newp->from == nbr)
            continue; /* examin next neighbor */

          /* (d) add retranslist */
          attach_lsa_to_retranslist (newp, nbr);
          o6log.dbex ("added to %s retranslist",
                       nbr->str);

          addretrans++;
          if (nbr->send_update == (struct thread *) NULL)
            {
              nbr->send_update = thread_add_timer
                (master, send_linkstate_update, nbr,
                nbr->ospf6_if->rxmt_interval);
            }
        }

      /* (2) */
      if (addretrans == 0)
        {
          o6log.dbex ("don't flood interface %s",
                      ospf6_if->interface->name);
          continue; /* examin next interface */
        }
      else if (newp->from && newp->from->ospf6_if == ospf6_if)
        {
          o6log.dbex ("flooding %s is floodback",
                      ospf6_if->interface->name);
          retval = FLOODBACK;
        }
      else
        o6log.dbex ("flood %s", ospf6_if->interface->name);

      /* (3) */
      if (newp->from && newp->from->ospf6_if == ospf6_if)
        {
          /* if from DR or BDR, don't need to flood this interface */
          if (newp->from->rtr_id == newp->from->ospf6_if->dr ||
              newp->from->rtr_id == newp->from->ospf6_if->bdr)
            continue; /* examin next interface */
        }

      /* (4) if I'm BDR, DR will flood this interface */
      if (newp->from && newp->from->ospf6_if == ospf6_if
          && ospf6_if->state == IFS_BDR)
        continue; /* examin next interface */

      /* (5) send LinkState Update */
      iov_clear (iov, MAXIOVLIST);
      newp->lsh->lsh_age =
        htons (calc_lsa_age_external (newp) + ospf6_if->inf_trans_delay);
      attach_lsa_to_iov (newp, iov);
      dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      dst.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
      dst.sin6_scope_id = if_nametoindex (nbr->ospf6_if->interface->name);
#endif /* HAVE_SIN6_SCOPE_ID */

      if (if_is_broadcast (ospf6_if->interface))
        {
          switch (ospf6_if->state)
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

      lsupdate = (struct linkstate_update *)
        iov_prepend (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (1);

      ospf6_send (MSGT_LINKSTATE_UPDATE, iov,
                 (struct sockaddr *)&dst, ospf6_if);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
    }

  return retval;
}


