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

void
delete_ospf6_nbr (struct neighbor *nbr)
{
}

int
nbs_change (state_t nbs_next, char *reason, struct neighbor *nbr)
{
  state_t nbs_previous;
  listnode n;
  struct area *area;

  nbs_previous = nbr->state;
  nbr->state = nbs_next;

  if (nbs_previous == nbs_next)
    return 0;

  if (reason)
    zvlog_info ("nbr %s: [%s]->[%s](%s)",
                 nbr->str,
                 nbs_name[nbs_previous], nbs_name[nbs_next],
                 reason);
  else
    zvlog_info ("nbr %s: [%s]->[%s]",
                 nbr->str,
                 nbs_name[nbs_previous], nbs_name[nbs_next]);

  if (nbs_previous == NBS_FULL || nbs_next == NBS_FULL)
    nbs_full_change (nbr->ospf6_if);

  /* check for LSAs that already reached MaxAge */
  /* for Area scope LSA */
  if (!count_nbr_in_state (NBS_EXCHANGE, nbr->ospf6_if->area) &&
      !count_nbr_in_state (NBS_LOADING, nbr->ospf6_if->area))
    ospf6_lsdb_maxage_remove_area (nbr->ospf6_if->area);

  /* for AS scope LSA */
  for (n = listhead (nbr->ospf6_if->area->ospf6->area_list); n;
       nextnode (n))
    {
      area = (struct area *) getdata (n);
      /* when there's one area fits, return */
      if (count_nbr_in_state (NBS_EXCHANGE, nbr->ospf6_if->area) ||
          count_nbr_in_state (NBS_LOADING, nbr->ospf6_if->area))
        return 0;
    }
  ospf6_lsdb_maxage_remove_as (nbr->ospf6_if->area->ospf6);

  return 0;
}

int
nbs_full_change (struct ospf6_if *ospf6_if)
{
  struct ospf6_lsa *lsa;

  /* construct Router-LSA */
  lsa = ospf6_make_router_lsa (ospf6_if->area);
  if (lsa)
    {
      ospf6_lsa_flood (lsa);
      ospf6_lsdb_install (lsa);
      ospf6_lsa_unlock (lsa);
    }

  if (ospf6_if->state == IFS_DR)
    {
      /* construct Network-LSA */
      lsa = ospf6_make_network_lsa (ospf6_if);
      if (lsa)
        {
          ospf6_lsa_flood (lsa);
          ospf6_lsdb_install (lsa);
          ospf6_lsa_unlock (lsa);
        }
      /* construct Intra-Area-Prefix-LSA */
      lsa = ospf6_make_intra_prefix_lsa (ospf6_if);
      if (lsa)
        {
          ospf6_lsa_flood (lsa);
          ospf6_lsdb_install (lsa);
          ospf6_lsa_unlock (lsa);
        }
    }
  return 0;
}

int
neighbor_thread_cancel (struct neighbor *nbr)
{
  if (nbr->inactivity_timer)
    thread_cancel (nbr->inactivity_timer);
  if (nbr->send_dd)
    thread_cancel (nbr->send_dd);
  if (nbr->send_lsreq)
    thread_cancel (nbr->send_lsreq);
  if (nbr->send_update)
    thread_cancel (nbr->send_update);

  nbr->inactivity_timer = nbr->send_dd = nbr->send_lsreq = nbr->send_update
    = (struct thread *)NULL;
  return 0;
}

int
list_cleared_of_lsa (struct neighbor *nbr)
{
  list_delete_all_node (nbr->dd_retrans);
  ospf6_lsdb_finish_neighbor (nbr);
  ospf6_lsdb_init_neighbor (nbr);
  return 0;
}

int
free_last_dd (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG (thread);
  assert (nbr);
  memset (&nbr->last_dd, 0, sizeof (struct database_description));
  return 0;
}

/* RFC2328 section 10.4 */
int
need_adjacency (struct neighbor *nbr)
{

  if (nbr->ospf6_if->state == IFS_PTOP)
    return 1;
  if (nbr->ospf6_if->state == IFS_DR)
    return 1;
  if (nbr->ospf6_if->state == IFS_BDR)
    return 1;
  if (nbr->rtr_id == nbr->ospf6_if->dr)
    return 1;
  if (nbr->rtr_id == nbr->ospf6_if->bdr)
    return 1;

  return 0;
}

int
hello_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  zvlog_info ("nbr %s: *HelloReceived*", nbr->str);

  if (nbr->inactivity_timer)
    thread_cancel (nbr->inactivity_timer);

  nbr->inactivity_timer = thread_add_timer (master, inactivity_timer, nbr,
                                            nbr->ospf6_if->rtr_dead_interval);
  if (nbr->state <= NBS_DOWN)
    nbs_change (NBS_INIT, "HelloReceived", nbr);
  return 0;
}

int
twoway_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state > NBS_INIT)
    return 0;

  zvlog_info ("nbr %s: *2Way-Received*", nbr->str);

  thread_add_event (master, neighbor_change, nbr->ospf6_if, 0);

  if (!need_adjacency (nbr))
    {
      nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
      return 0;
    }
  else
    {
      nbs_change (NBS_EXSTART, "Need Adjacency", nbr);
    }

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);
  if (nbr->send_dd)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbr, 0);

  return 0;
}

int
negotiation_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_EXSTART)
    return 0;

  zvlog_info ("nbr %s: *NegotiationDone*", nbr->str);

  nbs_change (NBS_EXCHANGE, "NegotiationDone", nbr);
  DD_IBIT_CLEAR (nbr->dd_bits);

  return 0;
}

int
exchange_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_EXCHANGE)
    return 0;

  if (nbr->send_dd != (struct thread *)NULL)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = (struct thread *)NULL;
    }
  zvlog_info ("nbr %s: *ExchangeDone*", nbr->str);

  list_delete_all_node (nbr->dd_retrans);

  thread_add_timer (master, free_last_dd, nbr,
                    nbr->ospf6_if->rtr_dead_interval);

  if (list_isempty (nbr->requestlist))
    nbs_change (NBS_FULL, "Requestlist Empty", nbr);
  else
    {
      if (nbr->send_lsreq == (struct thread *)NULL)
        thread_add_event (master, send_linkstate_request,
                          nbr, nbr->ospf6_if->rxmt_interval);
      nbs_change (NBS_LOADING, "Requestlist Not Empty", nbr);
    }
  return 0;
}

int
loading_done (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state != NBS_LOADING)
    return 0;

  zvlog_info ("nbr %s: *LoadingDone*", nbr->str);

  if (list_isempty (nbr->requestlist))
    nbs_change (NBS_FULL, "LoadingDone", nbr);
  else
    {
      zvlog_debug ("BUG: LoadingDone for %s but Requestlist Not Empty",
                   nbr->str);
      assert (0);
    }

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  zvlog_info ("nbr %s: *AdjOK?*", nbr->str);

  if (nbr->state == NBS_TWOWAY)
    {
      if (!need_adjacency (nbr))
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
          return 0;
        }
      else
        nbs_change (NBS_EXSTART, "Need Adjacency", nbr);

      DD_MSBIT_SET (nbr->dd_bits);
      DD_MBIT_SET (nbr->dd_bits);
      DD_IBIT_SET (nbr->dd_bits);
      if (nbr->send_dd)
        {
          thread_cancel (nbr->send_dd);
          nbr->send_dd = NULL;
        }
      thread_add_event (master, send_database_description, nbr, 0);
      return 0;
    }

  if (nbr->state >= NBS_EXSTART)
    {
      if (need_adjacency (nbr))
        return 0;
      else
        {
          nbs_change (NBS_TWOWAY, "No Need Adjacency", nbr);
          list_cleared_of_lsa (nbr);
        }
    }
  return 0;
}

int
seqnumber_mismatch (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_EXCHANGE)
    return 0;

  zvlog_info ("nbr %s: *SeqNumberMismatch*", nbr->str);
  nbs_change (NBS_EXSTART, "SeqNumberMismatch", nbr);

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);
  list_cleared_of_lsa (nbr);
  if (nbr->send_dd)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbr, 0);

  return 0;
}

int
bad_lsreq (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_EXCHANGE)
    return 0;

  zvlog_info ("nbr %s: *BadLSReq*", nbr->str);

  nbs_change (NBS_EXSTART, "BadLSReq", nbr);

  DD_MSBIT_SET (nbr->dd_bits);
  DD_MBIT_SET (nbr->dd_bits);
  DD_IBIT_SET (nbr->dd_bits);
  list_cleared_of_lsa (nbr);
  if (nbr->send_dd)
    {
      thread_cancel (nbr->send_dd);
      nbr->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbr, 0);

  return 0;
}

int
oneway_received (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  if (nbr->state < NBS_TWOWAY)
    return 0;

  zvlog_info ("nbr %s: *1Way-Received*", nbr->str);
  nbs_change (NBS_INIT, "1Way-Received", nbr);

  thread_add_event (master, neighbor_change, nbr->ospf6_if, 0);
  neighbor_thread_cancel (nbr);
  list_cleared_of_lsa (nbr);
  return 0;
}

int
inactivity_timer (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

  zvlog_info ("nbr %s: *InactivityTimer*", nbr->str);

  nbr->inactivity_timer = NULL;
  nbr->dr = nbr->bdr = nbr->prevdr = nbr->prevbdr = 0;
  nbs_change (NBS_DOWN, "InactivityTimer", nbr);
  neighbor_thread_cancel (nbr);
  list_cleared_of_lsa (nbr);
  thread_add_event (master, neighbor_change, nbr->ospf6_if, 0);

  return 0;
}


/* 9.4 of RFC2328 */
int
dr_election (struct ospf6_if *ospf6_if)
{
  list candidate_list = list_init ();
  listnode i, j, n;
  ifid_t prevdr, prevbdr, dr = 0, bdr;
  struct neighbor *nbpi, *nbpj, myself, *nbr;
  int declare = 0;
  int gofive = 0;

  /* pseudo neighbor "myself" */
  memset (&myself, 0, sizeof (myself));
  myself.state = NBS_TWOWAY;
  myself.dr = ospf6_if->dr;
  myself.bdr = ospf6_if->bdr;
  myself.rtr_pri = ospf6_if->rtr_pri;
  myself.ifid = ospf6_if->ifid;
  myself.rtr_id = ospf6_if->area->ospf6->router_id;

/* step_one: */

  ospf6_if->prevdr = prevdr = ospf6_if->dr;
  ospf6_if->prevbdr = prevbdr = ospf6_if->bdr;

step_two:

  /* Calculate Backup Designated Router. */
  /* Make Candidate list */
  if (!list_isempty (candidate_list))
    list_delete_all_node (candidate_list);
  declare = 0;
  for (i = listhead (ospf6_if->nbr_list); i; nextnode (i))
    {
      nbpi = (struct neighbor *)getdata (i);
      if (nbpi->rtr_pri == 0)
        continue;
      if (nbpi->state < NBS_TWOWAY)
        continue;
      if (nbpi->dr == nbpi->rtr_id)
        continue;
      if (nbpi->bdr == nbpi->rtr_id)
        declare++;
      list_add_node (candidate_list, nbpi);
    }

  if (myself.rtr_pri)
    {
      if (myself.dr != myself.rtr_id)
        {
          if (myself.bdr == myself.rtr_id)
            declare++;
          list_add_node (candidate_list, &myself);
        }
    }

  /* Elect BDR */
  for (i = listhead (candidate_list);
       candidate_list->count > 1;
       i = listhead (candidate_list))
    {
      j = i;
      nextnode(j);
      assert (j);
      nbpi = (struct neighbor *)getdata (i);
      nbpj = (struct neighbor *)getdata (j);
      if (declare)
        {
          int deleted = 0;
          if (nbpi->bdr != nbpi->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpi);
              deleted++;
            }
          if (nbpj->bdr != nbpj->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpj);
              deleted++;
            }
          if (deleted)
            continue;
        }
      if (nbpi->rtr_pri > nbpj->rtr_pri)
        {
          list_delete_by_val (candidate_list, nbpj);
          continue;
        }
      else if (nbpi->rtr_pri < nbpj->rtr_pri)
        {
          list_delete_by_val (candidate_list, nbpi);
          continue;
        }
      else /* equal, case of tie */
        {
          if (nbpi->rtr_id > nbpj->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpj);
              continue;
            }
          else if (nbpi->rtr_id < nbpj->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpi);
              continue;
            }
          else
            assert (0);
        }
    }

  if (!list_isempty (candidate_list))
    {
      assert (candidate_list->count == 1);
      n = listhead (candidate_list);
      nbr = (struct neighbor *)getdata (n);
      bdr = nbr->rtr_id;
    }
  else
    bdr = 0;

/* step_three: */

  /* Calculate Designated Router. */
  /* Make Candidate list */
  if (!list_isempty (candidate_list))
    list_delete_all_node (candidate_list);
  declare = 0;
  for (i = listhead (ospf6_if->nbr_list); i; nextnode (i))
    {
      nbpi = (struct neighbor *)getdata (i);
      if (nbpi->rtr_pri == 0)
        continue;
      if (nbpi->state < NBS_TWOWAY)
        continue;
      if (nbpi->dr == nbpi->rtr_id)
        {
          declare++;
          list_add_node (candidate_list, nbpi);
        }
    }
  if (myself.rtr_pri)
    {
      if (myself.dr == myself.rtr_id)
        {
          declare++;
          list_add_node (candidate_list, &myself);
        }
    }

  /* Elect DR */
  if (declare == 0)
    {
      assert (list_isempty (candidate_list));
      /* No one declare but candidate_list not empty */
      dr = bdr;
    }
  else
    {
      assert (!list_isempty (candidate_list));
      for (i = listhead (candidate_list);
           candidate_list->count > 1;
           i = listhead (candidate_list))
        {
          j = i;
          nextnode (j);
          assert (j);
          nbpi = (struct neighbor *)getdata (i);
          nbpj = (struct neighbor *)getdata (j);

          if (nbpi->dr != nbpi->rtr_id)
            {
              list_delete_node (candidate_list, i);
              continue;
            }
          if (nbpj->dr != nbpj->rtr_id)
            {
              list_delete_node (candidate_list, j);
              continue;
            }

          if (nbpi->rtr_pri > nbpj->rtr_pri)
            {
              list_delete_node (candidate_list, j);
              continue;
            }
          else if (nbpi->rtr_pri < nbpj->rtr_pri)
            {
              list_delete_node (candidate_list, i);
              continue;
            }
          else /* equal, case of tie */
            {
              if (nbpi->rtr_id > nbpj->rtr_id)
                {
                  list_delete_node (candidate_list, j);
                  continue;
                }
              else if (nbpi->rtr_id < nbpj->rtr_id)
                {
                  list_delete_node (candidate_list, i);
                  continue;
                }
              else
                {
                  o6log.neighbor ("!!the same router id"
                                  " for different neighbor");
                  list_delete_node (candidate_list, i);
                  continue;
                }
            }
        }
      if (!list_isempty (candidate_list))
        {
          assert (candidate_list->count == 1);
          n = listhead (candidate_list);
          nbr = (struct neighbor *)getdata (n);
          dr = nbr->rtr_id;
        }
      else
        assert (0);
    }

/* step_four: */

  if (gofive)
    goto step_five;

  if (dr != prevdr)
    {
      if ((dr == myself.rtr_id || prevdr == myself.rtr_id)
          && !(dr == myself.rtr_id && prevdr == myself.rtr_id))
        {
          myself.dr = dr;
          myself.bdr = bdr;
          gofive++;
          goto step_two;
        }
    }
  if (bdr != prevbdr)
    {
      if ((bdr == myself.rtr_id || prevbdr == myself.rtr_id)
          && !(bdr == myself.rtr_id && prevbdr == myself.rtr_id))
        {
          myself.dr = dr;
          myself.bdr = bdr;
          gofive++;
          goto step_two;
        }
    }

step_five:

  ospf6_if->dr = dr;
  ospf6_if->bdr = bdr;

  if (prevdr != dr || prevbdr != bdr)
    {
      for (i = listhead (ospf6_if->nbr_list); i; nextnode (i))
        {
          nbpi = getdata (i);
          if (nbpi->state < NBS_TWOWAY)
            continue;
          /* Schedule or Execute AdjOK. which does "invoke" mean? */
          thread_add_event (master, adj_ok, nbpi, 0);
        }
    }

  if (dr == myself.rtr_id)
    {
      assert (bdr != myself.rtr_id);
      return IFS_DR;
    }
  else if (bdr == myself.rtr_id)
    {
      assert (dr != myself.rtr_id);
      return IFS_BDR;
    }
  else
    return IFS_DROTHER;
}

/* count neighbor which is in "state" in this area*/
unsigned int
count_nbr_in_state (state_t state, struct area *area)
{
  listnode n, o;
  struct ospf6_if *o6if;
  struct neighbor *nbr;
  unsigned int count = 0;

  for (n = listhead (area->ospf6_if_list); n; nextnode (n))
    {
      o6if = (struct ospf6_if *) getdata (n);
      for (o = listhead (o6if->nbr_list); o; nextnode (o))
        {
          nbr = (struct neighbor *) getdata (o);
          if (nbr->state == state)
            count++;
        }
    }
  return count;
}

