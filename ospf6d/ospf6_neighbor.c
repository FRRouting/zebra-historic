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
nbs_change (state_t nbs_next, char *reason, struct neighbor *nbr)
{
  state_t nbs_previous;

  nbs_previous = nbr->state;
  nbr->state = nbs_next;

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBSCHANGE: [%s]->[%s](%s) on %s \n",
                nbs_name[nbs_previous], nbs_name[nbs_next], reason,
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

  if (nbs_previous == NBS_FULL && nbs_next == NBS_FULL)
    return 0;

  if (nbs_previous == NBS_FULL || nbs_next == NBS_FULL)
    nbs_full_change (nbr->ospf6_if);

  return 0;
}

int
nbs_full_change (struct ospf6_if *ospf6_if)
{
  construct_router_lsa (ospf6_if->area);
  if (ospf6_if->state == IFS_DR)
    {
      construct_network_lsa (ospf6_if);
      construct_intra_prefix_lsa (ospf6_if);
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
  list_delete_all_node (nbr->summarylist);
  list_delete_all_node (nbr->retranslist);
  lsa_list_clear_all (nbr->requestlist);
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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: HelloReceived on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: 2Way-Received on %s\n",
                 inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: NegotiationDone on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof(strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: ExchangeDone on %s\n",
                inet4str (nbp->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

  list_delete_all_node (nbr->dd_retrans);

  thread_add_timer (master, free_last_dd, nbr,
                    nbr->ospf6_if->rtr_dead_interval);

  if (listcount (nbr->requestlist) == 0)
    nbs_change (NBS_FULL, "Requestlist Empty", nbr);
  else
    {
      if (nbr->send_lsreq == NULL)
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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: LoadingDone on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

  if (listcount (nbr->requestlist) == 0)
    nbs_change (NBS_FULL, "LoadingDone", nbr);
  else
    {
#ifdef DEBUG_OSPF6
      ospf6_err ("BUG: LoadingDone but Requestlist Not Empty\n");
      assert (0);
#endif
    }

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG  (thread);
  assert (nbr);

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: AdjOK? on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: SeqNumberMismatch on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: BadLSReq on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: 1Way-Received on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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

#ifdef DEBUG_OSPF6
  {
    char strbuf[60];
    ospf6_info ("NBEVENT: InactivityTimer on %s\n",
                inet4str (nbr->rtr_id, strbuf, sizeof (strbuf)));
  }
#endif

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
  list candidate_list = NULL;
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
  if (candidate_list)
    list_delete_all (candidate_list);
  candidate_list = list_init();
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
          if (nbpi->bdr != nbpi->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpi);
              continue;
            }
          if (nbpj->bdr != nbpj->rtr_id)
            {
              list_delete_by_val (candidate_list, nbpj);
              continue;
            }
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
  if (candidate_list)
    list_delete_all (candidate_list);
  candidate_list = list_init();
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
      if (!list_isempty (candidate_list))
        assert (0); /* No one declare but candidate_list not empty */
      dr = bdr;
    }
  else
    {
      assert (candidate_list->count > 1);
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
                assert (0);
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
      if (dr == myself.rtr_id || prevdr == myself.rtr_id)
        {
#if 0
          myself.dr = dr;
          myself.bdr = bdr;
#endif
          gofive++;
          goto step_two;
        }
    }
  if (bdr != prevbdr)
    {
      if (bdr == myself.rtr_id || prevbdr == myself.rtr_id)
        {
#if 0
          myself.dr = dr;
          myself.bdr = bdr;
#endif
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
#if 0
          {
            struct thread dummy;

            dummy.arg = (void *)nbpi;
            adj_ok (&dummy);
          }
#else
          thread_add_event (master, adj_ok, nbpi, 0);
#endif
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

