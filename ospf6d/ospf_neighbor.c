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
nbs_change (state_t nbs_next, char *reason, struct neighbor *nbp)
{
  state_t nbs_previous;

  nbs_previous = nbp->state;
  nbp->state = nbs_next;

#ifdef DEBUG_OSPF
  log ("NBSCHANGE: [%s]->[%s](%s) on %s \n",
       nbs_name[nbs_previous], nbs_name[nbs_next], reason,
       inet_ntoa (nbp->rtr_id));
#endif

  if (nbs_previous == NBS_FULL || nbs_next == NBS_FULL)
    {
      if (nbs_previous == NBS_FULL && nbs_next == NBS_FULL)
	{
#ifdef DEBUG_OSPF
	  log ("NBSCHANGE: FULL->FULL, ???\n");
#endif
	  return 0;
	}
      nbs_full_change (nbp->interface);
    }

  return 0;
}

int
nbs_full_change (struct interface *iface)
{
  construct_router_lsa (iface->area);
  if (iface->state == IFS_DR)
    {
      construct_network_lsa (iface);
      construct_intra_prefix_lsa (iface);
    }
}

int
neighbor_thread_cancel (struct neighbor *nbp)
{
  if (nbp->inactivity_timer)
    thread_cancel (nbp->inactivity_timer);
  if (nbp->send_dd)
    thread_cancel (nbp->send_dd);
  if (nbp->send_lsreq)
    thread_cancel (nbp->send_lsreq);
  if (nbp->send_update)
    thread_cancel (nbp->send_update);

  nbp->inactivity_timer = nbp->send_dd = nbp->send_lsreq = nbp->send_update
    = (struct thread *)NULL;
}

int
list_cleared_of_lsa (struct neighbor *nbp)
{
  listnode n;

  list_clear_all (nbp->dd_retrans);
  list_clear_all (nbp->summarylist);
  list_clear_all (nbp->retranslist);
  lsa_list_clear_all (nbp->requestlist);
}

int
free_last_dd (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG (thread);
  if (!nbp)
    {
      log_warn ("free_last_dd() failed\n");
      return 0;
    }

  bzero (nbp->last_dd.options, sizeof (nbp->last_dd.options));
  nbp->last_dd.bits = 0;
  nbp->last_dd.sequence_number = 0;

  return 0;
}

/* RFC2328 section 10.4 */
int
need_adjacency (struct neighbor *nbp)
{

  if (nbp->interface->state == IFS_PTOP)
    return 1;
  if (nbp->interface->state == IFS_DR)
    return 1;
  if (nbp->interface->state == IFS_BDR)
    return 1;
  if (id_val (nbp->rtr_id) == id_val (nbp->interface->dr))
    return 1;
  if (id_val (nbp->rtr_id) == id_val (nbp->interface->bdr))
    return 1;

  return 0;
}

int
hello_received (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for hello_received()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("NBEVENT: HelloReceived on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  if (nbp->inactivity_timer)
    thread_cancel (nbp->inactivity_timer);

  nbp->inactivity_timer = thread_add_timer (master, inactivity_timer, nbp,
					    nbp->interface->rtr_dead_interval);

  if (nbp->state <= NBS_DOWN)
    nbs_change (NBS_INIT, "HelloReceived", nbp);

  return 0;
}

int
twoway_received (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for twoway_received()\n");
      return -1;
    }

  if (nbp->state > NBS_INIT)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: 2Way-Received on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  thread_add_event (master, neighbor_change, nbp->interface, 0);

  if (!need_adjacency (nbp))
    {
      nbs_change (NBS_TWOWAY, "No Need Adjacency", nbp);
      return 0;
    }
  else
    {
      nbs_change (NBS_EXSTART, "Need Adjacency", nbp);
    }

  DD_MSBIT_SET (nbp->dd_bits);
  DD_MBIT_SET (nbp->dd_bits);
  DD_IBIT_SET (nbp->dd_bits);
  if (nbp->send_dd)
    {
      thread_cancel (nbp->send_dd);
      nbp->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbp, 0);

  return 0;
}

int
negotiation_done (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for negotiation_done()\n");
      return -1;
    }

  if (nbp->state != NBS_EXSTART)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: NegotiationDone on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  nbs_change (NBS_EXCHANGE, "NegotiationDone", nbp);
  DD_IBIT_CLEAR (nbp->dd_bits);

  return 0;
}

int
exchange_done (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for exchange_done()\n");
      return -1;
    }

  if (nbp->state != NBS_EXCHANGE)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: ExchangeDone on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  list_clear_all (nbp->dd_retrans);

  thread_add_timer (master, free_last_dd, nbp, nbp->interface->rtr_dead_interval);

  if (listcount (nbp->requestlist) == 0)
    {
      nbs_change (NBS_FULL, "Requestlist Empty", nbp);
    }
  else
    {
      if (nbp->send_lsreq == NULL)
	thread_add_event (master, send_linkstate_request,
			  nbp, nbp->interface->rxmt_interval);
      nbs_change (NBS_LOADING, "Requestlist Not Empty", nbp);
    }
  return 0;
}

int
loading_done (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for exchange_done()\n");
      return -1;
    }

  if (nbp->state != NBS_LOADING)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: LoadingDone on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  if (listcount (nbp->requestlist) == 0)
    {
      nbs_change (NBS_FULL, "LoadingDone", nbp);
    }
  else
    {
#ifdef DEBUG_OSPF
      log ("BUG: LoadingDone but Requestlist Not Empty\n");
#endif
    }

  return 0;
}

int
adj_ok (struct thread *thread)
{
  struct neighbor *nbp;
  int i;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for adj_ok()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("NBEVENT: AdjOK? on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  if (nbp->state == NBS_TWOWAY)
    {
      if (!need_adjacency (nbp))
	{
	  nbs_change (NBS_TWOWAY, "No Need Adjacency", nbp);
	  return 0;
	}
      else
	{
	  nbs_change (NBS_EXSTART, "Need Adjacency", nbp);
	}

      DD_MSBIT_SET (nbp->dd_bits);
      DD_MBIT_SET (nbp->dd_bits);
      DD_IBIT_SET (nbp->dd_bits);
      if (nbp->send_dd)
	{
	  thread_cancel (nbp->send_dd);
	  nbp->send_dd = NULL;
	}
      thread_add_event (master, send_database_description, nbp, 0);
      return 0;
    }

  if (nbp->state >= NBS_EXSTART)
    {
      if (need_adjacency (nbp))
	{
	  return 0;
	}
      else
	{
	  nbs_change (NBS_TWOWAY, "No Need Adjacency", nbp);
	  list_cleared_of_lsa (nbp);
	}
    }

  return;
}

int
seqnumber_mismatch (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for seqnumber_mismatch()\n");
      return -1;
    }

  if (nbp->state < NBS_EXCHANGE)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: SeqNumberMismatch on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  nbs_change (NBS_EXSTART, "SeqNumberMismatch", nbp);

  DD_MSBIT_SET (nbp->dd_bits);
  DD_MBIT_SET (nbp->dd_bits);
  DD_IBIT_SET (nbp->dd_bits);
  list_cleared_of_lsa (nbp);
  if (nbp->send_dd)
    {
      thread_cancel (nbp->send_dd);
      nbp->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbp, 0);

  return 0;
}

int
bad_lsreq (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for bad_lsreq()\n");
      return -1;
    }

  if (nbp->state < NBS_EXCHANGE)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: BadLSReq on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  nbs_change (NBS_EXSTART, "BadLSReq", nbp);

  DD_MSBIT_SET (nbp->dd_bits);
  DD_MBIT_SET (nbp->dd_bits);
  DD_IBIT_SET (nbp->dd_bits);
  list_cleared_of_lsa (nbp);
  if (nbp->send_dd)
    {
      thread_cancel (nbp->send_dd);
      nbp->send_dd = NULL;
    }
  thread_add_event (master, send_database_description, nbp, 0);

  return 0;
}

int
oneway_received (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for oneway_received()\n");
      return -1;
    }

  if (nbp->state < NBS_TWOWAY)
    return 0;

#ifdef DEBUG_OSPF
  log ("NBEVENT: 1Way-Received on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  nbs_change (NBS_INIT, "1Way-Received", nbp);

  thread_add_event (master, neighbor_change, nbp->interface, 0);
  neighbor_thread_cancel (nbp);
  list_cleared_of_lsa (nbp);
  return 0;
}

int
inactivity_timer (struct thread *thread)
{
  struct neighbor *nbp;

  nbp = THREAD_ARG  (thread);
  if (!nbp)
    {
      log_warn ("!!!thread arg null for inactivity_timer()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("NBEVENT: InactivityTimer on %s\n", inet_ntoa (nbp->rtr_id));
#endif

  nbp->inactivity_timer = NULL;
  nbp->dr = nbp->bdr = nbp->prevdr = nbp->prevbdr = 0;
  nbs_change (NBS_DOWN, "InactivityTimer", nbp);
  neighbor_thread_cancel (nbp);
  list_cleared_of_lsa (nbp);
  thread_add_event (master, neighbor_change, nbp->interface, 0);

  return 0;
}

/* 9.4 of RFC2328 */
int
dr_election (struct ospf_if *iface)
{
  list candidate_list = NULL;
  listnode i, j;
  ifid_t prevdr, prevbdr, dr, bdr;
  struct neighbor *nbpi, *nbpj, myself;
  int declare = 0;
  int drchosen = 0;
  int gofive = 0;

  /* pseudo neighbor "myself" */
  bzero (&myself, sizeof (myself));
  myself.state = NBS_TWOWAY;
  myself.dr = id_val (iface->dr);
  myself.bdr = id_val (iface->bdr);
  myself.rtr_pri = iface->rtr_pri;
  myself.ifid = iface->ifid;
  id_val (myself.rtr_id) = id_val (iface->area->ospf->router_id);

 step_one:

  id_val (iface->prevdr) = prevdr = id_val (iface->dr);
  id_val (iface->prevbdr) = prevbdr = id_val (iface->bdr);

 step_two:

  /* Calculate Backup Designated Router. */
  /* Make Candidate list */
  if (candidate_list)
    list_delete_all (candidate_list);
  candidate_list = list_init();
  declare = 0;
  for (i = listhead (iface->nb_list); i; nextnode (i))
    {
      nbpi = getdata (i);
      if (nbpi->rtr_pri == 0)
	continue;
      if (nbpi->state < NBS_TWOWAY)
	continue;
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (nbpi->dr == nbpi->ifid)
	    continue;
	  if (nbpi->bdr == nbpi->ifid)
	    declare++;
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (nbpi->dr == id_val (nbpi->rtr_id))
	    continue;
	  if (nbpi->bdr == id_val (nbpi->rtr_id))
	    declare++;
	}
      else 
	{
	  log ("BUG! Unknown Version in dr_election\n");
	  return -1;
	}
      list_add_node (candidate_list, nbpi);
    }
  if (myself.rtr_pri)
    {
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (myself.dr != myself.ifid)
	    {
	      if (myself.bdr == myself.ifid)
		declare++;
	      list_add_node (candidate_list, &myself);
	    }
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (myself.dr != id_val (myself.rtr_id))
	    {
	      if (myself.bdr == id_val (myself.rtr_id))
		declare++;
	      list_add_node (candidate_list, &myself);
	    }
	}
      else
	{
	  log ("BUG! Unknown Version in dr_election\n");
	  return -1;
	}
    }

  /* Elect BDR */
  for (i = listhead (candidate_list);
       candidate_list->count > 1;
       i = listhead (candidate_list))
    {
      j = i;
      nextnode(j);
      if (!j)
	{
	  log ("bug in dr_election?, BDR section, %d time\n", gofive + 1);
	  exit (-1);
	}
      nbpi = (struct neighbor *)getdata (i);
      nbpj = (struct neighbor *)getdata (j);
      if (declare)
	{
	  if (iface->area->ospf->version == OSPF_V2)
	    {
	      if (nbpi->bdr != nbpi->ifid)
		{
		  list_delete_node (candidate_list, i);
		  continue;
		}
	      if (nbpj->bdr != nbpj->ifid)
		{
		  list_delete_node (candidate_list, j);
		  continue;
		}
	    }
	  else if (iface->area->ospf->version == OSPF_V3)
	    {
	      if (nbpi->bdr != nbpi->ifid)
		{
		  list_delete_node (candidate_list, i);
		  continue;
		}
	      if (nbpj->bdr != nbpj->ifid)
		{
		  list_delete_node (candidate_list, j);
		  continue;
		}
	    }
	  else
	    {
	      log ("BUG! Unknown Version in dr_election()\n");
	      return -1;
	    }
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
	  if (id_val (nbpi->rtr_id) > id_val (nbpj->rtr_id))
	    {
	      list_delete_node (candidate_list, j);
	      continue;
	    }
	  else if (id_val (nbpi->rtr_id) < id_val (nbpj->rtr_id))
	    {
	      list_delete_node (candidate_list, i);
	      continue;
	    }
	  else
	    {
	      char a[16], b[16];
	      log ("bug?, rtr_id compare in BDR section, %d time\n", gofive + 1);
	      bcopy (inet_ntoa (nbpi->rtr_id), a, sizeof (a));
	      bcopy (inet_ntoa (nbpj->rtr_id), b, sizeof (b));
	      log (" comparing %s, %s\n", a, b);
	      exit (-1);
	    }
	}
    }
  if (!list_isempty (candidate_list))
    {
      if (iface->area->ospf->version == OSPF_V2)
	bdr = ((struct neighbor *)getdata (listhead (candidate_list)))->ifid;
      else if (iface->area->ospf->version == OSPF_V3)
	bdr = id_val (((struct neighbor *)getdata (listhead (candidate_list)))->rtr_id);
      else
	{
	  log ("BUG! Unknown Version in dr_election()\n");
	  return -1;
	}
    }
  else
    bdr = 0;

 step_three:

  /* Make Candidate list */
  if (candidate_list)
    list_delete_all (candidate_list);
  candidate_list = list_init();
  declare = 0;
  for (i = listhead (iface->nb_list); i; nextnode (i))
    {
      nbpi = getdata (i);
      if (nbpi->rtr_pri == 0)
	continue;
      if (nbpi->state < NBS_TWOWAY)
	continue;
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (nbpi->dr == nbpi->ifid)
	    {
	      declare++;
	      list_add_node (candidate_list, nbpi);
	    }
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (nbpi->dr == id_val (nbpi->rtr_id))
	    {
	      declare++;
	      list_add_node (candidate_list, nbpi);
	    }
	}
      else
	{
	  log ("BUG! Unknown Version in dr_election()\n");
	  return -1;
	}
    }
  if (myself.rtr_pri)
    {
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (myself.dr == myself.ifid)
	    {
	      list_add_node (candidate_list, &myself);
	      declare++;
	    }
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (myself.dr == id_val (myself.rtr_id))
	    {
	      list_add_node (candidate_list, &myself);
	      declare++;
	    }
	}
      else
	{
	  log ("BUG! Unknown Version in dr_election()\n");
	  return -1;
	}
    }

  /* Elect DR */
  if (declare == 0)
    {
      if (!list_isempty (candidate_list))
	log ("bug? no-one declare but candidate list not empty\n");
      dr = bdr;
    }
  else
    {
      for (i = listhead (candidate_list);
	   candidate_list->count > 1;
	   i = listhead (candidate_list))
	{
	  j = i;
	  nextnode (j);
	  if (!j)
	    {
	      char a[16], b[16];
	      log ("bug in dr_election?, Elect DR section, %d time\n", gofive + 1);
	      exit (-1);
	    }
	  nbpi = (struct neighbor *)getdata (i);
	  nbpj = (struct neighbor *)getdata (j);

	  if (iface->area->ospf->version == OSPF_V2)
	    {
	      if (nbpi->dr != nbpi->ifid)
		{
		  list_delete_node (candidate_list, i);
		  continue;
		}
	      if (nbpj->dr != nbpj->ifid)
		{
		  list_delete_node (candidate_list, j);
		  continue;
		}
	    }
	  else if (iface->area->ospf->version == OSPF_V3)
	    {
	      if (nbpi->dr != id_val (nbpi->rtr_id))
		{
		  list_delete_node (candidate_list, i);
		  continue;
		}
	      if (nbpj->dr != id_val (nbpj->rtr_id))
		{
		  list_delete_node (candidate_list, j);
		  continue;
		}
	    }
	  else
	    {
	      log ("BUG! Unknown Version in dr_election()\n");
	      return -1;
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
	      if (id_val (nbpi->rtr_id) > id_val (nbpj->rtr_id))
		{
		  list_delete_node (candidate_list, j);
		  continue;
		}
	      else if (id_val (nbpi->rtr_id) < id_val (nbpj->rtr_id))
		{
		  list_delete_node (candidate_list, i);
		  continue;
		}
	      else
		{
		  char a[16], b[16];
		  log ("bug?, rtr_id compare in DR section, %d time\n", gofive + 1);
		  bcopy (inet_ntoa (nbpi->rtr_id), a, sizeof (a));
		  bcopy (inet_ntoa (nbpj->rtr_id), b, sizeof (b));
		  log (" comparing %s, %s\n", a, b);
		  exit (-1);
		}
	    }
	}
      if (!list_isempty (candidate_list))
	{
	  if (iface->area->ospf->version == OSPF_V2)
	    dr = ((struct neighbor *)getdata (listhead (candidate_list)))->ifid;
	  else if (iface->area->ospf->version == OSPF_V3)
	    dr = id_val (((struct neighbor *)getdata (listhead (candidate_list)))->rtr_id);
	  else
	    {
	      log ("BUG! Unknown Version in dr_election()\n");
	      return -1;
	    }
	}
      else
	{
	  log ("bug?, declared but no candidate found in DR election\n");
	}
    }

 step_four:

  if (gofive)
    goto step_five;

  if (dr != prevdr)
    {
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (dr == myself.ifid || prevdr == myself.ifid)
	    {
	      myself.dr = dr;
	      myself.bdr = bdr;
	      gofive++;
	      goto step_two;
	    }
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (dr == id_val (myself.rtr_id) || prevdr == id_val (myself.rtr_id))
	    {
	      myself.dr = dr;
	      myself.bdr = bdr;
	      gofive++;
	      goto step_two;
	    }
	}
      else
	{
	  log ("BUG! Unknown Version in dr_election()\n");
	  return -1;
	}
    }
  if (bdr != prevbdr)
    {
      if (iface->area->ospf->version == OSPF_V2)
	{
	  if (bdr == myself.ifid || prevbdr == myself.ifid)
	    {
	      myself.dr = dr;
	      myself.bdr = bdr;
	      gofive++;
	      goto step_two;
	    }
	}
      else if (iface->area->ospf->version == OSPF_V3)
	{
	  if (bdr == id_val (myself.rtr_id) || prevbdr == id_val (myself.rtr_id))
	    {
	      myself.dr = dr;
	      myself.bdr = bdr;
	      gofive++;
	      goto step_two;
	    }
	}
      else
	{
	  log ("BUG! Unknown Version in dr_election()\n");
	  return -1;
	}
    }

 step_five:

  id_val (iface->dr) = dr;
  id_val (iface->bdr) = bdr;

  if (prevdr != dr || prevbdr != bdr)
    {
      for (i = listhead (iface->nb_list); i; nextnode (i))
	{
	  nbpi = getdata (i);
	  if (nbpi->state < NBS_TWOWAY)
	    continue;
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

  if (iface->area->ospf->version == OSPF_V2)
    {
      if (dr == myself.ifid)
	{
	  assert (bdr != myself.ifid);
	  return IFS_DR;
	}
      else if (bdr == myself.ifid)
	{
	  assert (dr != myself.ifid);
	  return IFS_BDR;
	}
      else
	{
	  return IFS_DROTHER;
	}
    }
  else if (iface->area->ospf->version == OSPF_V3)
    {
      if (dr == id_val (myself.rtr_id))
	{
	  assert (bdr != id_val (myself.rtr_id));
	  return IFS_DR;
	}
      else if (bdr == id_val (myself.rtr_id))
	{
	  assert (dr != id_val (myself.rtr_id));
	  return IFS_BDR;
	}
      else
	{
	  return IFS_DROTHER;
	}
    }
  else
    {
      log ("BUG! Unknown Version in dr_election()\n");
      return -1;
    }
}
