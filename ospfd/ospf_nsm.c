/* OSPF version 2  Neighbor State Machine
   From RFC2328 [OSPF Version 2]
   Copyright (C) 1999 Toshiaki Takada

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"

/* OSPF NSM functions. */

int
ospf_inactivity_timer (struct thread *thread)
{
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);

  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_InactivityTimer);

  zlog (NULL, LOG_DEBUG, "NSM [%s]: Timer (Inactivity timer expire)",
	inet_ntoa (nbr->router_id));

  return 0;
}

int
nsm_ignore (struct ospf_neighbor *nbr)
{
  if (debug (DEBUG_OSPF_NSM))
    zlog (NULL, LOG_INFO, "NSM [%s]: nsm_ignore called", nbr->host);

  return 0;
}

int
nsm_hello_received (struct ospf_neighbor *nbr)
{
  /* Start or Restart Inactivity Timer. */
  if (nbr->t_inactivity)
    OSPF_NSM_TIMER_OFF (nbr->t_inactivity);
  
  OSPF_NSM_TIMER_ON (nbr->t_inactivity, ospf_inactivity_timer,
		     nbr->v_inactivity);

  return 0;
}

int
nsm_start (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_twoway_received (struct ospf_neighbor *nbr)
{
  struct ospf_interface *oi;
  int next_state = NSM_TwoWay;

  oi = nbr->oi;

  /* These netowork types must be adjacency. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    next_state = NSM_ExStart;

  /* Router itself is the DRouter or the BDRouter. */
  if (!IPV4_ADDR_CMP (&ospf_top->router_id, &oi->d_router) ||
      !IPV4_ADDR_CMP (&ospf_top->router_id, &oi->bd_router))
    next_state = NSM_ExStart;

  /* Neighboring Router is the DRouter or the BDRouter. */
  if (!IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router) ||
      !IPV4_ADDR_CMP (&nbr->router_id, &nbr->bd_router))
    next_state = NSM_ExStart;

  if (next_state == NSM_ExStart)
    {
      /* Get initial sequence number from time (). */
      if (nbr->dd_seqnum == 0)
	nbr->dd_seqnum = time (NULL);
      else
	nbr->dd_seqnum++;

      OSPF_NSM_WRITE_ON (nbr->t_write, ospf_db_desc_send, oi->fd);
      /* DD packet retransmitsion timer set. */
    }

  /* Schedule DR Election. */
  OSPF_ISM_EVENT_SCHEDULE (oi, ISM_NeighborChange);

  return next_state;
}

int
nsm_negotiation_done (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_exchange_done (struct ospf_neighbor *nbr)
{
  if (list_isempty (nbr->ls_request))
    return NSM_Full;

  /* Send Link State Request. */

  return NSM_Loading;
}

int
nsm_bad_ls_req (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_adj_ok (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_seq_number_mismatch (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_oneway_received (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_kill_nbr (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_inactivity_timer (struct ospf_neighbor *nbr)
{
  return 0;
}

int
nsm_ll_down (struct ospf_neighbor *nbr)
{
  return 0;
}

/* Neighbor State Machine */
struct {
  int (*func) ();
  int next_state;
} NSM [OSPF_NSM_STATUS_MAX][OSPF_NSM_EVENT_MAX] =
{
  {
    /* DependUpon: dummy state. */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_ignore,              NSM_DependUpon }, /* HelloReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* Start             */
    { nsm_ignore,              NSM_DependUpon }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* NegotiationDone   */
    { nsm_ignore,              NSM_DependUpon }, /* ExchangeDone      */
    { nsm_ignore,              NSM_DependUpon }, /* BadLSReq          */
    { nsm_ignore,              NSM_DependUpon }, /* LoadingDone       */
    { nsm_ignore,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_DependUpon }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_DependUpon }, /* 1-WayReceived     */
    { nsm_ignore,              NSM_DependUpon }, /* KillNbr           */
    { nsm_ignore,              NSM_DependUpon }, /* InactivityTimer   */
    { nsm_ignore,              NSM_DependUpon }, /* LLDown            */
  },
  {
    /* Down: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_start,               NSM_Attempt    }, /* Start             */
    { nsm_ignore,              NSM_Down       }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Down       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Down       }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Down       }, /* BadLSReq          */
    { nsm_ignore,              NSM_Down       }, /* LoadingDone       */
    { nsm_ignore,              NSM_Down       }, /* AdjOK?            */
    { nsm_ignore,              NSM_Down       }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Down       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Attempt: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Attempt    }, /* Start             */
    { nsm_ignore,              NSM_Attempt    }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Attempt    }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Attempt    }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Attempt    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Attempt    }, /* LoadingDone       */
    { nsm_ignore,              NSM_Attempt    }, /* AdjOK?            */
    { nsm_ignore,              NSM_Attempt    }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Attempt    }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Init: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Init       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Init       }, /* Start             */
    { nsm_twoway_received,     NSM_DependUpon }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Init       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Init       }, /* ExchangeDone      */
    { nsm_ignore,              NSM_Init       }, /* BadLSReq          */
    { nsm_ignore,              NSM_Init       }, /* LoadingDone       */
    { nsm_ignore,              NSM_Init       }, /* AdjOK?            */
    { nsm_ignore,              NSM_Init       }, /* SeqNumberMismatch */
    { nsm_ignore,              NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* 2-Way: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_TwoWay     }, /* HelloReceived     */
    { nsm_ignore,              NSM_TwoWay     }, /* Start             */
    { nsm_ignore,              NSM_TwoWay     }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_TwoWay     }, /* NegotiationDone   */
    { nsm_ignore,              NSM_TwoWay     }, /* ExchangeDone      */
    { nsm_ignore,              NSM_TwoWay     }, /* BadLSReq          */
    { nsm_ignore,              NSM_TwoWay     }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_TwoWay     }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* ExStart: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_ExStart    }, /* HelloReceived     */
    { nsm_ignore,              NSM_ExStart    }, /* Start             */
    { nsm_ignore,              NSM_ExStart    }, /* 2-WayReceived     */
    { nsm_negotiation_done,    NSM_Exchange   }, /* NegotiationDone   */
    { nsm_ignore,              NSM_ExStart    }, /* ExchangeDone      */
    { nsm_ignore,              NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_ExStart    }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_ignore,              NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Exchange: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Exchange   }, /* HelloReceived     */
    { nsm_ignore,              NSM_Exchange   }, /* Start             */
    { nsm_ignore,              NSM_Exchange   }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Exchange   }, /* NegotiationDone   */
    { nsm_exchange_done,       NSM_DependUpon }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Exchange   }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  {
    /* Loading: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Loading    }, /* HelloReceived     */
    { nsm_ignore,              NSM_Loading    }, /* Start             */
    { nsm_ignore,              NSM_Loading    }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Loading    }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Loading    }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Full       }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
  { /* Full: */
    { nsm_ignore,              NSM_DependUpon }, /* NoEvent           */
    { nsm_hello_received,      NSM_Full       }, /* HelloReceived     */
    { nsm_ignore,              NSM_Full       }, /* Start             */
    { nsm_ignore,              NSM_Full       }, /* 2-WayReceived     */
    { nsm_ignore,              NSM_Full       }, /* NegotiationDone   */
    { nsm_ignore,              NSM_Full       }, /* ExchangeDone      */
    { nsm_bad_ls_req,          NSM_ExStart    }, /* BadLSReq          */
    { nsm_ignore,              NSM_Full       }, /* LoadingDone       */
    { nsm_adj_ok,              NSM_DependUpon }, /* AdjOK?            */
    { nsm_seq_number_mismatch, NSM_ExStart    }, /* SeqNumberMismatch */
    { nsm_oneway_received,     NSM_Init       }, /* 1-WayReceived     */
    { nsm_kill_nbr,            NSM_Down       }, /* KillNbr           */
    { nsm_inactivity_timer,    NSM_Down       }, /* InactivityTimer   */
    { nsm_ll_down,             NSM_Down       }, /* LLDown            */
  },
};

static char *ospf_nsm_event_str[] =
{
  "NoEvent",
  "HelloReceived",
  "Start",
  "2-WayReceived",
  "NegotiationDone",
  "ExchangeDone",
  "BadLSReq",
  "LoadingDone",
  "AdjOK?",
  "SeqNumberMismatch",
  "1-WayReceived",
  "KillNbr",
  "InactivityTimer",
  "LLDown",
};

void
nsm_change_status (struct ospf_neighbor *nbr, int status)
{
  /* Logging change of status. */
  zlog (NULL, LOG_INFO, "NSM Status change [%s] %s -> %s", nbr->host,
	LOOKUP (ospf_nsm_status_msg, nbr->status),
	LOOKUP (ospf_nsm_status_msg, status));

  nbr->status = status;
  /* Preserve old status? */
}

/* Execute NSM event process. */
int
ospf_nsm_event (struct thread *thread)
{
  int event;
  int next_state;
  struct ospf_neighbor *nbr;

  nbr = THREAD_ARG (thread);
  event = THREAD_VAL (thread);

  /* Call function. */
  next_state = (*(NSM [nbr->status][event].func))(nbr);

  if (! next_state)
    next_state = NSM [nbr->status][event].next_state;

  if (debug (DEBUG_OSPF_NSM))
    zlog (NULL, LOG_INFO, "OSPF NSM[%s]: %s (%s)", nbr->host,
	  LOOKUP (ospf_nsm_status_msg, nbr->status),
	  ospf_nsm_event_str [event]);

  /* If status is changed. */
  if (next_state != nbr->status)
    nsm_change_status (nbr, next_state);

  /* Make sure timer is set. */
  /*  nsm_timer_set (nbr); */

  return 0;
}
