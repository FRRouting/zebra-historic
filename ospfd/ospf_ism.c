/* OSPF version 2  Interface State Machine
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
#include "if.h"
#include "table.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"

extern unsigned long ospf_debug_ism;


/* elect DR and BDR. Refer to RFC2319 section 9.4 */
struct in_addr
ospf_dr_election_sub (struct _list *routers)
{
  listnode node;
  int max_priority = 0;
  struct in_addr max_router_id;
  struct ospf_neighbor *r;

  bzero (&max_router_id, sizeof (struct in_addr));

  /* Choose highest router priority. In case of tie,
     choose highest Router ID. */
  for (node = listhead (routers); node; nextnode (node))
    {
      r = getdata (node);

      if (max_router_id.s_addr == 0)
	{
	  max_router_id = r->router_id;
	  max_priority = r->priority;
	  continue;
	}

      if (max_priority < r->priority)
	{
	  max_router_id = r->router_id;
	  max_priority = r->priority;
	}
      else if (max_priority == r->priority)
	if (ntohl (max_router_id.s_addr) < ntohl (r->router_id.s_addr))
	  {
	    max_router_id = r->router_id;
	    max_priority = r->priority;
	  }
    }

  return max_router_id;
}

void
ospf_elect_dr (struct ospf_interface *oi, list el_list)
{
  list dr_list;
  listnode node;
  struct ospf_neighbor *nbr;

  dr_list = list_init ();

  /* Add neighbors to the list. */
  for (node = listhead (el_list); node; nextnode (node))
    {
      nbr = getdata (node);

      /* neighbor declared to be DR. */
      if (!IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router))
	list_add_node (dr_list, nbr);
    }

  /* Elect Backup Designated Router. */
  if (list_isempty (dr_list))
    oi->d_router = oi->bd_router;
  else
    oi->d_router = ospf_dr_election_sub (dr_list);

  list_delete_all (dr_list);
}

void
ospf_elect_bdr (struct ospf_interface *oi, list el_list)
{
  list bdr_list, no_dr_list;
  listnode node;
  struct ospf_neighbor *nbr;

  bdr_list = list_init ();
  no_dr_list = list_init ();

  /* Add neighbors to the list. */
  for (node = listhead (el_list); node; nextnode (node))
    {
      nbr = getdata (node);

      /* neighbor declared to be DR. */
      if (!IPV4_ADDR_CMP (&nbr->router_id, &nbr->d_router))
	continue;

      /* neighbor declared to be BDR. */
      if (!IPV4_ADDR_CMP (&nbr->router_id, &nbr->bd_router))
	list_add_node (bdr_list, nbr);

      list_add_node (no_dr_list , nbr);
    }

  /* Elect Backup Designated Router. */
  if (list_isempty (bdr_list))
    oi->bd_router = ospf_dr_election_sub (no_dr_list);
  else
    oi->bd_router = ospf_dr_election_sub (bdr_list);

  list_delete_all (bdr_list);
  list_delete_all (no_dr_list);
}

int
ospf_ism_status (struct ospf_interface *oi)
{
  if (!IPV4_ADDR_CMP (&oi->d_router, &ospf_top->router_id))
    return ISM_DR;
  else if (!IPV4_ADDR_CMP (&oi->bd_router, &ospf_top->router_id))
    return ISM_Backup;
  else
    return ISM_DROther;
}

int
ospf_dr_election (struct ospf_interface *oi)
{
  struct in_addr old_dr, old_bdr;
  int old_status, new_status;
  list el_list;
  struct route_node *rn;
  struct ospf_neighbor *nbr, *myself;

  /* backup current values. */
  old_dr = oi->d_router;
  old_bdr = oi->bd_router;
  old_status = oi->status;

  el_list = list_init ();

  myself = NULL;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if (rn->info == NULL)
	continue;

      nbr = rn->info;

      /* ignore 0.0.0.0 node*/
      if (nbr->router_id.s_addr == 0)
	continue;

      /* Is neighbor eligible? */
      if (nbr->priority == 0)
	continue;

      /* Is neighbor upper 2-Way? */
      if (nbr->status < NSM_TwoWay)
	continue;

      /* keep myself. */
      if (!IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id))
	myself = nbr;

      list_add_node (el_list, nbr);
    }

  ospf_elect_bdr (oi, el_list);
  ospf_elect_dr (oi, el_list);

  new_status = ospf_ism_status (oi);
#ifdef DEBUG
  zlog (NULL, LOG_INFO, "d_router = %s", inet_ntoa (oi->d_router));
  zlog (NULL, LOG_INFO, "bd_router = %s", inet_ntoa (oi->bd_router));
#endif /* DEBUG */

  if (old_status < ISM_DROther || old_status != new_status)
    {
      /* declare DR and BDR in myself. */
      if (myself)
	{
	  myself->d_router = oi->d_router;
	  myself->bd_router = oi->bd_router;
	}

      ospf_elect_bdr (oi, el_list);
      ospf_elect_dr (oi, el_list);

      new_status = ospf_ism_status (oi);

      if (myself)
	{
	  myself->d_router = oi->d_router;
	  myself->bd_router = oi->bd_router;
	}

#ifdef DEBUG
      zlog (NULL, LOG_INFO, "d_router = %s", inet_ntoa (oi->d_router));
      zlog (NULL, LOG_INFO, "bd_router = %s", inet_ntoa (oi->bd_router));
#endif /* DEBUG */
    }

  list_delete_all (el_list);

  /* Multicast group change. */
  if ((old_status != ISM_DR || old_status != ISM_Backup) &&
      (new_status == ISM_DR || new_status == ISM_Backup))
    ospf_if_add_alldrouters (oi->ifp, oi->fd, oi->address);
  else if ((old_status == ISM_DR || old_status == ISM_Backup) &&
	   (new_status != ISM_DR || new_status == ISM_Backup))
    ospf_if_drop_alldrouters (oi->ifp, oi->fd, oi->address);

  return new_status;
}


int
ospf_hello_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_hello = NULL;

  zlog (NULL, LOG_DEBUG, "ISM [%s]: Timer (Hello timer expire)",
	oi->ifp->name);

  /* Sending hello packet. */
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_hello_send, oi->fd);

  /* Hello timer set. */
  OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);

  return 0;
}

int
ospf_wait_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_wait = NULL;

  zlog (NULL, LOG_DEBUG, "ISM [%s]: Timer (Wait timer expire)",
	oi->ifp->name);

  OSPF_ISM_EVENT_SCHEDULE (oi, ISM_WaitTimer);

  return 0;
}

/* Hook function called after ospf ISM event is occured. And vty's
   network command invoke this function after making interface
   structure. */
void
ism_timer_set (struct ospf_interface *oi)
{
  switch (oi->status)
    {
    case ISM_Down:
      /* First entry point of ospf interface state machine. In this state
	 interface parameters must be set to initial values, and timers are
	 reset also. */
      OSPF_ISM_TIMER_OFF (oi->t_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Loopback:
      /* In this state, the interface may be looped back and will be
	 unavailable for regular data traffic. */
      OSPF_ISM_TIMER_OFF (oi->t_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Waiting:
      /* The router is trying to determine the identity of DRouter and
	 BDRouter. The router begin to receive and send Hello Packets. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_ON (oi->t_wait, ospf_wait_timer, oi->v_wait);
      break;
    case ISM_PointToPoint:
      /* The interface connects to a physical Point-to-point network or
	 virtual link. The router attempts to form an adjacency with
	 neighboring router. Hello packets are also sent. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DROther:
      /* The network type of the interface is broadcast or NBMA network,
	 and the router itself is neither Designated Router nor
	 Backup Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Backup:
      /* The network type of the interface is broadcast os NBMA network,
	 and the router is Backup Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DR:
      /* The network type of the interface is broadcast or NBMA network,
	 and the router is Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ospf_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    }
}

/* This function is the first starting point of all OSPF instances.
 */
void
ospf_ism_start (struct ospf_interface *oi)
{
  switch (oi->status)
    {
      ;
    }
}

int
ism_stop (struct ospf_interface *oi)
{
  return 0;
}

int
ism_interface_up (struct ospf_interface *oi)
{
  int next_state = 0;

  /* if network type is point-to-point, Point-to-MultiPoint or virtual link,
     the state transitions to Point-to-Point. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    next_state = ISM_PointToPoint;
  /* Else if the router is not eligible to DR, the state transitions to
     DROther. */
  else if (oi->priority == 0) /* router is eligible? */
    next_state = ISM_DROther;
  else
    /* Otherwise, the state transitions to Waiting. */
    next_state = ISM_Waiting;

  /*  ospf_ism_event (t); */
  return next_state;
}

int
ism_loop_ind (struct ospf_interface *oi)
{
  int ret = 0;

  /* call ism_interface_down. */
  /*  ret = ism_interface_down (oi); */

  return ret;
}

int
ism_interface_down (struct ospf_interface *oi)
{
  struct route_node *rn;

  /* send Neighbor event KillNbr to all associated neighbors. */
  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      struct ospf_neighbor *nbr;

      if (!rn->info)
	continue;
      nbr = rn->info;

      if (!IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id))
	continue;

      OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_KillNbr);
    }

  /* Reset interface variables. */
  ospf_if_reset_variables (oi);

  /* Cancel Timers. */
  OSPF_ISM_TIMER_OFF (oi->t_hello);
  OSPF_ISM_TIMER_OFF (oi->t_wait);

  return 0;
}


int
ism_backup_seen (struct ospf_interface *oi)
{
  int status;

  status = ospf_dr_election (oi);

  return status;
}

int
ism_wait_timer (struct ospf_interface *oi)
{
  int status;

  status = ospf_dr_election (oi);

  return status;
}

int
ism_neighbor_change (struct ospf_interface *oi)
{
  int status;

  status = ospf_dr_election (oi);

  return status;
}

int
ism_ignore (struct ospf_interface *oi)
{
  zlog (NULL, LOG_INFO, "ISM [%s]: ism_ignore called", oi->ifp->name);

  return 0;
}

/* Interface State Machine */
struct {
  int (*func) ();
  int next_state;
} ISM [OSPF_ISM_STATUS_MAX][OSPF_ISM_EVENT_MAX] =
{
  {
    /* DependUpon: dummy state. */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DependUpon },    /* InterfaceUp    */
    { ism_ignore,          ISM_DependUpon },    /* WaitTimer      */
    { ism_ignore,          ISM_DependUpon },    /* BackupSeen     */
    { ism_ignore,          ISM_DependUpon },    /* NeighborChange */
    { ism_ignore,          ISM_DependUpon },    /* LoopInd        */
    { ism_ignore,          ISM_DependUpon },    /* UnloopInd      */
    { ism_ignore,          ISM_DependUpon },    /* InterfaceDown  */
  },
  {
    /* Down:*/
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_interface_up,    ISM_DependUpon },    /* InterfaceUp    */
    { ism_ignore,          ISM_Down },          /* WaitTimer      */
    { ism_ignore,          ISM_Down },          /* BackupSeen     */
    { ism_ignore,          ISM_Down },          /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_ignore,          ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Loopback: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Loopback },      /* InterfaceUp    */
    { ism_ignore,          ISM_Loopback },      /* WaitTimer      */
    { ism_ignore,          ISM_Loopback },      /* BackupSeen     */
    { ism_ignore,          ISM_Loopback },      /* NeighborChange */
    { ism_ignore,          ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Waiting: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Waiting },       /* InterfaceUp    */
    { ism_wait_timer,	   ISM_DependUpon },    /* WaitTimer      */
    { ism_backup_seen,     ISM_DependUpon },    /* BackupSeen     */
    { ism_neighbor_change, ISM_Waiting },       /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Waiting },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Point-to-Point: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_PointToPoint },  /* InterfaceUp    */
    { ism_ignore,          ISM_PointToPoint },  /* WaitTimer      */
    { ism_ignore,          ISM_PointToPoint },  /* BackupSeen     */
    { ism_ignore,          ISM_PointToPoint },  /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_PointToPoint },  /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DROther: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DROther },       /* InterfaceUp    */
    { ism_ignore,          ISM_DROther },       /* WaitTimer      */
    { ism_ignore,          ISM_DROther },       /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_DROther },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Backup: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_Backup },        /* InterfaceUp    */
    { ism_ignore,          ISM_Backup },        /* WaitTimer      */
    { ism_ignore,          ISM_Backup },        /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Backup },        /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DR: */
    { ism_ignore,          ISM_DependUpon },    /* NoEvent        */
    { ism_ignore,          ISM_DR },            /* InterfaceUp    */
    { ism_ignore,          ISM_DR },            /* WaitTimer      */
    { ism_ignore,          ISM_DR },            /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_DR },            /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
};  

static char *ospf_ism_event_str[] =
{
  "NoEvent",
  "InterfaceUp",
  "WaitTimer",
  "BackupSeen",
  "NeighborChange",
  "LoopInd",
  "UnLoopInd",
  "InterfaceDown",
};

void
ism_change_status (struct ospf_interface *oi, int status)
{
  struct ospf_lsa *lsa;

  /* Logging change of status. */
  if (ospf_debug_ism)
    zlog (NULL, LOG_INFO, "ISM Status change [%s] %s -> %s", oi->ifp->name,
	  LOOKUP (ospf_ism_status_msg, oi->status),
	  LOOKUP (ospf_ism_status_msg, status));

  oi->status = status;

  /* Originate router-LSA. */
  if (oi->area)
    {
      lsa = ospf_router_lsa (oi);
      ospf_add_router_lsa (oi->area, lsa);
    }

  /* Originate network-LSA. */
  if (status == ISM_DR)
    {
      lsa = ospf_network_lsa (oi);
      ospf_add_network_lsa (oi->area, lsa);
    }

  /* Preserve old status? */
}

/* Execute ISM event process. */
int
ospf_ism_event (struct thread *thread)
{
  int event;
  int next_state;
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  event = THREAD_VAL (thread);

  /* Call function. */
  next_state = (*(ISM [oi->status][event].func))(oi);

  if (! next_state)
    next_state = ISM [oi->status][event].next_state;

  if (0)
    zlog (NULL, LOG_INFO, "OSPF ISM[%s]: %s (%s)", oi->ifp->name,
	  LOOKUP (ospf_ism_status_msg, oi->status),
	  ospf_ism_event_str[event]);

  /* If status is changed. */
  if (next_state != oi->status)
    ism_change_status (oi, next_state);

  /* Make sure timer is set. */
  ism_timer_set (oi);

  return 0;
}

