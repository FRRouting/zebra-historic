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
#include "if.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_dump.h"

/* OSPF ISM functions. */

int
ism_hello_timer (struct thread *thread)
{
  struct ospf_interface *oi;

  oi = THREAD_ARG (thread);
  oi->t_hello = 0;

  zlog (NULL, LOG_DEBUG, "ISM [%s]:  Timer (Hello timer expire)",
	oi->ifp->name);

  /* sending hello packet. */
  /* actually add write thread and fire. */

  OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
  /*
    THREAD_VAL (thread) = Hello_timer_expired; */
  /* ospf_ism_event (thread); */

  return 0;
}

int
ism_wait_timer ()
{
  return 0;
}

/* Hook function called after ospf event is occured. And vty's
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
      OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_PointToPoint:
      /* The interface connects to a physical Point-to-point network or
	 virtual link. The router attempts to form an adjacency with
	 neighboring router. Hello packets are also sent. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DROther:
      /* The network type of the interface is broadcast or NBMA network, and
	 the router itself is Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_Backup:
      /* The network type of the interface is broadcast os NBMA network, and
	 the router is Backup Designated Router. */
      OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
      OSPF_ISM_TIMER_OFF (oi->t_wait);
      break;
    case ISM_DR:
      /* The network type of the interface is broadcast or NBMA network, and
       */
      OSPF_ISM_TIMER_ON (oi->t_hello, ism_hello_timer, oi->v_hello);
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
  /* if network type is point-to-point, Point-to-MultiPoint or virtual link,
     the state transitions to Point-to-Point. */
  if (oi->type == OSPF_IFTYPE_POINTOPOINT ||
      oi->type == OSPF_IFTYPE_POINTOMULTIPOINT ||
      oi->type == OSPF_IFTYPE_VIRTUALLINK)
    return ISM_PointToPoint;
  /* Else if the router is not eligible to DR, the state transitions to
     DROther. */
  else if (0) /* router is eligible? */
    return ISM_DROther;
  else
    /* Otherwise, the state transitions to Waiting. */
    return ISM_Waiting;

  /*  ospf_ism_event (t); */
  return 0;
}

int
ism_loop_ind ()
{
  /* send Neighbor event KillNbr to all associated neighbors. */

  /* call ism_interface_down. */

  return 0;
}

int
ism_interface_down ()
{
  return 0;
}


int
ism_backup_seen ()
{
  return 0;
}

int
ism_neighbor_change ()
{
  return 0;
}

int
ism_ignore (struct ospf_interface *oi)
{
  if (debug (DEBUG_OSPF_ISM))
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
    /* NoState: dummy state. */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_NoState },       /* InterfaceUp    */
    { ism_ignore,          ISM_NoState },       /* WaitTimer      */
    { ism_ignore,          ISM_NoState },       /* BackupSeen     */
    { ism_ignore,          ISM_NoState },       /* NeighborChange */
    { ism_ignore,          ISM_NoState },       /* LoopInd        */
    { ism_ignore,          ISM_NoState },       /* UnloopInd      */
    { ism_ignore,          ISM_NoState },       /* InterfaceDown  */
  },
  {
    /* Down: 
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_interface_up,    ISM_DependUpon },    /* InterfaceUp    */
    { ism_ignore,          ISM_Down },          /* WaitTimer      */
    { ism_ignore,          ISM_Down },          /* BackupSeen     */
    { ism_ignore,          ISM_Down },          /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_ignore,          ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Loopback:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_Loopback },      /* InterfaceUp    */
    { ism_ignore,          ISM_Loopback },      /* WaitTimer      */
    { ism_ignore,          ISM_Loopback },      /* BackupSeen     */
    { ism_ignore,          ISM_Loopback },      /* NeighborChange */
    { ism_ignore,          ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Down },          /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Waiting:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_Waiting },       /* InterfaceUp    */
    { ism_wait_timer,	   ISM_DependUpon },    /* WaitTimer      */
    { ism_backup_seen,     ISM_DependUpon },    /* BackupSeen     */
    { ism_ignore,          ISM_Waiting },       /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Waiting },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Point-to-Point:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_PointToPoint },  /* InterfaceUp    */
    { ism_ignore,          ISM_PointToPoint },  /* WaitTimer      */
    { ism_ignore,          ISM_PointToPoint },  /* BackupSeen     */
    { ism_ignore,          ISM_PointToPoint },  /* NeighborChange */
    { ism_loop_ind,	   ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_PointToPoint },  /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* Backup:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_Backup },        /* InterfaceUp    */
    { ism_ignore,          ISM_Backup },        /* WaitTimer      */
    { ism_ignore,          ISM_Backup },        /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_Backup },        /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DROther:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
    { ism_ignore,          ISM_DROther },       /* InterfaceUp    */
    { ism_ignore,          ISM_DROther },       /* WaitTimer      */
    { ism_ignore,          ISM_DROther },       /* BackupSeen     */
    { ism_neighbor_change, ISM_DependUpon },    /* NeighborChange */
    { ism_loop_ind,        ISM_Loopback },      /* LoopInd        */
    { ism_ignore,          ISM_DROther },       /* UnloopInd      */
    { ism_interface_down,  ISM_Down },          /* InterfaceDown  */
  },
  {
    /* DR:
     */
    { ism_ignore,          ISM_NoState },       /* NoEvent        */
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
  /* Logging change of status. */
  zlog (NULL, LOG_INFO, "ISM Status change [%s] %s -> %s", oi->ifp->name,
	LOOKUP (ospf_ism_status_msg, oi->status),
	LOOKUP (ospf_ism_status_msg, status));

  oi->status = status;
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

  if (debug (DEBUG_OSPF_ISM))
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

