/* BGP-4 Finite State Machine   
   From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "log.h"
#include "sockunion.h"
#include "thread.h"

#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_peer.h"
#include "bgp_dump.h"
#include "bgp_fsm.h"

/* BGP FSM (finite state machine) has three types of functions.  Type
   one is thread functions.  Type two is event functions.  Type three
   is FSM functions.  Timer functions are set by bgp_timer_set
   function. */

/* BGP event function. */
int bgp_event (struct thread *);

/* BGP thread functions. */
static int bgp_start_timer (struct thread *);
static int bgp_connect_timer (struct thread *);
static int bgp_holdtime_timer (struct thread *);
static int bgp_keepalive_timer (struct thread *);

static int fsm_read (struct thread *);
static int fsm_write (struct thread *);

/* BGP FSM functions. */
static void fsm_connect (struct peer *);
static void fsm_stop (struct peer *);

/* Hook function called after bgp event is occered.  And vty's
   neighbor command invoke this function after making neighbor
   structure. */
void
bgp_timer_set (struct peer *peer)
{
  switch (peer->status)
    {
    case Idle:
      /* First entry point of peer's finite state machine.  In Idle
	 status timer_start is on.  All other timer must be turned
	 off. */
      BGP_TIMER_ON (peer->t_start, bgp_start_timer, peer->v_start);
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Connect:
      /* After start timer is expired, the peer moves to Connnect
         status.  Make sure start timer is off and connect timer is
         on. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_ON (peer->t_connect, bgp_connect_timer, peer->v_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Active:
      /* Active is waiting connection from remote peer.  And if
         connect timer is expired, change status to Connect. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_ON (peer->t_connect, bgp_connect_timer, peer->v_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case OpenSent:
      /* OpenSent status. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer, peer->v_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case OpenConfirm:
      /* OpenConfirm status. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);

      /* If the negotiated Hold Time value is zero, then the Hold Time
         timer and KeepAlive timers are not started. */
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else
	{
	  BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer,
			peer->v_holdtime);
	  BGP_TIMER_ON (peer->t_keepalive, bgp_keepalive_timer, 
			peer->v_keepalive);
	}
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;

    case Established:
      /* In Established status start and connect timer is turned
         off. */
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);

      /* Same as OpenConfirm, if holdtime is zero then both holdtime
         and keepalive must be turned off. */
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else
	{
	  BGP_TIMER_ON (peer->t_holdtime, bgp_holdtime_timer,
			peer->v_holdtime);
	  BGP_TIMER_ON (peer->t_keepalive, bgp_keepalive_timer,
			peer->v_keepalive);
	}
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    }
}

/* BGP start timer.  This function set BGP_Start event to thread value
   and process event. */
static int
bgp_start_timer (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_start = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (start timer expire).\n", peer->host);

  thread_val (thread) = BGP_Start;
  bgp_event (thread);

  return 0;
}

/* BGP connect retry timer. */
static int
bgp_connect_timer (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_connect = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (connect timer expire).\n", peer->host);

  thread_val (thread) = ConnectRetry_timer_expired;
  bgp_event (thread);

  return 0;
}

/* BGP holdtime timer. */
static int
bgp_holdtime_timer (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_holdtime = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (holdtime timer expire).\n", peer->host);

  thread_val (thread) = Hold_Timer_expired;
  bgp_event (thread);

  return 0;
}

/* BGP keepalive fire ! */
static int
bgp_keepalive_timer (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_keepalive = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (keepalive timer expire).\n", peer->host);

  thread_val (thread) = KeepAlive_timer_expired;
  bgp_event (thread);

  return 0;
}

/* Administrative BGP peer stop event. */
void
fsm_stop (struct peer *peer)
{
  /* Clear read and write thread if exist. */
  BGP_READ_OFF (peer->t_read);
  BGP_WRITE_OFF (peer->t_write);

  /* Stop all timers. */
  BGP_TIMER_OFF (peer->t_start);
  BGP_TIMER_OFF (peer->t_connect);
  BGP_TIMER_OFF (peer->t_holdtime);
  BGP_TIMER_OFF (peer->t_keepalive);
  BGP_TIMER_OFF (peer->t_asorig);
  BGP_TIMER_OFF (peer->t_routeadv);

  /* Need of clear of peer. */
  bgp_peer_delete (peer);
  bgp_uptime_reset (peer);

  /* Close of file descriptor. */
  if (peer->fd)
    {
      close (peer->fd);
      peer->fd = -1;
    }

  /* Next status is Idle.*/
}

/* To check connect is established. */
void
fsm_connect_check (struct peer *peer)
{
  int ret;
  int status;
  int n;

  /* Anyway I have to reset read and write thread. */
  BGP_READ_OFF (peer->t_read)
  BGP_WRITE_OFF (peer->t_write)

  n = sizeof (status);
  ret = getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, &status, &n);
  if (ret < 0)
    {
      log ("can't get sockopt for nonblocking connect.\n");
      return;
    }      

  if (status == 0)
      BGP_EVENT_ADD (peer, TCP_connection_open);
  else
    {
      log ("Connect to [%s] failed : %s.\n", peer->host, strerror (status));
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
    }
}

/* File descriptor can be read. */
int
fsm_read (struct thread *thread)
{
  struct peer *peer;

  /* Fetch peer structure and reset read thread. */
  peer = thread_arg (thread);
  peer->t_read = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: FSM_read.\n", peer->host);

  switch (peer->status)
    {
    case Connect:
      /* If peer's status is Connect. This function is called for
	 non-blocking result checking. */
      fsm_connect_check (peer);
      break;
    case OpenSent:
    case OpenConfirm:
    case Established:
      /* We need check of read error at here. */
      BGP_READ_ON (peer->t_read, fsm_read, peer->fd);
      bgp_read_packet (peer);
      break;
    case Idle:
    case Active:
    default:
      break;
    }
  return 0;
}

/* File descriptor can be read.  Called from thead. */
int
fsm_write (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_write = NULL;

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: FSM_write.\n", peer->host);

  switch (peer->status)
    {
    case Connect:
      fsm_connect_check (peer);
      break;
    }
  return 0;
}

/* This function is the first starting point of all BGP connection. It
   try to connect to remote peer with non-blocking IO. */
void
fsm_connect (struct peer *peer)
{
  int status;

  status = bgp_connect (peer);

  switch (status)
    {
    case connect_error:
      if (debug (DEBUG_BGP_FSM))
	log ("FSM[%s] connect error\n", peer->host);
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
      break;
    case connect_success:
      if (debug (DEBUG_BGP_FSM))
	log ("FSM[%s] connect immediately success\n", peer->host);
      BGP_EVENT_ADD (peer, TCP_connection_open);
      break;
    case connect_in_progress:
      /* To check nonblocking connect, we wait until socket is
         readable or writable. */
      if (debug (DEBUG_BGP_FSM))
	log ("FSM[%s] fsm_connect non-block connect\n", peer->host);
      BGP_READ_ON (peer->t_read, fsm_read, peer->fd);
      BGP_WRITE_ON (peer->t_write, fsm_write, peer->fd);
      break;
    }
}

/* TCP connection open.  Next we send open message to remote peer. And
   add read thread for reading open message. */
void
fsm_connect_success (struct peer *peer)
{
  BGP_READ_ON (peer->t_read, fsm_read, peer->fd);
  bgp_open_send (peer);
}

/* TCP connect fail */
void
fsm_connect_fail (struct peer *peer)
{
  /* Failed file descriptor is meaning less so close it. */
  if (peer->fd >= 0)
    {
      close (peer->fd);
      peer->fd = -1;
    }

  /* To restart connect retry timer, once off it. If next status is
     Active bgp_timer_set start connect retry timer. */
  BGP_TIMER_OFF (peer->t_connect);
}

void
fsm_open (struct peer *peer)
{
  /* send keepalive and make keepalive timer */
  bgp_keepalive_send (peer);

  /* Reset holdtimer value. */
  BGP_TIMER_OFF (peer->t_holdtime);
}

/* HoldTimer is expired. Moves to Idle state. */
void
fsm_holdtime (struct peer *peer)
{
  /* Send notify to remote peer. */
  bgp_notify_send(peer, BGP_NOTIFY_HOLD_ERR, 0);

  if (peer->fd >= 0)
    {
      close (peer->fd);
      peer->fd = -1;
    }
}

/* Called after event occured, this function change status and reset
   read/write and timer thread. */
void
fsm_change_status (struct peer *peer, int status)
{
  /* Logging change of status. */
  log ( "Status change [%s] %s -> %s\n",
	peer->host,
	LOOKUP (bgp_status_msg, peer->status),
	LOOKUP (bgp_status_msg, status));

  /* Preserve old status and change into new status. */
  peer->ostatus = peer->status;
  peer->status = status;
}

/* Keepalive send to peer. */
void
fsm_keepalive_expire (struct peer *peer)
{
  bgp_keepalive_send(peer);
}

/* Keepalive message is comming. */
void
fsm_establish (struct peer *peer)
{
  assert (peer->status == OpenConfirm);

  bgp_uptime_reset (peer);
  bgp_keepalive_send (peer);
}

/* Keepalive packet is received. */
void
fsm_keepalive (struct peer *peer)
{
  BGP_TIMER_OFF (peer->t_holdtime);
}

/* Update packet is received. */
void
fsm_update (struct peer *peer)
{
  BGP_TIMER_OFF (peer->t_holdtime);
}

/* This is empty event. */
void
fsm_ignore (struct peer *peer)
{
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: fsm_ignore called\n", peer->host);
}

/* Finite State Machine structure */
struct {
  void (*func) ();
  int next_state;
} FSM [BGP_STATUS_MAX - 1][BGP_EVENTS_MAX - 1] = 
{
  {
    /* Idle state: In Idle state, all events other than BGP_Start is
       ignored.  With BGP_Start event, finite state machine calls
       fsm_connect(). */
    {fsm_connect, Connect},	/* BGP_Start                    */
    {fsm_ignore, Idle},		/* BGP_Stop                     */
    {fsm_ignore, Idle},		/* TCP_connection_open          */
    {fsm_ignore, Idle},		/* TCP_connection_closed        */
    {fsm_ignore, Idle},		/* TCP_connection_open_failed   */
    {fsm_ignore, Idle},		/* TCP_fatal_error              */
    {fsm_ignore, Idle},		/* ConnectRetry_timer_expired   */
    {fsm_ignore, Idle},		/* Hold_Timer_expired           */
    {fsm_ignore, Idle},		/* KeepAlive_timer_expired      */
    {fsm_ignore, Idle},		/* Receive_OPEN_message         */
    {fsm_ignore, Idle},		/* Receive_KEEPALIVE_message    */
    {fsm_ignore, Idle},		/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
  {
    /* Connect */
    {fsm_ignore, Connect},	/* BGP_Start                    */
    {fsm_stop,   Idle},		/* BGP_Stop                     */
    {fsm_connect_success, OpenSent}, /* TCP_connection_open          */
    {fsm_ignore, Idle},		/* TCP_connection_closed        */
    {fsm_connect_fail, Active}, /* TCP_connection_open_failed   */
    {fsm_connect_fail, Idle},	/* TCP_fatal_error              */
    {fsm_ignore, Connect},	/* ConnectRetry_timer_expired   */
    {fsm_ignore, Idle},		/* Hold_Timer_expired           */
    {fsm_ignore, Idle},		/* KeepAlive_timer_expired      */
    {fsm_ignore, Idle},		/* Receive_OPEN_message         */
    {fsm_ignore, Idle},		/* Receive_KEEPALIVE_message    */
    {fsm_ignore, Idle},		/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
  {
    /* Active, */
    {fsm_ignore, Active},	/* BGP_Start                    */
    {fsm_stop,   Idle},		/* BGP_Stop                     */
    {fsm_connect_success, OpenSent}, /* TCP_connection_open          */
    {fsm_ignore, Idle},		/* TCP_connection_closed        */
    {fsm_ignore, Active},	/* TCP_connection_open_failed   */
    {fsm_ignore, Idle},		/* TCP_fatal_error              */
    {fsm_connect, Connect},	/* ConnectRetry_timer_expired   */
    {fsm_ignore, Idle},		/* Hold_Timer_expired           */
    {fsm_ignore, Idle},		/* KeepAlive_timer_expired      */
    {fsm_ignore, Idle},		/* Receive_OPEN_message         */
    {fsm_ignore, Idle},		/* Receive_KEEPALIVE_message    */
    {fsm_ignore, Idle},		/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
  {
    /* OpenSent, */
    {fsm_ignore, OpenSent},	/* BGP_Start                    */
    {fsm_stop,   Idle},		/* BGP_Stop                     */
    {fsm_ignore, Idle},		/* TCP_connection_open          */
    {fsm_ignore, Active},	/* TCP_connection_closed        */
    {fsm_ignore, Idle},		/* TCP_connection_open_failed   */
    {fsm_ignore, Idle},		/* TCP_fatal_error              */
    {fsm_ignore, Idle},		/* ConnectRetry_timer_expired   */
    {fsm_holdtime, Idle},	/* Hold_Timer_expired           */
    {fsm_ignore, Idle},		/* KeepAlive_timer_expired      */
    {fsm_open, OpenConfirm},	/* Receive_OPEN_message         */
    {fsm_ignore, Idle},		/* Receive_KEEPALIVE_message    */
    {fsm_ignore, Idle},		/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
  {
    /* OpenConfirm, */
    {fsm_ignore, OpenConfirm},	/* BGP_Start                    */
    {fsm_stop,   Idle},		/* BGP_Stop                     */
    {fsm_ignore, Idle},		/* TCP_connection_open          */
    {fsm_ignore, Idle},		/* TCP_connection_closed        */
    {fsm_ignore, Idle},		/* TCP_connection_open_failed   */
    {fsm_ignore, Idle},		/* TCP_fatal_error              */
    {fsm_ignore, Idle},		/* ConnectRetry_timer_expired   */
    {fsm_holdtime, Idle},	/* Hold_Timer_expired           */
    {fsm_ignore, OpenConfirm},	/* KeepAlive_timer_expired      */
    {fsm_ignore, Idle},		/* Receive_OPEN_message         */
    {fsm_establish, Established}, /* Receive_KEEPALIVE_message    */
    {fsm_ignore, Idle},		/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
  {
    /* Established, */
    {fsm_ignore, Established},	/* BGP_Start                    */
    {fsm_stop,   Idle},		/* BGP_Stop                     */
    {fsm_ignore, Idle},		/* TCP_connection_open          */
    {fsm_ignore, Idle},		/* TCP_connection_closed        */
    {fsm_ignore, Idle},		/* TCP_connection_open_failed   */
    {fsm_ignore, Idle},		/* TCP_fatal_error              */
    {fsm_ignore, Idle},		/* ConnectRetry_timer_expired   */
    {fsm_ignore, Idle},		/* Hold_Timer_expired           */
    {fsm_keepalive_expire, Established}, /* KeepAlive_timer_expired      */
    {fsm_ignore, Idle},		/* Receive_OPEN_message         */
    {fsm_keepalive, Established}, /* Receive_KEEPALIVE_message    */
    {fsm_update, Established},	/* Receive_UPDATE_message       */
    {fsm_ignore, Idle},		/* Receive_NOTIFICATION_message */
  },
};

static char *bgp_event_str[] =
{
  NULL,
  "BGP_Start",
  "BGP_Stop",
  "TCP_connection_open",
  "TCP_connection_closed",
  "TCP_connection_open_failed",
  "TCP_fatal_error",
  "ConnectRetry_timer_expired",
  "Hold_Timer_expired",
  "KeepAlive_timer_expired",
  "Receive_OPEN_message",
  "Receive_KEEPALIVE_message",
  "Receive_UPDATE_message",
  "Receive_NOTIFICATION_message"
};

/* Execute event process. */
int
bgp_event (struct thread *thread)
{
  int event;
  struct peer *peer;

  peer = thread_arg (thread);
  event = thread_val (thread);

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: %s (%s)\n", peer->host, 
	 LOOKUP (bgp_status_msg, peer->status),
	 bgp_event_str[event]);

  /* Call function. */
  (*(FSM [peer->status - 1][event - 1].func))(peer);

  /* If status is changed. */
  if (FSM [peer->status - 1][event - 1].next_state != peer->status)
    fsm_change_status (peer, FSM [peer->status -1][event - 1].next_state);

  /* Make sure timer is set. */
  bgp_timer_set (peer);

  return 0;
}
