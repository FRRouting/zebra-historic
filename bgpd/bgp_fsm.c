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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "bgpd.h"
#include "bgp_peer.h"
#include "bgp_dump.h"
#include "sockunion.h"
#include "log.h"
#include "thread.h"

/* Export from bgpd.c */
extern struct thread_master *master;

/* Prototypes for fsm timer. */
int timer_start (struct thread *);
int timer_connect (struct thread *);
int timer_holdtime (struct thread *);
int timer_keepalive (struct thread *);
void fsm_connect (struct peer *);

/* Macro for BGP read add */
#define BGP_READ_ON(F,V) \
      thread_add_read (master, (F), peer, (V))

/* Macro for BGP read off. */
#define BGP_READ_OFF(X) \
      if (X) \
	{ \
	  thread_cancel (X); \
	  (X) = NULL; \
	}

/* Macro for BGP write add */
#define BGP_WRITE_ON(F,V) \
      thread_add_write (master, (F), peer, (V))

/* Macro for BGP write turn off. */
#define BGP_WRITE_OFF(X) \
      if (X) \
	{ \
	  thread_cancel (X); \
	  (X) = NULL; \
	}

/* Macro for timer turn on. */
#define BGP_TIMER_ON(F,V) \
      thread_add_timer (master, (F), peer, (V))

/* Macro for timer turn off. */
#define BGP_TIMER_OFF(X) \
      if (X) \
	{ \
	  thread_cancel (X); \
	  (X) = NULL; \
	}

/* Hook function called after bgp event is occered. And vty's neighbor
   command invoke this function after making neighbor structure. */
fsm_timer_set (struct peer *peer)
{
  switch (peer->status)
    {
    /* First entry point of peer's finite state machine.  From this
       timer timer_start function is called.  All other timer must be
       turned off. */
    case Idle:
      if (!peer->t_start)
	peer->t_start = BGP_TIMER_ON (timer_start, peer->v_start);
      BGP_TIMER_OFF (peer->t_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    case Connect:
      BGP_TIMER_OFF (peer->t_start);
      if (!peer->t_connect)
	peer->t_connect = BGP_TIMER_ON (timer_connect, peer->v_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    case Active:
      BGP_TIMER_OFF (peer->t_start);
      if (!peer->t_connect)
	peer->t_connect = BGP_TIMER_ON (timer_connect, peer->v_connect);
      BGP_TIMER_OFF (peer->t_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    case OpenSent:
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);
      if (!peer->t_holdtime)
	peer->t_holdtime = BGP_TIMER_ON (timer_holdtime, peer->v_holdtime);
      BGP_TIMER_OFF (peer->t_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    case OpenConfirm:
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);

      /* If the negotiated Hold Time value is zero, then the Hold Time
         timer and KeepAlive timers are not started. */
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	}
      else if (!peer->t_holdtime)
	peer->t_holdtime = BGP_TIMER_ON (timer_holdtime, peer->v_holdtime);
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else if (!peer->t_keepalive)
	peer->t_keepalive = BGP_TIMER_ON (timer_keepalive, peer->v_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    case Established:
      BGP_TIMER_OFF (peer->t_start);
      BGP_TIMER_OFF (peer->t_connect);
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_holdtime);
	}
      else if (!peer->t_holdtime)
	peer->t_holdtime = BGP_TIMER_ON (timer_holdtime, peer->v_holdtime);
      if (peer->v_holdtime == 0)
	{
	  BGP_TIMER_OFF (peer->t_keepalive);
	}
      else if (!peer->t_keepalive)
	peer->t_keepalive = BGP_TIMER_ON (timer_keepalive, peer->v_keepalive);
      BGP_TIMER_OFF (peer->t_asorig);
      BGP_TIMER_OFF (peer->t_routeadv);
      break;
    }
}

/* Start timer fire! To proceed event I set BGP_Start to thread value
   and after that call event process. */
timer_start (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_start = NULL;
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (start timer expire).\n", peer->host);
  thread_val(thread) = BGP_Start;
  event_process (thread);
}

/* Connect retry fire ! */
timer_connect (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_connect = NULL;
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (connect timer expire).\n", peer->host);
  thread_val (thread) = ConnectRetry_timer_expired;
  event_process (thread);
}

/* Holdtime fire ! */
timer_holdtime (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_holdtime = NULL;
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (holdtime timer expire).\n", peer->host);
  thread_val (thread) = Hold_Timer_expired;
  event_process (thread);
}

/* Keepalive fire ! */
timer_keepalive (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_keepalive = NULL;
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: Timer (keepalive timer expire).\n", peer->host);
  thread_val (thread) = KeepAlive_timer_expired;
  event_process (thread);
}

#if 0
/* AS origination interval fire ! */
timer_asorig (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_asorig = NULL;
  thread_val (thread) = 0;
  event_process (thread);
}

/* Route advetise fire ! */
timer_routeadv (struct thread *thread)
{
  struct peer *peer;

  peer = thread_arg (thread);
  peer->t_routeadv = NULL;
  thread_val (thread) = 0;
  event_process (thread);
}
#endif

/* First point of BGP finite state machine. */
FSM_start (struct peer *peer)
{
  assert (peer->fd == -1);
  assert (peer->status == Idle);

  fsm_connect (peer);

  /* Next status is Connect. */
}

/* Administrative BGP peer stop event. */
FSM_stop (struct peer *peer)
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

/* Conect timer expired. This function is called from connect retry
   timer. So connect retry timer does not exist at this time. */
FSM_connect_retry (struct peer *peer)
{
  assert (peer->fd == -1);
  assert (peer->status == Active);
  
  fsm_connect (peer);

  /* Next status is Connect. */
}

/* File descriptor can be read. */
fsm_read (struct thread *thread)
{
  struct peer *peer;

  /* Fetch peer structure and reset read thread. */
  peer = thread_arg (thread);
  peer->t_read = BGP_READ_ON (fsm_read, peer->fd);

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
      bgp_read_packet (peer);
      break;
    case Idle:
    case Active:
    default:
      break;
    }
}

FSM_open (struct peer *peer)
{
  /* send keepalive and make keepalive timer */
  bgp_keepalive_send (peer);

  /* Reset holdtimer value. */
  BGP_TIMER_OFF (peer->t_holdtime);

  /* Keepalive timer is set at fsm_timer_set(). */
}

/* File descriptor can be read.  Called from thead. */
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
}

/* Perform BGP connect. Called from FSM_start() and
   FSM_connect_retry(). */
void
fsm_connect (struct peer *peer)
{
  int status;

  status = bgp_connect (peer);
  switch (status)
    {
    case -1:
      event_add (peer, TCP_connection_open_failed);
      break;
    case 0:
      if (debug (DEBUG_BGP_FSM))
	log ("FSM[%s] connect immediately success\n", peer->host);
      event_add (peer, TCP_connection_open);
      break;
    case 1:
      /* To check nonblocking connect, we wait until socket is
         readable or writable. */
      if (debug (DEBUG_BGP_FSM))
	log ("FSM[%s] fsm_connect non-block connect\n", peer->host);
      peer->t_read  = BGP_READ_ON (fsm_read, peer->fd);
      peer->t_write  = BGP_WRITE_ON (fsm_write, peer->fd);
      break;
    default:
      break;
    }
}

/* To check connect is established. */
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
      event_add (peer, TCP_connection_open);
  else
    {
      log ("Connect to [%s] failed : %s.\n", peer->host, strerror (status));
      event_add (peer, TCP_connection_open_failed);
    }
}

/* TCP connection open.  Next we send open message to remote peer. And
   add read thread for reading open message. */
fsm_connect_success (struct peer *peer)
{
  if (peer->t_read)
    printf ("Already active read thread\n");
  peer->t_read = BGP_READ_ON (fsm_read, peer->fd);
  bgp_open_send (peer);
}

/* TCP connect fail */
fsm_connect_fail (struct peer *peer)
{
  /* Failed file descriptor is meaning less so close it. */
  if (peer->fd >= 0)
    {
      close (peer->fd);
      peer->fd = -1;
    }

  /* To restart connect retry timer, once off it. If next status is
     Active fsm_timer_set start connect retry timer. */
  BGP_TIMER_OFF (peer->t_connect);
}

/* HoldTimer is expired. Moves to Idle state. */
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
fsm_keepalive_expire (struct peer *peer)
{
  /* Send keepalive */
  bgp_keepalive_send(peer);

  /* At this time keepalive timer is expired.  So fsm_set_timer
     restart new keepalive timer. */
}

fsm_nothing (struct peer *peer)
{
  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: fsm_nothing called\n", peer->host);
}

/* Keepalive message is comming. */
fsm_establish (struct peer *peer)
{
  assert (peer->status == OpenConfirm);

  bgp_uptime_reset (peer);
  bgp_keepalive_send(peer);
  
  bgp_announce (peer);
  /* bgp_announce_v6 (peer); */
}


/* Keepalive packet is received. */
fsm_keepalive (struct peer *peer)
{
  /* Reset holdtimer value. */
  BGP_TIMER_OFF (peer->t_holdtime);
}

/* Update packet is received. */
fsm_update (struct peer *peer)
{
  /* Reset holdtimer value. */
  BGP_TIMER_OFF (peer->t_holdtime);
}

/* Finite State Machine structure */
struct {
  int (*func) ();
  int next_state;
} FSM [BGP_STATUS_MAX - 1][BGP_EVENTS_MAX - 1] = 
{
  {
    /* Idle */
    FSM_start,   Connect,	/* BGP_Start                    */
    FSM_stop,    Idle,		/* BGP_Stop                     */
    fsm_nothing, Idle,		/* TCP_connection_open          */
    fsm_nothing, Idle,		/* TCP_connection_closed        */
    fsm_nothing, Idle,		/* TCP_connection_open_failed   */
    fsm_nothing, Idle,		/* TCP_fatal_error              */
    fsm_nothing, Idle,		/* ConnectRetry_timer_expired   */
    fsm_nothing, Idle,		/* Hold_Timer_expired           */
    fsm_nothing, Idle,		/* KeepAlive_timer_expired      */
    fsm_nothing, Idle,		/* Receive_OPEN_message         */
    fsm_nothing, Idle,		/* Receive_KEEPALIVE_message    */
    fsm_nothing, Idle,		/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
  },
  {
    /* Connect */
    fsm_nothing, Connect,	/* BGP_Start                    */
    FSM_stop,    Idle,		/* BGP_Stop                     */
    fsm_connect_success, OpenSent, /* TCP_connection_open          */
    fsm_nothing, Idle,		/* TCP_connection_closed        */
    fsm_connect_fail, Active,	/* TCP_connection_open_failed   */
    fsm_connect_fail, Idle,	/* TCP_fatal_error              */
    fsm_nothing, Connect,	/* ConnectRetry_timer_expired   */
    fsm_nothing, Idle,		/* Hold_Timer_expired           */
    fsm_nothing, Idle,		/* KeepAlive_timer_expired      */
    fsm_nothing, Idle,		/* Receive_OPEN_message         */
    fsm_nothing, Idle,		/* Receive_KEEPALIVE_message    */
    fsm_nothing, Idle,		/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
  },
  {
    /* Active, */
    fsm_nothing, Active,          /* BGP_Start                    */
    FSM_stop,    Idle,		  /* BGP_Stop                     */
    fsm_connect_success, OpenSent, /* TCP_connection_open          */
    fsm_nothing, Idle,		/* TCP_connection_closed        */
    fsm_nothing, Active,	/* TCP_connection_open_failed   */
    fsm_nothing, Idle,		/* TCP_fatal_error              */
    FSM_connect_retry, Connect,	/* ConnectRetry_timer_expired   */
    fsm_nothing, Idle,		/* Hold_Timer_expired           */
    fsm_nothing, Idle,		/* KeepAlive_timer_expired      */
    fsm_nothing, Idle,		/* Receive_OPEN_message         */
    fsm_nothing, Idle,		/* Receive_KEEPALIVE_message    */
    fsm_nothing, Idle,		/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
  },
  {
    /* OpenSent, */
    fsm_nothing, OpenSent,	/* BGP_Start                    */
    FSM_stop,    Idle,		/* BGP_Stop                     */
    fsm_nothing, Idle,		/* TCP_connection_open          */
    fsm_nothing, Active,	/* TCP_connection_closed        */
    fsm_nothing, Idle,		/* TCP_connection_open_failed   */
    fsm_nothing, Idle,		/* TCP_fatal_error              */
    fsm_nothing, Idle,		/* ConnectRetry_timer_expired   */
    fsm_holdtime, Idle,		/* Hold_Timer_expired           */
    fsm_nothing, Idle,		/* KeepAlive_timer_expired      */
    FSM_open, OpenConfirm,	/* Receive_OPEN_message         */
    fsm_nothing, Idle,		/* Receive_KEEPALIVE_message    */
    fsm_nothing, Idle,		/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
  },
  {
    /* OpenConfirm, */
    fsm_nothing, OpenConfirm,	/* BGP_Start                    */
    FSM_stop,    Idle,		/* BGP_Stop                     */
    fsm_nothing, Idle,		/* TCP_connection_open          */
    fsm_nothing, Idle,		/* TCP_connection_closed        */
    fsm_nothing, Idle,		/* TCP_connection_open_failed   */
    fsm_nothing, Idle,		/* TCP_fatal_error              */
    fsm_nothing, Idle,		/* ConnectRetry_timer_expired   */
    fsm_holdtime, Idle,		/* Hold_Timer_expired           */
    fsm_nothing, OpenConfirm,	/* KeepAlive_timer_expired      */
    fsm_nothing, Idle,		/* Receive_OPEN_message         */
    fsm_establish, Established,	/* Receive_KEEPALIVE_message    */
    fsm_nothing, Idle,		/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
  },
  {
    /* Established, */
    fsm_nothing, Established,	/* BGP_Start                    */
    FSM_stop,    Idle,		/* BGP_Stop                     */
    fsm_nothing, Idle,		/* TCP_connection_open          */
    fsm_nothing, Idle,		/* TCP_connection_closed        */
    fsm_nothing, Idle,		/* TCP_connection_open_failed   */
    fsm_nothing, Idle,		/* TCP_fatal_error              */
    fsm_nothing, Idle,		/* ConnectRetry_timer_expired   */
    fsm_nothing, Idle,		/* Hold_Timer_expired           */
    fsm_keepalive_expire, Established, /* KeepAlive_timer_expired      */
    fsm_nothing, Idle,		/* Receive_OPEN_message         */
    fsm_keepalive, Established,	/* Receive_KEEPALIVE_message    */
    fsm_update, Established,	/* Receive_UPDATE_message       */
    fsm_nothing, Idle,		/* Receive_NOTIFICATION_message */
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
event_process (struct thread *thread)
{
  int ret;
  int event;
  struct peer *peer;

  peer = thread_arg (thread);
  event = thread_val (thread);

  if (debug (DEBUG_BGP_FSM))
    log ("FSM[%s]: %s (%s)\n", peer->host, 
	 LOOKUP (bgp_status_msg, peer->status),
	 bgp_event_str[event]);

  /* Call function. */
  ret = (*(FSM [peer->status - 1][event - 1].func))(peer);

  /* If status is changed. */
  if (FSM [peer->status - 1][event - 1].next_state != peer->status)
    fsm_change_status (peer, FSM [peer->status -1][event - 1].next_state);

  /* Make sure timer is set. */
  fsm_timer_set (peer);
}

/* Add event to the peer. */
event_add (struct peer *peer, int event) 
{
  thread_add_event (master, event_process, peer, event);
}
