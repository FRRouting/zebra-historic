/*
 * BGP packet management routine.
 * Copyright (C) 1999 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "thread.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"

int stream_put_prefix (struct stream *, struct prefix *);

/* Set up BGP packet marker and packet type. */
static int
bgp_packet_set_marker (struct stream *s, u_char type)
{
  int i;

  /* Fill in marker. */
  for (i = 0; i < BGP_MARKER_SIZE; i++)
    stream_putc (s, 0xff);

  /* Dummy total length. This field is should be filled in later on. */
  stream_putw (s, 0);

  /* BGP packet type. */
  stream_putc (s, type);

  /* Return current stream size. */
  return stream_get_putp (s);
}

/* Set BGP packet header size entry.  If size is zero then use current
   stream size. */
static int
bgp_packet_set_size (struct stream *s, bgp_size_t size)
{
  int cp;

  /* Preserve current pointer. */
  cp = stream_get_putp (s);
  stream_set_putp (s, BGP_MARKER_SIZE);

  /* If size is specifed use it. */
  if (size)
    stream_putw (s, size);
  else
    stream_putw (s, cp);

  /* Write back current pointer. */
  stream_set_putp (s, cp);

  return cp;
}

/* Add new packet to the peer. */
void
bgp_packet_add (struct peer *peer, struct stream *s)
{
  /* Add packet to the end of list. */
  stream_fifo_push (peer->obuf, s);
}

/* Free first packet. */
void
bgp_packet_delete (struct peer *peer)
{
  stream_free (stream_fifo_pop (peer->obuf));
}

/* Duplicate packet. */
struct stream *
bgp_packet_dup (struct stream *s)
{
  struct stream *new;

  new = stream_new (stream_get_endp (s));

  new->endp = s->endp;
  new->putp = s->putp;
  new->getp = s->getp;

  memcpy (new->data, s->data, stream_get_endp (s));

  return new;
}

/* Check file descriptor whether connect is established. */
static void
bgp_connect_check (struct peer *peer)
{
  int status;
  int slen;
  int ret;

  /* Anyway I have to reset read and write thread. */
  BGP_READ_OFF (peer->t_read);
  BGP_WRITE_OFF (peer->t_write);

  /* Check file descriptor. */
  slen = sizeof (status);
  ret = getsockopt(peer->fd, SOL_SOCKET, SO_ERROR, &status, &slen);

  /* If getsockopt is fail, this is fatal error. */
  if (ret < 0)
    {
      zlog (peer->log, LOG_INFO, "can't get sockopt for nonblocking connect");
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return;
    }      

  /* When status is 0 then TCP connection is established. */
  if (status == 0)
      BGP_EVENT_ADD (peer, TCP_connection_open);
  else
    {
      zlog (peer->log, LOG_INFO, "neighbor %s: Connect failed : %m",
	    peer->host);
      BGP_EVENT_ADD (peer, TCP_connection_open_failed);
    }
}

/* Write packet to the peer. */
int
bgp_write (struct thread *thread)
{
  struct peer *peer;
  u_char type;
 struct stream *s; 

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_write = NULL;

  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      return 0;
    }

  /* There should be at least one packet. */
  s = stream_fifo_head (peer->obuf);
  assert (s);
  assert (stream_get_endp (s) >= BGP_HEADER_SIZE);

  /* peer->fd is writable. */
  writen (peer->fd, STREAM_DATA (s), stream_get_endp (s));

  /* Retrieve BGP packet type. */
  stream_set_getp (s, BGP_MARKER_SIZE + 2);
  type = stream_getc (s);

  switch (type)
    {
    case BGP_MSG_OPEN:
      peer->open_out++;
      break;
    case BGP_MSG_UPDATE:
      peer->update_out++;
      break;
    case BGP_MSG_NOTIFY:
      peer->notify_out++;
      /* Double start timer. */
      peer->v_start *= 2;

      /* Overflow check. */
      if (peer->v_start >= (60 * 60))
	peer->v_start = (60 * 60);

      BGP_EVENT_ADD (peer, BGP_Stop);
      break;
    case BGP_MSG_KEEPALIVE:
      peer->keepalive_out++;
      break;
    }

  /* OK we send packet so delete it. */
  bgp_packet_delete (peer);
  
  /* If there is a packet still need bgp write thread. */
  if (stream_fifo_head (peer->obuf))
    BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
  
  return 0;
}

/* Make keepalive packet and send it to the peer. */
void
bgp_keepalive_send (struct peer *peer)
{
  struct stream *s;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make keepalive packet. */
  bgp_packet_set_marker (s, BGP_MSG_KEEPALIVE);
  bgp_packet_set_size (s, 0);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Make open packet and send it to the peer. */
void
bgp_open_send (struct peer *peer)
{
  struct stream *s;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make open packet. */
  bgp_packet_set_marker (s, BGP_MSG_OPEN);

  /* Set open packet values. */
  stream_putc (s, BGP_VERSION_4);        /* BGP version */
  stream_putw (s, peer->bgp->as);	 /* My Autonomous System*/
  stream_putw (s, peer->v_holdtime);	 /* Hold Time */
  stream_put_ipv4 (s, peer->bgp->ident); /* BGP Identifier */

  /* Opt Parm Len. */
  stream_putc (s, 0);			 

  /* Set BGP packet length. */
  bgp_packet_set_size (s, 0);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send BGP notify packet. */
void
bgp_notify_send (struct peer *peer, u_char code, u_char sub_code, char *data)
{
  struct stream *s;

  /* Allocate new stream. */
  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make nitify packet. */
  bgp_packet_set_marker (s, BGP_MSG_NOTIFY);

  /* Set notify packet values. */
  stream_putc (s, code);        /* BGP notify code */
  stream_putc (s, sub_code);	/* BGP notify sub_code */

  /* If notify data is present. */
  if (data)
    stream_write (s, data, strlen (data));
  
  /* Set BGP packet length. */
  bgp_packet_set_size (s, 0);

  /* Dump packet if debug option is set. */
  /* bgp_packet_dump (s); */

  /* Add packet to the peer. */
  bgp_packet_add (peer, s);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);

  /* For debug */
  {
    struct bgp_notify bgp_notify;

    bgp_notify.err_code = code;
    bgp_notify.err_subcode = sub_code;
    bgp_notify.data = NULL;
    bgp_notify_print (peer, &bgp_notify);
  }
}

/* Send BGP update packet. */
void
bgp_update_send (struct peer *peer, struct prefix *p, struct attr *attr)
{
  struct stream *s;
  struct stream *packet;
  unsigned long pos;
  bgp_size_t total_attr_len;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */
  stream_putw (s, 0);		

  /* Make place for total attribute length.  */
  pos = stream_get_putp (s);
  stream_putw (s, 0);
  total_attr_len = bgp_packet_attribute (peer, s, attr, p);

  /* Set Total Path Attribute Length. */
  stream_putw_at (s, pos, total_attr_len);

  /* NLRI set. */
  if (p->family == AF_INET)
    stream_put_prefix (s, p);

  /* Set size. */
  bgp_packet_set_size (s, 0);

  packet = bgp_packet_dup (s);
  stream_free (s);

  /* Dump packet if debug option is set. */
#ifdef DEBUG
  bgp_packet_dump (packet);
#endif /* DEBUG */
  /* Add packet to the peer. */
  bgp_packet_add (peer, packet);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Send BGP update packet. */
void
bgp_withdraw_send (struct peer *peer, struct prefix *p)
{
  struct stream *s;
  struct stream *packet;
  unsigned long pos;
  unsigned long cp;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;

  s = stream_new (BGP_MAX_PACKET_SIZE);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MSG_UPDATE);

  /* Unfeasible Routes Length. */;
  cp = stream_get_putp (s);
  stream_putw (s, 0);

  /* Withdrawn Routes. */
  if (p->family == AF_INET)
    stream_put_prefix (s, p);

  unfeasible_len = stream_get_putp (s) - cp - 2;
  stream_putw_at (s, cp, unfeasible_len);

  /* Make attribute. */
  if (p->family == AF_INET6)
    {
      pos = stream_get_putp (s);
      stream_putw (s, 0);
      total_attr_len = bgp_packet_withdraw (peer, s, p);

      /* Set Total Path Attribute Length. */
      stream_putw_at (s, pos, total_attr_len);
    }
  else
    stream_putw (s, 0);

  bgp_packet_set_size (s, 0);

  packet = bgp_packet_dup (s);
  stream_free (s);

  /* Add packet to the peer. */
  bgp_packet_add (peer, packet);

  BGP_WRITE_ON (peer->t_write, bgp_write, peer->fd);
}

/* Notify message treatment function. */
void
bgp_notify (struct peer *peer, bgp_size_t size)
{
  struct bgp_notify bgp_notify;

  bgp_notify.err_code = stream_getc (peer->ibuf);
  bgp_notify.err_subcode = stream_getc (peer->ibuf);

  bgp_notify_print(peer, &bgp_notify);

  BGP_EVENT_ADD (peer, Receive_NOTIFICATION_message);
}

/* BGP open message read. Should be called from finite state machine. */
void
bgp_open (struct peer *peer, bgp_size_t size)
{
  u_char version;
  u_char optlen;
  as_t asno;
  
  /* Increment packet count. */
  peer->open_in++;

  /* Parse open packet. */
  version = stream_getc (peer->ibuf);
  asno  = stream_getw (peer->ibuf);
  if (peer->v_holdtime == BGP_DEFAULT_HOLDTIME)
    peer->v_holdtime = stream_getw (peer->ibuf);
  peer->ident = stream_get_ipv4 (peer->ibuf);

  optlen = stream_getc (peer->ibuf);

  if (optlen != 0) 
    bgp_open_option_parse (peer, optlen);

  /* Peer BGP version check. */
  if (version != BGP_VERSION_4 && version != BGP_VERSION_5)
    {
      bgp_notify_send (peer, 
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_UNSUP_VERSION, 
		       NULL);
      return;
    }
  
  /* Check neighbor as number. */
  if (asno != peer->as)
    {
      bgp_notify_send (peer,
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_BAD_PEER_AS,
		       NULL);
      return;
    }

#ifdef DEBUG
  bgp_packet_dump (peer->ibuf);
#endif /* DEBUG */

  BGP_EVENT_ADD (peer, Receive_OPEN_message);
}

/* Keepalive treatment function -- get keepalive send keepalive */
void
bgp_keepalive (struct peer *peer, bgp_size_t size)
{
  if (size)
    {
      zlog (peer->log, LOG_WARNING,
	    "neighbor %s: Keepalive packet size error", peer->host);
      /* XXX We need notify at here. */
      return;
    }
  BGP_EVENT_ADD (peer, Receive_KEEPALIVE_message);
}

/* Parse BGP_UPDATE packet and make ATTRIBUTE object. */
void
bgp_update (struct peer *peer, bgp_size_t size)
{
  int ret;
  struct attr attr;
  bgp_size_t unfeasible_len;
  bgp_size_t attr_total_len;
  u_char *endp;
  struct stream *s;

  /* Get input buffer. */
  s = peer->ibuf;

#ifdef DEBUG
  bgp_packet_dump (s);
#endif /* DEBUG */

  /* Status check. */
  if (peer->status != Established) 
    {
      zlog (peer->log, LOG_ERR,
	    "neighbor %s: FSM error: "
	    "update message when status is not Established", peer->host);
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0, NULL);
      return;
    }

  /* BGP update size check.  At least it has unfeasible_len. */
  if (size <= 2)
    {
      zlog (peer->log, LOG_WARNING, 
	    "neighbor %s: BGP update message is too small %d",
	    peer->host, size);

      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, 
		       NULL);
      return;
    }

  /* Set end pointer. */
  endp = stream_pnt (s) + size;

  /* Unfeasible treatment */
  unfeasible_len = stream_getw (s);
  if (unfeasible_len > 0) 
    {
      /* Check length of unfeasible length. */
      if (stream_pnt (s) + unfeasible_len > endp)
	{
	  zlog (peer->log, LOG_ERR, 
		"neighbor %s: unfeasible length error %d", 
		peer->host, unfeasible_len);
	  bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, NULL);
	}
      peer->withdrow_in++;
      nlri_unfeasible (peer, unfeasible_len);
    }
  else 
    peer->update_in++;

  /* Fetch attribute total length. */
  attr_total_len = stream_getw (s);

  /* Clear attribute structure. */
  bzero (&attr, sizeof attr);

  /* If attribute is malformed, stop parsing packet. */
  ret = bgp_attr_parse (peer, &attr, attr_total_len);
  if (ret < 0)
    return;

#if 0
  /* Attribute check. In case of IPv6 withdraw with MBGP has attribute
     but don't have mandatory attribute.  So we have to check that. */
  if (attr_total_len)
    {
      ret = bgp_attr_check (peer, &attr);
      if (ret < 0)
	return;
    }
#endif /* 0 */

  /* Network Layer Reachability Information. */
  nlri_parse (peer, &attr, STREAM_PNT (s), endp - STREAM_PNT (s), AF_INET);

  BGP_EVENT_ADD (peer, Receive_UPDATE_message);
}

/* BGP read utility function. */
int
bgp_read_packet (struct peer *peer, bgp_size_t size)
{
  int nbytes;

  /* If size is zero then return. */
  if (! size)
    return 0;

  /* Read packet from fd. */
  nbytes = stream_read (peer->ibuf, peer->fd, size);

  /* If read byte is smaller than zero then error occured. */
  if (nbytes < 0) 
    {
      zlog (peer->log, LOG_WARNING, "neighbor %s: bgp_read_packet error: %m",
	    peer->host);
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return -1;
    }  

  /* When read byte is zero : clear bgp peer and return */
  if (nbytes == 0) 
    {
      zlog (peer->log, LOG_WARNING,
	    "neighbor %s: bgp connection closed at [%d]",
	    peer->host, peer->fd);
      BGP_EVENT_ADD (peer, TCP_connection_closed);
      return -1;
    }

  /* If header size is defferent print warning and return */
  if (nbytes != size) 
    {
      zlog (peer->log, LOG_WARNING,
	    "neighbor %s: bgp_read can't read all of packet %d/%d : %m",
	    peer->host, size, nbytes);
      BGP_EVENT_ADD (peer, TCP_fatal_error);
      return -1;
    }
  return 0;
}

/* Starting point of packet process function. */
int
bgp_read (struct thread *thread)
{
  int ret;
  struct peer *peer;
  u_char type;
  bgp_size_t size;

  /* Yes first of all get peer pointer. */
  peer = THREAD_ARG (thread);
  peer->t_read = NULL;

  /* For non-blocking IO check. */
  if (peer->status == Connect)
    {
      bgp_connect_check (peer);
      return 0;
    }
  else
    BGP_READ_ON (peer->t_read, bgp_read, peer->fd);

  /* Clear input buffer. */
  stream_reset (peer->ibuf);

  /* Read packet header to determin type of the packet */
  ret = bgp_read_packet (peer, BGP_HEADER_SIZE);

  if (ret < 0) 
    return ret;

  /* BGP packet dump to file function. */
  bgp_dump_incoming (peer, peer->ibuf);

  /* Get size and type. */
  stream_forward (peer->ibuf, BGP_MARKER_SIZE);
  size = stream_getw (peer->ibuf);
  type = stream_getc (peer->ibuf);

  /* Packet size check. */
  if (size > BGP_MAX_PACKET_SIZE) 
    {
      zlog (peer->log, LOG_WARNING,
	    "neighbor %s: bgp_get_message packet buffer over flow",
	    peer->host);
      bgp_notify_send (peer,
		       BGP_NOTIFY_HEADER_ERR,
		       BGP_NOTIFY_HEADER_BAD_MESLEN,
		       NULL);
      return 0;
    }

  /* Adjust size to message length. */
  size -= BGP_HEADER_SIZE;

  ret = bgp_read_packet (peer, size);
  if (ret < 0) 
    return ret;

  /* bgp_packet_dump (peer->ibuf); */

  /* Read rest of the packet and call each sort of packet routine */
  switch (type) 
    {
    case BGP_MSG_OPEN:
      bgp_open (peer, size);
      break;
    case BGP_MSG_UPDATE:
      bgp_update (peer, size);
      break;
    case BGP_MSG_NOTIFY:
      bgp_notify (peer, size);
      break;
    case BGP_MSG_KEEPALIVE:
      bgp_keepalive (peer, size);
      break;
    default:
      zlog (peer->log, LOG_WARNING,
	    "neighbor %s: BGP packet header type %d is illegal",
	    peer->host, type);
      bgp_notify_send (peer, BGP_NOTIFY_HEADER_ERR,
		       BGP_NOTIFY_HEADER_BAD_MESTYPE, NULL);
      /* Notify and clear bgp peer. */
      break;
    }
  return 0;
}
