/*
 * $Id: bgp_network.c,v 1.11 1999/02/22 12:15:37 developer Exp $
 *
 * BGP network related fucntions
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
#include "sockunion.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"

/* BGP try to connect to the peer.  */
int
bgp_connect (struct peer *peer)
{
  struct servent *sp;
  unsigned short port;

  /* Make socket for the peer. */
  peer->fd = sockunion_socket (peer->su);
  if (peer->fd < 0)
    return -1;

  /* If we can get socket for the peer, adjest TTL and make connection. */
  if (bgp_peer_sort (peer) == BGP_PEER_EBGP)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  /* Get service port number. */
  sp = getservbyname ("bgp", "tcp");
  if (sp != NULL) 
    port = sp->s_port;
  else
    port = htons (BGP_PORT_DEFAULT);

  /* Connect to the remote peer. */
  return sockunion_connect (peer->fd, peer->su, port);
}

/* Accept bgp connection. */
int
bgp_accept (struct thread *thread)
{
  int bgp_sock;
  int accept_sock;
  union sockunion su;
  struct peer *peer;
  char buf[BUFSIZ];

  accept_sock = THREAD_FD (thread);

  bgp_sock = sockunion_accept (accept_sock, &su);

  zlog (NULL, LOG_INFO, "OK I got BGP connection from host %s",
	  inet_sutop (&su, buf));
  
  thread_add_read (master, bgp_accept, NULL, accept_sock);

  /* This router is not neighbor router. */
  peer = peer_lookup_by_su (&su);
  if (!peer) 
    {
      zlog (NULL, LOG_INFO, "This peer is not neighbor connection closed : %s",
	      inet_sutop (&su, buf));
      close (bgp_sock);
      return -1;
    }

  /* Check status of the peer. */
  if (peer->status != Active) 
    {
      zlog (peer->log, LOG_INFO, "But I'm not Active status so connection is closed : %s",
	      inet_sutop (&su, buf));
      close (bgp_sock);
      return -1;
    }

  peer->fd = bgp_sock;
  BGP_EVENT_ADD (peer, TCP_connection_open);

  return 0;
}

/* Make bgpd's server socket. */
int
bgp_serv_sock (unsigned short port, int family)
{
  int ret;
  int bgp_sock;
  union sockunion su;

  bzero (&su, sizeof (union sockunion));

  /* Specify address family. */
  su.sa.sa_family = family;
  bgp_sock = sockunion_stream_socket (&su);

  sockopt_reuseaddr (bgp_sock);

  ret = sockunion_bind (bgp_sock, &su, port, NULL);

  ret = listen (bgp_sock, 3);
  if (ret < 0) 
    {
      zlog (NULL, LOG_INFO, "can't listen bgp server socket : %m");
      return ret;
    }

  thread_add_read (master, bgp_accept, NULL, bgp_sock);

  return bgp_sock;
}
