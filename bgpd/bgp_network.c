/*
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
#include "memory.h"
#include "log.h"
#include "if.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_fsm.h"

/* BGP socket bind. */
int
bgp_bind (struct peer *peer)
{
#ifdef SO_BINDTODEVICE
  int ret;
  struct ifreq ifreq;

  if (!peer->ifname)
    return 0;

  strncpy ((char *)&ifreq.ifr_name, peer->ifname, sizeof (ifreq.ifr_name));

  ret = setsockopt (peer->fd, SOL_SOCKET, SO_BINDTODEVICE, 
		    &ifreq, sizeof (ifreq));
  if (ret < 0)
    {
      zlog (peer->log, LOG_INFO, "bind to interface %s failed", peer->ifname);
      return ret;
    }
#endif /* SO_BINDTODEVICE */
  return 0;
}

int
bgp_update_source (struct peer *peer)
{
  struct interface *ifp;

  /* Ifname is exist. */
  if (peer->update_if)
    {
      ifp = if_lookup_by_name (peer->update_if);
      if (!ifp)
	return -1;
      return 0;
    }

  if (peer->update_source)
    return sockunion_bind (peer->fd, peer->update_source, 
			   BGP_PORT_DEFAULT, peer->update_source);

  return 0;
}

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

  /* Bind socket. */
  bgp_bind (peer);

  /* Update source bind. */
  bgp_update_source (peer);

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

  thread_add_read (master, bgp_accept, NULL, accept_sock);

  /* Convert IPv4 compatible IPv6 address to IPv4 address. */
#ifdef HAVE_IPV6
  if (su.sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_V4MAPPED (&su.sin6.sin6_addr))
	{
	  struct sockaddr_in sin;

	  sin.sin_family = AF_INET;
	  memcpy (&sin.sin_addr, ((char *)&su.sin6.sin6_addr) + 12, 4);
	  memcpy (&su, &sin, sizeof (struct sockaddr_in));
	}
    }
#endif /* HAVE_IPV6 */

  zlog (NULL, LOG_INFO, "OK I got BGP connection from host %s",
	inet_sutop (&su, buf));
  
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

#ifdef HAVE_IPV6
void
bgp_serv_sock_addrinfo (unsigned short port)
{
  int ret;
  struct addrinfo req;
  struct addrinfo *ainfo;
  struct addrinfo *ainfo_save;
  int sock;
  char port_str[BUFSIZ];

  memset (&req, 0, sizeof (struct addrinfo));
  req.ai_flags = AI_PASSIVE;
  req.ai_family = AF_UNSPEC;
  req.ai_socktype = SOCK_STREAM;
  sprintf (port_str, "%d", port);

  ret = getaddrinfo (NULL, port_str, &req, &ainfo);

  if (ret != 0)
    {
      fprintf (stderr, "getaddrinfo failed: %s\n", strerror (errno));
      exit (1);
    }

  ainfo_save = ainfo;

  do
    {
      sock = socket (ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
      if (sock < 0)
	continue;

      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);

      ret = bind (sock, ainfo->ai_addr, ainfo->ai_addrlen);
      if (ret < 0)
	continue;

      ret = listen (sock, 3);
      if (ret < 0) 
	continue;

      thread_add_read (master, bgp_accept, NULL, sock);
    }
  while ((ainfo = ainfo->ai_next) != NULL);

  freeaddrinfo (ainfo_save);
}
#endif /* HAVE_IPV6 */

/* Make bgpd's server socket. */
void
bgp_serv_sock_family (unsigned short port, int family)
{
  int ret;
  int bgp_sock;
  union sockunion su;

  bzero (&su, sizeof (union sockunion));

  /* Specify address family. */
  su.sa.sa_family = family;
  bgp_sock = sockunion_stream_socket (&su);

  sockopt_reuseaddr (bgp_sock);
  sockopt_reuseport (bgp_sock);

  ret = sockunion_bind (bgp_sock, &su, port, NULL);

  ret = listen (bgp_sock, 3);
  if (ret < 0) 
    {
      zlog (NULL, LOG_INFO, "Can't listen bgp server socket : %s",
	    strerror (errno));
      return;
    }

  thread_add_read (master, bgp_accept, NULL, bgp_sock);
}

void
bgp_serv_sock (unsigned short port)
{
#ifdef HAVE_IPV6
  bgp_serv_sock_addrinfo (port);
#else
  bgp_serv_sock_family (port, AF_INET);
#endif /* HAVE_IPV6 */
}

/* After TCP connection is established.  Get local address and port. */
void
bgp_getsockname (struct peer *peer)
{
  if (peer->su_local)
    XFREE (MTYPE_TMP, peer->su_local);
  peer->su_local = sockunion_getsockname (peer->fd);
}
