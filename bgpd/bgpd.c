/* BGP-4, BGP-4+, BGP-5 daemon program
   Copyright (C) 1996, 97 Kunihiro Ishiguro

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
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <netdb.h>

#include "bgpd.h"
#include "bgp_aspath.h"
#include "bgp_route.h"
#include "bgp_peer.h"
#include "bgp_dump.h"
#include "bgp_attr.h"
#include "log.h"
#include "route.h"
#include "thread.h"
#include "buffer.h"

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"

/* List head of bgp instance list. */
list bgp_list;

/* List of all bgp peer. */
extern list peer_list;

/* BGP multiple instance option. */
char bgp_multiple_instance;

/* Thread master. */
extern struct thread_master *master;

/* Top node of bgpd's routing table. */
extern struct radix_top *bgp_radix;
#ifdef HAVE_IPV6
extern struct radix_top *bgp_radix_ipv6;
#endif /* HAVE_IPV6 */

/* Return socket of sockunion. */
int
sockunion_socket (union sockunion *su)
{
  int sock;

  sock = socket (su->sa.sa_family, SOCK_STREAM, 0);
  if (sock < 0)
    {
      log ("Can't make socket : %s\n", strerror (errno));
      return -1;
    }

  return sock;
}

int
sockunion_sizeof (union sockunion *su)
{
  int ret;

  ret = 0;
  switch (su->sa.sa_family)
    {
    case AF_INET:
      ret = sizeof (struct sockaddr_in);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      ret = sizeof (struct sockaddr_in6);
      break;
#endif /* AF_INET6 */
    }
  return ret;
}

#include <fcntl.h>

/* sockunion_connect returns
   -1 : error occured
   0 : connect success
   1 : connect is in progress */
int
sockunion_connect (struct peer *peer)
{
  int ret;
  int val;
  struct servent *sp;
  union sockunion *su;
  unsigned short port;
  
  /* Fetch peer's sockunion. */
  su = peer->su;

  /* Get service port number. */
  sp = getservbyname ("bgp", "tcp");
  if (sp != NULL) 
    port = sp->s_port;
  else
    port = htons (BGP_PORT_DEFAULT);

  switch (su->sa.sa_family)
    {
    case AF_INET:
      su->sin.sin_port = port;
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      su->sin6.sin6_port  = port;
      break;
#endif /* HAVE_IPV6 */
    }      

  /* For bgp_connect_from_peer */
  val = fcntl (peer->fd, F_GETFL, 0);
  fcntl (peer->fd, F_SETFL, val|O_NONBLOCK);

  /* Call connect function. */
  ret = connect (peer->fd, (struct sockaddr *) su, sockunion_sizeof (su));

  /* Immediate success */
  if (ret == 0)
    {
      fcntl (peer->fd, F_SETFL, val);
      return 0;
    }

  /* If connect is in progress then return 1 else it's real error. */
  if (ret < 0)
    {
      if (errno != EINPROGRESS)
	{
	  log ("can't connect to ");
	  sockunion_log (su);
	  log2 (" fd %d : %s\n", peer->fd, strerror (errno));
	  return ret;
	}
    }

  fcntl (peer->fd, F_SETFL, val);
  return 1;
}

/* BGP try to connect to peer.  */
bgp_connect (struct peer *peer)
{
  /* Make socket for the peer. */
  peer->fd = sockunion_socket (peer->su);

  /* If we can get socket for the peer, adjest TTL and make connection. */
  if (peer->fd < 0)
    return -1;

  if (peer_sort (peer) == BGP_PEER_EBGP)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  return sockunion_connect (peer);
}

/* Utility function. */
bgp_read (int fd, char *ptr, int nbytes)
{
  int ret = readn (fd, ptr, nbytes);
  
  if (ret < 0) {
    log ("bgp_read errno  : %s\n", strerror (errno));
    /* XXX need event here.*/
  } else {
    return ret;
  }
}

/* Starting point of packet process function. */
bgp_read_packet (struct peer *peer)
{
  int ret;
  struct bgp_header h;

  /* read packet header to determin type of the packet */
  ret = bgp_read_header (peer, &h);
  if (ret < 0) 
    {
      event_add (peer, TCP_connection_closed);
      return ret;
    }

  /* read rest of the packet and call each sort of packet routine */
  switch (h.type) 
    {
    case BGP_MSG_OPEN:
      if (bgp_get_message (peer, &h))
	bgp_open_recv (peer, h.length);
      break;
    case BGP_MSG_UPDATE:
      if (bgp_get_message (peer, &h))
	bgp_update (peer, h.length);
      break;
    case BGP_MSG_NOTIFY:
      if (bgp_get_message (peer, &h))
	bgp_notify (peer, h.length);
      break;
    case BGP_MSG_KEEPALIVE:
      bgp_keepalive (peer, h.length);
      break;
    default:
      log_warn ("Header type is illegal\n");
      /* Notify and clear bgp peer. */
      break;
    }
}

/* Accept bgp connection. */
bgp_accept (struct thread *thread)
{
  int bgp_sock;
  int accept_sock;
  union sockunion su;
  struct peer *peer;
  char buf[SU_ADDRSTRLEN];

  accept_sock = thread_fd (thread);

  bgp_sock = sockunion_accept (accept_sock, &su);

  log ( "OK I got BGP connection from host %s\n", inet_sutop (&su, buf));
  
  thread_add_read (master, bgp_accept, NULL, accept_sock);

  /* this router is not neighbor router */
  peer = peer_lookup_by_su (&su);
  if (!peer) 
    {
      log ( "This peer is not neighbor connection closed : %s\n",
	    inet_sutop (&su, buf));
      close (bgp_sock);
      return -1;
    }

  /* Check status of the peer. */
  if (peer->status != Active) 
    {
      log ( "But I'm not Active status so connection is closed : %s\n",
	    inet_sutop (&su, buf));
      close (bgp_sock);
      return -1;
    }

  peer->fd = bgp_sock;
  event_add (peer, TCP_connection_open);

  return 0;
}

/* Make bgpd's server socket. */
bgp_serv_sock (unsigned short port, int family)
{
  int ret;
  int bgp_sock;
  union sockunion su;
  struct sockaddr_in name;

  bzero (&su, sizeof (union sockunion));

  /* Specify address family. */
  su.sa.sa_family = family;
  bgp_sock = sockunion_stream_socket (&su);

  sockopt_reuseaddr (bgp_sock);

  ret = sockunion_bind (bgp_sock, &su, port, NULL);

  ret = listen (bgp_sock, 3);
  if (ret < 0) 
    {
      log ("can't listen bgp server socket : %s\n", strerror (errno));
      return ret;
    }

  thread_add_read (master, bgp_accept, NULL, bgp_sock);

  return bgp_sock;
}

/* BGP header read */
bgp_read_header (struct peer *peer, struct bgp_header *h)
{
  int nbyte;
  u_char *pnt = peer->header_buf;

  nbyte = bgp_read (peer->fd, pnt, BGP_HEADER_SIZE);

  /* when read byte is zero : clear bgp peer and return */
  if (nbyte <= 0) 
    {
      log ("bgp connection closed at [%d]. try again.\n", peer->fd);
      bgp_clear (peer, 0);
      return -1;
    }

  /* if header size is defferent print warning and return */
  if (nbyte != BGP_HEADER_SIZE) 
    {
      log ("bgp header size can't read\n");
      close (peer->fd);
      peer->fd = -1;
      return -1;
    }

  /* get all header packet */
  memcpy (h->marker, pnt, BGP_MARKER_SIZE);
  pnt += BGP_MARKER_SIZE;
  ld_2byte (h->length, pnt);
  ld_1byte (h->type, pnt);

  /* call dump function */
  bgp_dump_header (h);

  return 1;
}

/* Make a bgp packet, return start ponter of packet and set whole size
   of packet into packet_size */
u_char *
bgp_make_packet (int *packet_size, int type, char *data)
{
  int i, dsize;
  char buffer[BGP_MAX_PACKET_SIZE];
  char *pnt = buffer;
  char *begin = buffer;
  char *ret;
  
  /* First of all make marker */
  for (i = 0; i < BGP_MARKER_SIZE; i++)
    st_1byte(0xff, pnt);

  /* Dummy total length, filled in after */
  st_2byte(0, pnt);

  /* BGP Packet type */
  st_1byte(type, pnt);

  /* Each data type routine call */
  switch (type) 
    {
    case BGP_MSG_OPEN:
      dsize = bgp_make_open ((struct bgp_open *)data, pnt);
      break;
    case BGP_MSG_UPDATE:
      dsize = bgp_make_update ((struct prefix_in *)data, pnt);
      break;
    case BGP_MSG_KEEPALIVE:
      /* Keepalive contains no data. */
      dsize = 0;
      break;
    case BGP_MSG_NOTIFY:
      dsize = bgp_make_notify ((struct bgp_notify *)data, pnt);
      break;
    default:
      break;
    }

  /* set total length of the message */
  pnt = begin + BGP_MARKER_SIZE;
  dsize += BGP_HEADER_SIZE;
  st_2byte (dsize, pnt);
  
  /* set packet size */
  *packet_size = dsize;

  /* Return new allocated pointer */
  ret = (char *) malloc (dsize);
  memcpy (ret, buffer, dsize);

  return ret;
}

/* Read bgp packet from peer. */
bgp_get_message (struct peer *peer, struct bgp_header *h)
{
  int nbyte;
  int len;

  /* message length count */
  len = h->length - BGP_HEADER_SIZE;

  /* check buffer overflow */
  if (len > BGP_MAX_PACKET_SIZE) 
    {
      log ("bgp_get_message packet buffer over flow\n");
      return 0;
    }

  /* read message into buffer */
  nbyte = bgp_read (peer->fd, peer->read_buf, len);
  if (nbyte != len) 
    {
      log ("bgp_read can't read all of packet %d/%d : %s\n",
	   len, nbyte,strerror (errno));
      bgp_clear (peer, 0);
      return 0;
    }

  return nbyte;
}

/* Make open packet and send it to remote peer. */
bgp_open_send (struct peer *peer)
{
  struct bgp_open bgp_open;
  u_char *packet;
  int nbytes;
  int nwritten;

  bgp_open.version = BGP_VERSION_4;
  bgp_open.asno = peer->bgp->as;
  bgp_open.holdtime = BGP_DEFAULT_HOLDTIME;
  /* bgp_open.holdtime = peer->v_holdtime; */
  bgp_open.ident = peer->bgp->ident;
  bgp_open.optlen = 0;

  packet = (u_char *) bgp_make_packet (&nbytes, BGP_MSG_OPEN, (u_char *)&bgp_open);

  nwritten = writen (peer->fd, packet, nbytes);

  peer->open_out++;
  free(packet);
}

/* Notify send function. */
bgp_notify_send (struct peer *peer, u_char err_code, u_char err_subcode)
{
  int nbytes;
  u_char *packet;
  struct bgp_notify bgp_notify;

  bgp_notify.err_code = err_code;
  bgp_notify.err_subcode = err_subcode;

  packet = (u_char *)bgp_make_packet(&nbytes, BGP_MSG_NOTIFY, (u_char *)&bgp_notify);
  writen(peer->fd, packet, nbytes);
  free(packet);
}

/* Parse BGP_UPDATE packet and make ATTRIBUTE object. */
bgp_get_update (struct peer *peer, int size)
{
  struct attr *attr;
  u_int16_t attr_len;
  u_char attr_flag;
  u_char attr_type;
  u_int16_t unfeasible_len;
  u_int16_t attr_total_len;
  u_char *attrlim;

  u_char *pnt = peer->read_buf;

  /* status check */
  if (peer->status != Established) 
    {
      bgp_notify_send (peer, BGP_NOTIFY_FSM_ERR, 0);
      log ("FSM error: update message when status is not Established\n");
      bgp_clear (peer, 1);
      return;
    }

  /* Unfeasible treatment */
  ld_2byte(unfeasible_len, pnt);

  if (unfeasible_len > 0) 
    {
      peer->withdrow_in++;
      withdraw_route(pnt, unfeasible_len, peer);
    }
  else 
    peer->update_in++;

  pnt += unfeasible_len;

  /* attribute total length */
  ld_2byte(attr_total_len, pnt);

  /* Parse attribute. */
  attr = attr_get (pnt, attr_total_len, peer);
  pnt += attr_total_len;
  
  /* Attribute check. */
  attr_check (attr);

  /* Network Layer Reachability Information. */
  dump_update_size (size, (pnt - peer->read_buf));
    
  route_parse (pnt, size - (pnt - peer->read_buf), attr, peer);
}

/* Notify message treatment function. */
bgp_notify(peer, length)
     struct peer * peer;
     int length;
{
  struct bgp_notify bgp_notify;
  u_char *pnt = peer->read_buf;

  ld_1byte (bgp_notify.err_code, pnt);
  ld_1byte (bgp_notify.err_subcode, pnt);

  bgp_notify_print(peer, &bgp_notify);

  /* Next this peer goes to Idle state. Below should be move to
     bgp_fsm.c */
  bgp_clear (peer, 1);
}

/* Clear bgp peer. */
bgp_clear(struct peer *peer, int error)
{
  /* This function delete all routing information which coming from
     the peer. */
  bgp_peer_delete (peer);

  /* If this function is executed outside of bgp_read_packet. Cancel
     next read. */
  if (peer->t_read)
    {
      thread_cancel (peer->t_read);
      peer->t_read = NULL;
    }
  
  /* If this peer has active fd. */
  if (peer->fd != -1)
    {
      close (peer->fd);
      peer->fd = -1;
    }

  bgp_uptime_reset (peer);

  if (error)
    event_add (peer, TCP_connection_closed);
}

/* Update message treatment function. */
bgp_update(struct peer *peer, int length)
{
  if (length != 0)
    bgp_get_update(peer, length - BGP_HEADER_SIZE);
  else
    printf ("empty bgp update message");

  event_add (peer, Receive_UPDATE_message);
}

/* Keepalive treatment function -- get keepalive send keepalive */
bgp_keepalive(struct peer *peer, int length)
{
  if (length != BGP_HEADER_SIZE) 
    {
      log ("keepalive header error\n");
      return 0;
    }

  event_add (peer, Receive_KEEPALIVE_message);
}

/**/
bgp_uptime_reset (struct peer *peer)
{
  time (&peer->uptime);
}

#if 0
/* Output static bgp nlri */
radix_output (peer, route)
     struct peer * peer;
     route_t route;
{
  int nbytes;
  byte *packet;
  
  route->attr->next_hop = peer->next_hop;
  packet = (byte *)bgp_make_packet (&nbytes, BGP_MSG_UPDATE, (char *)route);
  writen (peer->fd, packet, nbytes);

  free (packet);
}
#endif

/* Keep alive send function. */
bgp_keepalive_send(peer)
     struct peer * peer;
{
  int nbytes;
  int nwritten;
  u_char *packet;
  
  /* make keepalive packet and send to peer */
  packet = (u_char *)bgp_make_packet(&nbytes, BGP_MSG_KEEPALIVE, NULL);

  nwritten = writen (peer->fd, packet, nbytes);

  peer->keepalive_out++;
  free (packet);

  /* peer count update */
  peer->keepalive_in++;
}


/**/
bgp_make_update (struct prefix_in *pin, char *pnt)
{
  char *start = pnt;
  char *total_len;
  int count;
  struct attr *attr;
  int attr_len;

  attr = pin->gate.info;

  /* make Unfeasible Routes Length */
  st_2byte(0, pnt);		/* in case of no Unfeasible Routes */

  /* make Total Path Attribute Length */
  total_len = pnt;		/* remind this point for later write */
  st_2byte(0, pnt);		/* for reserve space */

  attr_len = attr_make (pnt, attr);
  st_2byte (attr_len, total_len);
  pnt += attr_len;

  /* If prefix is zero then this route is IPv6 route */
  {
    int len = PSIZE (pin->mask);

    /* Network Layer Reachability Information */
    st_1byte (pin->mask, pnt);
    memcpy (pnt, &pin->prefix, len);
    pnt += len;
  }
  return pnt - start;
}

/* Make notify packet */
bgp_make_notify (struct bgp_notify *bgp_notify, u_char *pnt)
{
  u_char *start = pnt;

  st_1byte (bgp_notify->err_code, pnt);
  st_1byte (bgp_notify->err_subcode, pnt);

  return pnt - start;
}

/* make open message */
bgp_make_open (struct bgp_open *bgp_open, u_char *pnt)
{
  u_char *start = pnt;

  st_1byte (bgp_open->version, pnt);
  st_2byte (bgp_open->asno, pnt);
  st_2byte (bgp_open->holdtime, pnt);
  st_4octet (bgp_open->ident, pnt);

  if (bgp_open->optlen != 0) 
    ;				/* Option parse need at here. */
  else 
    st_1byte (bgp_open->optlen, pnt);

  return pnt - start;
}

/* Allocate new bgp structure. */
struct bgp *
bgp_new ()
{
  struct bgp *new = (struct bgp *) malloc (sizeof (struct bgp));
  bzero (new, sizeof (struct bgp));
  return new;
}

/* BGP structure specify by asno. */
struct bgp *
bgp_lookup_by_as (u_int16_t as)
{
  struct bgp *bgp; 
  listnode node;

  node = listhead (bgp_list);
  while (node)
    {
      bgp = getdata (node);
      if (bgp->as == as)
	return bgp;
      nextnode (node);
    }
  return NULL;
}

/* Called when SIGINT signal is received */
bgp_terminate ()
{
  /* Close all bgp peer. */
  
}

DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       "Enable bgp multiple instance.")
{
  bgp_multiple_instance = 1;
  return CMD_SUCCESS;
}

DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       "Enable bgp multiple instance.")
{
  if (listcount (bgp_list) > 1)
    {
      vty_out (vty, "There are more than two active bgp instances.\r\n");
      return CMD_WARNING;
    }
  
  bgp_multiple_instance = 0;
  return CMD_SUCCESS;
}

/* router bgp AS_NO command.*/
DEFUN (router_bgp, 
       router_bgp_cmd, 
       "router bgp AS_NO", 
       "Make BGP instance command.")
{
  struct bgp *bgp;
  u_int16_t as;

  /* Check duplicate instance as same AS value. */
  as = strtol (argv[0], NULL, 10);

  /* Check existing bgp. */
  bgp = bgp_lookup_by_as (as);

  /* There is already active bgp instance. */
  if (bgp != NULL)
    {
      vty->node = BGP_NODE;
      vty->index = bgp;
      return CMD_SUCCESS;
    }

  if (!bgp_multiple_instance && !list_isempty (bgp_list))
    {
      bgp = getdata (listhead (bgp_list));
      
      vty_out (vty, "bgp is already active at %d.\r\n", bgp->as);
      return CMD_WARNING;
    }
  
  /* Make new bgp instance. */
  bgp = bgp_new ();
  bgp->as = as;
  bgp->ident = 0;
  bgp->peer = list_init ();
  list_add_node (bgp_list, bgp);

  /* Set current bgp point. */
  vty->node = BGP_NODE;
  vty->index = bgp;
  return CMD_SUCCESS;
}

DEFUN (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id IPV4_ADDRESS",
       "Set my own router identifier")
{
  int ret;
  struct bgp *bgp;

  bgp = (struct bgp *) vty->index;
  
  ret = inet_aton (argv[0], &bgp->ident);
  if (!ret)
    {
      vty_out (vty, "malformed bgp router identifier\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_router_bgp, 
       no_router_bgp_cmd, 
       "no router bgp AS_NO", 
       "Delete BGP instance command.")
{
  struct bgp *bgp;
  struct peer *peer;
  listnode node;
  u_int16_t as;

  as = strtol (argv[0], NULL, 10);

  bgp = bgp_lookup_by_as (as);

  if (bgp == NULL)
    {
      vty_out (vty, "There isn't active bgp instance under as number %d.\r\n", as);
      return CMD_WARNING;
    }

  for (node = listhead (bgp->peer); node; nextnode (node))
    {
      peer = getdata (node);
      ;
    }
  return CMD_SUCCESS;
}

/* called from terminal list command */
route_vty_out (struct prefix_in *pin, struct vty *vty)
{
  /* message of route origin */
  char *bgp_update_origin[] = {"i","e","?"};
  struct bgp_route *br;
  int len;

  br = (struct bgp_route *) pin;

  /* print prefix and mask */
  route_vty_out_route (pin, vty);

  /* print attribute */
  if (br->attr != NULL) {
    vty_out (vty, "%-16s%10lu%10lu ", 
	     inet_ntoa(br->attr->next_hop), br->attr->med,
	     br->attr->local_pref);
    
    /* print aspath */
    if (br->attr->aspath != NULL)
      aspath_print_vty (vty, br->attr->aspath);

    /* print origin */
    vty_out (vty, " %s", bgp_update_origin[br->attr->origin]);
  }

  vty_out (vty, "\r\n");
}  

#ifdef HAVE_IPV6
/* called from terminal list command */
routev6_vty_out (struct prefix_in6 *pin6, struct vty *vty)
{
  /* message of route origin */
  char *bgp_update_origin[] = {"i","e","?"};
  struct bgp_info *binfo;
  struct attr *attr;
  char buf[INET6_ADDRSTRLEN];
  int len;

  binfo = pin6->gate.info;

  /* print prefix and mask */
  route_vty_out_route_in6 (pin6, vty);

  /* print attribute */
  if (binfo && binfo->attr != NULL) {
    attr = binfo->attr;
    vty_out (vty, "%-s[%d]%5lu%5lu ", 
	     inet_ntop (AF_INET6, attr->mp_nexthop, buf, INET6_ADDRSTRLEN), 
	     attr->mp_nexthop_len,
	     attr->med,
	     attr->local_pref);
    
    /* print aspath */
    if (attr->aspath != NULL)
      aspath_print_vty (vty, attr->aspath);

    /* print origin */
    vty_out (vty, " %s", bgp_update_origin[attr->origin]);
  }

  vty_out (vty, "\r\n");
}  
#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp [IPV4_ADDR]",
       "Show bgpd's own routing information.")

{
  int ret;
  struct prefix_in match;
  struct prefix_in *rt;

  if (argc == 0)
    {
      vty_out (vty, "\r\nNetwork             Next Hop            Metric    LocPrf Path\r\n");
      radix_apply_func (bgp_radix, route_vty_out, vty);
      return;
    }

  ret = inet_aton (argv[0], &match.prefix);
  if (! ret)
    {
      vty_out (vty, "address is malformed\r\n");
      return;
    }
#define HOST_MASK 32
  match.mask = HOST_MASK;
  
  rt = (struct prefix_in *) radix_match (bgp_radix, (struct prefix *) &match);

  if (rt == NULL)
    {
      vty_out (vty, "can't find route\r\n");
      return;
    }

  while (rt)
    {
      bgp_print_route (vty, rt);
      rt = rt->next;
    }
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       "Show bgpd's own routing information of IPv6.")
{
  vty_out (vty, "\r\nNetwork                  Next Hop       Metric    LocPrf Path\r\n");
  radix_apply_func (bgp_radix_ipv6, routev6_vty_out, vty);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */


DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors [PEER]",
       "Show neighbor's information")
{
  struct peer *p;
  listnode node;

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down.\r\n");

  for (node = listhead (peer_list); node; nextnode (node))
    {
      p = getdata (node);

      vty_out (vty, "%-15s ", p->host);
      switch (p->version) {
      case BGP_VERSION_4:
	vty_out (vty, " %d ", p->version);
	break;
      case BGP_VERSION_MP_4:
	vty_out (vty, "4- ");
	break;
      case BGP_VERSION_MP_4_DRAFT_00:
	vty_out (vty, "4+ ");
	break;
      }
      vty_out(vty, "%5d %7d %7d %8d %4d %4d ", p->as,
	       p->open_in+p->update_in+p->withdrow_in+p->keepalive_in,
	       p->open_out+p->update_out+p->withdrow_out+p->keepalive_out,
	       0, 0, 0);

      peer_uptime_vty (vty, p);

      vty_out (vty, "\r\n  Remote router ID %s\r\n", inet_ntoa (p->ident));

      vty_out (vty,
	       "  Status: %-12s keepalive: %d holdtime: %d"
	       "\r\n  open: in/out %d/%d"
	       "  update: in/out %d+%d/%d+%d"
	       "  keepalive: in/out %d/%d\r\n",
	       LOOKUP (bgp_status_msg, p->status),
	       p->v_keepalive, p->v_holdtime,
	       p->open_in, p->open_out,
	       p->update_in, p->withdrow_in,
	       p->update_out, p->withdrow_out,
	       p->keepalive_in, p->keepalive_out
	       );
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_summary, 
       show_ip_bgp_summary_cmd,
       "show ip bgp summary",
       "List all bgp neighbor status summary")
{
  listnode node;
  struct peer *peer;

  vty_out (vty, "Neighbor        V     AS MsgRcvd MsgSent"
	   "   TblVer  InQ OutQ Up/Down  State/Pref\r\n");

  for (node = listhead (peer_list); node; nextnode (node))
    {
      int length;
      peer = getdata (node);
	  
      length = sockunion_vty_out (vty, peer->su);
      length = 16 - length;
      if (length < 0)
	length = 0;

      vty_out (vty, "%*s", length, " ");
      switch (peer->version) 
	{
	case BGP_VERSION_4:
	  vty_out (vty, "%d ", peer->version);
	  break;
	case BGP_VERSION_MP_4:
	  vty_out (vty, "4- ");
	  break;
	case BGP_VERSION_MP_4_DRAFT_00:
	  vty_out (vty, "4+ ");
	  break;
	}
      vty_out (vty, "%5d %7d %7d %8d %4d %4d ",
	       peer->as,
	       peer->open_in + peer->update_in +
	       peer->withdrow_in + peer->keepalive_in,
	       peer->open_out + peer->update_out +
	       peer->withdrow_out + peer->keepalive_out,
	       0, 0, 0);
      peer_uptime_vty (vty, peer);
      if (peer->status == Established)
	vty_out (vty, " %6d\r\n", peer->prefix_count);
      else
	vty_out (vty, " %-12s\r\n", LOOKUP(bgp_status_msg, peer->status));
    }
  return CMD_SUCCESS;

}

DEFUN (show_ip_bgp_paths, 
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       "List all bgp path information.")
{
  vty_out (vty, "Address Refcnt Path\r\n");
  aspath_print_all_vty (vty);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_community, 
       show_ip_bgp_community_cmd,
       "show ip bgp community",
       "List all bgp community information.")
{
  vty_out (vty, "Address Refcnt Community\r\n");
  community_print_all_vty (vty);

  return CMD_SUCCESS;
}

bgp_regexp (struct prefix_in *pin, struct vty *vty, ASPATH_regex *rp)
{
  struct bgp_route *br;
  struct aspath *aspath;

  br = (struct bgp_route *) pin;
  if (br->attr && (aspath = br->attr->aspath))
    {
      if (aspath_regex_exec (rp, aspath) >= 0)
	route_vty_out (pin, vty);
    }
}

DEFUN (show_ip_bgp_regexp, 
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp ...",
       "Show regular expression matched bgp routes.")
{
  int i;
  struct buffer *b;
  char *regstr;
  ASPATH_regex *rp;
  
  b = buffer_new (BUFFER_STRING, 1024);
  for (i = 0; i < argc; i++)
    {
      buffer_putstr (b, argv[i]);
      buffer_putc (b, ' ');
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  rp = aspath_regex_comp (regstr);
  if (!rp)
    {
      vty_out (vty, "can't compile regexp %s\r\n", argv[0]);
      return;
    }
  radix_apply_func2 (bgp_radix, bgp_regexp, vty, rp);

  aspath_regex_free (rp);
  return CMD_SUCCESS;
}

DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       "neighbor IP_ADDR ebgp-multihop [TTL]",
       "Change TTL value of BGP connection.")
{
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;

  peer = peer_lookup_from_bgp (bgp, argv[0]);
  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return;
    }

  if (argc == 2)
    peer->ttl = atoi (argv[1]);
  else
    peer->ttl = TTL_MAX;

  if (peer->ttl == 0)
    {
      vty_out (vty, "please specify plus integer value.\r\n");
      return;
    }

  if (peer->fd >= 0)
    sockopt_ttl (peer->su->sa.sa_family, peer->fd, peer->ttl);

  return CMD_SUCCESS;
}

DEFUN (neighbor_next_hop,
       neighbor_next_hop_cmd,
       "neighbor IP_ADDR next-hop IP_ADDR",
       "Set neighbor's announce next-hop value.")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return;
    }

  ret = inet_aton (argv[1], &peer->next_hop);
  if (!ret)
    {
      vty_out (vty, "malformed bgp nexthop address\r\n");
      return;
    }
  return CMD_SUCCESS;
}


DEFUN (neighbor_version,
       neighbor_version_cmd,
       "neighbor IP_ADDR version BGP_VERSION",
       "Set neighbor's bgp version.")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (strcmp (argv[1], "bgp4") == 0)
    peer->version = BGP_VERSION_4;
  else if (strcmp (argv[1], "bgp4+") == 0)
    peer->version = BGP_VERSION_MP_4;
  else if (strcmp (argv[1], "bgp4+-draft-00") == 0)
    peer->version = BGP_VERSION_MP_4_DRAFT_00;
  else
    vty_out (vty, "bgp version malformed!\r\n");

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_version,
       no_neighbor_version_cmd,
       "no neighbor IP_ADDR version [BGP_VERSION]",
       "Set neighbor's bgp version to default [bgp4].")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return;
    }

  peer->version = BGP_VERSION_4;
  return CMD_SUCCESS;
}

DEFUN (neighbor_router_id,
       neighbor_router_id_cmd,
       "neighbor IP_ADDR router-id IP_ADDR",
       "Set neighbor's special router-id value.")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  if (! peer)
    {
      vty_out (vty, "can't find neighbor %s\r\n", argv[0]);
      return;
    }
  
  ret = inet_aton (argv[0], &peer->myident);
  if (!ret)
    {
      vty_out (vty, "malformed bgp neighbor router identifier\r\n");
      return;
    }
  return CMD_SUCCESS;
}

/* Make peer and enable further neighbor configuration. */
DEFUN (neighbor, 
       neighbor_cmd, 
       "neighbor IP_ADDR remote-as AS_NO [passive]",
       "Make neighbor.")
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  u_int16_t as;
  union sockunion *su;

  /* Check argument. */
  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  /* If there is already same IP_ADDR peer, only change AS_NO. */
  if (peer)
    {
      /* Change of AS_NO. */

      /* If peer is established then clear it's peer and clear all
         resources and make it again. */

      /* XXXXX*/
      return;
    }

  /* This is new neighbor. */
  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    {
      vty_out (vty, "Malformed IP address.\r\n");
      return;
    }

  as = strtol (argv[1], NULL, 10);
  if (as == 0)
    {
      vty_out (vty, "AS path value malformed.\r\n");
      return;
    }

  /* Create peer. */
  peer = peer_new ();
  list_add_node (bgp->peer , peer);
  list_add_node (peer_list, peer);

  peer->bgp = bgp;
  peer->as = as;
  peer->su = su;
  peer->host = sockunion_su2str (su);
  if (peer_sort (peer) == BGP_PEER_IBGP)
    peer->ttl = 255;
  else
    peer->ttl = 1;
  peer->fd = -1;

  /* If this peer is in passive mode star it in Active mode. */
  if (argc == 3 && (strcmp (argv[2], "passive") == 0))
    peer->status = Active;
  else
    {
      peer->status = Idle;
      fsm_timer_set (peer);
    }
  return CMD_SUCCESS;
}


DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor IP_ADDR remote-as AS_NO",
       "Delete BGP neighbor.")
{
  struct bgp *bgp;
  struct peer *peer;
  listnode node;

  bgp = (struct bgp *) vty->index;
  peer = peer_lookup_from_bgp (bgp, argv[0]);

  /* There is no matched peer. */
  if (peer == NULL)
    {
      vty_out (vty, "Can't find peer %s.\r\n", argv[0]);
      return;
    }

  /* Check AS number. */
  if (peer->as != atoi (argv[1]))
    {
      vty_out (vty, "Different AS number for the peer %s.\r\n", argv[0]);
      return;
    }

  /* Now delete from the neighbor from lists. */
  list_delete_by_val (bgp->peer, peer);
  list_delete_by_val (peer_list, peer);

  /* Clear routes and deallocate peer structure. */
  bgp_clear (peer, 1);
  peer_delete (peer);
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp,
       clear_ip_bgp_cmd, 
       "clear ip bgp IPADDR",
       "clear bgp connection.")
{
  int cleared;
  struct bgp *bgp;
  struct peer *peer;
  listnode bgp_node;
  listnode peer_node;

  if (argc != 1)
    {
      vty_out (vty, "please specify neighbor's address\r\n");
      return;
    }

  /* Clear all bgp neighbor. */
  if (strcmp (argv[0], "*") == 0)
    {
      for (bgp_node = listhead (bgp_list); bgp_node; nextnode(bgp_node))
	{
	  bgp = getdata (bgp_node);
	  for (peer_node = listhead (bgp->peer); peer_node; nextnode (peer_node))
	    {
	      peer = getdata (peer_node);
	      event_add (peer, BGP_Stop);
	      /* bgp_clear (peer, 0); */
	    }
	}
      vty_out (vty, "All bgp neighbor cleared.\r\n");
      return;
    }

  /* Clear one bgp neighbor. */
  cleared = 0;

  for (bgp_node = listhead (bgp_list); bgp_node; nextnode (bgp_node))
    {
      bgp = getdata (bgp_node);
      peer = peer_lookup_from_bgp (bgp, argv[0]);
      if (peer)
	{
	  event_add (peer, BGP_Stop);
	  cleared = 1;
	}
    }

  if (cleared)
    vty_out (vty, "Peer %s cleared.\r\n", argv[0]);
  else
    vty_out (vty, "Can't find peer %s.\r\n", argv[0]);

  return CMD_SUCCESS;
}


/* BGP configuration write function. */
bgp_config_write (struct vty *vty, vector v)
{
  listnode node;
  struct bgp *bgp; 

  /* BGP Multiple instance. */
  if (bgp_multiple_instance)
    {    
      vty_out (vty, "bgp multiple-instance%s", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  /* BGP neighbor's configuration. */
  for (node = listhead (bgp_list); node; nextnode (node))
    {
      bgp = getdata (node);

      vty_out (vty, "router bgp %d%s", bgp->as, VTY_NEWLINE);
      config_write_network (vty, bgp);
      peer_config_write (vty, bgp->peer);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }
}

/* BGP node structure. */
struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

/* Install bgp related commands. */
bgp_init ()
{
  /* Install bgp top node. */
  install_node (&bgp_node, bgp_config_write);

  /* Install bgp commands. */
  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_summary_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_paths_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_community_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_neighbors_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_paths_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_community_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_regexp_cmd);
  install_element (ENABLE_NODE, &clear_ip_bgp_cmd);
  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &no_router_bgp_cmd);
  install_element (CONFIG_NODE, &bgp_multiple_instance_cmd);
  install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd);
  install_element (BGP_NODE, &config_end_cmd);
  install_element (BGP_NODE, &config_exit_cmd);
  install_element (BGP_NODE, &config_help_cmd);
  install_element (BGP_NODE, &neighbor_cmd);
  install_element (BGP_NODE, &no_neighbor_cmd);
  install_element (BGP_NODE, &neighbor_next_hop_cmd);
  install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd);
  install_element (BGP_NODE, &bgp_router_id_cmd);
  install_element (BGP_NODE, &neighbor_version_cmd);
  install_element (BGP_NODE, &no_neighbor_version_cmd);
#ifdef HAVE_IPV6
  /* IPV6 specific commands. */
  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
#endif /* HAVE_IPV6 */

  /* Make empty list of bgp and peer list. */
  bgp_list = list_init ();
  peer_list = list_init ();

  /* BGP multiple instance. */
  bgp_multiple_instance = 0;
}
