/*
 * Zebra daemon core routine.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#include <zebra.h>

#include "prefix.h"
#include "linklist.h"
#include "command.h"
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "buffer.h"
#include "memory.h"
#include "rib.h"
#include "roken.h"
#include "network.h"
#include "sockunion.h"
#include "log.h"
#include "table.h"

#include "zebra/zebra.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"

int ipforward ();
int ipforward_on ();
int ipforward_off ();
#ifdef HAVE_IPV6
int ipforward_ipv6 ();
int ipforward_ipv6_on ();
int ipforward_ipv6_off ();
#endif /* HAVE_IPV6 */

/* Event list of zebra. */
enum event { ZEBRA_SERV, ZEBRA_READ, ZEBRA_WRITE };

list client_list;

/* Default rtm_table for all clients */
int rtm_table_default;

/* For logging of zebra meesages. */
char *zebra_command_str [] =
{
  "NULL",
  "ZEBRA_IPV4_ROUTE_ADD",
  "ZEBRA_IPV4_ROUTE_DELETE",
  "ZEBRA_IPV6_ROUTE_ADD",
  "ZEBRA_IPV6_ROUTE_DELETE",
  "ZEBRA_GET_ALL_INTERFACE",
  "ZEBRA_GET_ONE_INTERFACE",
  "ZEBRA_GET_HOSTINFO",
  "ZEBRA_REDISTRIBUTE_ADD",
  "ZEBRA_REDISTRIBUTE_DELETE"
};

void zebra_event (enum event event, int sock, struct zebra_client *client);

void
zebra_forward_on ()
{
  ipforward_on ();
#ifdef HAVE_IPV6
  ipforward_ipv6_on ();
#endif /* HAVE_IPV6 */
}

/* Zebra route add and delete treatment. */
void
zebra_read_ipv4 (int command, struct zebra_client *client, u_short length)
{
  u_char type;
  struct in_addr nexthop;
  u_char *pnt;
  u_char *lim;

  pnt = stream_pnt (client->ibuf);
  lim = pnt + length;

  /* Fetch type and nexthop first. */
  type = *pnt++;
  memcpy(&nexthop, pnt, 4);
  pnt += 4;

  /* Then fetch IPv4 prefixes. */
  while (pnt < lim)
    {
      int size;
      struct prefix_ipv4 p;

      bzero (&p, sizeof (struct prefix_ipv4));
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      size = PSIZE (p.prefixlen);
      memcpy (&p.prefix, pnt, size);
      pnt += size;

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	rib_add_ipv4 (type, &p, &nexthop, 0, client->rtm_table);
      else
	rib_delete_ipv4 (type, &p, &nexthop, 0, client->rtm_table);
    }
}

#ifdef HAVE_IPV6
void
zebra_read_ipv6 (int command, struct zebra_client *client, u_short length)
{
  u_char type;
  struct in6_addr nexthop;
  u_char *lim;
  u_char *pnt;
  unsigned int ifindex;

  pnt = stream_pnt (client->ibuf);
  lim = pnt + length;

  type = stream_getc (client->ibuf);
  memcpy (&nexthop, stream_pnt (client->ibuf), sizeof (struct in6_addr));
  stream_forward (client->ibuf, sizeof (struct in6_addr));
  
  while (stream_pnt (client->ibuf) < lim)
    {
      int size;
      struct prefix_ipv6 p;
      
      ifindex = stream_getl (client->ibuf);

      bzero (&p, sizeof (struct prefix_ipv6));
      p.family = AF_INET6;
      p.prefixlen = stream_getc (client->ibuf);
      size = PSIZE(p.prefixlen);
      memcpy (&p.prefix, stream_pnt (client->ibuf), size);
      stream_forward (client->ibuf, size);

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	rib_add_ipv6 (type, &p, &nexthop, ifindex, 0);
      else
	rib_delete_ipv6 (type, &p, &nexthop, ifindex, 0);
    }
}
#endif /* HAVE_IPV6 */

/* Close zebra client. */
void
zebra_close (struct zebra_client *client)
{
  /* Close file descriptor. */
  if (client->fd)
    close (client->fd);

  /* Free stream buffers. */
  if (client->ibuf)
    stream_free (client->ibuf);
  if (client->obuf)
    stream_free (client->obuf);

  /* Release threads. */
  if (client->t_read)
    thread_cancel (client->t_read);
  if (client->t_write)
    thread_cancel (client->t_write);
}

/* Interface infomation send routine. */
void
zebra_request_all_interface (int sock)
{
  int size;
  struct interface *ifp;
  struct connected *connected;
  listnode ifnode;
  listnode node;
  char *pnt, *start;

  /* Calculate storage size. */
  size = 0;
  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);
      size += sizeof (struct interface);
      for (node = listhead (ifp->connected); node; nextnode (node))
	size += (sizeof (struct prefix) * 2);
    }

  /* Allocate buffer for make interface information. */
  start = pnt = XMALLOC (0, size);

  /* This is place holder of packet size. */
  PUTW (size, pnt);
  PUTC (ZEBRA_GET_ALL_INTERFACE, pnt);

  /* Put each interface's information. */
  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      /* Set inteface's name. */
      memcpy (pnt, ifp->name, INTERFACE_NAMSIZ);
      pnt += INTERFACE_NAMSIZ;

      /* Set inteface's index. */
      PUTC (ifp->index ,pnt);

      /* Set interface's value. */
      PUTL (ifp->flags, pnt);
      PUTL (ifp->metric, pnt);
      PUTL (ifp->mtu, pnt);

      /* Set interface's address count. */
      PUTL (ifp->connected->count, pnt);

      /* Set interface's address. */
      for (node = listhead (ifp->connected); node; nextnode (node))
	{
	  struct prefix *p;
	  int plen;

	  connected = getdata (node);

	  /* Interface's address */
	  p = connected->address;
	  *pnt++ = p->family;
	  plen = prefix_blen (p);
	  memcpy (pnt, &p->u.prefix, plen);
	  pnt += plen;
	  *pnt++ = p->prefixlen;

	  /* Interface's address destination. */
	  p = connected->destination;
	  if (p)
	    memcpy (pnt, &p->u.prefix, plen);
	  else
	    memset (pnt, 0, plen);
	  pnt += plen;
	}
    }

  /* Calculate packet size. */
  size = pnt - start;
  pnt = start;
  PUTW (size, pnt);

  /* Write information to socket. */
  writen (sock, start, size);

  /* Free storage buffer. */
  XFREE (0, start);
}

/* Send host information. */
void
zebra_request_hostinfo (int sock)
{
  u_char *pnt;
  u_char buf[10];

  pnt = buf;

  PUTL(10, pnt);
  PUTL(ZEBRA_GET_HOSTINFO, pnt);

  /* Ip forwarding. 0 => OFF, 1 => ON */
  *pnt++ = ipforward ();
  
  /* ip forwarding6 . 0 => OFF, 1 => ON */
#ifdef HAVE_IPV6
  *pnt = (ipforward_ipv6 () == 0 ? 0 : 1);
#else
  *pnt = 0;
#endif /* HAVE_IPV6*/

  writen (sock, buf, 10);
}

/* Handler of zebra service request. */
int
zebra_read (struct thread *thread)
{
  int sock;
  struct zebra_client *client;
  int nbyte;
  u_short length;
  u_char command;

  /* Get thread data.  Reset reading thread because I'm running. */
  sock = THREAD_FD (thread);
  client = THREAD_ARG (thread);
  client->t_read = NULL;

  /* Read length and command. */
  nbyte = stream_read (client->ibuf, sock, 3);
  if (nbyte <= 0) 
    {
      if (IS_ZEBRA_DEBUG_EVENT)
	zlog (NULL, LOG_INFO, "connection closed socket [%d]", sock);
      zebra_close (client);
      return -1;
    }
  length = stream_getw (client->ibuf);
  command = stream_getc (client->ibuf);

  assert (length >= 3);
  length -= 3;

  /* Read rest of data. */
  if (length)
    {
      nbyte = stream_read (client->ibuf, sock, length);
      if (nbyte <= 0) 
	{
	  if (IS_ZEBRA_DEBUG_EVENT)
	    zlog (NULL, LOG_INFO, "connection closed [%d] when reading zebra data", sock);
	  zebra_close (client);
	  return -1;
	}
    }

  /* Debug packet information. */
  if (IS_ZEBRA_DEBUG_EVENT)
    zlog (NULL, LOG_INFO, "connection from socket [%d]", sock);

  if (IS_ZEBRA_DEBUG_PACKET && IS_ZEBRA_DEBUG_RECV)
    zlog (NULL, LOG_INFO, "zebra message received [%s] %d", 
	 zebra_command_str[command], length);

  switch (command) 
    {
    case ZEBRA_IPV4_ROUTE_ADD:
    case ZEBRA_IPV4_ROUTE_DELETE:
      zebra_read_ipv4 (command, client, length);
      break;
#ifdef HAVE_IPV6
    case ZEBRA_IPV6_ROUTE_ADD:
    case ZEBRA_IPV6_ROUTE_DELETE:
      zebra_read_ipv6 (command, client, length);
      break;
#endif /* HAVE_IPV6 */
    case ZEBRA_GET_ALL_INTERFACE:
      zebra_request_all_interface (sock);
      break;
    case ZEBRA_GET_ONE_INTERFACE:
      /* zebra_get_one_interface (sock); */
      break;
    case ZEBRA_GET_HOSTINFO:
      zebra_request_hostinfo (sock);
      break;
    case ZEBRA_REDISTRIBUTE_ADD:
      zebra_redistribute_add (command, client, length);
      break;
    case ZEBRA_REDISTRIBUTE_DELETE:
      zebra_redistribute_delete (command, client, length);
      break;
    default:
      zlog (NULL, LOG_INFO, "Zebra received unknown command %d", command);
      break;
    }

  stream_reset (client->ibuf);
  zebra_event (ZEBRA_READ, sock, client);

  return 0;
}

/* Write output buffer to the socket. */
void
zebra_write (struct thread *thread)
{
  int sock;
  struct zebra_client *client;

  /* Thread treatment. */
  sock = THREAD_FD (thread);
  client = THREAD_ARG (thread);
  client->t_write = NULL;

  stream_flush (client->obuf, sock);
}

/* Add new client. */
void
client_new (int client_sock)
{
  struct zebra_client *client;

  client = XMALLOC (0, sizeof (struct zebra_client));
  bzero (client, sizeof (struct zebra_client));

  /* Make client input/output buffer. */
  client->fd = client_sock;
  client->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);

  client->rtm_table = rtm_table_default;

  list_add_node (client_list, client);
  
  zebra_event (ZEBRA_READ, client_sock, client);
}

struct zebra_client *
client_lookup (int sock)
{
  struct zebra_client *client;
  listnode node;
  
  for (node = listhead (client_list); node; nextnode (node))
    {
      client = getdata (node);
      if (client->fd == sock)
	return client;
    }
  return NULL;
}

/* Accept code of zebra server socket. */
int
zebra_accept (struct thread *thread)
{
  struct sockaddr_in client;
  int accept_sock;
  int client_sock;
#ifdef HAVE_SOCKLEN_T
  socklen_t size;
#else
  int size;
#endif /* HAVE_SOCKLEN_T */

  accept_sock = THREAD_FD (thread);

  size = sizeof (client);
  client_sock = accept (accept_sock, (struct sockaddr *) &client, &size);
  if (client_sock < 0)
    perror ("accept");

  client_new (client_sock);

  zebra_event (ZEBRA_SERV, accept_sock, NULL);

  return 0;
}

/* Make zebra's server socket. */
void
zebra_serv ()
{
  int accept_sock;
  struct sockaddr_in me;

  accept_sock = socket (AF_INET, SOCK_STREAM, 0);

  if (accept_sock < 0) 
    {
      zlog (NULL, LOG_WARNING, "can't init client routing socket");
      return;
    }

  sockopt_reuseaddr (accept_sock);

  me.sin_family = AF_INET;
  me.sin_port = htons (ZEBRA_PORT);
  me.sin_addr.s_addr = htonl (INADDR_ANY);

  if (bind (accept_sock, (struct sockaddr *)&me, sizeof (me)) < 0) 
    {
      zlog (NULL, LOG_WARNING, "can't bind socket");
      exit (1);
    }

  if (listen (accept_sock, 1) < 0)
    {
      zlog (NULL, LOG_WARNING, "can't listen socket");
      exit (1);
    }

  zebra_event (ZEBRA_SERV, accept_sock, NULL);
}

/* Zebra's event management function. */
extern struct thread_master *master;

void
zebra_event (enum event event, int sock, struct zebra_client *client)
{
  switch (event)
    {
    case ZEBRA_SERV:
      thread_add_read (master, zebra_accept, client, sock);
      break;
    case ZEBRA_READ:
      client->t_read = thread_add_read (master, zebra_read, client, sock);
      break;
    case ZEBRA_WRITE:
      /**/
      break;
    }
}

/* Display default rtm_table for all clients. */
DEFUN (show_table,
       show_table_cmd,
       "show table",
       SHOW_STR
       "default routing table to use for all clients\n")
{
  vty_out (vty, "table %d\r\n", rtm_table_default);
  return CMD_SUCCESS;
}

DEFUN (config_table, 
       config_table_cmd,
       "table TABLENO",
       "Configure target kernel routing table\n"
       "TABLE integer\n")
{
  rtm_table_default = strtol (argv[0], (char**)0, 10);
  return CMD_SUCCESS;
}

DEFUN (no_ip_forwarding,
       no_ip_forwarding_cmd,
       "no ip forwarding",
       NO_STR
       IP_STR
       "Doesn't forward IP protocol packet")
{
  int ret;

  ret = ipforward_off ();
  if (ret != 0)
    {
      vty_out (vty, "Can't turn off IP forwarding\r\n");
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* Table configuration write function. */
int
config_write_table (struct vty *vty)
{
  if (rtm_table_default)
    vty_out (vty, "table %d%s", rtm_table_default,
      VTY_NEWLINE);
  return 0;
}

/* table node for routing tables. */
struct cmd_node table_node =
{
  TABLE_NODE,
  "",				/* This node has no interface. */
};

/* Radix treee for IP version 4 RIB */
struct radix_top *ipv4_static_radix;
#ifdef HAVE_IPV6
struct radix_top *ipv6_static_radix;
#endif /* HAVE_IPV6 */

/* Only display ip forwarding is enabled or not. */
DEFUN (show_ip_forwarding,
       show_ip_forwarding_cmd,
       "show ip forwarding",
       SHOW_STR
       IP_STR
       "IP forwarding status\n")
{
  int ret;

  ret = ipforward ();

  if (ret == 0)
    vty_out (vty, "ip forward is off\r\n");
  else
    vty_out (vty, "ip forward is on\r\n");
  return CMD_SUCCESS;
}

DEFUN (ip_route, 
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP desitination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;

  /* a.b.c.d/mask gateway format. */
  ret = str2prefix_ipv4 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x\r\n");
      return CMD_WARNING;
    }
  /* Gateway. */
  ret = inet_aton (argv[1], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid\r\n");
	  return CMD_WARNING;
	}
      ifindex = ifp->index;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask (&p);

  /* We need rib error treatment here. */
  if (ifindex)
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, &p, NULL, ifindex, table);
  else
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, table);

  /* Error checking and display meesage. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "Same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.\r\n", inet_ntoa (p.prefix), p.prefixlen);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       "IP information\n"
       "IP routing set\n"
       "IP desitination prefix\n"
       "IP desitination netmask\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;
  struct in_addr tmpmask;

  /* A.B.C.D */
  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid\r\n");
      return CMD_WARNING;
    }

  /* X.X.X.X */
  ret = inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid\r\n");
      return CMD_WARNING;
    }
  p.prefixlen = ip_masklen (tmpmask);

  /* Gateway. */
  ret = inet_aton (argv[2], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[2]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid\r\n");
	  return CMD_WARNING;
	}
      ifindex = ifp->index;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask (&p);

  /* We need rib error treatment here. */
  if (ifindex)
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, &p, NULL, ifindex, table);
  else
    ret = rib_add_ipv4 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, table);

  /* Error checking and display meesage. */
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "Same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	}
      vty_out (vty, "%s/%d.\r\n", inet_ntoa (p.prefix), p.prefixlen);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP desitination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = str2prefix_ipv4 (argv[0], &p);

  if (! ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask "
	       "or a.b.c.d x.x.x.x\r\n");
      return CMD_WARNING;
    }
  /* Gateway. */
  ret = inet_aton (argv[1], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid\r\n");
	  return CMD_WARNING;
	}
      ifindex = ifp->index;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  if (ifindex)
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, &p, NULL, ifindex, table);
  else
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, table);

  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.\r\n", inet_ntoa (p.prefix), p.prefixlen);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP desitination prefix\n"
       "IP desitination netmask\n"
       "IP gateway interface name\n")
{
  int ret;
  struct prefix_ipv4 p;
  struct in_addr gate;
  int table = rtm_table_default;
  struct in_addr tmpmask;
  unsigned int ifindex = 0;
  struct interface *ifp;

  ret = inet_aton (argv[0], &p.prefix);
  if (!ret)	
    {
      vty_out (vty, "destination address is invalid\r\n");
      return CMD_WARNING; 
    }
  inet_aton (argv[1], &tmpmask);
  if (!ret)	
    {
      vty_out (vty, "netmask address is invalid\r\n");
      return CMD_WARNING; 
    }
  p.prefixlen = ip_masklen (tmpmask);
      
  ret = inet_aton (argv[2], &gate);
  if (!ret)	
    {
      ifp = if_lookup_by_name (argv[1]);
      if (! ifp)
	{
	  vty_out (vty, "Gateway address or device name is invalid\r\n");
	  return CMD_WARNING;
	}
      ifindex = ifp->index;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  if (ifindex)
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, &p, NULL, ifindex, table);
  else
    ret = rib_delete_ipv4 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, table);

  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "same static route already exists ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	case ZEBRA_ERR_RTNOEXIST:
	  vty_out (vty, "route doesn't match ");
	  break;
	default:
	  vty_out (vty, "route delete error ");
	  break;
	}
      vty_out (vty, "%s/%d.\r\n", inet_ntoa (p.prefix), p.prefixlen);

      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Only display ipv6 forwarding is enabled or not. */
DEFUN (show_ipv6_forwarding,
       show_ipv6_forwarding_cmd,
       "show ipv6 forwarding",
       SHOW_STR
       "IPv6 information\n"
       "Forwarding status\n")
{
  int ret;

  ret = ipforward_ipv6 ();

  switch (ret)
    {
    case -1:
      vty_out (vty, "ipv6 forwarding is unknown\r\n");
      break;
    case 0:
      vty_out (vty, "ipv6 forwarding is %s\r\n", "off");
      break;
    case 1:
      vty_out (vty, "ipv6 forwarding is %s\r\n", "on");
      break;
    default:
      vty_out (vty, "ipv6 forwarding is %s\r\n", "off");
      break;
    }
  return CMD_SUCCESS;
}

DEFUN (ipv6_route, ipv6_route_cmd,
       "ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "IP Netmask\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gate;

  /* Route prefix/prefixlength format check. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Gateway format check. */
  ret = inet_pton (AF_INET6, argv[1], &gate);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  /* We need rib error treatment here. */
  ret = rib_add_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gate, 0, 0);
  
  if (ret)
    {
      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist\r\n");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable\r\n");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied\r\n");
	  break;
	default:
	  /* Success */
	  break;
	}
    }
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "IP Netmask\n")
{
  int ret;
  struct prefix_ipv6 p;
  struct in6_addr gateway;
  
  /* Check ipv6 prefix. */
  ret = str2prefix_ipv6 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      return CMD_WARNING;
    }

  /* Check gateway. */
  ret = inet_pton (AF_INET6, argv[1], &gateway);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask_ipv6 (&p);

  ret = rib_delete_ipv6 (ZEBRA_ROUTE_STATIC, &p, &gateway, 0, 0);

  switch (ret)
    {
    default:
      /* Success */
      break;
    }

  vty_out (vty, "static route deleted\r\n");
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_forwarding,
       no_ipv6_forwarding_cmd,
       "no ipv6 forwarding",
       NO_STR
       IP_STR
       "Doesn't forward IPv6 protocol packet")
{
  int ret;

  ret = ipforward_ipv6_off ();
  if (ret != 0)
    {
      vty_out (vty, "Can't turn off IPv6 forwarding\r\n");
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

#endif /* HAVE_IPV6 */
       
/* Static ip route configuration write function. */
int
config_write_ip (struct vty *vty)
{
  extern int rib_static_list (struct vty *, struct route_table *);
  int write = 0;

  write += rib_static_list (vty, ipv4_rib_table);
#ifdef HAVE_IPV6
  write += rib_static_list (vty, ipv6_rib_table);
#endif /* HAVE_IPV6 */

  return write;
}

/* IP node for static routes. */
struct cmd_node ip_node =
{
  IP_NODE,
  "",				/* This node has no interface. */
};

/* Initialisation of zebra and installation of commands. */
void
zebra_init ()
{
  /* Client list init. */
  client_list = list_init ();

  /* Forwarding on. */
  zebra_forward_on ();

  /* Make zebra server socket. */
  zebra_serv ();

  /* Install configuration write function. */
  install_node (&ip_node, config_write_ip);
  install_node (&table_node, config_write_table);

  install_element (VIEW_NODE, &show_ip_forwarding_cmd);
  install_element (ENABLE_NODE, &show_ip_forwarding_cmd);
  install_element (CONFIG_NODE, &ip_route_cmd);
  install_element (CONFIG_NODE, &ip_route_mask_cmd);
  install_element (CONFIG_NODE, &no_ip_route_cmd);
  install_element (CONFIG_NODE, &no_ip_route_mask_cmd);
  install_element (CONFIG_NODE, &no_ip_forwarding_cmd);

#ifdef HAVE_LINUX_RTNETLINK_H
  install_element (VIEW_NODE, &show_table_cmd);
  install_element (CONFIG_NODE, &config_table_cmd);
#endif

#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ipv6_forwarding_cmd);
  install_element (ENABLE_NODE, &show_ipv6_forwarding_cmd);
  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_forwarding_cmd);
#endif /* HAVE_IPV6 */
}
