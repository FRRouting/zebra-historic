/* Zebra daemon core routine.
   Copyright (C) 1997 Kunihiro Ishiguro

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
along with GNU Zebra; see the file COPYING.  If not, write to the 
Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
Boston, MA 02111-1307, USA.  */

#include <config.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

#include "zebra.h"
#include "route.h"
#include "vector.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "if.h"
#include "sockunion.h"
#include "ifa.h"
#include "rib.h"
#include "radix.h"
#include "thread.h"
#include "buffer.h"
#include "memory.h"

#ifdef SUNOS_5
typedef unsigned int u_int32_t; 
typedef unsigned short u_int16_t; 
#endif /* SUNOS_5 */

#define st_1byte(val, pnt) \
{ \
    (*(u_char *)(pnt)++) = (u_char)(val); \
}

#define st_4byte(val, pnt) \
{\
   u_int32_t t = htonl((u_int32_t)(val)); \
   bcopy (&t, (pnt), 4); \
   (pnt) += 4;\
}

/* This host's information. */
struct
{
  /* IP forwarding */
  int ipforward;

  /* IPv6 capable host. */
  int ipv6;
  int ipv6forward;

} hinfo;

/* Event list of zebra. */
enum event { ZEBRA_SERV, ZEBRA_READ, ZEBRA_WRITE };

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
};

/* Client structure. */
struct zebra_client
{
  /* Client file descriptor. */
  int fd;

  /* Input/output buffer to the client. */
  struct stream *ibuf;
  struct stream *obuf;

  /* Threads for read/write. */
  struct thread *t_read;
  struct thread *t_write;
};

/* Debug related variables and functions. */
unsigned int debug_zebra_opt = 0;

#define DEBUG_EVENT   0x01
#define DEBUG_PACKET  0x02

void
debug_set (unsigned int option)
{
  debug_zebra_opt |= option;
}

void
debug_unset (unsigned int option)
{
  debug_zebra_opt &= ~option;
}

int
debug_is_set (unsigned int option)
{
  return debug_zebra_opt & option;
}     

/* Zebra route add and delete treatment. */
zebra_request_ipv4 (int command, struct zebra_client *client, u_short length)
{
  u_char *pnt;
  u_char *lim;

  struct in_addr nexthop;
  u_char type;

  pnt = stream_pnt (client->ibuf);

  lim = pnt + length;

  /* Fetch zebra command */
  type = *pnt++;
  memcpy (&nexthop, pnt, 4);
  pnt += 4;

  while (pnt < lim)
    {
      int ret;
      int size;
      struct prefix_in *pin;

      pin = prefix_in_new ();

      pin->type = type;
      pin->gate.addr = nexthop;
      
      pin->mask = *pnt++;
      size = PSIZE (pin->mask);
      memcpy (&pin->prefix, pnt, size);
      pnt += size;

      if (command == ZEBRA_IPV4_ROUTE_ADD)
	rib_add_in (pin);
      else
	rib_delete_in (pin);

      /* Policy check needs here. */
      ret = kernel_rt_in (command, pin);
    }
}

#ifdef HAVE_IPV6
zebra_request_ipv6 (u_int32_t command, 
		    struct zebra_client *client, 
		    u_short length)
{
  int ret;
  int size;
  struct prefix_in6 *pin6;
  struct in6_addr nexthop;
  u_char type;
  u_char *lim;
  unsigned int ifindex;
  u_char *pnt;

  pnt = stream_pnt (client->ibuf);

  lim = pnt + length;

  type = *pnt++;
  memcpy (&nexthop, pnt, sizeof (struct in6_addr));
  pnt += sizeof (struct in6_addr);
  
  while (pnt < lim)
    {
      pin6 = prefix_in6_new ();
      pin6->type = type;
      pin6->gate.addr = nexthop;

      ifindex = *pnt++;
      pin6->mask = *pnt++;
      size = PSIZE(pin6->mask);
      memcpy (&pin6->prefix, pnt, size);
      pnt += size;

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	rib_add_in6 (pin6, ifindex);
      else
	rib_delete_in6 (pin6, ifindex);
    }
}
#endif /* HAVE_IPV6 */

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
  sock = thread_fd (thread);
  client = thread_arg (thread);
  client->t_read = NULL;

  /* Read length and command. */
  nbyte = stream_read (client->ibuf, sock, 3);
  if (nbyte <= 0) 
    {
      if (debug_is_set (DEBUG_EVENT))
	log ("connection closed socket [%d]\n", sock);
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
	  if (debug_is_set (DEBUG_EVENT))
	    log ("connection closed [%d] when reading zebra data\n", sock);
	  zebra_close (client);
	  return -1;
	}
    }

  /* Debug packet information. */
  if (debug_is_set (DEBUG_EVENT))
    log ("connection from socket [%d]\n", sock);

  if (debug_is_set (DEBUG_PACKET))
    log ("zebra message received [%s] %d\n", 
	 zebra_command_str[command], length);

  switch (command) 
    {
    case ZEBRA_IPV4_ROUTE_ADD:
    case ZEBRA_IPV4_ROUTE_DELETE:
      zebra_request_ipv4 (command, client, length);
      break;
#ifdef HAVE_IPV6
    case ZEBRA_IPV6_ROUTE_ADD:
    case ZEBRA_IPV6_ROUTE_DELETE:
      zebra_request_ipv6 (command, client, length);
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
    default:
      log ("Zebra received unknown command %d\n", command);
      break;
    }

  stream_reset (client->ibuf);
  zebra_event (ZEBRA_READ, sock, client);

  return 0;
}

/* Write output buffer to the socket. */
int
zebra_write (struct thread *thread)
{
  int sock;
  struct zebra_client *client;

  /* Thread treatment. */
  sock = thread_fd (thread);
  client = thread_arg (thread);
  client->t_write = NULL;

  stream_flush (client->obuf, sock);
}

/* Close zebra client. */
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

/* Add new client. */
zebra_create (int client_sock)
{
  struct zebra_client *client;

  client = XMALLOC (0, sizeof (struct zebra_client));
  bzero (client, sizeof (struct zebra_client));

  /* Make client input/output buffer. */
  client->fd = client_sock;
  client->ibuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  client->obuf = stream_new (ZEBRA_MAX_PACKET_SIZ);
  
  zebra_event (ZEBRA_READ, client_sock, client);
}

/* Accept code of zebra server socket. */
zebra_accept (struct thread *thread)
{
  size_t size;
  struct sockaddr_in client;
  int accept_sock;
  int client_sock;

  accept_sock = thread_fd (thread);

  size = sizeof (client);
  client_sock = accept (accept_sock, (struct sockaddr *) &client, &size);
  if (client_sock < 0)
    perror ("accept");

  zebra_create (client_sock);

  zebra_event (ZEBRA_SERV, accept_sock, NULL);
}

/* Make zebra's server socket. */
zebra_serv ()
{
  int accept_sock;
  struct sockaddr_in me;

  accept_sock = socket (AF_INET, SOCK_STREAM, 0);

  if (accept_sock < 0) 
    {
      log_warn ("can't init client routing socket\n");
      return;
    }

  sockopt_reuseaddr (accept_sock);

  me.sin_family = AF_INET;
  me.sin_port = htons (ZEBRA_PORT);
  me.sin_addr.s_addr = htonl (INADDR_ANY);

  if (bind (accept_sock, (struct sockaddr *)&me, sizeof (me)) < 0) 
    {
      log_warn ("can't bind socket\n");
      exit (1);
    }

  if (listen (accept_sock, 1) < 0)
    {
      log_warn ("can't listen socket\n");
      exit (1);
    }

  zebra_event (ZEBRA_SERV, accept_sock, NULL);
}

/* Send host information. */
zebra_request_hostinfo (int sock)
{
  u_char *pnt;
  u_char buf[10];

  pnt = buf;

  st_4byte (10, pnt);
  st_4byte (ZEBRA_GET_HOSTINFO, pnt);

  /* Ip forwarding. 0 => OFF, 1 => ON */
  *pnt++ = (hinfo.ipforward == 0 ? 0 : 1);
  
  /* ip forwarding6 . 0 => OFF, 1 => ON */
#ifdef HAVE_IPV6
  *pnt = (hinfo.ipv6forward == 0 ? 0 : 1);
#else
  *pnt = 0;
#endif /* HAVE_IPV6*/

  writen (sock, buf, 10);
}

/* Interface infomation send routine. */
zebra_request_all_interface (int sock)
{
  int i;
  int size;
  struct interface *ifp;
  struct if_addr *ifa;
  listnode ifnode;
  listnode node;
  char *pnt, *start;

  /* Calculate storage size. */
  size = 0;
  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);
      size += sizeof (struct interface);
      for (node = listhead (ifp->addr); node; nextnode (node))
	size += sizeof (struct if_addr);
    }

  /* Allocate buffer for make interface information. */
  start = pnt = (char *) malloc (size);

  /* This is place holder of packet size. */
  st_4byte (size, pnt);

  st_4byte (ZEBRA_GET_ALL_INTERFACE, pnt);

  /* Put each interface's information. */
  for (ifnode = listhead (iflist); ifnode; nextnode (ifnode))
    {
      ifp = getdata (ifnode);

      /* Set inteface's name. */
      memcpy (pnt, ifp->name, INTERFACE_NAMSIZ);
      pnt += INTERFACE_NAMSIZ;

      /* Set inteface's index. */
      st_1byte (ifp->index ,pnt);

      /* Set interface's value. */
      st_4byte (ifp->flags, pnt);
      st_4byte (ifp->metric, pnt);
      st_4byte (ifp->mtu, pnt);

      /* Set interface's address count. */
      st_4byte (ifp->addr->count, pnt);

      /* Set interface's address. */
      for (node = ifp->addr->head; node; nextnode (node))
	{
	  ifa = getdata (node);

	  memcpy (pnt, &ifa->ifa_addr, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (pnt, &ifa->ifa_mask, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (pnt, &ifa->ifa_dest, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	}
    }

  size = pnt - start;
  pnt = start;
  st_4byte (size, pnt);

  /* Write information to socket. */
  writen (sock, start, size);

  /* Free storage buffer. */
  free (start);
}

/* Host information logging. */
hostinfo_get ()
{
  hinfo.ipforward = ipforward();

#ifdef HAVE_IPV6
  hinfo.ipv6 = 1;
  hinfo.ipv6forward = ipforward_ipv6 ();
#else
  hinfo.ipv6 = 0;
  hinfo.ipv6forward = 0;
#endif /* HAVE_IPV6 */
}

/* Zebra's event management function. */

extern struct thread_master *master;

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

/* Radix treee for IP version 4 RIB */
struct radix_top *ipv4_static_radix;
#ifdef HAVE_IPV6
struct radix_top *ipv6_static_radix;
#endif /* HAVE_IPV6 */

/* Only display ip forwarding is enabled or not. */
DEFUN (show_ipforward,
       show_ipforward_cmd,
       "show ipforward",
       "Show ipforward status.")
{
  vty_out (vty, "ip forward is [%s]\r\n", hinfo.ipforward == 0 ? "off" : "on");
  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Only display ipv6 forwarding is enabled or not. */
DEFUN (show_ipv6forward, 
       show_ipv6forward_cmd,
       "show ipv6forward", 
       "Show ipv6forward status.")
{
  vty_out (vty, "ipv6 forward is [%s]\r\n", hinfo.ipv6forward == 0 ? "off" : "on");
  return CMD_SUCCESS;
}

DEFUN (ipv6_route, ipv6_route_cmd,
       "ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       "Static ip6 route add command.")
{
  int ret;
  struct prefix_in6 *pin6;
  struct prefix_in6 *pfind;

  pin6 = (struct prefix_in6 *) str2routev6 (argv[0]);
  if (pin6 == NULL)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      prefix_in6_free (pin6);
      return;
    }
  ret = inet_pton (AF_INET6, argv[1], &pin6->gate.addr);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      prefix_in6_free (pin6);
      return;
    }

  masked_route_in6 (&pin6->prefix, pin6->mask);
  pin6->type = ZEBRA_ROUTE_STATIC;

  pfind = (struct prefix_in6 *) radix_lookup_rt (ipv6_static_radix,
						 (struct prefix *) pin6);
  if (pfind != NULL)
    {
      vty_out (vty, "There is already same static route.\r\n");
      prefix_in6_free (pin6);
      return;
    }
  /* Add to configuration tree. Only hold prefix information. */
  radix_add (ipv6_static_radix, (struct prefix *) prefix_in6_dup (pin6));

  ret = rib_add_in6 (pin6);
  
  pfind = rib_search_prefix_in6 (ZEBRA_ROUTE_KERNEL, pin6);
  
  if (pfind != NULL)
    vty_out (vty, "There is a same kernel route.\r\n");
  else
    {
      ret = kernel_rt_in6 (ZEBRA_IPV6_ROUTE_ADD, pin6);
      
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
	  pin6->fib = 1;
	  break;
	}
    }
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS",
       "Delete static ip6 route add command.")
{
  int ret;
  struct prefix_in6 *pin6;
  struct prefix_in6 *pfind;
  
  pin6 = (struct prefix_in6 *) str2routev6 (argv[0]);
  if (pin6 == NULL)
    {
      vty_out (vty, "Malformed IPv6 address\r\n");
      prefix_in6_free (pin6);
      return;
    }
  ret = inet_pton (AF_INET6, argv[1], &pin6->gate.addr);
  if (!ret)
    {
      vty_out (vty, "Gateway address is invalid\r\n");
      prefix_in6_free (pin6);
      return;
    }
  masked_route_in6 (&pin6->prefix, pin6->mask);
  pin6->type = ZEBRA_ROUTE_STATIC;

  pfind = (struct prefix_in6 *) radix_lookup_prefix (ipv6_static_radix,
						     ZEBRA_ROUTE_STATIC,
						     (struct prefix *) pin6);
  
  if (pfind == NULL)
    {
      char buf[INET6_ADDRSTRLEN];
      vty_out (vty, "Can't find static route %s/%d.\r\n",
	       inet_ntop (AF_INET6, &pin6->prefix, buf, INET6_ADDRSTRLEN),
	       pin6->mask);
      prefix_in6_free (pin6);
      return;
    }

  radix_delete (ipv6_static_radix, (struct prefix *) pin6);

  rib_delete_in6 (pin6);

  ret = kernel_rt_in6 (ZEBRA_IPV6_ROUTE_DELETE, pin6);
  
  switch (ret)
    {
    default:
      /* Success */
      break;
    }

  prefix_in6_free (pin6);

  vty_out (vty, "static route deleted\r\n");
  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

DEFUN (ip_route, 
       ip_route_cmd,
       "ip route IPV4_ADDRESS IPV4_ADDRESS [IPV4_ADDRESS]",
       "Static ip route add command.")
{
  int ret;
  struct prefix_in *pin;
  struct prefix_in *pfind;

  if (argc <= 1 || argc >= 4)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask or a.b.c.d x.x.x.x\r\n");
      return;
    }

  /* New prefix to set a inputed route. */
  pin = prefix_in_new ();

  /* a.b.c.d/mask gateway format. */
  if (argc == 2)
    {
      /* a.b.c.d/mask */
      ret = str2prefix_in (argv[0], pin);
      
      if (! ret)
	{
	  vty_out (vty, "Please specify address by a.b.c.d/mask or a.b.c.d x.x.x.x\r\n");
	  prefix_in_free (pin);
	  return;
	}
      
      /* Gateway. */
      ret = inet_aton (argv[1], &pin->gate.addr);
      if (!ret)	
	{
	  vty_out (vty, "gateway address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
    }

  /* a.b.c.d x.x.x.x gateway format. */
  if (argc == 3)
    {
      struct in_addr tmpmask;

      /* a.b.c.d */
      ret = inet_aton (argv[0], &pin->prefix);
      if (!ret)	
	{
	  vty_out (vty, "destination address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}

      /* x.x.x.x */
      ret = inet_aton (argv[1], &tmpmask);
      if (!ret)	
	{
	  vty_out (vty, "netmask address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
      pin->mask = ip_masklen (tmpmask);

      /* Gateway. */
      ret = inet_aton (argv[2], &pin->gate.addr);
      if (!ret)	
	{
	  vty_out (vty, "gateway address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
    }

  /* Make sure mask is applied and set type to static route*/
  apply_mask (pin);
  pin->type = ZEBRA_ROUTE_STATIC;

  /* First check does this prefix exist in rib. */
  pfind = (struct prefix_in *) radix_lookup_rt (ipv4_static_radix, (struct prefix *) pin);

  if (pfind != NULL)
    {
      vty_out (vty, "There is already same static route.\r\n");
      prefix_in_free (pin);
      return;
    }

  /* Add to configuration tree. Only hold prefix information. */
  radix_add (ipv4_static_radix, (struct prefix *) prefix_in_dup (pin));

  /* We need rib error treatment here. */
  ret = rib_add_in (pin);

  /* Check kernel route. */
  pfind = rib_search_prefix (ZEBRA_ROUTE_KERNEL, pin);

  if (pfind != NULL)
    vty_out (vty, "There is a same kernel route.\r\n");
  else
    {
      /* OK call kernel interface. */
      ret = kernel_rt_in (ZEBRA_IPV4_ROUTE_ADD, pin);

      switch (ret)
	{
	case ZEBRA_ERR_RTEXIST:
	  vty_out (vty, "route already exist in the kernel ");
	  break;
	case ZEBRA_ERR_RTUNREACH:
	  vty_out (vty, "network is unreachable ");
	  break;
	case ZEBRA_ERR_EPERM:
	  vty_out (vty, "permission denied ");
	  break;
	default:
	  /* Success */
	  pin->fib = 1;
	  return;
	  break;
	}
      vty_out (vty, "[%s/%d]\r\n", inet_ntoa (pin->prefix), pin->mask);
    }
  return CMD_SUCCESS;
}

DEFUN (no_ip_route, 
       no_ip_route_cmd,
       "no ip route IPV4_ADDRESS IPV4_ADDRESS [IPV4_ADDRESS]",
       "Delete static ip route command.")
{
  int ret;
  struct prefix_in *pin;
  struct prefix_in *pfind;

  if (argc <= 1 || argc >= 4)
    {
      vty_out (vty, "Please specify address as a.b.c.d/mask or a.b.c.d m.m.m.m\r\n");
      return;
    }

  pin = prefix_in_new ();

  /* a.b.c.d/mask gateway */
  if (argc == 2)
    {
      ret = str2prefix_in (argv[0], pin);

      if (! ret)
	{
	  vty_out (vty, "Please specify address by a.b.c.d/mask or a.b.c.d x.x.x.x\r\n");
	  prefix_in_free (pin);
	  return;
	}
      /* Gateway. */
      ret = inet_aton (argv[1], &pin->gate.addr);
      if (!ret)	
	{
	  vty_out (vty, "gateway address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
    }

  /* a.b.c.d x.x.x.x gateway */
  if (argc == 3)
    {
      struct in_addr tmpmask;

      ret = inet_aton (argv[0], &pin->prefix);
      if (!ret)	
	{
	  vty_out (vty, "destination address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
      inet_aton (argv[1], &tmpmask);
      if (!ret)	
	{
	  vty_out (vty, "netmask address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
      pin->mask = ip_masklen (tmpmask);
      
      ret = inet_aton (argv[2], &pin->gate.addr);
      if (!ret)	
	{
	  vty_out (vty, "gateway address is invalid\r\n");
	  prefix_in_free (pin);
	  return; 
	}
    }

  /* Make sure mask is applied. */
  apply_mask (pin);
  pin->type = ZEBRA_ROUTE_STATIC;

  /* Is there this static route in configuration ? */
  pfind = (struct prefix_in *) radix_lookup_prefix (ipv4_static_radix, 
						    ZEBRA_ROUTE_STATIC, pin);
  if (pfind == NULL)
    {
      vty_out (vty, "can't find static route %s/%d\r\n", 
	       inet_ntoa (pin->prefix), pin->mask);
      prefix_in_free (pin);
      return;
    }

  radix_delete (ipv4_static_radix, (struct prefix *) pin);

  rib_delete_in (pin);

  ret = kernel_rt_in (ZEBRA_IPV4_ROUTE_DELETE, pin);

  switch (ret)
    {
    default:
      /* Success */
      break;
    }
  prefix_in_free (pin);

  vty_out (vty, "static route deleted\r\n");
  return CMD_SUCCESS;
}

/* Debug options. */
DEFUN (show_debug_zebra, show_debug_zebra_cmd, "show debug zebra",
       "Show debug information of zebra.")
{
  vty_out (vty, "Debug option of zebra\r\n");
  vty_out (vty, "=====================\r\n");

  vty_out (vty, "debug zebra event   : ");
  vty_out (vty, "%s\r\n", debug_is_set (DEBUG_EVENT) ? "set" : "unset");

  vty_out (vty, "debug zebra packet  : ");
  vty_out (vty, "%s\r\n", debug_is_set (DEBUG_PACKET) ? "set" : "unset");
  return CMD_SUCCESS;
}

DEFUN (debug_zebra, debug_zebra_cmd, "debug zebra [DEBUG_OPT]",
       "Debug option set for zebra.")
{
  if (argc == 0)
    {
      vty_out (vty, "Debug optoin of zebra\r\n");
      vty_out (vty, "---------------------\r\n");
      vty_out (vty, "debug zebra event  -- Event of zebra.\r\n");
      vty_out (vty, "debug zebra packet -- Packet of zebra.\r\n");
      vty_out (vty, "---------------------\r\n");
      return;
    }
  if (strcmp (argv[0], "event") == 0)
    debug_set (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_set (DEBUG_PACKET);
  return CMD_SUCCESS;
}

DEFUN (no_debug_zebra, no_debug_zebra_cmd, "no_debug zebra [DEBUG_OPT]",
       "Debug option unset for zebra.")
{
  if (strcmp (argv[0], "event") == 0)
    debug_unset (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_unset (DEBUG_PACKET);
  return CMD_SUCCESS;
}
       
config_static_dump (struct prefix *rt, struct vty *vty)
{
  struct prefix_in *pin = (struct prefix_in *) rt;

  vty_out (vty, "ip route %s/%d ", inet_ntoa (pin->prefix), pin->mask);
  vty_out (vty, "%s%s", inet_ntoa (pin->gate.addr), VTY_NEWLINE);
}

#ifdef HAVE_IPV6
config_static_dump_ipv6 (struct prefix *rt, struct vty *vty)
{
  char buf[INET6_ADDRSTRLEN];
  struct prefix_in6 *pin6 = (struct prefix_in6 *) rt;

  vty_out (vty, "ipv6 route %s/%d ", 
	   inet_ntop (AF_INET6, &pin6->prefix, buf, INET6_ADDRSTRLEN),
	   pin6->mask);
  vty_out (vty, "%s%s", 
	   inet_ntop (AF_INET6, &pin6->gate.addr, buf, INET6_ADDRSTRLEN),
	   VTY_NEWLINE);
}
#endif /* HAVE_IPV6 */

/* Static ip route configuration write function. */
config_write_ip (struct vty *vty, vector v)
{
  radix_apply_func (ipv4_static_radix, config_static_dump, vty);
#ifdef HAVE_IPV6
  radix_apply_func (ipv6_static_radix, config_static_dump_ipv6, vty);
#endif /* HAVE_IPV6 */
}

/* IP node for static routes. */
struct cmd_node ip_node =
{
  IP_NODE,
  "",				/* This node has no interface. */
};

/* Initializetion of zebra and installation of commands. */
zebra_init ()
{
  /* Make kernel routing socket. */
  kernel_routing_socket ();

  /* Make zebra server socket. */
  zebra_serv ();

  /* Static route tree. */
  ipv4_static_radix = radix_make_rib (AF_INET);
  ipv4_static_radix->sameprefix = rt_ip_sameprefix;
#ifdef HAVE_IPV6
  ipv6_static_radix = radix_make_rib (AF_INET6);
  ipv6_static_radix->sameprefix = rt_ipv6_sameprefix;
#endif /* HAVE_IPV6 */

  /* Install configuration write function. */
  install_node (&ip_node, config_write_ip);

  install_element (VIEW_NODE, &show_ipforward_cmd);
  install_element (VIEW_NODE, &show_debug_zebra_cmd);
  install_element (ENABLE_NODE, &show_ipforward_cmd);
  install_element (ENABLE_NODE, &show_debug_zebra_cmd);
  install_element (ENABLE_NODE, &debug_zebra_cmd);
  install_element (ENABLE_NODE, &no_debug_zebra_cmd);
  install_element (CONFIG_NODE, &ip_route_cmd);
  install_element (CONFIG_NODE, &no_ip_route_cmd);
  install_element (CONFIG_NODE, &debug_zebra_cmd);
  install_element (CONFIG_NODE, &no_debug_zebra_cmd);
#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ipv6forward_cmd);
  install_element (ENABLE_NODE, &show_ipv6forward_cmd);
  install_element (CONFIG_NODE, &ipv6_route_cmd);
  install_element (CONFIG_NODE, &no_ipv6_route_cmd);
#endif /* HAVE_IPV6 */
}
