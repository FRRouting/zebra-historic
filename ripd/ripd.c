/* RIP version 1 and 2.
   Copyright (C) 1997,98 Kunihiro Ishiguro

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
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <net/route.h>
#include <sys/time.h>
#include <errno.h>

#include "ripd.h"
#include "zebra.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "route.h"
#include "radix.h"
#include "host.h"
#include "linklist.h"
#include "if.h"
#include "thread.h"
#include "memory.h"

extern struct thread_master *master;

/* RIP Structure. */
struct rip rip_master;

/* Pointer to RIP structure. */
struct rip *rip;

/* RIP routing table radix tree. */
struct radix_top *rip_radix;

/* RIP command strings. */
struct message rip_msg[] = 
{
  { 0,             "NULL"},
  {RIP_REQUEST,    "RIP_REQUEST"},
  {RIP_RESPONSE,   "RIP_RESPONSE"},
  {RIP_TRACEON,    "RIP_TRACEON"},
  {RIP_TRACEOFF,  "RIP_TRACEOFF"},
  {RIP_POLL,       "RIP_POLL"},
  {RIP_POLL_ENTRY, "RIP_POLL_ENTRY"},
};

struct message route_sort_msg[] =
{
  { ZEBRA_ROUTE_SYSTEM,  "X"},
  { ZEBRA_ROUTE_KERNEL,  "K"},
  { ZEBRA_ROUTE_CONNECT, "C"},
  { ZEBRA_ROUTE_STATIC,  "S"},
  { ZEBRA_ROUTE_RIP,     "R"},
  { ZEBRA_ROUTE_RIPNG,   "R"},
  { ZEBRA_ROUTE_BGP,     "B"},
};


/* Called when flash timer expired. */
rip_announce_route (struct thread *thread)
{
  rip_age ();
  rip_announce ();

  rip->timer = thread_add_timer (master, rip_announce_route, NULL,
				 RIP_FLASH_TIMER);
}

/* Create new RIP instance and set it to global variable rip. */
rip_create ()
{
  /* Allocaste RIP instance. */
  rip = &rip_master;
  
  /* Set default version to RIP version 2. */
  rip->version = RIPv2;

  /* Try to use multicast for all interface. */
  rip->multicast = 1;

  /* Make RIP timer. */
  rip->timer = thread_add_timer (master, rip_announce_route, NULL,
				 RIP_FLASH_TIMER);
}


/* Set boradcast option to the socket. */
sockopt_broadcast (int sock)
{
  int ret;
  int on = 1;

  ret = setsockopt (sock, SOL_SOCKET, SO_BROADCAST, (char *) &on, sizeof on);
  if (ret < 0)
    {
      log_warn ("can't set sockopt SO_BROADCAST to socket %d\n", sock);
      return -1;
    }
  return 0;
}

int 
rip_create_socket (local_addr)
     u_long local_addr;
{
  int ret;
  struct sockaddr_in addr;
  struct servent *sp;
  int sock;

  bzero ((char *) & addr, sizeof (addr));
  addr.sin_family = PF_INET;

  sp = getservbyname ("router", "udp");
  if (sp != NULL) 
    addr.sin_port = sp->s_port;
  else 
    addr.sin_port = htons (RIP_PORT_DEFAULT);

  addr.sin_addr.s_addr = local_addr;

  /* Make datagram socket. */
  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) 
    {
      perror ("socket");
      exit (1);
    }

  sockopt_broadcast (sock);

  ret = bind (sock, (struct sockaddr *) & addr, sizeof (addr));
  if (ret < 0)
    perror ("bind");
  
  return sock;
}

/* First entry point of RIP packet. */
rip_read (struct thread *thread)
{
  int ret;
  union rip_buf rip_buf;
  struct rip_packet *packet;
  struct sockaddr_in from;
  int fromlen, len;
  struct interface *ifp;
  int sock;

  /* Fetch thread argument. */
  sock = thread_fd (thread);

  /* RIPd manages only IPv4. */
  fromlen = sizeof (struct sockaddr_in);
  len = recvfrom (sock, (char *)&rip_buf.buf, sizeof (rip_buf.buf), 0, 
		  (struct sockaddr *) &from, &fromlen);
  if (len < 0) 
    {
      log ("recvfrom failed by %s.", strerror (errno));
      return len;
    }

  /* For easy to handle. */
  packet = &rip_buf.rip_packet;
  ifp = (struct interface *) if_lookup_address (from.sin_addr);

  /* Dump packet header. */
  log ("RIP version %d packet size [%d] command [%s]"
       "host [%s] port [%d] if [%s]\n",
       packet->version, len, LOOKUP (rip_msg, packet->command),
       inet_ntoa(from.sin_addr), ntohs (from.sin_port),
       ifp ? ifp->name : "unknown");

  /* Dump packet rte. */
  rip_dump_rte (packet, len);

  /* If this packet come from unknown inteface, ignore it. */
  if (ifp == NULL)
    {
      log ("RIP packet come from unknown inteface.");
      return;
    }

  /* RIP version check. */
  if (packet->version == 0)
    {
      log ("RIP version 0 which has command %d received.\n", packet->command);
      return;
    }

  if (packet->version > RIPv2)
    packet->version = RIPv2;

  if (packet->version != rip->version) 
    {
      log ("This packet's version[%d] doesn't fit to my version.\n", 
	   packet->version);
      return;
    }

  /* check is this packet comming from myself? */
  if (if_check_address (from.sin_addr) && packet->command != RIP_POLL) 
    {
      log ("This packet is coming from myself\n");
      return;
    }
  
  switch (packet->command)
    {
    case RIP_RESPONSE:
      rip_process_route (packet, len, &from, ifp);
      break;
    case RIP_REQUEST:
    case RIP_POLL:
      rip_process_query (packet, len, &from, ifp);
      break;
    case RIP_TRACEON:
    case RIP_TRACEOFF:
      log ("Obsolete command %s received, please send it to routed.\n", 
	   LOOKUP (rip_msg, packet->command));
      break;
    case RIP_POLL_ENTRY:
      break;
    default:
      break;
    }
  thread_add_read (master, rip_read, NULL, sock);
}

/* Make rip's socket */
rip_make_socket ()
{
  int sock;

  sock = rip_create_socket (INADDR_ANY);

  if (rip->multicast)
    rip_multicast_socket (sock);

  rip->sock = sock;

  thread_add_read (master, rip_read, NULL, rip->sock);
}

/* Dump rip packet */
rip_dump_rte (struct rip_packet *packet, int size)
{
  caddr_t end;
  struct rte *rte;

  rte = packet->route;
  end = ((caddr_t) packet) + size;
  
  log ("------------- Routing information -----------\n");
  while ((caddr_t) rte < end) 
    {
      log ("family [%d]", ntohs (rte->family));
      log2 (" tag [%d]", ntohs (rte->tag));
      log2 (" metric [%ld]\n", ntohl (rte->metric));
      log ("prefix  [%s]", inet_ntoa (rte->prefix));
      log2 (" netmask [%s]", inet_ntoa (rte->netmask));
      log2 (" nexthop [%s]\n", inet_ntoa (rte->nexthop));
      rte ++;
    }
  log ("------------- Routing information -----------\n");
}

/* Check packet's validity. */
rip_check_packet (struct rip_packet *packet, struct sockaddr_in *sin)
{
}

struct rip_info *
new_rip_info ()
{
  struct rip_info *new;

  new = XMALLOC (MTYPE_RIP_INFO, sizeof (struct rip_info));
  bzero (new, sizeof (struct rip_info));
  return new;
}

/* RIP routing information. */
rip_process_route (struct rip_packet *packet, 
		   int size, 
		   struct sockaddr_in *from,
		   struct interface *ifp)
{
  struct rte *rte;
  caddr_t end;
  struct rip_info *rinfo;
  time_t gettime;
  

  /* Check port number of incoming packet. */
  if (ntohs (from->sin_port) != RIP_PORT_DEFAULT) 
    {
      log ("This packet doesn't come from rip port : %d\n", from->sin_port);
      return;
    }

  time (&gettime);

  rte = packet->route;
  end = ((caddr_t) packet) + size;

  while ((caddr_t) rte < end) 
    {
      struct prefix_in *pin;

      /* Address family check. ripd only supports AF_INET. */
      if (ntohs (rte->family) != AF_INET)
	{
	  log ("unsupported family %d from %s.", ntohs (rte->family),
	       inet_ntoa (from->sin_addr));
	  continue;
	}

      /* Allocate new rt_in. */
      pin = prefix_in_new ();
      pin->prefix.s_addr = rte->prefix;
      pin->mask = ip_masklen (rte->netmask);
      pin->type = ZEBRA_ROUTE_RIP;

      /* Fetch information into rip_info structure */
      rinfo = new_rip_info ();
      rinfo->metric = ntohl (rte->metric);
      rinfo->gateway.s_addr = from->sin_addr.s_addr;
      rinfo->tag = ntohl (rte->tag);
      if (ntohl (rte->nexthop) == 0)
	rinfo->nexthop.s_addr = from->sin_addr.s_addr;
      else
	rinfo->nexthop.s_addr = rte->nexthop;
      rinfo->timer = gettime;

      /* Link rip_info to prefix_in. */
      pin->gate.info = rinfo;

      /* Check metric is INFINITY or not. */
      if (rinfo->metric == RIP_METRIC_INFINITY) 
	{
	  rip_delete_route (pin, rte, from);
	}
      else 
	{
	  rip_add_route (pin, rte, from, gettime, ifp);
	}
      rte++;
    }
}

/* If compare success then return 1 else return 0. This will need from
   address comparison. */
rip_cmp_route (struct prefix_in *pin1, struct prefix_in *pin2)
{
  if (pin1->prefix.s_addr == pin2->prefix.s_addr &&
      pin1->mask == pin2->mask &&
      pin1->type == pin2->type)
    {
      struct rip_info *rinfo1, *rinfo2;
      
      rinfo1 = pin1->gate.info;
      rinfo2 = pin2->gate.info;
      
      if (rinfo1->gateway.s_addr == rinfo2->gateway.s_addr)
	return 1;
      }      
  return 0;
}

/* If compare success then return 1 else return 0. This will need from
   address comparison. */
rip_lookup_interface (struct prefix_in *pin1, struct prefix_in *pin2)
{
  if (pin1->prefix.s_addr == pin2->prefix.s_addr 
      && pin1->mask == pin2->mask 
      && pin1->type == ZEBRA_ROUTE_CONNECT)
    {
	return 1;
    }      
  return 0;
}

ri_check (struct prefix_in *pin, struct interface *ifp)
{
  struct rip_interface *ri;

  ri = ifp->if_data;
  if (pin->prefix.s_addr == 0 && pin->mask == 0)
    {
      if (ri->ri_default_receive == RIP_DEFAULT_ACCEPT_UNSPEC ||
	  ri->ri_default_receive == RIP_DEFAULT_ACCEPT_NONE)
	return 0;
    }
  return 1;
}

/* RIP packet adding routine. */
rip_add_route (struct prefix_in *pin,
	       struct rte *rte,
	       struct sockaddr_in *from,
	       time_t gettime,
	       struct interface *ifp)
{
  int ret;
  struct prefix_in *find;
  struct rip_info *rinfo;

  /* Is this route same as interface's network? */
  find = radix_lookup_fn (rip_radix, pin, rip_lookup_interface);
  if (find)
    {
      log ("This route is same as interface's address so ignore it.\n");
      return;
    }

  rinfo = pin->gate.info;

  /* Is this route's nexthop is me? */
  ret = if_check_address (rinfo->gateway);
  if (ret)
    {
      log ("This route's nexthop set to me.\n");
      return;
    }

  /* if is this route exist in RIP routing table? */
  find = radix_lookup_fn (rip_radix, pin, rip_cmp_route);

  if (find)
    {
      /* If route already exist in routing table then update
         timer of the route. */
      log ("rip update route %s/%d\n", inet_ntoa (pin->prefix), 
	   pin->mask);

      rinfo = find->gate.info;
      rinfo->timer = gettime;
      
      free (pin->gate.info);
      prefix_in_free (pin);
    }
  else 
    {
      ret = ri_check (pin, ifp);
      if (!ret)
	{
	  log ("rip filtered route %s/%d\n", inet_ntoa (pin->prefix), pin->mask);
	  return;
	}
      else
	log ("rip add route %s/%d\n", inet_ntoa (pin->prefix), pin->mask);
      
      rinfo = pin->gate.info;
      rinfo->metric += ifp->metric;

      /* If this is new rip route then add to radix tree. */
      radix_add (rip_radix, (struct prefix *) pin);

      rip_zebra (ZEBRA_IPV4_ROUTE_ADD, pin, rinfo->nexthop);
    }
}

/* Process delete of route. */
rip_delete_route (struct prefix_in *pin,
		  struct rte *rte,
		  struct sockaddr_in *from)
{
  struct prefix_in *find;

  /* If route is alread exist update timer. */
  log ("rip delete route %s/%d\n", inet_ntoa (pin->prefix), 
       pin->mask);

  find = radix_lookup_fn (rip_radix, pin, rip_cmp_route);

  /* Check route */
  if (! find)
    {
      log ("can't find route \n");
      return -1;
    }

  radix_delete (rip_radix, (struct prefix *) find);

  free (find->gate.info);
  prefix_in_free (find);

  free (pin->gate.info);
  prefix_in_free (pin);

  rip_zebra (ZEBRA_IPV4_ROUTE_DELETE, pin, 0);
}

rip_make_request (u_char *pnt, int version)
{
  u_char *start = pnt;
  
  /*
   * RIP first Initializetaion query is
   *  command = RIP_REQUEST
   *  address family = AF_UNSPEC
   *  metric = 16 (RIP_METRIC_INFINITY)
   */
  st_1byte (RIP_REQUEST, pnt);	/* command */
  st_1byte (version, pnt);	/* version */
  st_2byte (0, pnt);		/* domain */
  st_2byte (AF_UNSPEC, pnt);	/* family */
  st_2byte (0, pnt);		/* tag */
  st_4byte (0, pnt);		/* prefix */
  st_4byte (0, pnt);		/* netmask */
  st_4byte (0, pnt);		/* nexthop */
  st_4byte (RIP_METRIC_INFINITY, pnt); /* metric */

  /* return packet size */
  return pnt - start;
}

ripv2_make_auth ()
{
  /* family = 0xffff, route tag = 2 */
  
}

/**/
rip_udp_send (int sock, u_char *pnt, int size, struct sockaddr_in *broadcast)
{
  int ret;
  struct sockaddr_in sin;

  if (broadcast == NULL)
    return;

#ifdef HAVE_SIN_LEN
  sin.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */
  sin.sin_family = AF_INET;
  if (broadcast->sin_port == 0)
    sin.sin_port = htons (RIP_PORT_DEFAULT);
  else
    sin.sin_port = broadcast->sin_port;
  sin.sin_addr.s_addr = broadcast->sin_addr.s_addr;

  ret = sendto (sock, pnt, size, 0, (struct sockaddr *)&sin,
		sizeof(struct sockaddr_in));

  if (ret < 0)
    log ("can't send packet : %s\n", strerror (errno));

  return ret;
}

DEFUN (router_rip,
       router_rip_cmd,
       "router rip",
       "Make RIP instance command.")
{
  vty->node = RIP_NODE;
  return CMD_SUCCESS;
}

DEFUN (rip_version,
       rip_version_cmd,
       "version VERSION",
       "Set default rip version.")
{
  int version;

  version = atoi (argv[0]);
  if (version != 1 && version != 2)
    {
      vty_out (vty, "invalid rip version %d\r\n", version);
      return;
    }
  rip->version = version;
  return CMD_SUCCESS;
} 

DEFUN (rip_network,
       rip_network_cmd,
       "network IPV4_ADDR",
       "Set announced network for RIP.")
{
  return CMD_SUCCESS;
}

/**/
rip_vty_out_uptime (struct vty *vty, struct rip_info *rinfo)
{
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char timebuf [TIME_BUF];

  time (&clock);
  clock -= rinfo->timer;
  tm = gmtime (&clock);
  strftime (timebuf, TIME_BUF, "%H:%M:%S", tm);
  vty_out (vty, "%7s", timebuf);
}

/**/
vty_rt_dump (struct prefix *pr, struct vty *vty)
{
  struct prefix_in *pin = (struct prefix_in *) pr;
  int len;

  len = vty_out (vty, "%s%s %s/%d",
		 route_sort_msg[pin->type].str,
		 pin->fib ? "*" : " ",
		 inet_ntoa (pin->prefix), pin->mask);
  len = 22 - len;

  /* Route which exist in kernel routing table. */
  switch (pin->type)
    {
    case ZEBRA_ROUTE_RIP:
      {
	struct rip_info *rinfo;

	rinfo = pin->gate.info;

	if (len > 0)
	  vty_out (vty, "%*s", len, " ");
      
	vty_out (vty, "%s ", inet_ntoa (rinfo->nexthop));
	vty_out (vty, "%5d %5d ", rinfo->metric, rinfo->tag);
	vty_out (vty, "%s ", inet_ntoa (rinfo->gateway));
	rip_vty_out_uptime (vty, rinfo);
	vty_out (vty, "\r\n");
      }
      break;
    case ZEBRA_ROUTE_CONNECT:
      {
	struct interface *ifp;

	if (len > 0)
	  vty_out (vty, "%*s", len, " ");
      
	ifp = pin->gate.info;
	vty_out (vty, "%s\t%d\r\n", ifp->name, ifp->metric);
      }
      break;
    }
}

DEFUN (show_ip_rip,
       show_ip_rip_cmd,
       "show ip rip",
       "Show RIP routes.")
{
  vty_out (vty, "\r\n");
  vty_out (vty, "Codes: R - RIP C - connected\r\n");
  vty_out (vty, "Network               Next Hop        Metric   Tag From\r\n");
  
  radix_apply_func (rip_radix, vty_rt_dump, vty);
  return CMD_SUCCESS;
}

/* RIP configuration write function. */
config_write_rip (struct vty *vty, vector v)
{
  vty_out (vty, "router rip%s", VTY_NEWLINE);
  
  if (rip->version != RIPv2)
    {
      vty_out (vty, "  version %d%s", rip->version, VTY_NEWLINE);
    }
}

/* RIP node structure. */
struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

/* Allocate new rip structure and set default value. */
rip_init ()
{
  /* Install top nodes. */
  install_node (&rip_node, config_write_rip);

  /* Install rip commands. */
  install_element (VIEW_NODE, &show_ip_rip_cmd);
  install_element (ENABLE_NODE, &show_ip_rip_cmd);
  install_element (RIP_NODE, &config_end_cmd);
  install_element (RIP_NODE, &config_exit_cmd);
  install_element (RIP_NODE, &config_help_cmd);
  install_element (RIP_NODE, &rip_version_cmd);
  install_element (CONFIG_NODE, &router_rip_cmd);

  /* Make new rip instance.*/
  rip_create ();

  /* RIP routig table. */
  radix_init ();

  rip_radix = radix_make_rib (AF_INET);
  rip_radix->sameprefix = rt_ip_sameprefix;
}
