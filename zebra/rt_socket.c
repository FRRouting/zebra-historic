/* Kernel routing table updates by routing socket.
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#ifndef SUNOS_5
#include <sys/sysctl.h>
#endif /* ! SUNOS_5 */
#include <sys/time.h>
#include <errno.h>
#include <assert.h>

#include "zebra.h"
#include "route.h"
#include "sockunion.h"
#include "rib.h"
#include "thread.h"
#include "log.h"

extern struct thread_master *master;

/* Socket length roundup function. */
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* Kernel routing update socket. */
static int routing_socket;

/* Routing message string. */
char *rtm_str [] =
{
  "RTM_NOTHING",
  "RTM_ADD",
  "RTM_DELETE",
  "RTM_CHANGE",
  "RTM_GET",
  "RTM_LOSING",
  "RTM_REDIRECT",
  "RTM_MISS",
  "RTM_LOCK",
  "RTM_OLDADD",
  "RTM_OLDDEL",
  "RTM_RESOLVE",
  "RTM_NEWADDR",
  "RTM_DELADDR",
  "RTM_IFINFO",
  "RTM_EXPIRE",
  "RTM_RTLOST",
  "RTM_GETNEXT",
};

/* For debug purpose. */
void
rtmsg_dump (struct rt_msghdr *rtm)
{
  log ("Kernel: Len: %d ", rtm->rtm_msglen);
  log2 ("Type: %s ", rtm_str[rtm->rtm_type]);
#ifdef IMPLIMENT
  rtm_flag_dump (rtm->rtm_flags);
#endif
  log2 ("\n");
}

/* Get and set kernel routing table update socket. */
/* Read kernel between zebra interface socket. */
kernel_read (struct thread *thread)
{
  int size;
  char *buf;
  int nbytes;
#define KRT_BUFLEN 300 /* XXX */
  union 
  {
    struct rt_msghdr rtm;
    char buf[KRT_BUFLEN];
  } rtmbuf;
  int sock;

  sock = thread_fd (thread);

  /* I'm not sure KRT_BUFLEN is enough... */
  nbytes= read (sock, &rtmbuf.buf, KRT_BUFLEN);
  rtmsg_dump (&rtmbuf.rtm);

  if (rtmbuf.rtm.rtm_type == RTM_ADD)
    {
      struct prefix *pin;
      union sockunion dest;
      union sockunion mask;
      union sockunion gate;

#ifdef IMPLIMENT
      rtm_read (&rtmbuf.rtm, &dest, &mask, &gate);
#endif

      log ("Kernel: route added by seq[%d] ", rtmbuf.rtm.rtm_seq);
      sockunion_log (&dest);
      sockunion_log (&mask);
      sockunion_log (&gate);
      log2 ("\n");

      /* New prefix structure allocated. */
      pin = sockunion2prefix (&dest, &mask);

      if (dest.sa.sa_family == AF_INET)
	{
	  struct prefix_in *pfind1;
	  struct prefix_in *pfind2;

	  /* I assume this route is added by hand or other daemon. */
	  pfind1 = rib_search_prefix (ZEBRA_ROUTE_KERNEL, 
				      (struct prefix_in *)pin);
	  pfind2 = rib_search_prefix (ZEBRA_ROUTE_STATIC, 
				      (struct prefix_in *)pin);
	  if (!pfind1 && !pfind2)
	    rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, 
			  (struct sockaddr_in *) &dest,
			  (struct sockaddr_in *) &mask,
			  (struct sockaddr_in *) &gate);
	  prefix_in_free (pin);
	}
#ifdef HAVE_IPV6
      if (dest.sa.sa_family == AF_INET6)
	{
	  struct prefix_in6 *pfind1;
	  struct prefix_in6 *pfind2;

	  pfind1 = rib_search_prefix_in6 (ZEBRA_ROUTE_KERNEL, 
					  (struct prefix_in6 *)pin);
	  pfind2 = rib_search_prefix_in6 (ZEBRA_ROUTE_STATIC, 
					  (struct prefix_in6 *)pin);
	  if (!pfind1 && !pfind2)
	    rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, 
			  (struct sockaddr_in6 *) &dest,
			  (struct sockaddr_in6 *) &mask,
			  (struct sockaddr_in6 *) &gate);
	  prefix_in6_free (pin);
	}
#endif /* HAVE_IPV6 */
    }      
  if (rtmbuf.rtm.rtm_type == RTM_DELETE)
    {
      struct prefix *pin;
      union sockunion dest;
      union sockunion mask;
      union sockunion gate;

#ifdef IMPLIMENT
      rtm_read (&rtmbuf.rtm, &dest, &mask, &gate);
#endif

      ;
    }

#ifdef IMPLIMENT
  if (rtmbuf.rtm.rtm_type == RTM_IFINFO)
    ifm_read_ifinfo (&rtmbuf.rtm);

  if (rtmbuf.rtm.rtm_type == RTM_NEWADDR)
    ifm_read_newaddr (&rtmbuf.rtm);
#endif

  thread_add_read (master, kernel_read, NULL, sock);
}

/* Interface function for the kernel routing table updates.  Support
   for RTM_CHANGE will be needed. */
rtm_write (int command,
	   union sockunion *dest,
	   union sockunion *mask,
	   union sockunion *gate)
{
  int ret;
  caddr_t pnt;

  /* Sequencial number of routing message. */
  static int msg_seq = 0;

  /* Struct of rt_msghdr and buffer for storing socket's data. */
  struct 
  {
    struct rt_msghdr rtm;
    char buf[512];
  } msg;
  
  if (routing_socket < 0)
    return ZEBRA_ERR_EPERM;

  /* Clear and set rt_msghdr values */
  bzero (&msg, sizeof (struct rt_msghdr));
  msg.rtm.rtm_version = RTM_VERSION;
  msg.rtm.rtm_type = command;
  msg.rtm.rtm_seq = msg_seq++;
  msg.rtm.rtm_addrs = RTA_DST|RTA_GATEWAY;
  msg.rtm.rtm_flags = RTF_UP;
  msg.rtm.rtm_index = 0;

  /* Sould we add default route treatment to this function? (in that
     case RTF_GATEWAY doesn't need ?)*/
#ifdef HAVE_SIN_LEN
  if (mask->sa.sa_len == 0) 
#else
  if (sizeof(mask->sa) == 0) 
#endif /* HAVE_SIN_LEN */
    {
      if (command == RTM_ADD) 
	msg.rtm.rtm_flags |= RTF_HOST;
    }
  else 
    {
      if (command == RTM_ADD) 
	msg.rtm.rtm_flags |= RTF_GATEWAY;
      msg.rtm.rtm_addrs |= RTA_NETMASK;
    }
  
#ifdef HAVE_SIN_LEN
#define SOCKADDRSET(X,R) \
  if (msg.rtm.rtm_addrs & (R)) \
    { \
      int len = ROUNDUP ((X)->sa.sa_len); \
      bcopy ((caddr_t)(X), pnt, len); \
      pnt += len; \
    }
#else 
#define SOCKADDRSET(X,R) \
  if (msg.rtm.rtm_addrs & (R)) \
    { \
      int len = ROUNDUP (sizeof((X)->sa)); \
      bcopy ((caddr_t)(X), pnt, len); \
      pnt += len; \
    }
#endif /* HAVE_SIN_LEN */

  pnt = (caddr_t) msg.buf;

  /* Write each socket data into rtm message buffer */
  SOCKADDRSET (dest, RTA_DST);
  SOCKADDRSET (gate, RTA_GATEWAY);
  SOCKADDRSET (mask, RTA_NETMASK);

  msg.rtm.rtm_msglen = pnt - (caddr_t) &msg;

  ret = write (routing_socket, &msg, msg.rtm.rtm_msglen);

  if (ret != msg.rtm.rtm_msglen) 
    {
      if (errno == EEXIST) 
	return ZEBRA_ERR_RTEXIST;
      if (errno == ENETUNREACH)
	return ZEBRA_ERR_RTUNREACH;
      
      log_warn ("write : %s (%d)\n", strerror (errno), errno);
      return -1;
    }
  return 0;
}

/* Adjust netmask socket length. Return value is a adjusted sin_len
   value. */
int
sin_mask_len (struct in_addr mask)
{
  struct sockaddr_in sin;
  char *p, *lim;
  int len;

  if (mask.s_addr == 0) 
      return sizeof (long);

  sin.sin_addr = mask;
  len = sizeof (struct sockaddr_in);

  lim = (char *) & sin.sin_addr;
  p = lim + sizeof (sin.sin_addr);

  while (*--p == 0 && p >= lim) 
    len--;

  return len;
}

#ifdef HAVE_IPV6
/* Calculate sin6_len value for netmask socket value. */
sin6_mask_len (struct in6_addr mask)
{
  struct sockaddr_in6 sin6;
  char *p, *lim;
  int len;

#if defined (INRIA)
  if (IN_ANYADDR6(mask)) 
    {
      return sizeof (long);
    }
#elif defined (HYDRANGEA)
  if (IN6_IS_ADDR_ANY(&mask)) 
    {
      return sizeof (long);
    }
#endif /* def HYDRANGEA */

  sin6.sin6_addr = mask;
  len = sizeof (struct sockaddr_in6);

  lim = (char *) & sin6.sin6_addr;
  p = lim + sizeof (sin6.sin6_addr);

  while (*--p == 0 && p >= lim) 
    len--;

  return len;
}
#endif

/* Convert zebra message into rtm message. */
static int
zebra2rtm (int zebra_message)
{
  switch (zebra_message) 
    {
    case ZEBRA_IPV4_ROUTE_ADD:
    case ZEBRA_IPV6_ROUTE_ADD:
      return RTM_ADD;
      break;
    case ZEBRA_IPV4_ROUTE_DELETE:
    case ZEBRA_IPV6_ROUTE_DELETE:
      return RTM_DELETE;
      break;
    defaul:
      assert (0);
      break;
    }
}

/* Initialize prototype of struct sockaddr_in. */
static struct sockaddr_in in_proto = {sizeof (struct sockaddr_in), 
				      AF_INET, 0, 0, 0};

/* Low level OS interface independent routine for updating kernel
   routing table.  This function is a routing socket version of
   kernel_rt_ip */
kernel_rt_ip (int type,
	      struct in_addr addr_dest,
	      struct in_addr addr_mask,
	      struct in_addr addr_gate)
{
  int ret;
  struct sockaddr_in dest, mask, gate;

  dest = gate = mask = in_proto;

  dest.sin_addr = addr_dest;
  gate.sin_addr = addr_gate;

  if (ip_masklen (addr_mask) == 32) 
#ifdef HAVE_SIN_LEN
    mask.sin_len = 0;
#else
    ;
#endif /* HAVE_SIN_LEN */
  else 
    {
      mask.sin_addr = addr_mask;
      mask.sin_family = AF_UNSPEC;
#ifdef HAVE_SIN_LEN
      mask.sin_len = sin_mask_len (addr_mask);
#endif /* HAVE_SIN_LEN */
    }

  ret = rtm_write (zebra2rtm (type),
		   (union sockunion *) &dest,
		   (union sockunion *) &mask,
		   (union sockunion *) &gate);
  
  return ret;
}

/* Low level OS interface independent routine for updating kernel
   routing table.  This function is a routing socket version of
   kernel_rt_ip */
kernel_rt_in (int command,
	      struct prefix_in *pin)
{
  int ret;
  struct sockaddr_in dest, mask, gate;

  dest = gate = mask = in_proto;

  dest.sin_addr = pin->prefix;
  gate.sin_addr = pin->gate.addr;

  if (pin->mask == 32) 
#ifdef HAVE_SIN_LEN
    mask.sin_len = 0;
#else
    ;
#endif /* HAVE_SIN_LEN */
  else 
    {
      masklen2ip (pin->mask, &mask.sin_addr);
      mask.sin_family = AF_UNSPEC;
#ifdef HAVE_SIN_LEN
      mask.sin_len = sin_mask_len (mask.sin_addr);
#endif /* HAVE_SIN_LEN */
    }

  ret = rtm_write (zebra2rtm (command),
		   (union sockunion *) &dest,
		   (union sockunion *) &mask,
		   (union sockunion *) &gate);
  
  return ret;
}

/* Below is IPv6 specific functions. */
#ifdef HAVE_IPV6

/* Initializing prototype of struct sockaddr_in6. */
static struct sockaddr_in6 in6_proto = 
{
#ifdef SIN6_LEN
  sizeof (struct sockaddr_in6),
#endif /* SIN6_LEN */
  AF_INET6, 0, 0, 0
};

/* Generic function to add route to the kernel. */
kernel_in6 (int type,
	    struct in6_addr *prefix,
	    u_char prefixlen,
	    struct in6_addr *gateway,
	    unsigned int ifindex)
{
  int ret;
  struct sockaddr_in6 dest;
  struct sockaddr_in6 mask;
  struct sockaddr_in6 gate;

  assert (prefixlen <= 128);

  /* Initialize sockaddr_in6 structures. */
  dest = mask = gate = in6_proto;

  /* Structure asignment. */
  dest.sin6_addr = *prefix;
  gate.sin6_addr = *gateway;

  /* Check and convert prefixlen. */
  if (prefixlen == 128)
    mask.sin6_len = 0;
  else 
    {
      masklen2ip6 (prefixlen, &mask.sin6_addr);
      mask.sin6_family = AF_UNSPEC;
#ifdef SIN6_LEN
      mask.sin6_len = sin6_mask_len (mask.sin6_addr);
#endif /* SIN6_LEN */
    }

  ret = rtm_write (zebra2rtm (type), 
		   (union sockunion *) &dest,
		   (union sockunion *) &mask,
		   (union sockunion *) &gate);
  return ret;
}

/* Wrapper for adding IPv6 route to the kernel. */
kernel_add_in6 (struct in6_addr *prefix,
		u_char prefixlen,
		struct in6_addr *gateway,
		unsigned int ifindex)
{
  kernel_in6 (ZEBRA_IPV6_ROUTE_ADD, prefix, prefixlen, gateway, ifindex);
}

/* Wrapper for deleting IPv6 route from the kernel. */
kernel_delete_in6 (struct in6_addr *prefix,
		   u_char prefixlen,
		   struct in6_addr *gateway,
		   unsigned int ifindex)
{
  kernel_in6 (ZEBRA_IPV6_ROUTE_DELETE, prefix, prefixlen, gateway, ifindex);
}

/* Same as kernel_rt_ip() but this function is IPv6 version. */
kernel_rt_ip6 (int type,
	       struct in6_addr addr_dest,
	       struct in6_addr addr_mask,
	       struct in6_addr addr_gate)
{
  int ret;
  struct sockaddr_in6 dest, mask, gate;

  dest = gate = mask = in6_proto;

  dest.sin6_addr = addr_dest;
  gate.sin6_addr = addr_gate;

  if (ip6_masklen (addr_mask) == 128)
    mask.sin6_len = 0;
  else 
    {
      mask.sin6_addr = addr_mask;
      mask.sin6_family = AF_UNSPEC;
      mask.sin6_len = sin6_mask_len (addr_mask);
    }

  ret = rtm_write (zebra2rtm (type), 
		   (union sockunion *) &dest,
		   (union sockunion *) &mask,
		   (union sockunion *) &gate);

  return ret;
}

kernel_rt_in6_index (int type, struct prefix_in6 *pin6, unsigned int ifindex)
{
  int ret;
  struct sockaddr_in6 dest, mask, gate;

  dest = gate = mask = in6_proto;

  memcpy (&dest.sin6_addr, &pin6->prefix, sizeof (struct in6_addr));
  memcpy (&gate.sin6_addr, &pin6->gate.addr, sizeof (struct in6_addr));

  if (pin6->mask == 128)
    mask.sin6_len = 0;
  else 
    {
      masklen2ip6 (pin6->mask, &mask.sin6_addr);
      mask.sin6_family = AF_UNSPEC;
      mask.sin6_len = sin6_mask_len (mask.sin6_addr);
    }

  ret = rtm_write (zebra2rtm (type), 
		   (union sockunion *) &dest,
		   (union sockunion *) &mask,
		   (union sockunion *) &gate);

  return ret;
}

kernel_rt_in6 (int type, struct prefix_in6 *pin6)
{
  kernel_rt_in6_index (type, pin6, 0);
}
#endif /* HAVE_IPV6 */

void
kernel_routing_socket ()
{
  routing_socket = socket (AF_ROUTE, SOCK_RAW, 0);

  if (routing_socket < 0) 
    {
      log_warn ("can't init kernel routing socket\n");
      return;
    }

  if (fcntl (routing_socket, F_SETFL, O_NONBLOCK) < 0) 
    log_warn ("fcntl() to routing socket  O_NONBLOCK can't set.\n");

  thread_add_read (master, kernel_read, NULL, routing_socket);
}
