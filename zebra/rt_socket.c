/*
 * Kernel routing table updates by routing socket.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "zebra/zebra.h"
#include "thread.h"
#include "prefix.h"
#include "sockunion.h"
#include "log.h"

/* Macro to set link local index to the IPv6 address.  For KAME IPv6
   stack. */
#ifdef KAME
#define	IN6_LINKLOCAL_IFINDEX(a)  ((a).s6_addr8[2] << 8 | (a).s6_addr8[3])
#define SET_IN6_LINKLOCAL_IFINDEX(a, i) \
  do { \
    (a).s6_addr8[2] = ((i) >> 8) & 0xff; \
    (a).s6_addr8[3] = (i) & 0xff; \
  } while (0)
#else
#define	IN6_LINKLOCAL_IFINDEX(a)
#define SET_IN6_LINKLOCAL_IFINDEX(a, i)
#endif /* KAME */

extern struct thread_master *master;

/* Kernel routing update socket. */
struct
{
  int sock;
} routing = { -1 };

/* Initialize prototype of struct sockaddr_in. */
static struct sockaddr_in sin_proto = 
{
#ifdef HAVE_SIN_LEN
  sizeof (struct sockaddr_in), 
#endif /* HAVE_SIN_LEN */
  AF_INET, 0, {0}, {0}
};
#ifdef HAVE_IPV6
static struct sockaddr_in6 sin6_proto = 
{
#ifdef SIN6_LEN
  sizeof (struct sockaddr_in6),
#endif /* SIN6_LEN */
  AF_INET6, 0, 0, {{{ 0 }}}
};
#endif /* HAVE_IPV6 */

#include "linklist.h"
#include "if.h"

/* Interface function for the kernel routing table updates.  Support
   for RTM_CHANGE will be needed. */
int
rtm_write (int message,
	   union sockunion *dest,
	   union sockunion *mask,
	   union sockunion *gate,
	   unsigned int index)
{
  int ret;
  caddr_t pnt;
  struct sockaddr_in tmp_gate = sin_proto;
#ifdef HAVE_IPV6
  struct sockaddr_in6 tmp_gate6 = sin6_proto;
#endif /* HAVE_IPV6 */

  /* Sequencial number of routing message. */
  static int msg_seq = 0;

  /* Struct of rt_msghdr and buffer for storing socket's data. */
  struct 
  {
    struct rt_msghdr rtm;
    char buf[512];
  } msg;
  
  if (routing.sock < 0)
    return ZEBRA_ERR_EPERM;

  /* Clear and set rt_msghdr values */
  bzero (&msg, sizeof (struct rt_msghdr));
  msg.rtm.rtm_version = RTM_VERSION;
  msg.rtm.rtm_type = message;
  msg.rtm.rtm_seq = msg_seq++;
  msg.rtm.rtm_addrs = RTA_DST;
  msg.rtm.rtm_addrs |= RTA_GATEWAY;
  msg.rtm.rtm_flags = RTF_UP;
  msg.rtm.rtm_index = index;

  if (gate && (message == RTM_ADD))
    msg.rtm.rtm_flags |= RTF_GATEWAY;

  if (mask)
    msg.rtm.rtm_addrs |= RTA_NETMASK;
  else if (message == RTM_ADD) 
    msg.rtm.rtm_flags |= RTF_HOST;

  /* Tagging route with flags */
  msg.rtm.rtm_flags |= (RTF_PROTO2|RTF_PROTO1);

  /* Route to the interface test.  This should be rewritten later on
     -- Kunihiro*/
  if (!gate)
    {
      #define MAX_IFACES 400
      int sock;
      struct ifreq iflist[MAX_IFACES];
      struct ifconf ifconf;
      struct ifreq *ifr, *ifr_end;
      struct sockaddr_dl *dl, *sdl = NULL;
      struct interface *ifp;
      char *s; /* ifname */

      ifp = if_lookup_by_index (index);      
      if (!ifp)
        {
          zlog (NULL, LOG_WARNING, "can't find interface of index %u", index);
	  goto noifname;
	}
      s = ifp->name;

      if ((sock = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
        zlog (NULL, LOG_WARNING, "can't open socket for iflist: %s (%d)",
              strerror (errno), errno);

      /* get interface list of this host */
      ifconf.ifc_req = iflist;
      ifconf.ifc_len = sizeof (iflist);
      if (ioctl (sock, SIOCGIFCONF, &ifconf) < 0)
        zlog (NULL, LOG_WARNING, "can't get iflist: %s (%d)",
              strerror (errno), errno);

      /* close sock */
      close (sock);

      /* get ifr that matches ifindex */
      ifr_end = (struct ifreq *)(ifconf.ifc_buf + ifconf.ifc_len);
      for (ifr = ifconf.ifc_req; ifr < ifr_end;
           ifr = (struct ifreq *) ((char *)&ifr->ifr_addr
                                   + ifr->ifr_addr.sa_len))
        {
          dl = (struct sockaddr_dl *)&ifr->ifr_addr;
          if (ifr->ifr_addr.sa_family != AF_LINK)
            continue;
          if (strncmp(s, dl->sdl_data, dl->sdl_nlen) || s[dl->sdl_nlen] != 0)
            continue;
          sdl = dl;
          break;
        }

      if (sdl)
        gate = (union sockunion *)sdl;
      else
        zlog (NULL, LOG_WARNING, "can't find interface: %s", s);
    }
noifname:

  /* if still we don't have gate to specify, use previous way. */
  if (! gate )
    {
      struct interface *ifp;
      listnode node;
      struct connected *connected;

      ifp = if_lookup_by_index (index);      
      if (ifp)
	for (node = listhead (ifp->connected); node; nextnode (node))
	  {
	    struct prefix *p;

	    connected = getdata (node);
	    p = connected->address;

	    if (p->family != dest->sa.sa_family)
              continue;

	    if (p->family == AF_INET)
              {
		tmp_gate.sin_addr = p->u.prefix4;
		gate = (union sockunion *)&tmp_gate;
	      }
#ifdef HAVE_IPV6
            if (p->family == AF_INET6)
              {
                memcpy (&tmp_gate6.sin6_addr, &p->u.prefix6,
                         sizeof (struct in6_addr));
                gate = (union sockunion *)&tmp_gate6;
              }
#endif /* HAVE_IPV6 */
	  }
    }

  if (!gate)
    {
      zlog (NULL, LOG_WARNING, "no gateway");
      return -1;
    }

/* Socket length roundup function. */
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

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

  ret = write (routing.sock, &msg, msg.rtm.rtm_msglen);

  if (ret != msg.rtm.rtm_msglen) 
    {
      if (errno == EEXIST) 
	return ZEBRA_ERR_RTEXIST;
      if (errno == ENETUNREACH)
	return ZEBRA_ERR_RTUNREACH;
      
      zlog (NULL, LOG_WARNING, "write : %s (%d)", strerror (errno), errno);
      return -1;
    }
  return 0;
}

/* Adjust netmask socket length. Return value is a adjusted sin_len
   value. */
int
sin_masklen (struct in_addr mask)
{
  char *p, *lim;
  int len;
  struct sockaddr_in sin;

  if (mask.s_addr == 0) 
    return sizeof (long);

  sin.sin_addr = mask;
  len = sizeof (struct sockaddr_in);

  lim = (char *) &sin.sin_addr;
  p = lim + sizeof (sin.sin_addr);

  while (*--p == 0 && p >= lim) 
    len--;
  return len;
}

/* Interface between zebra message and rtm message. */
int
kernel_rtm_ipv4 (int message, struct prefix_ipv4 *dest,
		 struct in_addr *gate, unsigned int index, int metric)
{
  struct sockaddr_in *mask;
  struct sockaddr_in sin_dest, sin_mask, sin_gate;

  sin_dest = sin_mask = sin_gate = sin_proto;
  sin_dest.sin_addr = dest->prefix;
  if (gate)
    sin_gate.sin_addr = *gate;

  if (dest->prefixlen != 32)
    {
      masklen2ip (dest->prefixlen, &sin_mask.sin_addr);
      sin_mask.sin_len = sin_masklen (sin_mask.sin_addr);
      sin_mask.sin_family = AF_UNSPEC;
      mask = &sin_mask;
    }
  else 
    mask = NULL;

  return rtm_write (message,
		    (union sockunion *)&sin_dest, 
		    (union sockunion *)mask, 
		    gate ? (union sockunion *)&sin_gate : NULL,
		    index);
}

/* Add IPv4 prefix to kernel routing table. */
int
kernel_add_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		 unsigned int index, int metric, int table)
{
  return kernel_rtm_ipv4 (RTM_ADD, dest, gate, index, metric);
}

/* Delete IPv4 prefix from kernel routing table. */
int
kernel_delete_ipv4 (struct prefix_ipv4 *dest, struct in_addr *gate,
		    unsigned int index, int metric, int table)
{
  return kernel_rtm_ipv4 (RTM_DELETE, dest, gate, index, metric);
}

#ifdef HAVE_IPV6

/* Calculate sin6_len value for netmask socket value. */
int
sin6_masklen (struct in6_addr mask)
{
  struct sockaddr_in6 sin6;
  char *p, *lim;
  int len;

#if defined (INRIA)
  if (IN_ANYADDR6(mask)) 
    {
      return sizeof (long);
    }
#elif defined (KAME)
  if (IN6_IS_ADDR_ANY(&mask)) 
    {
      return sizeof (long);
    }
#endif /* def KAME*/

  sin6.sin6_addr = mask;
  len = sizeof (struct sockaddr_in6);

  lim = (char *) & sin6.sin6_addr;
  p = lim + sizeof (sin6.sin6_addr);

  while (*--p == 0 && p >= lim) 
    len--;

  return len;
}

/* Interface between zebra message and rtm message. */
int
kernel_rtm_ipv6 (int message, struct prefix_ipv6 *dest,
		 struct in6_addr *gate, int index, int metric)
{
  struct sockaddr_in6 *mask;
  struct sockaddr_in6 sin_dest, sin_mask, sin_gate;

  sin_dest = sin_mask = sin_gate = sin6_proto;
  sin_dest.sin6_addr = dest->prefix;

  /* Under kame set interface index to link local address. */
#ifdef KAME
  if (gate && IN6_IS_ADDR_LINKLOCAL(gate))
    {
      SET_IN6_LINKLOCAL_IFINDEX (*gate, index);
    }
#endif /* KAME */

  if (gate)
    memcpy (&sin_gate.sin6_addr, gate, sizeof (struct in6_addr));

  if (dest->prefixlen != 128)
    {
      masklen2ip6 (dest->prefixlen, &sin_mask.sin6_addr);
      sin_mask.sin6_family = AF_UNSPEC;
#ifdef SIN6_LEN
      sin_mask.sin6_len = sin6_masklen (sin_mask.sin6_addr);
#endif /* SIN6_LEN */
      mask = &sin_mask;
    }
  else
    mask = NULL;

  return rtm_write (message, 
		   (union sockunion *) &sin_dest,
		   (union sockunion *) mask,
		   gate ? (union sockunion *)&sin_gate : NULL,
		    index);
}

/* Add IPv6 route to the kernel. */
int
kernel_add_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		 int index, int metric, int table)
{
  return kernel_rtm_ipv6 (RTM_ADD, dest, gate, index, metric);
}

/* Delete IPv6 route from the kernel. */
int
kernel_delete_ipv6 (struct prefix_ipv6 *dest, struct in6_addr *gate,
		    int index, int metric, int table)
{
  return kernel_rtm_ipv6 (RTM_DELETE, dest, gate, index, metric);
}
#endif /* HAVE_IPV6 */

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
rtmsg_log (struct rt_msghdr *rtm)
{
  char *rtm_flag_dump (int);

  zlog (NULL, LOG_INFO, "Kernel: Len: %d Type: %s", rtm->rtm_msglen,
	  rtm_str[rtm->rtm_type]);
  rtm_flag_dump (rtm->rtm_flags);
}

/* Prototype from rtread_sysctl.c */
int
rtm_read (struct rt_msghdr *rtm,
	  union sockunion *dest,
	  union sockunion *mask,
	  union sockunion *gate);

void ifm_read_ifinfo (struct if_msghdr *);
void ifm_read_newaddr (struct ifa_msghdr *);

/* Get and set kernel routing table update socket.  Read kernel
   between zebra interface socket. */
int
kernel_read (struct thread *thread)
{
  int nbytes;
#define KRT_BUFLEN 300 /* XXX */
  union 
  {
    struct rt_msghdr rtm;
    char buf[KRT_BUFLEN];
  } rtmbuf;
  int sock;

  sock = THREAD_FD (thread);

  /* I'm not sure KRT_BUFLEN is enough... */
  nbytes= read (sock, &rtmbuf.buf, KRT_BUFLEN);
  rtmsg_log (&rtmbuf.rtm);

  if (rtmbuf.rtm.rtm_type == RTM_ADD)
    {
      struct prefix *pin;
      union sockunion dest;
      union sockunion mask;
      union sockunion gate;

      rtm_read (&rtmbuf.rtm, &dest, &mask, &gate);

      /* XXX non-reentrant calls - BROKEN */
      zlog (NULL, LOG_INFO, "Kernel: route added by seq[%d] %s %s %s", rtmbuf.rtm.rtm_seq, sockunion_log (&dest), sockunion_log (&mask), sockunion_log (&gate));

      /* New prefix structure allocated. */
      pin = sockunion2prefix (&dest, &mask);

      if (dest.sa.sa_family == AF_INET)
	{
	}
#ifdef HAVE_IPV6
      if (dest.sa.sa_family == AF_INET6)
	{
	}
#endif /* HAVE_IPV6 */
    }      

  if (rtmbuf.rtm.rtm_type == RTM_DELETE)
    {
      union sockunion dest;
      union sockunion mask;
      union sockunion gate;

      rtm_read (&rtmbuf.rtm, &dest, &mask, &gate);
      ;
    }

  if (rtmbuf.rtm.rtm_type == RTM_IFINFO)
    ifm_read_ifinfo ((struct if_msghdr *) &rtmbuf.rtm);

  if (rtmbuf.rtm.rtm_type == RTM_NEWADDR)
    ifm_read_newaddr ((struct ifa_msghdr *) &rtmbuf.rtm);

  thread_add_read (master, kernel_read, NULL, sock);

  return 0;
}

/* Make routing socket. */
void
routing_socket ()
{
  routing.sock = socket (AF_ROUTE, SOCK_RAW, 0);

  if (routing.sock < 0) 
    {
      zlog (NULL, LOG_WARNING, "can't init kernel routing socket");
      return;
    }

  if (fcntl (routing.sock, F_SETFL, O_NONBLOCK) < 0) 
    zlog (NULL, LOG_WARNING, "fcntl() to routing socket  O_NONBLOCK can't set");

  /* kernel_read needs rewrite. */
  /* thread_add_read (master, kernel_read, NULL, routing.sock); */
}

/* Exported interface function.  This function simply calls
   routing_socket (). */
void
kernel_init ()
{
  routing_socket ();
}
