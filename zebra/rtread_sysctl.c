/* Kernel routing table read by sysctl function.
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
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <errno.h>

#include "prefix.h"
#include "sockunion.h"
#include "memory.h"
#include "log.h"

#include "zebra.h"
#include "rib.h"

/* Socket length roundup function. */
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* Dump routing table flag for debug purpose. */
void
rtm_flag_dump (int flag)
{
  if (flag & RTF_PROTO1)
    log2 ("PROTO1 ");
  if (flag & RTF_PROTO2)
    log2 ("PROTO2 ");
#ifdef RTF_PROTO3
  if (flag & RTF_PROTO3)
    log2 ("PROTO3 ");
#endif /* RTF_PROTO3 */
  if (flag & RTF_BLACKHOLE)
    log2 ("BLACKHOLE ");
#ifdef RTF_BROADCAST
  if (flag & RTF_BROADCAST)
    log2 ("BROADCAST ");
#endif /* RTF_BROADCAST */
  if (flag & RTF_CLONING)
    log2 ("CLONING ");
#ifdef RTF_PRCLONING
  if (flag & RTF_PRCLONING)
    log2 ("PRCLONING ");
#endif /* RTF_PRCLONING */
  if (flag & RTF_DYNAMIC)
    log2 ("DYNAMIC ");
  if (flag & RTF_GATEWAY)
    log2 ("GATEWAY ");
  if (flag & RTF_HOST)
    log2 ("HOST ");
  if (flag & RTF_LLINFO)
    log2 ("LLINFO ");
  if (flag & RTF_MODIFIED)
    log2 ("MODIFIED ");
  if (flag & RTF_REJECT)
    log2 ("REJECT ");
  if (flag & RTF_STATIC)
    log2 ("STATIC ");
  if (flag & RTF_UP)
    log2 ("UP ");
#ifdef RTF_WASCLONED
  if (flag & RTF_WASCLONED)
    log2 ("WASCLONED ");
#endif /* RTF_WASCLONED */
  if (flag & RTF_XRESOLVE)
    log2 ("XRESOLVE ");
  /* log2 ("\n"); */
}

/* Interface function for reading kernel routing table information. */
int
rtm_read (struct rt_msghdr *rtm,
	  union sockunion *dest,
	  union sockunion *mask,
	  union sockunion *gate)
{
  caddr_t pnt, end;

  /* Pnt points out socket data start point. */
  pnt = (caddr_t)(rtm + 1);
  end = ((caddr_t)rtm) + rtm->rtm_msglen;

  /* rt_msghdr version check. */
  if (rtm->rtm_version != RTM_VERSION) 
      log_warn ("Routing message version different %d should be %d."
		"This may cause problem\n", rtm->rtm_version, RTM_VERSION);

#define SOCKADDRGET(X,R) \
    if (rtm->rtm_addrs & (R)) \
      { \
	int len = ROUNDUP (((struct sockaddr *)pnt)->sa_len); \
	if ((X) != NULL) \
	  memcpy ((caddr_t)(X), pnt, len); \
	pnt += len; \
      }

  /* Be sure structure is cleared */
  bzero (dest, sizeof (union sockunion));
  bzero (gate, sizeof (union sockunion));
  bzero (mask, sizeof (union sockunion));

  /* We fetch each socket variable into sockunion. */
  SOCKADDRGET (dest, RTA_DST);
  SOCKADDRGET (gate, RTA_GATEWAY);
  SOCKADDRGET (mask, RTA_NETMASK);
  SOCKADDRGET (NULL, RTA_GENMASK);
  SOCKADDRGET (NULL, RTA_IFP);
  SOCKADDRGET (NULL, RTA_IFA);
  SOCKADDRGET (NULL, RTA_AUTHOR);
  SOCKADDRGET (NULL, RTA_BRD);

  /* If there is netmask information set it's family same as
     destination family*/
  if (rtm->rtm_addrs & RTA_NETMASK)
    mask->sa.sa_family = dest->sa.sa_family;

  /* Assert read up to the end of pointer. */
  if (pnt != end) 
      log_warn ("rtm_read() does't read all socket data.");

  return rtm->rtm_flags;
}

/* Kernel routing table read up by sysctl function. */
void
route_read ()
{
  caddr_t buf, end, ref;
  size_t bufsiz;
  struct rt_msghdr *rtm;
  union sockunion dest, mask, gate;
  int flags;
  
#define MIBSIZ 6
  int mib[MIBSIZ] = { CTL_NET,
		      PF_ROUTE,
		      0,
		      0,
		      NET_RT_DUMP,
		      0 };
		      
  if (sysctl (mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) 
    {
      log_warn ("sysctl() fail by %s", strerror (errno));
      return;
    }

  ref = buf = XMALLOC (MTYPE_TMP, bufsiz);
  
  /* Read routing table information by calling sysctl(). */
  if (sysctl (mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) 
    {
      log_warn ("sysctl() fail by %s", strerror (errno));
      return;
    }

  for (end = buf + bufsiz; buf < end; buf += rtm->rtm_msglen) 
    {
      rtm = (struct rt_msghdr *) buf;

      /* Read destination and netmask and gateway from rtm message
	 structure. */
      flags = rtm_read (rtm, &dest, &mask, &gate);

      /* Ignore route which does not have HOST and GATEWAY attribute. */
      if (! (flags & RTF_UP))
	continue;
      if ((flags & RTF_GATEWAY) && (flags & RTF_HOST))
	continue;
      if (! (flags & RTF_GATEWAY))
	continue;

      if (dest.sa.sa_family == AF_INET)
	{
	  struct prefix_ipv4 p;

	  p.family = AF_INET;
	  p.prefix = dest.sin.sin_addr;
	  p.prefixlen = ip_masklen (mask.sin.sin_addr);

	  rib_add_ipv4 (ZEBRA_ROUTE_KERNEL, &p, &gate.sin.sin_addr, 0);
	}
#ifdef HAVE_IPV6
      if (dest.sa.sa_family == AF_INET6)
	{
	  struct prefix_ipv6 p;

	  p.family = AF_INET6;
	  p.prefix = dest.sin6.sin6_addr;
	  p.prefixlen = ip6_masklen (mask.sin6.sin6_addr);

	  rib_add_ipv6 (ZEBRA_ROUTE_KERNEL, &p, &gate.sin6.sin6_addr, 0);
	}
#endif /* HAVE_IPV6 */
    }
  XFREE (MTYPE_TMP, ref);
}
