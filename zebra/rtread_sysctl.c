/*
 * $Id: rtread_sysctl.c,v 1.26 1999/02/22 12:15:40 developer Exp $
 *
 * Kernel routing table read by sysctl function.
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

#include "prefix.h"
#include "sockunion.h"
#include "memory.h"
#include "str.h"
#include "zebra/zebra.h"
#include "rib.h"
#include "log.h"

/* Socket length roundup function. */
#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

/* Dump routing table flag for debug purpose. */
char *
rtm_flag_dump (int flag)
{
  static char buf[BUFSIZ];

  if (flag & RTF_PROTO1)
    strlcat (buf, "PROTO1 ", BUFSIZ);
  if (flag & RTF_PROTO2)
    strlcat (buf, "PROTO2 ", BUFSIZ);
#ifdef RTF_PROTO3
  if (flag & RTF_PROTO3)
    strlcat (buf, "PROTO3 ", BUFSIZ);
#endif /* RTF_PROTO3 */
  if (flag & RTF_BLACKHOLE)
    strlcat (buf, "BLACKHOLE ", BUFSIZ);
#ifdef RTF_BROADCAST
  if (flag & RTF_BROADCAST)
    strlcat (buf, "BROADCAST ", BUFSIZ);
#endif /* RTF_BROADCAST */
  if (flag & RTF_CLONING)
    strlcat (buf, "CLONING ", BUFSIZ);
#ifdef RTF_PRCLONING
  if (flag & RTF_PRCLONING)
    strlcat (buf, "PRCLONING ", BUFSIZ);
#endif /* RTF_PRCLONING */
  if (flag & RTF_DYNAMIC)
    strlcat (buf, "DYNAMIC ", BUFSIZ);
  if (flag & RTF_GATEWAY)
    strlcat (buf, "GATEWAY ", BUFSIZ);
  if (flag & RTF_HOST)
    strlcat (buf, "HOST ", BUFSIZ);
  if (flag & RTF_LLINFO)
    strlcat (buf, "LLINFO ", BUFSIZ);
  if (flag & RTF_MODIFIED)
    strlcat (buf, "MODIFIED ", BUFSIZ);
  if (flag & RTF_REJECT)
    strlcat (buf, "REJECT ", BUFSIZ);
  if (flag & RTF_STATIC)
    strlcat (buf, "STATIC ", BUFSIZ);
  if (flag & RTF_UP)
    strlcat (buf, "UP ", BUFSIZ);
#ifdef RTF_WASCLONED
  if (flag & RTF_WASCLONED)
    strlcat (buf, "WASCLONED ", BUFSIZ);
#endif /* RTF_WASCLONED */
  if (flag & RTF_XRESOLVE)
    strlcat (buf, "XRESOLVE ", BUFSIZ);

  return buf;
}

/* Supported address family check. */
int
af_check (int family)
{
  if (family == AF_INET)
    return 1;
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    return 1;
#endif /* HAVE_IPV6 */
  return 0;
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
      zlog (NULL, LOG_WARNING,
	      "Routing message version different %d should be %d."
	      "This may cause problem\n", rtm->rtm_version, RTM_VERSION);

#define SOCKADDRGET(X,R) \
    if (rtm->rtm_addrs & (R)) \
      { \
	int len = ROUNDUP (((struct sockaddr *)pnt)->sa_len); \
        if (((X) != NULL) && af_check (((struct sockaddr *)pnt)->sa_family)) \
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
      zlog (NULL, LOG_WARNING, "rtm_read() does't read all socket data.");

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
      zlog (NULL, LOG_WARNING, "sysctl() fail by %m");
      return;
    }

  ref = buf = XMALLOC (MTYPE_TMP, bufsiz);
  
  /* Read routing table information by calling sysctl(). */
  if (sysctl (mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) 
    {
      zlog (NULL, LOG_WARNING, "sysctl() fail by %m");
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
