/*
 * Get interface's address and mask information by sysctl() function.
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

#include "linklist.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "connected.h"
#include "memory.h"
#include "ioctl.h"
#include "log.h"

/* Interface adding function called from interface_list. */
void
ifm_interface_add (struct if_msghdr *ifm)
{
  struct interface *ifp;
  struct sockaddr_dl *sdl;

  sdl = (struct sockaddr_dl *)(ifm + 1);

  /* Check does this interface index exist? */
  ifp = if_lookup_by_name (sdl->sdl_data);
  if (ifp == NULL)
    {
      ifp = if_new ();
      strncpy (ifp->name, sdl->sdl_data, sdl->sdl_nlen);
    }

  /* Set ifm value into struct interface. */
  ifp->ifindex = ifm->ifm_index;
  ifp->flags = ifm->ifm_flags;

  if_get_mtu (ifp);
  if_get_metric (ifp);

  zlog (NULL, LOG_DEBUG, "interface %s index %d", ifp->name, ifp->ifindex);
}

/* Supported address family check. */
static int
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

/* Address read from struct ifa_msghdr. */
void
ifm_read (struct ifa_msghdr *ifm,
	  union sockunion *addr,
	  union sockunion *mask,
	  union sockunion *dest)
{
  caddr_t pnt, end;

  pnt = (caddr_t)(ifm + 1);
  end = ((caddr_t)ifm) + ifm->ifam_msglen;

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

#define SOCKADDRGET(X,R) \
    if (ifm->ifam_addrs & (R)) \
      { \
        int len = ROUNDUP (((struct sockaddr *)pnt)->sa_len); \
        if (((X) != NULL) && af_check (((struct sockaddr *)pnt)->sa_family)) \
          memcpy ((caddr_t)(X), pnt, len); \
        pnt += len; \
      }

#define SOCKMASKGET(X,R) \
    if (ifm->ifam_addrs & (R)) \
      { \
	int len = ROUNDUP (((struct sockaddr *)pnt)->sa_len); \
        if ((X) != NULL) \
	  memcpy ((caddr_t)(X), pnt, len); \
	pnt += len; \
      }

  /* Be sure structure is cleared */
  bzero (mask, sizeof (union sockunion));
  bzero (addr, sizeof (union sockunion));
  bzero (dest, sizeof (union sockunion));

  /* We fetch each socket variable into sockunion. */
  SOCKADDRGET (NULL, RTA_DST);
  SOCKADDRGET (NULL, RTA_GATEWAY);
  SOCKMASKGET (mask, RTA_NETMASK);
  SOCKADDRGET (NULL, RTA_GENMASK);
  SOCKADDRGET (NULL, RTA_IFP);
  SOCKADDRGET (addr, RTA_IFA);
  SOCKADDRGET (NULL, RTA_AUTHOR);
  SOCKADDRGET (dest, RTA_BRD);

  /* Assert read up end point matches to end point */
  if (pnt != end)
    zlog (NULL, LOG_WARNING, "ifm_read() does't read all socket data");
}

/* Interface's address information get. */
int
ifm_address_add (struct ifa_msghdr *ifm)
{
  struct interface *ifp;
  union sockunion addr, mask, gate;

  /* Check does this interface exist or not. */
  ifp = if_lookup_by_index (ifm->ifam_index);
  if (ifp == NULL) 
    {
      zlog (NULL, LOG_WARNING, "no interface for index %d", ifm->ifam_index); 
      return -1;
    }

  /* Allocate and read address information. */
  ifm_read (ifm, &addr, &mask, &gate);

  /* Add connected address. */
  switch (sockunion_family (&addr))
    {
    case AF_INET:
      connected_add_ipv4 (ifp, 
			  &addr.sin.sin_addr, 
			  ip_masklen (mask.sin.sin_addr),
			  &gate.sin.sin_addr);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      connected_add_ipv6 (ifp,
			  &addr.sin6.sin6_addr, 
			  ip6_masklen (mask.sin6.sin6_addr),
			  &gate.sin6.sin6_addr);
      break;
#endif /* HAVE_IPV6 */
    default:
      /* Unsupported family silently ignore... */
      break;
    }
  return 0;
}

/* Interface listing up function using sysctl(). */
void
interface_list ()
{
  caddr_t ref, buf, end;
  size_t bufsiz;
  struct if_msghdr *ifm;

#define MIBSIZ 6
  int mib[MIBSIZ] =
  { 
    CTL_NET,
    PF_ROUTE,
    0,
    0, /*  AF_INET & AF_INET6 */
    NET_RT_IFLIST,
    0 
  };

  /* Query buffer size. */
  if (sysctl (mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) 
    {
      zlog (NULL, LOG_WARNING, "sysctl() error by %s", strerror (errno));
      return;
    }

  /* We free this memory at the end of this function. */
  ref = buf = XMALLOC (MTYPE_TMP, bufsiz);

  /* Fetch interface informations into allocated buffer. */
  if (sysctl (mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) 
    {
      zlog (NULL, LOG_WARNING, "sysctl error by %s", strerror (errno));
      return;
    }

  /* Parse both interfaces and addresses. */
  for (end = buf + bufsiz; buf < end; buf += ifm->ifm_msglen) 
    {
      ifm = (struct if_msghdr *) buf;

      switch (ifm->ifm_type) 
	{
	case RTM_IFINFO:
	  ifm_interface_add (ifm);
	  break;
	case RTM_NEWADDR:
	  ifm_address_add ((struct ifa_msghdr *) ifm);
	  break;
	default:
	  zlog_info ("interfaces_list(): unexpected message type");
	  XFREE (MTYPE_TMP, ref);
	  return;
	  break;
	}
    }

  /* Free sysctl buffer. */
  XFREE (MTYPE_TMP, ref);
}

/* Called from rt_sysctl.c. */
void
ifm_read_ifinfo (struct if_msghdr *ifm)
{
  struct interface *ifp;
  caddr_t pnt, end;

  ifp = if_lookup_by_index (ifm->ifm_index);
  if (ifp == NULL)
    {
      ifp = if_new();
      ifp->ifindex = ifm->ifm_index;
      zlog (NULL, LOG_INFO, "New interface from routing socket");
    }
  else
    zlog (NULL, LOG_INFO, "Interface %s's information change from routing socket", 
	    ifp->name);

  pnt = (caddr_t)(ifm + 1);
  end = ((caddr_t)(ifm)) + ifm->ifm_msglen;
}

/* Called from rt_sysctl.c */
void
ifm_read_newaddr (struct ifa_msghdr *ifam)
{
  ;
}
