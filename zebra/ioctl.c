/* Common ioctl functions.
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
#include <sys/types.h>
#include <unistd.h>		/* for close() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

#ifdef HAVE_LINUX_VERSION_H
#include <linux/version.h>
#endif /* HAVE_LINUX_VERSION_H */

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "ioctl.h"
#include "log.h"
#include "rt.h"

/* clear and set interface name string */
void
ifreq_set_name (struct ifreq *ifreq, struct interface *ifp)
{
  strncpy (ifreq->ifr_name, ifp->name, IFNAMSIZ);
}

/* call ioctl system call */
int
if_ioctl (int request, caddr_t buffer)
{
  int sock;
  int ret = 0;
  int err = 0;

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      perror ("socket");
      exit (1);
    }

  ret = ioctl (sock, request, buffer);
  if (ret < 0)
    {
      err = errno;
    }
  close (sock);
  
  if (ret < 0) 
    {
      errno = err;
      return ret;
    }
  return 0;
}

/*
 * get interface metric
 *   -- if value is not avaliable set -1
 */
void
if_get_metric (struct interface *ifp)
{
#ifdef SIOCGIFMETRIC
  struct ifreq ifreq;

  ifreq_set_name (&ifreq, ifp);

  if (if_ioctl (SIOCGIFMETRIC, (caddr_t) &ifreq) < 0) 
    {
      perror ("ioctl (SIOCGIFMETRIC");
      exit (1);
    }
  ifp->metric = ifreq.ifr_metric;
  if (ifp->metric == 0)
    ifp->metric = 1;
#else /* SIOCGIFMETRIC */
  ifp->metric = -1;
#endif /* SIOCGIFMETRIC */
}

/* get interface MTU */
void
if_get_mtu (struct interface *ifp)
{
  struct ifreq ifreq;

  ifreq_set_name (&ifreq, ifp);

  if (if_ioctl (SIOCGIFMTU, (caddr_t) & ifreq) < 0) 
    {
      log ("Can't lookup mtu by ioctl(SIOCGIFMTU).\n");
      ifp->mtu = -1;
    }

#ifdef SUNOS_5
  ifp->mtu = ifreq.ifr_metric;
#else
  ifp->mtu = ifreq.ifr_mtu;
#endif /* SUNOS_5 */
}

#ifdef HAVE_IFALIASREQ
/* Set up interface's IP address, netmask (and broadcas? ).  *BSD may
   has ifaliasreq structure.  */
int
if_set_prefix (struct interface *ifp, struct prefix_ipv4 *p)
{
  int ret;
  struct ifaliasreq addreq;
  struct sockaddr_in addr;
  struct sockaddr_in mask;

  bzero (&addreq, sizeof addreq);
  strncpy ((char *)&addreq.ifra_name, ifp->name, sizeof addreq.ifra_name);

  addr.sin_addr = p->prefix;
  addr.sin_family = p->family;
  memcpy (&addreq.ifra_addr, &addr, sizeof (struct sockaddr_in));

  masklen2ip (p->prefixlen, &mask.sin_addr);
  mask.sin_family = p->family;
  memcpy (&addreq.ifra_mask, &mask, sizeof (struct sockaddr_in));
  
  ret = if_ioctl (SIOCAIFADDR, (caddr_t) &addreq);
  if (ret < 0)
    return ret;
  return 0;
}
#else
/* Set up interface's address, netmask (and broadcas? ).  Linux or
   Solaris uses ifname:number semantics to set IP address aliases. */
int
if_set_prefix (struct interface *ifp, struct prefix_ipv4 *p)
{
  int ret;
  struct ifreq ifreq;
  struct sockaddr_in addr;
  struct sockaddr_in mask;

  ifreq_set_name (&ifreq, ifp);

  addr.sin_addr = p->prefix;
  addr.sin_family = p->family;
  memcpy (&ifreq.ifr_addr, &addr, sizeof (struct sockaddr_in));
  ret = if_ioctl (SIOCSIFADDR, (caddr_t) &ifreq);
  if (ret < 0)
    return ret;
  
  masklen2ip (p->prefixlen, &mask.sin_addr);
  mask.sin_family = p->family;
#ifdef SUNOS_5
  memcpy (&mask, &ifreq.ifr_addr, sizeof (mask));
#else
  memcpy (&ifreq.ifr_netmask, &mask, sizeof (struct sockaddr_in));
#endif /* SUNOS5 */
  ret = if_ioctl (SIOCSIFNETMASK, (caddr_t) &ifreq);
  if (ret < 0)
    return ret;

  /* Linux version before 2.1.0 need to interface route setup. */
#if LINUX_VERSION_CODE < 131328
  {
    struct prefix_ipv4 ifroute;

    ifroute = *p;
    apply_mask (&ifroute);
    kernel_add_ipv4 (&ifroute, NULL, ifp->index, 0);
  }
#endif /* LINUX_VERSION_CODE */

  return 0;
}
#endif /* HAVE_IFALIASREQ */

/* get interface flags */
void
if_get_flags (struct interface *ifp)
{
  int ret;
  struct ifreq ifreq;

  ifreq_set_name (&ifreq, ifp);

  ret = if_ioctl (SIOCGIFFLAGS, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      /* XXX */
      perror ("ioctl");
      exit (1);
    }

  ifp->flags = ifreq.ifr_flags & 0x0000ffff;
}

/* Set interface flags */
int
if_set_flags (struct interface *ifp, unsigned long flag)
{
  int ret;
  struct ifreq ifreq;

  if_get_flags (ifp);

  ifreq_set_name (&ifreq, ifp);

  ifp->flags |= flag;
  ifreq.ifr_flags = ifp->flags;

  ret = if_ioctl (SIOCSIFFLAGS, (caddr_t) &ifreq);

  if (ret < 0)
    {
      log ("can't set interface flags\n");
      return ret;
    }
  return 0;
}

/* Unset interface's flag. */
int
if_unset_flags (struct interface *ifp, unsigned long flag)
{
  int ret;
  struct ifreq ifreq;

  if_get_flags (ifp);

  ifreq_set_name (&ifreq, ifp);

  ifp->flags &= ~flag;
  ifreq.ifr_flags = ifp->flags;

  ret = if_ioctl (SIOCSIFFLAGS, (caddr_t) &ifreq);

  if (ret < 0)
    {
      log ("can't unset interface flags\n");
      return ret;
    }
  return 0;
}
