/* interface looking up by ioctl ().
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
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <errno.h>

#include "linklist.h"
#include "if.h"
#include "sockunion.h"
#include "ifa.h"
#include "memory.h"
#include "log.h"

/* Interface looking up using SIOCGIFCONF and ioctl. */
interface_list ()
{
  int sock;
  struct ifconf ifconf;
  struct ifreq *ifreq;
  caddr_t ifpnt, iflim;

  /* We must setup buffer and it's size for ioctl really ugly... */
#define MAX_INTERFACE 32
  ifconf.ifc_len = MAX_INTERFACE * sizeof (struct ifreq);
  ifconf.ifc_buf = (caddr_t) XMALLOC (0, ifconf.ifc_len);

  sock = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    {
      log_warn ("can't make socket\n");
      exit (1);
    }

  if (ioctl (sock, SIOCGIFCONF, (char *) &ifconf) < 0) 
    {
      log_warn ("ioctl() error by %s", strerror (errno));
      exit (1);
    }
  close (sock);

  ifpnt = ifconf.ifc_buf;
  iflim = ifpnt + ifconf.ifc_len;

  while (ifpnt < iflim) 
    {
      ifreq = (struct ifreq *) ifpnt;
    
      if_add_ioctl (ifreq, ifreq->ifr_addr);

#ifdef HAVE_SIN_LEN
      ifpnt += sizeof ifreq->ifr_name + ifreq->ifr_addr.sa_len;
#else
      ifpnt += sizeof (struct ifreq);
#endif /* HAVE_SIN_LEN */
    }
#ifdef HAVE_IPV6
  interface_list_ipv6 ();
#endif /* HAVE_IPV6 */
}

/* interface adding function called from interface_list(ioctl) */
if_add_ioctl (struct ifreq *ifreq, struct sockaddr addr)
{
  int sock;
  struct interface *ifp;

  /* Is this new interface ? */
  ifp = if_lookup_by_name (ifreq->ifr_name);

  /* If this is new interface then make one. */
  if (ifp == NULL) {
    {
      ifp = if_new ();
      /* Copy inteface name. XXX We will need ifname:0 treatment here. */
      strncpy (ifp->name, ifreq->ifr_name, IFNAMSIZ);
    }
  }
  ifp->index = 0;

  /* get interface values */
  if_get_addr (ifp);
  if_get_flags (ifp);
  if_get_mtu (ifp);
  if_get_metric (ifp);
}

/* get interface flags */
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

if_get_addr (struct interface *ifp)
{
  int ret;
  struct if_addr *ifa;
  struct ifreq ifreq;
  
  ifa = (struct if_addr *) ifa_new ();

  ifreq_set_name (&ifreq, ifp);

  /* Get interface's address. */
  ret = if_ioctl (SIOCGIFADDR, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno == EADDRNOTAVAIL) 
	return;
      perror ("ioctl");
      exit (1);
    }
  ifa->ifa_addr.sa = ifreq.ifr_addr;

  /* Do we need tunnel interface treatment here? */

#ifndef SUNOS_5
  /* Get interface's mask */
  ret = if_ioctl (SIOCGIFNETMASK, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno == EADDRNOTAVAIL) 
	return;
      perror ("ioctl");
      exit (1);
    }
  ifa->ifa_mask.sa = ifreq.ifr_netmask;
  ifa->ifa_mask.sa.sa_family = ifa->ifa_addr.sa.sa_family;
#endif /* SUNOS_5 */

  /* Get interface's destination address. */
  if (ifp->flags, IFF_POINTOPOINT) 
    {
      ret = if_ioctl (SIOCGIFDSTADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno == EADDRNOTAVAIL) 
	    return;
	  perror ("ioctl");
	  exit (1);
	}
      ifa->ifa_dest.sa = ifreq.ifr_dstaddr;
    }

  if (ifp->flags, IFF_BROADCAST)
    {
      ret = if_ioctl (SIOCGIFBRDADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno == EADDRNOTAVAIL) 
	    return;
	  perror ("ioctl");
	  exit (1);
	}
      ifa->ifa_dest.sa = ifreq.ifr_dstaddr;
    }

  list_add_node (ifp->addr, ifa);

  /* Add connected route to rib. */
  ifa_rib_insert (ifa, ifp);
}


#ifdef HAVE_IPV6
/* This code will be only for Linux. */

/* Proc file system for IPv6 interface information. */
#ifndef _PATH_PROCNET_IFINET6
#define _PATH_PROCNET_IFINET6          "/proc/net/if_inet6"
#endif /* _PATH_PROCNET_IFINET6 */

#define IF_BUFSIZ 1024

#include "route.h"

str2in6_addr (char *str, struct in6_addr *addr)
{
  int i;
  unsigned int x;

  /* %x must point to unsinged int */
  for (i = 0; i < 16; i++)
    {
      sscanf (str + (i * 2), "%02x", &x);
      addr->s6_addr[i] = x & 0xff;
    }
}

int
interface_list_ipv6 ()
{
  FILE *fp;
  char buf[IF_BUFSIZ];

  struct if_addr *ifa;

  /* Open /proc filesyste. */
  fp = fopen (_PATH_PROCNET_IFINET6, "r");
  if (fp == NULL)
    {
      log_warn ("Can't open %s : %s\n", _PATH_PROCNET_IFINET6, 
		strerror (errno));
      return -1;
    }
  
  while (fgets (buf, IF_BUFSIZ, fp) != NULL)
    {
      int n;
      char addr[33];
      int ifindex, plen, scope, status;
      char ifstr[100];
      struct interface *ifp;

      struct prefix_in6 *p;

      n = sscanf (buf, "%32s %02x %02x %02x %02x %s", 
		  addr, &ifindex, &plen, &scope, &status, ifstr);
      if (n != 6)
	{
	  /* log ("can't read interface information %d\n%s\n", n, buf); */
	  continue;
	}

      ifp = if_lookup_by_name (ifstr);
      if (ifp == NULL)
	{
	  ifp = if_new ();
	  strcpy (ifp->name, ifstr);
	}
      ifp->index = ifindex;
      
#if 0 /* I will use this code when ifa strucutre moved to prefix union. */
      p = prefix_in6_new ();
      str2in6_addr (addr, &p->prefix);
      p->mask = plen;
      dump_route_in6 (p);
#endif /* 0 */

      ifa = ifa_new ();
      ifa->ifa_addr.sa.sa_family = AF_INET6;
      ifa->ifa_mask.sa.sa_family = AF_INET6;
      str2in6_addr (addr, &ifa->ifa_addr.sin6.sin6_addr);
      masklen2ip6 (plen, &ifa->ifa_mask.sin6.sin6_addr);
      
      list_add_node (ifp->addr, ifa);
      ifa_rib_insert (ifa, ifp);
    }
}
#endif /* HAVE_IPV6 */
