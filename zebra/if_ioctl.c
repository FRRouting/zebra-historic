/* Interface looking up by ioctl ().
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
#include <unistd.h>		/* for close () */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>

#include "linklist.h"
#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "memory.h"
#include "log.h"
#include "ioctl.h"
#include "dropline.h"
#include "connected.h"

/* Path to device proc file system. */
#ifndef _PATH_PROCNET_DEV
#define _PATH_PROCNET_DEV             "/proc/net/dev"
#endif /* _PATH_PROCNET_DEV */

#define IF_BUFSIZ 1024
#define IF_NAMELEN 10

/* For interface_list_ioctl ().  SIOCGIFCONF needs pre allocated
   interface information buffer. */
#define MAX_INTERFACE 32

/* Get interface's index by ioctl. */
void
if_get_index (struct interface *ifp)
{
  int ret;
  static int fake_index = 1;

  struct ifreq ifreq;

  ifreq_set_name (&ifreq, ifp);
  
#ifdef SIOCGIFINDEX
  ret = if_ioctl (SIOCGIFINDEX, (caddr_t) &ifreq);

  /* Make fake index for the interface */
  if (ret < 0)
    {
      ifp->index= fake_index++;
      return;
    }
  ifp->index = ifreq.ifr_ifindex;
  /* If there is method to get interface's index. Make fake index for
     the interface. */
  ifp->index= fake_index++;
#endif /* SIOCGIFINDEX */
}

/* Interface address lookup by ioctl.  This function only looks up
   IPv4 address. */
int
if_addr_ioctl (struct interface *ifp, char *alias)
{
  int ret;
  struct ifreq ifreq;
  struct sockaddr_in addr;
  struct sockaddr_in mask;
  struct sockaddr_in sin_broad;
  struct in_addr *broad;
  u_char prefixlen;

  /* Set interface's name and address family. */
  if (alias)
    strncpy (ifreq.ifr_name, alias, IFNAMSIZ);
  else
    ifreq_set_name (&ifreq, ifp);
  ifreq.ifr_addr.sa_family = AF_INET;

#ifdef SUNOS_5
  ret = if_ioctl (SIOCGIFFLAGS, (caddr_t) &ifreq);
  if (ret < 0)
    {
      log ("ioctl SIOCGIFLAGS fail: %s\n", strerror (errno));
      return 0;
    }
  
  ret = if_ioctl (SIOCGIFMTU, (caddr_t) & ifreq);
  if (ret < 0)
    {
      log ("ioctl SIOCGIFMTU fail: %s\n", strerror (errno));
      return 0;
    }
  memcpy (&mask, &ifreq.ifr_addr, sizeof (struct sockaddr_in));
#else  /* ! SUNOS_5 */
  /* Get interface's address. */
  ret = if_ioctl (SIOCGIFADDR, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno == EADDRNOTAVAIL)
	return 0;
      log ("ioctl SIOCGIFADDR fail: %s\n", strerror (errno));
      return ret;
    }
  memcpy (&addr, &ifreq.ifr_addr, sizeof (struct sockaddr_in));

  /* Get interface's mask. */
  ret = if_ioctl (SIOCGIFNETMASK, (caddr_t) &ifreq);
  if (ret < 0) 
    {
      if (errno == EADDRNOTAVAIL) 
	return 0;
      log ("ioctl SIOCGIFNETMASK fail: %s\n", strerror (errno));
      return ret;
    }
  memcpy (&mask, &ifreq.ifr_netmask, sizeof (struct sockaddr_in));
  prefixlen = ip_masklen (mask.sin_addr);
#endif /* SUNOS_5 */

  /* Point to point or borad cast address pointer init. */
  broad = NULL;

  /* Point to point destination address check. */
  if (ifp->flags & IFF_POINTOPOINT) 
    {
      ret = if_ioctl (SIOCGIFDSTADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno == EADDRNOTAVAIL) 
	    return 0;
	  log ("ioctl SIOCGIFDSTADDR fail: %s\n", strerror (errno));
	  return ret;
	}
      memcpy (&sin_broad, &ifreq.ifr_dstaddr, sizeof (struct sockaddr_in));
      broad = &sin_broad.sin_addr;
    }

  /* Broadcast address check. */
  if (ifp->flags & IFF_BROADCAST)
    {
      ret = if_ioctl (SIOCGIFBRDADDR, (caddr_t) &ifreq);
      if (ret < 0) 
	{
	  if (errno == EADDRNOTAVAIL) 
	    return 0;
	  log ("ioctl SIOCGIFBRDADDR fail: %s\n", strerror (errno));
	  return ret;
	}
      memcpy (&sin_broad, &ifreq.ifr_broadaddr, sizeof (struct sockaddr_in));
      broad = &sin_broad.sin_addr;
    }

  connected_add_ipv4 (ifp, &addr.sin_addr, prefixlen, broad);

  return 0;
}

/* Interface lookup by /proc/net/dev. */
void
interface_list_proc ()
{ 
  FILE *fp;
  char buf[IF_BUFSIZ];

  fp = fopen (_PATH_PROCNET_DEV, "r");
  if (fp == NULL) 
    {
      log ("Can't open device %s\n", _PATH_PROCNET_DEV);
      exit (1);
    }

  /* Drop two header line. */
  dropline (fp);
  dropline (fp);

  /* Look up all inteface from /proc/net/dev. */
  while (fgets (buf, IF_BUFSIZ, fp) != NULL)
    {
      int i, j;
      int alias;
      char *index;
      char name[IF_NAMELEN];
      char ifname[IF_NAMELEN];
      struct interface *ifp;

      i = 0;
      j = 0;

      index = strrchr (buf, ':');
      *index = '\0';

      /* Skip white space. */
      while (buf[i] == ' ')
	i++;

      /* Get interface name which may includes aliase interface. */
      while (j < IF_NAMELEN && buf[i] != '\0')
	name[j++] = buf[i++];
      name[j] = '\0';


      /* Get pure interface name. */
      for (i = 0; i < IF_NAMELEN && name[i] != ':' && name[i] != '\0'; i++)
	ifname[i] = name[i];
      ifname[i] = '\0';

      alias = (i == j) ? 0 : 1;

      ifp = if_get_by_name (ifname);

      if (!alias)
	{
	  if (log_mode)
	    log ("interface %s is added.\n", name);
	  if_get_index (ifp);
	  if_get_flags (ifp);
	  if_addr_ioctl (ifp, NULL);
	  if_get_mtu (ifp);
	  if_get_metric (ifp);
	}
      else
	{
	  if (log_mode)
	    log ("interface alias %s is added.\n", name);
	  if_addr_ioctl (ifp, name);
	}
    }
}

/* Interface looking up using SIOCGIFCONF and ioctl. */
void
interface_list_ioctl ()
{
  int sock;
  struct ifconf ifconf;
  struct ifreq *ifreq;
  caddr_t ifpnt, iflim;

  /* We must setup buffer and it's size for ioctl really ugly... */
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
      struct interface *ifp;

      ifreq = (struct ifreq *) ifpnt;

      ifp = if_get_by_name (ifreq->ifr_name);

      if_get_index (ifp);
      if_get_flags (ifp);
      if_addr_ioctl (ifp, NULL);
      if_get_mtu (ifp);
      if_get_metric (ifp);

#ifdef HAVE_SIN_LEN
      ifpnt += sizeof ifreq->ifr_name + ifreq->ifr_addr.sa_len;
#else
      ifpnt += sizeof (struct ifreq);
#endif /* HAVE_SIN_LEN */
    }
}

#ifdef HAVE_IPV6
/* This code will be only for Linux.  Proc file system for IPv6
   interface information. */

#ifndef _PATH_PROCNET_IFINET6
#define _PATH_PROCNET_IFINET6          "/proc/net/if_inet6"
#endif /* _PATH_PROCNET_IFINET6 */

void
interface_list_ipv6 ()
{
  FILE *fp;
  char buf[IF_BUFSIZ];

  /* Open /proc filesyste. */
  fp = fopen (_PATH_PROCNET_IFINET6, "r");
  if (fp == NULL)
    {
      log_warn ("Can't open %s : %s\n", _PATH_PROCNET_IFINET6, 
		strerror (errno));
      return;
    }
  
  while (fgets (buf, IF_BUFSIZ, fp) != NULL)
    {
      int n;
      char addr[33];
      int ifindex, plen, scope, status;
      char ifstr[100];
      struct interface *ifp;
      struct prefix_ipv6 p;

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
      
      str2in6_addr (addr, &p.prefix);
      p.prefixlen = plen;

      connected_add_ipv6 (ifp, &p.prefix, p.prefixlen, NULL);
    }
}
#endif /* HAVE_IPV6 */

void
interface_status ()
{
  /* dummy */
}

void
interface_status_ipv6 ()
{
  /* dummy */
}

/* Lookup all interface and get detailed information of it. */
void
interface_list ()
{
#ifndef SUNOS_5
  interface_list_proc ();
#ifdef HAVE_IPV6
  interface_list_ipv6 ();
#endif /* HAVE_IPV6 */
#else /* XXX: SUNOS_5 */
  interface_status ();
#ifdef HAVE_IPV6
  interface_status_ipv6 ();
#endif /* HAVE_IPV6 */
#endif /* !SUNOS_5 */
}
