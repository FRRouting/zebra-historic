/* This implementation assumes network mask is sequential.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>		/* atoi */
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <arpa/inet.h>

/* for sockaddr_dl */
#ifdef AF_LINK
#include <net/if_dl.h>
#endif /* AF_LINK */

#include "route.h"
#include "sockunion.h"
#include "memory.h"

/* Maskbit. */
static u_char maskbit[] = 
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* Allocate new prefix structure. */
struct prefix_in *
prefix_in_new ()
{
  struct prefix_in *pin;

  pin = XMALLOC (MTYPE_PREFIX_IN, sizeof (struct prefix_in));
  bzero (pin, sizeof (struct prefix_in));
  return pin;
}

/* Free prefix strucutre. */
void
prefix_in_free (struct prefix_in *pin)
{
  XFREE (MTYPE_PREFIX_IN, pin);
}

/* Duplicate prefix structure.  Used in zebra.c. */
struct prefix_in *
prefix_in_dup (struct prefix_in *pin)
{
  struct prefix_in *new;

  new = XMALLOC (MTYPE_PREFIX_IN, sizeof (struct prefix_in));
  memcpy (new, pin, sizeof (struct prefix_in));
  return new;
}

/* If string format if invalid return 0. */
int
str2prefix_in (char *str, struct prefix_in *pin)
{
  int ret;
  char *p;
  char *cp;

  /* Find slash inside string. */
  p = strchr (str, '/');

  /* String doesn't contail slash. */
  if (p == NULL)
    return 0;

  cp = XMALLOC (0, (p - str) + 1);
  strncpy (cp, str, p - str);
  *(cp + (p - str)) = '\0';
  ret = inet_aton (cp, &pin->prefix);
  free (cp);

  pin->mask = (char) atoi (++p);
  pin->prefixlen = pin->mask;

  return ret;
}

/* Convert masklen into IP address's netmask. */
void
masklen2ip (int masklen, struct in_addr *netmask)
{
  unsigned char *pnt;
  int bit;
  int offset;

  bzero (netmask, sizeof (struct in_addr));
  pnt = (unsigned char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;
  
  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}

/* Convert IP address's netmask into integer. We assume netmask is
   sequential one. Argument netmask should be network byte order. */
u_char
ip_masklen (struct in_addr netmask)
{
  u_char len;
  u_char *pnt;
  u_char *end;
  u_char val;

  len = 0;
  pnt = (u_char *) &netmask;
  end = pnt + 4;

  while ((*pnt == 0xff) && pnt < end)
    {
      len+= 8;
      pnt++;
    } 

  if (pnt < end)
    {
      val = *pnt;
      while (val)
	{
	  len++;
	  val <<= 1;
	}
    }

  return len;
}

/* Sockunion to mask length conversion. */
int
sockunion_masklen (union sockunion *su)
{
  switch (su->sa.sa_family)
    {
    case AF_INET:
      return ip_masklen (su->sin.sin_addr);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      return ip6_masklen (su->sin6.sin6_addr);
      break;      
#endif /* HAVE_IPV6 */
    }
  return 0;
}

/* If two routes have same prefix then return 1 else return 0. */
int
rt_ip_sameprefix (struct prefix *rt1, struct prefix *rt2)
{
  int ret;
  struct prefix_in *rin1;
  struct prefix_in *rin2;

  rin1 = (struct prefix_in *) rt1;
  rin2 = (struct prefix_in *) rt2;
  ret = memcmp (&rin1->prefix, &rin2->prefix, sizeof (struct in_addr));
  if (ret == 0)
    return 1;
  else
    return 0;
}

/* Utility function of convert between struct prefix <=> union sockunion */
struct prefix *
sockunion2prefix (union sockunion *dest,
		  union sockunion *mask)
{
  if (dest->sa.sa_family == AF_INET)
    {
      struct prefix_in *pin;

      pin = prefix_in_new ();
      pin->prefix = dest->sin.sin_addr;
      pin->mask = ip_masklen (mask->sin.sin_addr);
      return (struct prefix *) pin;
    }
#ifdef HAVE_IPV6
  if (dest->sa.sa_family == AF_INET6)
    {
      struct prefix_in6 *pin6;

      pin6 = prefix_in6_new ();
      pin6->mask = ip6_masklen (mask->sin6.sin6_addr);
      memcpy (&pin6->prefix, &dest->sin6.sin6_addr, sizeof (struct in6_addr));
      return (struct prefix *) pin6;
    }
#endif /* HAVE_IPV6 */
  return NULL;
}

/* Apply mask to IPv4 prefix. */
void
apply_mask (struct prefix_in *pin)
{
  u_char *rp;
  int index;
  int offset;

  index = pin->mask / 8;

  if (index < 4)
    {
      rp = (u_char *) &pin->prefix;
      offset = pin->mask % 8;

      rp[index] &= maskbit[offset];
      index++;

      while (index < 4)
	rp[index++] = 0;
    }
}

/* Temporary dump routine. */
void
dump_route (struct prefix *rt)
{
  struct prefix_in *rin;

  rin = (struct prefix_in *)rt;
  printf ("DEBUG %s/%d\n", inet_ntoa (rin->prefix), rin->mask);
  fflush (stdout);
}

#ifdef HAVE_IPV6

/* IPv6 prefix_in6 functions. */

/* Allocate prefix for IPv4. */
struct prefix_in6 *
prefix_in6_dup (struct prefix_in6 *pin6)
{
  struct prefix_in6 *new;

  new = XMALLOC (MTYPE_PREFIX_IN6, sizeof (struct prefix_in6));
  bzero (new, sizeof (struct prefix_in6));

  memcpy (new, pin6, sizeof (struct prefix_in6));

  return new;
}

/* Allocate a new ip version 6 route */
struct prefix_in6 *
prefix_in6_new ()
{
  struct prefix_in6 *pin6;

  pin6 = XMALLOC (MTYPE_PREFIX_IN6, sizeof (struct prefix_in6));
  bzero (pin6, sizeof (struct prefix_in6));
  return pin6;
}

/* Free prefix for IPv6. */
void
prefix_in6_free (struct prefix_in6 *pin6)
{
  XFREE (MTYPE_PREFIX_IN6, pin6);
}

int
rt_ipv6_sameprefix (struct prefix *rt1, struct prefix *rt2)
{
  int ret;
  struct prefix_in6 *rin1;
  struct prefix_in6 *rin2;

  rin1 = (struct prefix_in6 *) rt1;
  rin2 = (struct prefix_in6 *) rt2;
  
  ret = memcmp (&rin1->prefix, &rin2->prefix, sizeof (struct in6_addr));
  if (ret == 0)
    return 1;
  else
    return 0;
}

void
dump_route_in6 (struct prefix *rt)
{
  struct prefix_in6 *rin;
  char buf[INET6_ADDRSTRLEN];
  
  rin = (struct prefix_in6 *)rt;
  printf ("inet6 %s/%d\n", 
	  inet_ntop (AF_INET6, &rt->prefix, buf, INET6_ADDRSTRLEN), rt->mask);
  fflush (stdout);
}

struct prefix *
str2routev6 (char *str)
{
  char *cp;
  char *p = strchr(str, '/');
  struct prefix_in6 *new = prefix_in6_new ();
  bzero (new, sizeof (struct prefix_in6));

  if (p == NULL) 
    {
      new->mask = IPV6_MAX_BITLEN;
      inet_pton (AF_INET6, str, &new->prefix);
    }
  else 
    {
      int ret;

      cp = XMALLOC (0, (p - str) + 1);
      strncpy (cp, str, p - str);
      *(cp + (p - str)) = '\0';
      ret = inet_pton (AF_INET6, cp, &new->prefix);
      free (cp);
      if (ret < 0)
	{
	  prefix_in6_free (new);
	  return NULL;
	}
      new->mask = (char) atoi (++p);
    }
  return (struct prefix *) new;
}

/* If given string is valid return pin6 else return NULL */
struct prefix_in6 *
str2prefix_in6 (char *str, struct prefix_in6 *pin6)
{
  char *p;
  char *cp;
  int ret;

  p = strchr (str, '/');

  if (p == NULL) 
    {
      pin6->mask = IPV6_MAX_BITLEN;
      ret = inet_pton (AF_INET6, str, &pin6->prefix);
      if (ret < 0)
	return NULL;
    }
  else 
    {
      cp = XMALLOC (0, (p - str) + 1);
      strncpy (cp, str, p - str);
      *(cp + (p - str)) = '\0';
      ret = inet_pton (AF_INET6, cp, &pin6->prefix);
      free (cp);
      if (ret < 0)
	return NULL;
      pin6->mask = (u_char) atoi (++p);
    }
  return pin6;
}

/* Convert struct in6_addr netmask into integer. */
int
ip6_masklen (struct in6_addr netmask)
{
  int len = 0;
  unsigned char val;
  unsigned char *pnt;
  
  pnt = (unsigned char *) & netmask;

  while ((*pnt == 0xff) && len < 128) 
    {
      len += 8;
      pnt++;
    } 
  
  if (len < 128) 
    {
      val = *pnt;
      while (val) 
	{
	  len++;
	  val <<= 1;
	}
    }
  return len;
}

void
masklen2ip6 (int masklen, struct in6_addr *netmask)
{
  unsigned char *pnt;
  int bit;
  int offset;

  bzero (netmask, sizeof (struct in6_addr));
  pnt = (unsigned char *) netmask;

  offset = masklen / 8;
  bit = masklen % 8;

  while (offset--)
    *pnt++ = 0xff;

  if (bit)
    *pnt = maskbit[bit];
}
#endif /* HAVE_IPV6 */
