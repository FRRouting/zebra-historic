/* Prefix structure.
   Copyright (C) 1998 Kunihiro Ishiguro

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

/* Generic structure for prefix. */
struct prefix
{
  /* Linked list pointer. */
  struct prefix *next;

  /* Type of this prefix. */
  u_char type;

  /* Tags of this route. */
  u_char fib;

  /* Network mask length. */
  u_char mask;

  /* Prefix of this route. */
  struct in_addr prefix;
};

/* This experimental structure. */
struct prefix_in
{
  /* For radix tree. */
  struct prefix_in  *next;

  /* Type of this prefix */
  u_char type;

  /* Tags of this route. */
  u_char fib;

  /* Network mask length of this prefix */
  u_char mask;

  /* Network mask length of this prefix */
  u_char prefixlen;

  /* Prefix of this route. */
  struct in_addr prefix;

  /* Gateway of this route. */
  union
  {
    struct in_addr addr;
    void *info;
  } gate;
};

/* IP version 6 type struct route. */
#ifdef HAVE_IPV6
struct prefix_in6
{
  /* Linked list pointer. */
  struct prefix_in6 *next;

  /* Type of this prefix. */
  u_char type;

  /* Tags of this route. */
  u_char fib;

  /* Network mask length. */
  u_char mask;

  /* Prefix of this route. */
  struct in6_addr prefix;

  /* Destination of this route */
  union
  {
    struct in6_addr addr;
    void *info;
  } gate;
};
#endif /* HAVE_IPV6 */

struct prefix_union
{
  u_char family;
  union 
  {
    struct prefix_in pin;
#ifdef HAVE_IPV6
    struct prefix_in6 pin6;
#endif /* HAVE_IPV6 */
  } u;
};

/* Max bit length of each ip address. */
#define IPV4_MAX_BITLEN  32
#define IPV6_MAX_BITLEN 128

/* Prototypes. */
struct prefix_in *prefix_in_new ();
void prefix_in_free ();
/* struct prefix *str2prefix (char *); */
int rt_ip_sameprefix (struct prefix *, struct prefix *);
int rt_ip_samecontents (struct prefix *, struct prefix *);
struct prefix_in *rt_in_new ();
struct prefix *sockunion2prefix ();
int str2prefix_in (char *, struct prefix_in *);

#ifdef HAVE_IPV6
struct prefix_in6 *prefix_in6_new ();
struct prefix *str2routev6 (char *);
int rt_ipv6_sameprefix (struct prefix *, struct prefix *);
int rt_ipv6_samecontents (struct prefix *, struct prefix *);
#endif /* HAVE_IPV6 */
