/* As path related definitions.
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

/* We use radix's RPSL aspath regexp. */
#define RADIX_REGEXP

/* AS path segment type. */
#define AS_SET             1
#define AS_SEQUENCE        2
#define AS_CONFED_SET      3
#define AS_CONFED_SEQUENCE 4

#ifdef SUNOS_5
#ifndef _BGPD_SUNOS_H
#define _BGPD_SUNOS_H
typedef unsigned int u_int32_t; 
typedef unsigned short u_int16_t; 
#endif /* _BGPD_SUNOS_H */
#endif /* SUNOS_5 */

/* AS path may be include some AsSegments. */
struct aspath 
{
  /* Reference count to this aspath. */
  unsigned long refcnt;

  /* Rawdata length */
  int length;

  /* Rawdata */
  caddr_t data;

#ifdef RADIX_REGEXP
  int hop_count;

  u_int16_t *pasn;
#endif /* RADIX_REGEXP*/
};

/* Prototypes. */
struct aspath *aspath_parse ();
struct aspath *aspath_val2as (u_short);
void aspath_free (struct aspath *);
void aspath_log (FILE *, struct aspath *);

#ifdef RADIX_REGEXP
typedef struct aspath ASPATH;
typedef struct aspath_regex_t ASPATH_regex;

ASPATH_regex *aspath_regex_comp(const char *pat);
#endif /* RADIX_REGEXP */
