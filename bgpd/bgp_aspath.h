/*
 * AS path related definitions.
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

#ifndef _ZEBRA_BGP_ASPATH_H
#define _ZEBRA_BGP_ASPATH_H

/* We use radix's RPSL aspath regexp. */
#define RADIX_REGEXP

/* AS path segment type. */
#define AS_SET             1
#define AS_SEQUENCE        2
#define AS_CONFED_SET      3
#define AS_CONFED_SEQUENCE 4

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
void aspath_init ();
struct aspath *aspath_parse ();
struct aspath *aspath_dup (struct aspath *);
void aspath_undup (struct aspath *);
struct aspath *aspath_add_left (struct aspath *, as_t);
struct aspath *aspath_empty_aspath ();
struct aspath *aspath_val2as (u_short);
void aspath_free (struct aspath *);
const char *aspath_print (struct aspath *);
void aspath_print_vty (struct vty *, struct aspath *);
void aspath_print_all_vty (struct vty *);
unsigned int aspath_key_make (struct aspath *);
int aspath_loop_check (struct aspath *, as_t);

#ifdef RADIX_REGEXP
typedef struct aspath ASPATH;
typedef struct aspath_regex_t ASPATH_regex;

void aspath_regex_free(ASPATH_regex *regex);
int aspath_regex_exec(const ASPATH_regex *rp, const ASPATH *info);
ASPATH_regex *aspath_regex_comp(const char *pat);
const char *aspath_regex_string(const ASPATH_regex *regex);
#endif /* RADIX_REGEXP */

#endif /* _ZEBRA_BGP_ASPATH_H */
