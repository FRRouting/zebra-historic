/* radix header
   Copyright (C) 1996, 97 Kunihiro Ishiguro

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

/* Top structure which include radix tree. */
struct radix_top 
{
  /* Top of radix tree. */
  struct radix *top;

  /* Sameprefix check fucntion. */
  int (*sameprefix) (struct prefix *, struct prefix *);

  /* Same contents check fucntion. */
  int (*samecontents) (struct prefix *, struct prefix *);
};

/* I assume network mask is sequencial. */
struct radix 
{
  struct radix *parent;
  struct radix *left;
  struct radix *right;

  /* Bit posision to be tested. */
  int bit;

  /* For node. */
  struct mask *mlist;
  int offset;
  int mask;

  /* For leaf. */
  struct prefix *rt;
};

/* For mask. */
struct mask 
{
  u_char masklen;
  int refcnt;
  struct mask *next;
};

#define PREFIX(X) ((unsigned char *) & ((X)->prefix))

/* For rt_add/rt_delete return value */
#define RADIX_RT_SUCCESS  0
#define RADIX_RT_REPLACE  1
#define RADIX_RT_NOTFOUND 2

/* Prototypes */
struct radix_top *radix_make_rib (int);
int radix_lookup_rt (struct radix_top *, struct prefix *);
struct prefix *radix_search_rt (struct radix_top *, struct prefix *);
struct prefix_in *radix_lookup_fn (struct radix_top *, struct prefix_in *, int (*)(struct prefix_in *, struct prefix_in *));
struct prefix *radix_delete (struct radix_top *, struct prefix *);
