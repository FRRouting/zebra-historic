/* Community attribute related functions.
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

/* Community attribute. */
struct community 
{
  unsigned long refcnt;
  int size;
  u_int32_t *val;
};

/* Community pre-defined values definition. */
#define COMMUNITY_NO_EXPORT             0xFFFFFF01
#define COMMUNITY_NO_ADVERTIZE          0xFFFFFF02
#define COMMUNITY_NO_EXPORT_SUBCONFED   0xFFFFFF03

/* Macros of community attribute. */
#define com_length(X)    ((X)->size * 4)
#define com_lastval(X)   (*((X)->val + (X)->size - 1))
#define com_nthval(X,n)  (*((X)->val + (n)))

/* Prototypes of community attribute functions. */
void community_init ();
struct community *community_parse (char *, u_short);
void community_free (struct community *);
void community_print (FILE *, struct community *);
void community_print_vty (struct vty *, struct community *);
void community_print_all_vty (struct vty *);
