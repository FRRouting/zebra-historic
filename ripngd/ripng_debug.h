/* RIPng debug output routines
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

/* Debug sort enumeration. */
enum
{
  /* Debug option sort. */
  DEBUG_EVENT  = 0x01,
  DEBUG_PACKET = 0x02,
  DEBUG_ACTION = 0x04,
  DEBUG_ZEBRA   = 0x08,
};

#if 0
enum
{
  /* Debug direction. */
  DEBUG_BOTH   = 0x01,
  DEBUG_IN     = 0x02,
  DEBUG_OUT    = 0x04,

  /* Debug detail. */
  DEBUG_NORMAL = 0x01,
  DEBUG_DETAIL = 0x02,
};
#endif /* 0 */

int debug (unsigned int option);
void ripng_debug_init ();
