/* OSPF calculation.
   Copyright (C) 1999 Kunihiro Ishiguro

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

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "memory.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"

struct vertex *
ospf_vertex_new ()
{
  struct vertex *new;

  new = XMALLOC (MTYPE_OSPF_VERTEX, sizeof (struct vertex));
  memset (new, 0, sizeof (struct vertex));
  return new;
}

void
ospf_vertex_free (struct vertex *v)
{
  XFREE (MTYPE_OSPF_VERTEX, v);
}

void
ospf_spf_free ()
{
  ;
}

struct vertex *
ospf_spf_lookup_top ()
{
  return NULL;
}

void
ospf_spf_make ()
{
  struct vertex *v;

  /* Free spf tree. */
  ospf_spf_free ();

  v = ospf_spf_lookup_top ();
}
