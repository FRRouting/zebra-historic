/*
 * OSPFv3 Top Level Data Structure
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospf6d.h"

void
ospf6_vty (struct vty *vty)
{
  listnode n;
  struct area *area;
  vty_out (vty, "\tVersion: %d\tRouter-ID: %s%s",
	   ospf6->version, 
	   inet4str (ospf6->router_id),
	   VTY_NEWLINE);
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);
      ospf6_area_vty (vty, area);
    }
}

static struct ospf6 *
ospf6_new ()
{
  struct ospf6 *new;
  new = XMALLOC (MTYPE_OSPF6_TOP, sizeof (struct ospf6));
  if (new)
    memset (new, 0, sizeof (struct ospf6));
  return new;
}

static void
ospf6_free (struct ospf6 *ospf6)
{
  XFREE (MTYPE_OSPF6_TOP, ospf6);
}

static struct ospf6 *
ospf6_make (void)
{
  struct ospf6 *ospf6;

  /* allocate memory to global pointer */
  ospf6 = ospf6_new ();

  /* initialize */
  ospf6->version = OSPF_V3;
  ospf6->ase_ls_id = 0;
  ospf6->area_list = list_init ();
  ospf6_lsdb_init_as (ospf6);

  /* route table init */
  ospf6->table = ospf6_route_table_init ();
  ospf6->table_zebra = ospf6_route_table_init ();
  ospf6->table_connected = ospf6_route_table_init ();
  ospf6->table_external = ospf6_route_table_init ();

  /* default redistribute */
  ospf6->redist_connected = 1;

  return ospf6;
}

static void
ospf6_delete (struct ospf6 *ospf6)
{
  listnode n;
  struct area *area;

  /* shutdown areas */
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);
      ospf6_area_terminate (area);
    }
  list_delete_all (ospf6->area_list);

  /* finish AS scope link state database */
  ospf6_lsdb_finish_as (ospf6);

  /* finish route tables */
  ospf6_route_table_finish (ospf6->table);
  ospf6_route_table_finish (ospf6->table_zebra);
  ospf6_route_table_finish (ospf6->table_connected);
  ospf6_route_table_finish (ospf6->table_external);

  ospf6_free (ospf6);
}

void
ospf6_start ()
{
  if (ospf6)
    {
      zlog (NULL, LOG_INFO, "ospf6 already started");
      return;
    }

  /* make ospf6 top data structure */
  ospf6 = ospf6_make ();
}

void
ospf6_stop ()
{
  if (!ospf6)
    {
      zlog (NULL, LOG_INFO, "ospf6 already stopped");
      return;
    }

  /* delete ospf6 top data structure */
  ospf6_delete (ospf6);
  ospf6 = (struct ospf6 *) NULL;
}

