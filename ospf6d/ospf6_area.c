/*
 * OSPF6 Area Data Structure
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

static struct area *
area_new ()
{
  struct area *new;
  new = (struct area *) XMALLOC (MTYPE_OSPF6_AREA,
                                 sizeof (struct area));
  if (new)
    memset (new, 0, sizeof (struct area));

  return new;
}

static void
area_free (struct area *area)
{
  XFREE (MTYPE_OSPF6_AREA, area);
}

/* Make new area structure */
static struct area *
make_area (unsigned long area_id)
{
  struct area *area;
  char area_id_str[16];

  /* make area id strings for log */
  inet_ntop (AF_INET, &area_id, area_id_str, sizeof (area_id_str));

  area = area_new ();
  if (!area)
    {
      zlog (NULL, LOG_WARNING, "can't malloc area %s", area_id_str);
      return area;
    }

  /* set area id */
  area->area_id = area_id;

  /* set area id string for log */
  inet_ntop (AF_INET, &area_id, area->str, sizeof (area->str));

  /* ospf6 interface list */
  area->ospf6_if_list = list_init ();

  /* RouterLSA initial seqnum */
  area->router_lsa_seqnum = INITIAL_SEQUENCE_NUMBER;

  /* Initialize LSDB */
  ospf6_lsdb_init_area (area);

  /* new route table init */
  area->table = ospf6_route_table_init ();

  assert (ospf6->version == OSPF_V3);

  /* xxx, set options */
  V3OPT_SET (area->options, V3OPT_V6);
  V3OPT_SET (area->options, V3OPT_E);
  V3OPT_SET (area->options, V3OPT_R);

  /* add area list */
  list_add_node (ospf6->area_list, area);

  /* set back pointer */
  area->ospf6 = ospf6;

  return area;
}

static void
delete_area (struct area *area)
{
  listnode n;
  struct ospf6_if *o6if;

  /* ospf6 interface list */
  for (n = listhead (area->ospf6_if_list); n; nextnode (n))
    {
      o6if = (struct ospf6_if *) getdata (n);
      /* xxx */
    }
  list_delete_all (area->ospf6_if_list);

  /* terminate LSDB */
  ospf6_lsdb_finish_area (area);

  /* spf tree terminate */
  /* xxx */

  /* threads */
  if (area->spf_calc)
    thread_cancel (area->spf_calc);
  area->spf_calc = (struct thread *) NULL;
  if (area->route_calc)
    thread_cancel (area->route_calc);
  area->route_calc = (struct thread *) NULL;

  /* route table terminate */
  ospf6_route_table_finish (area->table);

  /* free area */
  area_free (area);
}

struct area *
ospf6_area_lookup (unsigned long area_id)
{
  struct area *area;
  listnode n;

  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *)getdata (n);
      if (area->area_id == area_id)
        return area;
    }
  return (struct area *)NULL;
}

struct area *
ospf6_area_init (unsigned long area_id)
{
  struct area *area;

  area = ospf6_area_lookup (area_id);
  if (!area)
    area = make_area (area_id);
  return area;
}

void
ospf6_area_terminate (struct area *area)
{
  delete_area (area);
}

