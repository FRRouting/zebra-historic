/* OSPF routing table.
   Copyright (C) 1999 Toshiaki Takada

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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "linklist.h"
#include "log.h"
#include "command.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_zebra.h"

struct ospf_route *
ospf_route_new ()
{
  struct ospf_route *new;

  new = XMALLOC (MTYPE_OSPF_ROUTE, sizeof (struct ospf_route));
  memset (new, 0, sizeof (struct ospf_route));
  return new;
}

void
ospf_route_free (struct ospf_route *or)
{
  XFREE (MTYPE_OSPF_ROUTE, or);
}

struct ospf_path *
ospf_path_new ()
{
  struct ospf_path *new;

  new = XMALLOC (MTYPE_OSPF_PATH, sizeof (struct ospf_path));
  memset (new, 0, sizeof (struct ospf_path));
  return new;
}

void
ospf_path_free (struct ospf_path *op)
{
  XFREE (MTYPE_OSPF_PATH, op);
}

void
ospf_delete_route (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct ospf_path *path;
  listnode pnode;

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      if (or->type == OSPF_DESTINATION_NETWORK)
	for (pnode = listhead (or->path); pnode; nextnode (pnode))
	  {
	    path = getdata (pnode);
	      
	    if (path->nexthop.s_addr != INADDR_ANY)
	      ospf_zebra_delete ((struct prefix_ipv4 *)&rn->p,
				 &path->nexthop);
	  }
}

void
ospf_route_table_free (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  listnode pnode;

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
	if (or->path && listcount (or->path) > 0)
	  for (pnode = listhead (or->path); pnode; nextnode (pnode))
	    ospf_path_free (pnode->data);

	ospf_route_free (or);

	rn->info = NULL;
	route_unlock_node (rn);
      }
}

void
ospf_install_route (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct ospf_path *path;
  listnode pnode;

  if (ospf_top->old_table)
    {
      ospf_delete_route (ospf_top->old_table);
      ospf_route_table_free (ospf_top->old_table);
    }

  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      if (or->type == OSPF_DESTINATION_NETWORK)
	for (pnode = listhead (or->path); pnode; nextnode (pnode))
	  {
	    path = getdata (pnode);

	    if (path->nexthop.s_addr != INADDR_ANY)
	      ospf_zebra_add ((struct prefix_ipv4 *)&rn->p, &path->nexthop);
	  }

  ospf_top->old_table = ospf_top->new_table;
  ospf_top->new_table = rt;
}

void
ospf_intra_route_add (struct route_table *rt, struct vertex *v,
		      struct ospf_area *area)
{
  struct route_node *rn;
  struct ospf_route *or;
  struct prefix_ipv4 p;
  struct ospf_path *path;
  struct ospf_nexthop *nexthop;
  listnode nnode;

  p.family = AF_INET;
  p.prefix = v->id;
  if (v->type == OSPF_VERTEX_ROUTER)
    p.prefixlen = IPV4_MAX_BITLEN;
  else
    {
      struct network_lsa *lsa = (struct network_lsa *) v->lsa;
      p.prefixlen = ip_masklen (lsa->mask);
    }
  apply_mask_ipv4 (&p);

  rn = route_node_get (rt, (struct prefix *) &p);
  if (rn->info)
    {
      zlog_warn ("Same routing information exists for %s", inet_ntoa (v->id));
      route_unlock_node (rn);
      return;
    }

  or = ospf_route_new ();

  if (v->type == OSPF_VERTEX_NETWORK)
    {
      or->type = OSPF_DESTINATION_NETWORK;
      or->path = list_init ();

      for (nnode = listhead (v->nexthop); nnode; nextnode (nnode))
	{
	  nexthop = getdata (nnode);
	  path = ospf_path_new();
	  path->nexthop = nexthop->router;
	  list_add_node (or->path, path);
	}
    }
  else
    or->type = OSPF_DESTINATION_ROUTER;

  or->id = v->id;
  or->area = area;
  or->path_type = OSPF_PATH_INTRA_AREA;
  or->cost = v->distance;

  rn->info = or;
}

char *ospf_path_type_str[] =
{
  "unknown-type",
  "intra-area",
  "inter-area",
  "type1-external",
  "type2-external"
};

void
ospf_route_table_dump (struct route_table *rt)
{
  struct route_node *rn;
  struct ospf_route *or;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  listnode pnode;
  struct ospf_path *path;

#if 0
  zlog_info ("Type   Dest   Area   Path	 Type	 Cost	Next	 Adv.");
  zlog_info ("					Hop(s)	 Router(s)");
#endif /* 0 */

  zlog_info ("========== OSPF routing table ==========");
  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
        if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    zlog_info ("N %s/%d\t%s\t%s\t%d", 
		       inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		       rn->p.prefixlen,
		       inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		       ospf_path_type_str[or->path_type],
		       or->cost);
	    for (pnode = listhead (or->path); pnode; nextnode (pnode))
	      {
		path = getdata (pnode);
		zlog_info ("  -> %s", inet_ntoa (path->nexthop));
	      }
	  }
        else
	  zlog_info ("R %s\t%s\t%s\t%d", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     ospf_path_type_str[or->path_type],
		     or->cost);
      }
  zlog_info ("========================================");
}

void
ospf_terminate ()
{
  struct route_table *rt;

  if (ospf_top)
    {
      rt = ospf_top->new_table;

      if (rt)
	ospf_delete_route (rt);
    }
}

DEFUN (show_ip_ospf_route,
       show_ip_ospf_route_cmd,
       "show ip ospf route",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "OSPF routing table\n")
{
  struct route_table *rt;
  struct route_node *rn;
  struct ospf_route *or;
  char buf1[BUFSIZ];
  char buf2[BUFSIZ];
  listnode pnode;
  struct ospf_path *path;

  rt = ospf_top->new_table;

  if (rt == NULL)
    {
      vty_out (vty, "No OSPF routing information exist\r\n");
      return CMD_SUCCESS;
    }

  vty_out (vty, "========== OSPF routing table ==========\r\n");
  for (rn = route_top (rt); rn; rn = route_next (rn))
    if ((or = rn->info) != NULL)
      {
        if (or->type == OSPF_DESTINATION_NETWORK)
	  {
	    vty_out (vty, "N %s/%d\t%s\t%s\t%d\r\n", 
		     inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		     rn->p.prefixlen,
		     inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		     ospf_path_type_str[or->path_type],
		     or->cost);
	    for (pnode = listhead (or->path); pnode; nextnode (pnode))
	      {
		path = getdata (pnode);
		vty_out (vty, "  -> %s\r\n", inet_ntoa (path->nexthop));
	      }
	  }
        else
	  vty_out (vty, "R %s\t%s\t%s\t%d\r\n", 
		   inet_ntop (AF_INET, &rn->p.u.prefix4, buf1, BUFSIZ),
		   inet_ntop (AF_INET, &or->area->area_id, buf2, BUFSIZ),
		   ospf_path_type_str[or->path_type],
		   or->cost);
      }
  return CMD_SUCCESS;
}

void
ospf_route_init ()
{
  install_element (VIEW_NODE, &show_ip_ospf_route_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_route_cmd);
}
