/*
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

/* global ospf6d variable */
int  ospf6_sock;
struct ospf6 *ospf6;
list iflist;
list nexthoplist = NULL;
struct sockaddr_in6 allspfrouters6;
struct sockaddr_in6 alldrouters6;
char *recent_reason; /* set by ospf6_lsa_check_recent () */


/* Neighbor section */
/* Allocate new Neighbor data structure */
static struct neighbor *
neighbor_new ()
{
  struct neighbor *new = (struct neighbor *)
      XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct neighbor));
  if (new)
    memset (new, 0, sizeof (struct neighbor));
  else
    zvlog_warn ("Can't malloc neighbor");
  return new;
}



/* Make new neighbor structure */
struct neighbor *
make_neighbor (rtr_id_t rtr_id, struct ospf6_if *ospf6_if)
{
  struct neighbor *nbr = neighbor_new ();

  if (!nbr)
    return (struct neighbor *)NULL;
  nbr->state = NBS_DOWN;
  nbr->ospf6_if = ospf6_if;
  nbr->rtr_id = rtr_id;
  inet_ntop (AF_INET, &rtr_id, nbr->str, sizeof (nbr->str));
  nbr->inactivity_timer = (struct thread *)NULL;
  nbr->dd_retrans = list_init ();
  nbr->summarylist = list_init ();
  nbr->retranslist = list_init ();
  nbr->requestlist = list_init ();
  nbr->direct_ack = list_init ();
  list_add_node (ospf6_if->nbr_list, nbr);

  return nbr;
}

/* delete neighbor from ospf6_if nbr_list */
void
delete_neighbor (struct neighbor *nbr, struct ospf6_if *ospf6_if)
{
  /* xxx not yet */
  return;
}

/* delete all neighbor on ospf6_if nbr_list */
void
delete_all_neighbors (struct ospf6_if *ospf6_if)
{
  /* xxx not yet */
  return;
}



/* Lookup functions. */
/* lookup neighbor from OSPF6 interface.
   because neighbor may appear on two different OSPF interface */
struct neighbor *
nbr_lookup (rtr_id_t rtr_id, struct ospf6_if *o6if)
{
  struct neighbor *nbr;
  listnode k;

  for (k = listhead (o6if->nbr_list); k; nextnode (k))
    {
      nbr = (struct neighbor *)getdata (k);
      if (nbr->rtr_id == rtr_id)
        return nbr;
    }

  return (struct neighbor *)NULL;
}


/* show specified area structure */
int
show_area (struct vty *vty, struct area *area)
{
  listnode i;
  struct ospf6_if *ospf6_if;

  vty_out (vty, "   Area %s\r\n",
           inet4str (area->area_id));
  vty_out (vty, "      Interface attached to this area:");
  for (i = listhead (area->ospf6_if_list); i; nextnode (i))
    {
      ospf6_if = (struct ospf6_if *)getdata (i);
      vty_out (vty, " %s", ospf6_if->interface->name);
    }
  vty_out (vty, "\r\n");

  return 0;
}

/* show neighbor structure */
int
show_nbr (struct vty *vty, struct neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

#if 0
  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]\r\n",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State");
#endif

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]\r\n",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_if->interface->name,
           ifs_name[nbr->ospf6_if->state]);
  return 0;
}



/* vty commands */
DEFUN (show_ipv6_ospf6_neighbor_ifname_nbrid,
       show_ipv6_ospf6_neighbor_ifname_nbrid_cmd,
       "show ipv6 ospf6 neighbor IFNAME NEIGHBOR_ID",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       "A.B.C.D OSPF6 neighbor Router ID in IP address format\n"
       )
{
  rtr_id_t rtr_id;
  struct interface *ifp;
  struct neighbor *nbr;
  struct ospf6_if *ospf6_if;
  struct area *area;
  listnode i, j, k;

  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]\r\n",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State");

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (!ifp)
        return CMD_ERR_NO_MATCH;

      ospf6_if = (struct ospf6_if *) ifp->info;
      if (!ospf6_if)
        return CMD_ERR_NO_MATCH;

      if (argc > 1)
        {
          inet_pton (AF_INET, argv[1], &rtr_id);
          nbr = nbr_lookup (rtr_id, ospf6_if);
          if (!nbr)
            return CMD_ERR_NO_MATCH;
          show_nbr (vty, nbr);
          return CMD_SUCCESS;
        }

      for (i = listhead (ospf6_if->nbr_list); i; nextnode (i))
        {
          nbr = (struct neighbor *) getdata (i);
          show_nbr (vty, nbr);
        }
      return CMD_SUCCESS;
    }

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      area = (struct area *)getdata (i);
      for (j = listhead (area->ospf6_if_list); j; nextnode (j))
        {
          ospf6_if = (struct ospf6_if *)getdata (j);
          for (k = listhead (ospf6_if->nbr_list); k; nextnode (k))
            {
              nbr = (struct neighbor *)getdata (k);
              show_nbr (vty, nbr);
            }
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_neighbor_ifname_nbrid,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       )

ALIAS (show_ipv6_ospf6_neighbor_ifname_nbrid,
       show_ipv6_ospf6_neighbor_ifname_cmd,
       "show ipv6 ospf6 neighbor IFNAME",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       )

/* start ospf6 */
DEFUN (router_ospf6,
       router_ospf6_cmd,
       "router ospf6",
       OSPF6_ROUTER_STR
       OSPF6_STR
       )
{
  if (ospf6)
    {
      vty_out (vty, "ospf6 already started.\r\n");
    }
  else
    ospf6_start ();

  /* set current ospf point. */
  vty->node = OSPF6_NODE;
  vty->index = ospf6;

  return CMD_SUCCESS;
}

/* stop ospf6 */
DEFUN (no_router_ospf6,
       no_router_ospf6_cmd,
       "no router ospf6",
       NO_STR
       OSPF6_ROUTER_STR
       )
{
  if (!ospf6)
    {
      vty_out (vty, "ospf6 already stopped.\r\n");
    }
  else
    ospf6_stop ();

  /* return to config node . */
  vty->node = CONFIG_NODE;
  vty->index = NULL;

  return CMD_SUCCESS;
}

/* show top level structures */
DEFUN (show_ipv6_ospf6,
       show_ipv6_ospf6_cmd,
       "show ipv6 ospf6",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       )
{
  if (!ospf6)
    vty_out (vty, "ospfv6 not started\r\n");
  else
    ospf6_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_requestlist,
       show_ipv6_ospf6_requestlist_cmd,
       "show ipv6 ospf6 request-list",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Link State request list\n"
       )
{
  struct area *area;
  struct ospf6_if *o6if;
  struct neighbor *nbr;
  listnode i, j, k, l;
  struct ospf6_lsa *lsa;
  char buf[256];

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      area = (struct area *) getdata (i);
      for (j = listhead (area->ospf6_if_list); j; nextnode (j))
        {
          o6if = (struct ospf6_if *) getdata (j);
          for (k = listhead (o6if->nbr_list); k; nextnode (k))
            {
              nbr = (struct neighbor *) getdata (k);
              vty_out (vty, "neighbor %s, interface %s\r\n", nbr->str,
                       nbr->ospf6_if->interface->name);
              for (l = listhead (nbr->requestlist); l; nextnode (l))
                {
                  lsa = (struct ospf6_lsa *) getdata (l);
                  ospf6_lsa_str (lsa, buf, sizeof (buf));
                  vty_out (vty, "  %s\r\n", buf);
                }
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_retranslist,
       show_ipv6_ospf6_retranslist_cmd,
       "show ipv6 ospf6 retransmission-list",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Link State retransmission list\n"
       )
{
  struct area *area;
  struct ospf6_if *o6if;
  struct neighbor *nbr;
  listnode i, j, k, l;
  struct ospf6_lsa *lsa;
  char buf[256];

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      area = (struct area *) getdata (i);
      for (j = listhead (area->ospf6_if_list); j; nextnode (j))
        {
          o6if = (struct ospf6_if *) getdata (j);
          for (k = listhead (o6if->nbr_list); k; nextnode (k))
            {
              nbr = (struct neighbor *) getdata (k);
              vty_out (vty, "neighbor %s, interface %s\r\n", nbr->str,
                       nbr->ospf6_if->interface->name);
              for (l = listhead (nbr->retranslist); l; nextnode (l))
                {
                  lsa = (struct ospf6_lsa *) getdata (l);
                  ospf6_lsa_str (lsa, buf, sizeof (buf));
                  vty_out (vty, "  %s\r\n", buf);
                }
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_nexthoplist,
       show_ipv6_ospf6_nexthoplist_cmd,
       "show ipv6 ospf6 nexthop-list",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "List of nexthop\n")
{
  listnode i;
  struct ospf6_nexthop *nh;
  char buf[128];
  for (i = listhead (nexthoplist); i; nextnode (i))
    {
      nh = (struct ospf6_nexthop *) getdata (i);
      nexthop_str (nh, buf, sizeof (buf));
      vty_out (vty, "%s\r\n", buf);
    }
  return CMD_SUCCESS;
}

/* show interface */
DEFUN (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_ifname_cmd,
       "show ipv6 ospf6 interface IFNAME",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       )
{
  struct interface *ifp;
  listnode i;

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (!ifp)
        {
          vty_out (vty, "No such Interface: %s\r\n", argv[0]);
          return CMD_WARNING;
        }
      show_if (vty, ifp);
    }
  else
    {
      for (i = listhead (iflist); i; nextnode (i))
        {
          ifp = (struct interface *)getdata (i);
          show_if (vty, ifp);
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_cmd,
       "show ipv6 ospf6 interface",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       )

DEFUN (show_ipv6_ospf6_database_router,
       show_ipv6_ospf6_database_router_cmd,
       "show ipv6 ospf6 database router",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s\r\n", inet4str (area->area_id));
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_ROUTER_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_network,
       show_ipv6_ospf6_database_network_cmd,
       "show ipv6 ospf6 database network",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Network-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s\r\n", inet4str (area->area_id));
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_NETWORK_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_link,
       show_ipv6_ospf6_database_link_cmd,
       "show ipv6 ospf6 database link",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Link-LSA\n"
       )
{
  listnode j, k, n;
  list l;
  struct area *area;
  struct ospf6_if *ospf6_if;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s\r\n", inet4str (area->area_id));
      for (k = listhead (area->ospf6_if_list); k; nextnode (k))
        {
          ospf6_if = (struct ospf6_if *) getdata (k);
          vty_out (vty, "Interface %s\r\n", ospf6_if->interface->name);
          l = list_init ();
          ospf6_lsdb_collect_type (l, htons (LST_LINK_LSA), ospf6_if);
          for (n = listhead (l); n; nextnode (n))
            {
              vty_lsa (vty, (struct ospf6_lsa *) getdata (n));
            }
          list_delete_all (l);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_intraprefix,
       show_ipv6_ospf6_database_intraprefix_cmd,
       "show ipv6 ospf6 database intra-area-prefix",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Intra-Area-Prefix-LSA\n"
       )
{
  listnode j, k;
  struct area *area;
  list l;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      vty_out (vty, "Area %s\r\n", inet4str (area->area_id));
      l = list_init ();
      ospf6_lsdb_collect_type (l, htons (LST_INTRA_AREA_PREFIX_LSA), area);
      for (k = listhead (l); k; nextnode (k))
        {
          vty_lsa (vty, (struct ospf6_lsa *) getdata (k));
        }
      list_delete_all (l);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_asexternal,
       show_ipv6_ospf6_database_asexternal_cmd,
       "show ipv6 ospf6 database as-external",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "AS-External-LSA\n"
       )
{
  listnode j;

  for (j = listhead (ospf6->lsdb); j; nextnode (j))
    {
      vty_lsa (vty, (struct ospf6_lsa *) getdata (j));
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       )
{
  show_ipv6_ospf6_database_router (&show_ipv6_ospf6_database_router_cmd,
                                   vty, 0, NULL);
  show_ipv6_ospf6_database_network (&show_ipv6_ospf6_database_network_cmd,
                                    vty, 0, NULL);
  show_ipv6_ospf6_database_link (&show_ipv6_ospf6_database_link_cmd,
                                 vty, 0, NULL);
  show_ipv6_ospf6_database_intraprefix (&show_ipv6_ospf6_database_intraprefix_cmd,
                                        vty, 0, NULL);
  show_ipv6_ospf6_database_asexternal (&show_ipv6_ospf6_database_asexternal_cmd,
                                        vty, 0, NULL);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_ospf6_area,
       show_ipv6_route_ospf6_area_cmd,
       "show ipv6 route ospf6 area A.B.C.D",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       "OSPF6 area ID\n"
       )
{
  struct area *area;
  area_id_t area_id;
  struct route_node *rn;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started\r\n");
      return CMD_WARNING;
    }

  if (argc)
    inet_pton (AF_INET, argv[0], &area_id);
  else
    area_id = 0;

  area = ospf6_area_lookup (area_id);
  if (!area)
    {
       vty_out (vty, "no match by area id: %s\r\n", argv[0]);
       return CMD_WARNING;
    }

  for (rn = route_top (area->table); rn; rn = route_next (rn))
    {
      if (rn->info)
        ospf6_route_vty (vty, rn);
    }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_route_ospf6_area,
       show_ipv6_route_ospf6_backbone_cmd,
       "show ipv6 route ospf6 area",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show route table in area structure\n"
       )

DEFUN (show_ipv6_route_ospf6,
       show_ipv6_route_ospf6_cmd,
       "show ipv6 route ospf6",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       )
{
  struct route_node *rn;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started\r\n");
      return CMD_WARNING;
    }

  for (rn = route_top (ospf6->table); rn; rn = route_next (rn))
    {
      if (rn->info)
        ospf6_route_vty (vty, rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_connected,
       show_ipv6_route_connected_cmd,
       "show ipv6 route connected",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       "connected route to advertise\n"
       )
{
  struct route_node *rn;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started\r\n");
      return CMD_WARNING;
    }

  for (rn = route_top (ospf6->table_connected); rn; rn = route_next (rn))
    {
      if (rn->info)
        ospf6_route_vty (vty, rn);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_redistribute,
       show_ipv6_route_redistribute_cmd,
       "show ipv6 route redistribute",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       "redistributed route\n"
       )
{
  struct route_node *rn;

  if (!ospf6)
    {
      vty_out (vty, "OSPF6 not started\r\n");
      return CMD_WARNING;
    }

  for (rn = route_top (ospf6->table_external); rn; rn = route_next (rn))
    {
      if (rn->info)
        ospf6_route_vty (vty, rn);
    }

  return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (router_id,
       router_id_cmd,
       "router-id ROUTER_ID",
       "Configure ospf Router-ID.\n"
       V4NOTATION_STR)
{
  int ret;
  rtr_id_t router_id;

  ret = inet_pton (AF_INET, argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "malformed ospf router identifier\r\n");
      vty_out (vty, "\r\n");
      return CMD_WARNING;
    }

  ospf6->router_id = router_id;

  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_static,
       ospf6_redistribute_static_cmd,
       "redistribute static",
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_static = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_static,
       no_ospf6_redistribute_static_cmd,
       "no redistribute static",
       NO_STR
       "Redistribute\n"
       "Static route\n")
{
  ospf6->redist_static = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_STATIC);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_connected,
       ospf6_redistribute_connected_cmd,
       "redistribute connected",
       "Redistribute\n"
       "Connected route\n")
{
  ospf6->redist_connected = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_connected,
       no_ospf6_redistribute_connected_cmd,
       "no redistribute connected",
       NO_STR
       "Redistribute\n"
       "Connected route\n")
{
  ospf6->redist_connected = 0;
  /* ospf6_route_external_withdraw (ZEBRA_ROUTE_CONNECT); */
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_CONNECT);
  return CMD_SUCCESS;
}

DEFUN (ospf6_redistribute_ripng,
       ospf6_redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_ripng = 1;
  ospf6_zebra_redistribute (ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (no_ospf6_redistribute_ripng,
       no_ospf6_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute\n"
       "RIPng route\n")
{
  ospf6->redist_ripng = 0;
  ospf6_zebra_no_redistribute (ZEBRA_ROUTE_RIPNG);
  return CMD_SUCCESS;
}

DEFUN (interface_area,
       interface_area_cmd,
       "interface IFNAME area AREA_ID",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Set the OSPF6 area ID\n"
       "A.B.C.D OSPF6 area ID in IP address format\n"
       )
{
  struct interface *ifp;
  struct ospf6_if *ospf6_if;
  struct area *area;
  area_id_t area_id;

  ifp = if_get_by_name (argv[0]);

  inet_pton (AF_INET, argv[1], &area_id);
  area = ospf6_area_lookup (area_id);
  if (!area)
    area = ospf6_area_init (area_id);

  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  else
    {
      if (ospf6_if->area && area == ospf6_if->area)
        return CMD_ERR_NOTHING_TODO;
      else if (ospf6_if->area)
        {
          vty_out (vty, "Already attached to area %s\n", 
                   inet4str (ospf6_if->area->area_id));
          return CMD_ERR_NO_MATCH;
        }
    }

  list_add_node (area->ospf6_if_list, ospf6_if);
  ospf6_if->area = area;

  /* must check if got already interface info from zebra */
  if (if_is_up (ifp))
    thread_add_event (master, interface_up, ospf6_if, 0);

  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
ospf6_config_write (struct vty *vty)
{
  listnode j, k;
  struct area *area;
  struct ospf6_if *ospf6_if;

  /* OSPFv6 configuration. */
  vty_out (vty, "router ospf6%s", VTY_NEWLINE);
  vty_out (vty, " router-id %s%s",
                 inet4str(ospf6->router_id),
                 VTY_NEWLINE);

  /* redistribution */
  if (!ospf6->redist_connected)
    vty_out (vty, " no redistribute connected%s", VTY_NEWLINE);
  if (ospf6->redist_static)
    vty_out (vty, " redistribute static%s", VTY_NEWLINE);
  if (ospf6->redist_ripng)
    vty_out (vty, " redistribute ripng%s", VTY_NEWLINE);

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *)getdata (j);
      for (k = listhead (area->ospf6_if_list); k; nextnode (k))
        {
          ospf6_if = (struct ospf6_if *)getdata (k);
          vty_out (vty, " interface %s area %s",
                         ospf6_if->interface->name,
                         inet4str (area->area_id));
          vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
  vty_out (vty, "!%s", VTY_NEWLINE);
  return 0;
}

/* OSPF6 node structure. */
struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# ",
};

/* Install ospf related commands. */
void
ospf6_init ()
{
  /* Install ospf6 top node. */
  install_node (&ospf6_node, ospf6_config_write);

  install_element (VIEW_NODE, &show_ipv6_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_requestlist_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_retranslist_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_nexthoplist_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_asexternal_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_area_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_backbone_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_connected_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_redistribute_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_requestlist_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_retranslist_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_nexthoplist_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_asexternal_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);

  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_area_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_backbone_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_connected_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_redistribute_cmd);

  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &interface_cmd);

  install_default (OSPF6_NODE);
  install_element (OSPF6_NODE, &ospf6_redistribute_static_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_static_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_connected_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_connected_cmd);
  install_element (OSPF6_NODE, &ospf6_redistribute_ripng_cmd);
  install_element (OSPF6_NODE, &no_ospf6_redistribute_ripng_cmd);
  install_element (OSPF6_NODE, &router_id_cmd);
  install_element (OSPF6_NODE, &interface_area_cmd);

  /* Make empty list of top list. */
  if_init ();

  ospf6_if_init ();
  ospf6_zebra_init ();
  ospf6_debug_init ();
  access_list_init ();
}

void
ospf6_terminate ()
{
  /* stop ospf6 */
  ospf6_stop ();

  /* log */
  zlog (NULL, LOG_INFO, "OSPF6d terminated");
}

