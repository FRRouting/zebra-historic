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

/* global ospfd variable */
int  ospf6_sock;
list ospf6_list;
list iflist;
struct sockaddr_in6 allspfrouters6;
struct sockaddr_in6 alldrouters6;



/* OSPF Instance section */
/* Allocate new ospf6 instance. */
static struct ospf6 *
ospf6_new ()
{
  struct ospf6 *new = (struct ospf6 *)
      XMALLOC (MTYPE_OSPF6_INSTANCE, sizeof (struct ospf6));
  if (new)
    memset (new, 0, sizeof (struct ospf6));
  else
    zlog (NULL, LOG_WARNING, "Can't malloc instance");

  return new;
}

/* Make new ospf6 instance */
struct ospf6 *
make_ospf6 (rtr_id_t rtr_id)
{
  struct ospf6 *ospf6 = ospf6_new ();

  if (!ospf6)
    {
      zlog (NULL, LOG_WARNING, "Can't allocate ospf6 instance");
      return (struct ospf6 *)NULL;
    }

  ospf6->version = OSPF_V3;
  ospf6->instance_id = 1;      /* xxx multiple instance not yet */
  ospf6->router_id = rtr_id;
  ospf6->area_list = list_init ();
  list_add_node (ospf6_list, ospf6);
  return ospf6;
}



/* Area section */
/* Allocate new area structure. */
static struct area *
area_new ()
{
  struct area *new = (struct area *)
      XMALLOC (MTYPE_OSPF6_AREA, sizeof (struct area));
  if (new)
    memset (new, 0, sizeof (struct area));
  else
    zlog (NULL, LOG_WARNING,"Can't malloc area");

  return new;
}

/* Make new area structure */
struct area *
make_area (area_id_t area_id, struct ospf6 *ospf6)
{
  struct area *area = area_new ();

  if (!area)
    {
      /* xxx */
      zvlog_warn ("Can't alloc area for %s", inet4str (area_id));
      return (struct area *)NULL;
    }

  area->area_id = area_id;
  inet_ntop (AF_INET, &area_id, area->str, sizeof (area->str));
  area->ospf6_if_list = list_init ();

  area->router_lsa_seqnum = area->network_lsa_seqnum
                          = area->link_lsa_seqnum
                          = area->intra_prefix_seqnum
                          = INITIAL_SEQUENCE_NUMBER;

  /* Initialize LSDB */
  ospf6_lsdb_init_area (area);

  assert (ospf6->version == OSPF_V3);

  V3OPT_SET (area->options, V3OPT_V6);
  V3OPT_SET (area->options, V3OPT_E);
  V3OPT_SET (area->options, V3OPT_R);

  list_add_node (ospf6->area_list, area);
  area->ospf6 = ospf6;
  return area;
}



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
struct ospf6 *
ospf6_lookup (instance_id_t instance_id)
{
  struct ospf6 *ospf6;
  listnode n;

  for (n = listhead (ospf6_list); n; nextnode (n))
    {
      ospf6 = (struct ospf6 *)getdata (n);
      if (ospf6->instance_id == instance_id)
        return ospf6;
    }
  return (struct ospf6 *)NULL;
}

struct area *
area_lookup (area_id_t area_id, struct ospf6 *ospf6)
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

/* lookup neighbor from OSPF instance.
   because router-id may not be identical between
   two different OSPF instance */
struct neighbor *
nbr_lookup (rtr_id_t rtr_id, struct ospf6 *ospf6)
{
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  listnode i, j, k;
  struct area *area;

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      area = (struct area *)getdata (i);
      for (j = listhead (area->ospf6_if_list); j; nextnode (j))
        {
          ospf6_if = (struct ospf6_if *)getdata (j);
          for (k = listhead (ospf6_if->nbr_list); k; nextnode (k))
            {
              nbr = (struct neighbor *)getdata (k);
              if (nbr->rtr_id == rtr_id)
              return nbr;
            }
        }
    }

  return (struct neighbor *)NULL;
}

/* Called when SIGINT signal is received
   Close all ospf instance. */
void
ospf6_terminate ()
{
  zvlog_info ("OSPF6d terminated");

  return;
}



/* show specified ospf top level structure */
int
show_ospf6_top (struct vty *vty, struct ospf6 *ospf6)
{
  listnode n;
  struct area *area;

  vty_out (vty, "Instance-ID: %d\tVersion: %d\tRouter-ID: %s\r\n",
                 ospf6->instance_id, ospf6->version,
                 inet4str (ospf6->router_id));
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      area = (struct area *)getdata (n);
      show_area (vty, area);
    }

  return 0;
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
  struct ospf6 *ospf6;
  listnode i, j, k, l;

  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]\r\n",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State");

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (!ifp)
        return CMD_ERR_NO_MATCH;

      ospf6_if = (struct ospf6_if *) ifp->if_data;
      if (!ospf6_if)
        return CMD_ERR_NO_MATCH;

      if (argc > 1)
        {
          inet_pton (AF_INET, argv[1], &rtr_id);
          nbr = nbr_lookup (rtr_id, ospf6_if->area->ospf6);
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

  for (l = listhead (ospf6_list); l; nextnode (l))
    {
      ospf6 = (struct ospf6 *) getdata (l);
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

/* make ospf instance by INSTANCE_ID. */
DEFUN (router_ospf6,
       router_ospf6_cmd,
       "router ospf6",
       OSPF6_ROUTER_STR
       OSPF6_STR
       )
{
  struct ospf6 *ospf6;
  instance_id_t instance_id;
  rtr_id_t router_id;

  if (argc != 0)
    instance_id = strtol (argv[0], NULL, 10);
  else
    instance_id = 1;

  /* lookup existing ospf structure */
  ospf6 = ospf6_lookup (instance_id);
  if (!ospf6 && list_isempty (ospf6_list))
    {
      /* Make new ospf instance. */
      router_id = 0;
      ospf6 = make_ospf6(router_id);
    }
  else if (!ospf6)
    {
      vty_out (vty, "Multiple OSPF6 Instance, Not yet\r\n");
      return CMD_ERR_NO_MATCH;
    }

  /* Set current ospf point. */
  vty->node = OSPF6_NODE;
  vty->index = ospf6;
  return CMD_SUCCESS;
}

ALIAS (router_ospf6,
       router_ospf6_instance_cmd,
       "router ospf6 instance INSTANCE_ID",
       OSPF6_ROUTER_STR
       OSPF6_STR
       "Specify OSPF instance\n"
       OSPF6_INSTANCE_STR
       )

/* Delete ospf instance by INSTANCE_ID. */
DEFUN (no_router_ospf6_instance,
       no_router_ospf6_instance_cmd,
       /* "no router ospf [instance INSTANCE_ID]", */
       "no router ospf6",
       NO_STR
       OSPF6_ROUTER_STR
       "Delete OSPF6 instance(by INSTANCE_ID is not supported).")
{
  struct ospf6 *ospf6;
  instance_id_t id;

  if (argc != 0)
    {
      id = strtol (argv[0], NULL, 10);
      ospf6 = ospf6_lookup (id);
    }
  else
    {
      ospf6 = ospf6_lookup (1);
    }

  if (ospf6 == NULL)
    {
      vty_out (vty, "No match by INSTANCE_ID.\r\n");
      vty_out (vty, "\r\n");
      return CMD_SUCCESS;
    }

  /* xxx delete_ospf6 (ospf6); */
  return CMD_SUCCESS;
}

/* show top level structures */
DEFUN (show_ipv6_ospf6_instance,
       show_ipv6_ospf6_instance_cmd,
       "show ipv6 ospf6 instance INSTANCE_ID",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Specify OSPF instance\n"
       OSPF6_INSTANCE_STR
       )
{
  struct ospf6 *ospf6;
  instance_id_t id;
  listnode i;

  if (argc)
    {
      id = strtol (argv[0], NULL, 10);
      ospf6 = ospf6_lookup (id);
      if (!ospf6)
        vty_out (vty, "No match by Instance-ID: %d\r\n", id);
      else
        show_ospf6_top (vty, ospf6);
    }
  else
    {
      for (i = listhead (ospf6_list); i; nextnode (i))
        {
          ospf6 = (struct ospf6 *)getdata (i);
          show_ospf6_top (vty, ospf6);
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_instance,
       show_ipv6_ospf6_cmd,
       "show ipv6 ospf6",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       )

DEFUN (show_ipv6_ospf6_requestlist,
       show_ipv6_ospf6_requestlist_cmd,
       "show ipv6 ospf6 request-list ADDR",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Specify address\n"
       "A.B.C.D OSPF6 router ID in IP address format\n")
{
  rtr_id_t rtr_id;
  struct ospf6 *ospf6;
  struct neighbor *nbr = NULL;
  listnode n;
  struct ospf6_lsa *lsa;

  inet_pton (AF_INET, argv[0], &rtr_id);
  for (n = listhead (ospf6_list); n; nextnode (n))
    {
      ospf6 = (struct ospf6 *) getdata (n);
      if ((nbr = nbr_lookup (rtr_id, ospf6)) != NULL)
        break;
    }
  if (nbr == NULL)
    {
      vty_out (vty, "Neighbor %s not found\r\n", argv[0]);
      return CMD_SUCCESS;
    }
  vty_out (vty, "Neighbor %s, interface %s\r\n", nbr->str,
           nbr->ospf6_if->interface->name);
  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      vty_out (vty, "%s\r\n", print_lsahdr (lsa->lsa_hdr));
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
  listnode i, j, k;
  struct ospf6 *ospf6;
  struct area *area;
  list l;

  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *) getdata (i);
      vty_out (vty, "OSPF: instance %d\r\n", ospf6->instance_id);
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
  listnode i, j, k;
  struct ospf6 *ospf6;
  struct area *area;
  list l;

  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *) getdata (i);
      vty_out (vty, "OSPF: instance %d\r\n", ospf6->instance_id);
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
  listnode i, j, k, n;
  list l;
  struct ospf6 *ospf6;
  struct area *area;
  struct ospf6_if *ospf6_if;

  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *) getdata (i);
      vty_out (vty, "OSPF: instance %d\r\n", ospf6->instance_id);
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
  listnode i, j, k;
  struct ospf6 *ospf6;
  struct area *area;
  list l;

  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *) getdata (i);
      vty_out (vty, "OSPF: instance %d\r\n", ospf6->instance_id);
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
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_ospf6,
       show_ipv6_route_ospf6_area_cmd,
       "show ipv6 route ospf6 area AREA",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "show routing table in area structure\n"
       "A.B.C.D OSPF6 area ID in IP address format\n"
       )
{
  struct ospf6 *ospf6;
  struct area *area;
  instance_id_t instance_id;
  area_id_t area_id;
  struct ospf6_rtentry *p;

  instance_id = 1;
  if (argc)
    {
      inet_pton (AF_INET, argv[0], &area_id);
    }
  else
    {
      area_id = 0;
    }

  ospf6 = ospf6_lookup (instance_id);
  if (!ospf6)
    {
       vty_out (vty, "invalid instance id: %lu\r\n", instance_id);
       return CMD_WARNING;
    }
  area = area_lookup (area_id, ospf6);
  if (!area)
    {
       vty_out (vty, "invalid area id: %lu\r\n", area_id);
       return CMD_WARNING;
    }

  vty_out (vty, "Routing Table\r\n");
  vty_out (vty, "%-26s %-26s %-3s %5s %-5s\r\n",
     "Destination", "Gateway", "Netif", "Cost", "PathType");
  vty_out (vty, "----------\r\n");

  if (argc)
    for (p = area->rtable.current_top; p; p = p->next)
      {
        rtable_vty_entry (vty, p);
      }
  else
    for (p = ospf6->rtable.current_top; p; p = p->next)
      {
        rtable_vty_entry (vty, p);
      }

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_route_ospf6,
       show_ipv6_route_ospf6_cmd,
       "show ipv6 route ospf6",
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       )

/* change Router_ID commands. */
DEFUN (router_id,
       router_id_cmd,
       "router-id ROUTER_ID",
       "Configure ospf Router-ID.\n"
       V4NOTATION_STR)
{
  struct ospf6 *ospf6;
  int ret;
  rtr_id_t router_id;

  ret = inet_pton (AF_INET, argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "malformed ospf router identifier\r\n");
      vty_out (vty, "\r\n");
      return CMD_WARNING;
    }

  ospf6 = (struct ospf6 *) vty->index;
  assert (ospf6);
  ospf6->router_id = router_id;

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
  struct ospf6 *ospf6;
  area_id_t area_id;

  ifp = if_lookup_by_name (argv[0]);
  if (!ifp)
    {
      vty_out (vty, "No such interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  ospf6 = (struct ospf6 *) vty->index;
  assert (ospf6);

  inet_pton (AF_INET, argv[1], &area_id);
  area = area_lookup (area_id, ospf6);
  if (!area)
    area = make_area (area_id, ospf6);

  ospf6_if = (struct ospf6_if *)ifp->if_data;
  if (!ospf6_if)
    {
      ospf6_if = make_ospf6_if (ifp->name);
    }
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

/* XXX must check if got already interface info from zebra
  if (ospf6_if->interface)
    thread_add_event (master, interface_up, ospf6_if, 0);
*/

  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
ospf6_config_write (struct vty *vty)
{
  listnode i, j, k;
  struct ospf6 *ospf6;
  struct area *area;
  struct ospf6_if *ospf6_if;

  /* OSPF instance configuration. */
  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *)getdata (i);

      vty_out (vty, "router ospf6 instance %d%s",
               ospf6->instance_id, VTY_NEWLINE);
      vty_out (vty, " router-id %s%s",
                     inet4str(ospf6->router_id),
                     VTY_NEWLINE);
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
    }
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
  install_element (VIEW_NODE, &show_ipv6_ospf6_instance_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_requestlist_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_route_ospf6_area_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_instance_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_requestlist_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_network_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_link_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_intraprefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_cmd);
  install_element (ENABLE_NODE, &show_ipv6_route_ospf6_area_cmd);

  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &router_ospf6_instance_cmd);
  install_element (CONFIG_NODE, &interface_cmd);

  install_default (OSPF6_NODE);
  install_element (OSPF6_NODE, &router_id_cmd);
  install_element (OSPF6_NODE, &interface_area_cmd);

  /* Make empty list of top list. */
  ospf6_list = list_init ();
  if_init ();

  ospf6_zebra_init ();
  access_list_init ();
}

