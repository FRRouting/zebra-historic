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

char ospf6_daemon_version[] = OSPF6_DAEMON_VERSION;


/* vty commands */
/* Show version. */
DEFUN (show_version_ospf6,
       show_version_ospf6_cmd,
       "show version ospf6",
       SHOW_STR
       "Displays ospf6d version\n")
{
  vty_out (vty, "Zebra OSPF6d Version: %s%s",
           ospf6_daemon_version, VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_neighbor_ifname_nbrid_detail,
       show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd,
       "show ipv6 ospf6 neighbor IFNAME NBR_ID detail",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       "A.B.C.D OSPF6 neighbor Router ID in IP address format\n"
       "detailed infomation\n"
       )
{
  rtr_id_t rtr_id;
  struct interface *ifp;
  struct ospf6_neighbor *nbr;
  struct ospf6_interface *ospf6_interface;
  struct ospf6_area *area;
  listnode i, j, k;

  i = j = k = NULL;

  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State", VTY_NEWLINE);

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (!ifp)
        return CMD_ERR_NO_MATCH;

      ospf6_interface = (struct ospf6_interface *) ifp->info;
      if (!ospf6_interface)
        return CMD_ERR_NO_MATCH;

      if (argc > 1)
        {
          inet_pton (AF_INET, argv[1], &rtr_id);
          nbr = ospf6_neighbor_lookup (rtr_id, ospf6_interface);
          if (!nbr)
            return CMD_ERR_NO_MATCH;
          if (argc == 3)
            ospf6_neighbor_vty_detail (vty, nbr);
          else
            ospf6_neighbor_vty (vty, nbr);
          return CMD_SUCCESS;
        }

      for (i = listhead (ospf6_interface->neighbor_list); i; nextnode (i))
        {
          nbr = (struct ospf6_neighbor *) getdata (i);
          ospf6_neighbor_vty_summary (vty, nbr);
        }
      return CMD_SUCCESS;
    }

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      area = (struct ospf6_area *)getdata (i);
      for (j = listhead (area->if_list); j; nextnode (j))
        {
          ospf6_interface = (struct ospf6_interface *)getdata (j);
          for (k = listhead (ospf6_interface->neighbor_list); k; nextnode (k))
            {
              nbr = (struct ospf6_neighbor *)getdata (k);
              ospf6_neighbor_vty_summary (vty, nbr);
            }
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_neighbor_ifname_nbrid_detail,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       )

ALIAS (show_ipv6_ospf6_neighbor_ifname_nbrid_detail,
       show_ipv6_ospf6_neighbor_ifname_cmd,
       "show ipv6 ospf6 neighbor IFNAME",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       )

ALIAS (show_ipv6_ospf6_neighbor_ifname_nbrid_detail,
       show_ipv6_ospf6_neighbor_ifname_nbrid_cmd,
       "show ipv6 ospf6 neighbor IFNAME NBR_ID",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       "A.B.C.D OSPF6 neighbor Router ID in IP address format\n"
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
      vty_out (vty, "ospf6 already started.%s", VTY_NEWLINE);
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
      vty_out (vty, "ospf6 already stopped.%s", VTY_NEWLINE);
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
    vty_out (vty, "ospfv6 not started%s", VTY_NEWLINE);
  else
    ospf6_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_neighborlist,
       show_ipv6_ospf6_neighborlist_cmd,
       "show ipv6 ospf6 (summary-list|request-list|retransmission-list)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Link State summary list\n"
       "Link State request list\n"
       "Link State retransmission list\n"
       )
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n;
  listnode i, j, k, l;
  struct ospf6_lsa *lsa;
  list lslist = NULL;

  i = j = k = l = NULL;

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);
          for (k = listhead (o6i->neighbor_list); k; nextnode (k))
            {
              o6n = (struct ospf6_neighbor *) getdata (k);

              if (strncmp (argv[0], "sum", 3) == 0)
                lslist = o6n->summarylist;
              else if (strncmp (argv[0], "req", 3) == 0)
                lslist = o6n->requestlist;
              else if (strncmp (argv[0], "ret", 3) == 0)
                lslist = o6n->retranslist;

              vty_out (vty, "neighbor %s on interface %s: %d%s", o6n->str,
                       o6i->interface->name, listcount (lslist), VTY_NEWLINE);
              for (l = listhead (lslist); l; nextnode (l))
                {
                  lsa = (struct ospf6_lsa *) getdata (l);
                  vty_out (vty, "  %s%s", lsa->str, VTY_NEWLINE);
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
      vty_out (vty, "%s%s", buf,
	       VTY_NEWLINE);
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
          vty_out (vty, "No such Interface: %s%s", argv[0],
		   VTY_NEWLINE);
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
      vty_out (vty, "malformed ospf router identifier%s", VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf6->router_id = router_id;

  return CMD_SUCCESS;
}

DEFUN (interface_area,
       interface_area_cmd,
       "interface IFNAME area A.B.C.D",
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Set the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       )
{
  struct ospf6 *o6;
  struct interface *ifp;
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;
  u_int32_t area_id;

  o6 = (struct ospf6 *) vty->index;

  ifp = if_get_by_name (argv[0]);

  o6i = (struct ospf6_interface *) ifp->info;
  if (!o6i)
    o6i = ospf6_interface_create (ifp, ospf6);

  /* find/create ospf6 area */
  inet_pton (AF_INET, argv[1], &area_id);
  o6a = ospf6_area_lookup (area_id, o6);
  if (!o6a)
    {
      o6a = ospf6_area_create (area_id);
      o6a->ospf6 = o6;
      list_add_node (o6->area_list, o6a);
    }

  if (o6i && o6i->area)
    {
      if (o6i->area != o6a)
        vty_out (vty, "Aready attached to area %s%s",
                 o6i->area->str, VTY_NEWLINE);
      return CMD_ERR_NOTHING_TODO;
    }

  list_add_node (o6a->if_list, o6i);
  o6i->area = o6a;

  /* must check if got already interface info from zebra */
  if (if_is_up (ifp))
    thread_add_event (master, interface_up, o6i, 0);

  return CMD_SUCCESS;
}

DEFUN (no_interface,
       no_interface_cmd,
       "no interface IFNAME",
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       )
{
  listnode n;
  struct interface *ifp;
  struct ospf6_neighbor *o6n;
  struct ospf6_interface *o6i;
  struct ospf6_lsa *lsa;
  struct ospf6 *o6;

  o6 = (struct ospf6 *) vty->index;

  ifp = if_lookup_by_name (argv[0]);
  if (!ifp)
    return CMD_ERR_NO_MATCH;

  o6i = (struct ospf6_interface *) ifp->info;
  if (!o6i)
    return CMD_SUCCESS;

  if (o6i->area)
    thread_execute (master, interface_down, o6i, 0);

  list_delete_by_val (o6i->area->if_list, o6i);
  o6i->area = (struct ospf6_area *) NULL;

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      ospf6_neighbor_delete (o6n);
    }
  list_delete_all_node (o6i->neighbor_list);

  if (o6i->thread_send_hello)
    {
      thread_cancel (o6i->thread_send_hello);
      o6i->thread_send_hello = NULL;  
    }
  if (o6i->thread_send_lsack_delayed);
    {
      thread_cancel (o6i->thread_send_lsack_delayed);
      o6i->thread_send_lsack_delayed = NULL;
    }

  while (listcount (o6i->lsa_delayed_ack))
    {
      n = listhead (o6i->lsa_delayed_ack);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_delayed_ack (lsa, o6i);
    }

  ospf6_lsdb_remove_all (o6i->lsdb);
  return CMD_SUCCESS;
}

DEFUN (area_range,
       area_range_cmd,
       "area A.B.C.D range X:X::X:X/M",
       "OSPFv3 area parameters\n"
       "OSPFv3 area ID in IPv4 address format\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "IPv6 address range\n")
{
  struct ospf6 *o6;
  struct ospf6_area *o6a;
  u_int32_t area_id;
  int ret;

  o6 = (struct ospf6 *) vty->index;
  inet_pton (AF_INET, argv[0], &area_id);
  o6a = ospf6_area_lookup (area_id, o6);
  if (! o6a)
    {
      vty_out (vty, "No such area%s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  ret = str2prefix_ipv6 (argv[1], &o6a->area_range);
  if (ret <= 0)
    {
      vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

DEFUN (passive_interface,
       passive_interface_cmd,
       "passive-interface IFNAME",
       "Suppress routing updates on an interface\n"
       IFNAME_STR
       )
{
  struct interface *ifp;
  struct ospf6_interface *o6i;

  ifp = if_get_by_name (argv[0]);
  if (ifp->info)
    o6i = (struct ospf6_interface *) ifp->info;
  else
    o6i = ospf6_interface_create (ifp, ospf6);

  o6i->is_passive = 1;
  if (o6i->thread_send_hello)
    {
      thread_cancel (o6i->thread_send_hello);
      o6i->thread_send_hello = (struct thread *) NULL;
    }

  return CMD_SUCCESS;
}

DEFUN (no_passive_interface,
       no_passive_interface_cmd,
       "no passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       IFNAME_STR
       )
{
  struct interface *ifp;
  struct ospf6_interface *o6i;

  ifp = if_lookup_by_name (argv[0]);
  if (! ifp)
    return CMD_ERR_NO_MATCH;

  o6i = (struct ospf6_interface *) ifp->info;
  o6i->is_passive = 0;
  if (o6i->thread_send_hello == NULL)
    thread_add_event (master, ospf6_send_hello, o6i, 0);

  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
ospf6_config_write (struct vty *vty)
{
  listnode j, k;
  struct ospf6_area *area;
  struct ospf6_interface *ospf6_interface;

  if (!ospf6)
    {
      vty_out (vty, "!%s", VTY_NEWLINE);
      return 0;
    }

  /* OSPFv6 configuration. */
  vty_out (vty, "router ospf6%s", VTY_NEWLINE);
  vty_out (vty, " router-id %s%s",
                 inet4str(ospf6->router_id),
                 VTY_NEWLINE);

  ospf6_redistribute_config_write (vty);

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct ospf6_area *)getdata (j);
      for (k = listhead (area->if_list); k; nextnode (k))
        {
          ospf6_interface = (struct ospf6_interface *)getdata (k);
          vty_out (vty, " interface %s area %s%s",
                   ospf6_interface->interface->name,
                   inet4str (area->area_id),
                   VTY_NEWLINE);
          if (ospf6_interface->is_passive)
            vty_out (vty, " passive-interface %s%s",
                     ospf6_interface->interface->name,
                     VTY_NEWLINE);
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
  install_element (VIEW_NODE, &show_version_ospf6_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighborlist_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_nexthoplist_cmd);

  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd);
  install_element (ENABLE_NODE, &show_version_ospf6_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighborlist_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_nexthoplist_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd);

  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &interface_cmd);

  install_default (OSPF6_NODE);
  install_element (OSPF6_NODE, &router_id_cmd);
  install_element (OSPF6_NODE, &interface_area_cmd);
  install_element (OSPF6_NODE, &no_interface_cmd);
  install_element (OSPF6_NODE, &passive_interface_cmd);
  install_element (OSPF6_NODE, &no_passive_interface_cmd);
  install_element (OSPF6_NODE, &area_range_cmd);

  /* Make empty list of top list. */
  if_init ();

  ospf6_interface_init ();
  ospf6_zebra_init ();
  ospf6_debug_init ();

  /* Install access list */
  access_list_init ();
#if 0
  access_list_add_hook (xxx);
  access_list_delete_hook (xxx);
#endif

  /* Install prefix list */
  prefix_list_init ();
#if 0
  prefix_list_add_hook (xxx);
  prefix_list_delete_hook (xxx);
#endif

  /* Install ospf6 route map */
  ospf6_routemap_init ();
  ospf6_lsdb_init ();
  ospf6_rtable_init ();
}

void
ospf6_terminate ()
{
  /* stop ospf6 */
  ospf6_stop ();

  /* log */
  zlog (NULL, LOG_INFO, "OSPF6d terminated");
}

