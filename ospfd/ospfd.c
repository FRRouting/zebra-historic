/* OSPF version 2 daemon program
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

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"

/* OSPF instance top. */
struct ospf *ospf_top;

static char *ospf_network_type_str[] =
{
  "Null",
  "POINTOPOINT",
  "BROADCAST",
  "NBMA",
  "POINTOMULTIPOINT",
  "VIRTUALLINK"
};


/* Allocate new ospf structure. */
struct ospf *
ospf_new ()
{
  struct ospf *new = XMALLOC (MTYPE_OSPF_TOP, sizeof (struct ospf));
  bzero (new, sizeof (struct ospf));

  new->iflist = iflist;
  new->areas = list_init ();
  new->networks = (struct route_table *) route_table_init ();

  return new;
}


/* allocate new OSPF Area object */
struct ospf_area *
ospf_area_new (struct in_addr area_id)
{
  struct ospf_area *new;

  /* Allocate new config_network. */
  new = XMALLOC (MTYPE_OSPF_AREA, sizeof (struct ospf_area));
  bzero (new, sizeof (struct ospf_area));

  new->count = 0;

  new->area_id = area_id;
  new->router_lsa = list_init ();
  new->network_lsa = list_init ();
  new->summary_lsa = list_init ();

  new->auth_type = OSPF_AUTH_NULL;

  return new;
}

void
ospf_area_free (struct ospf_area *area)
{
  list_delete_all (area->router_lsa);
  list_delete_all (area->network_lsa);
  list_delete_all (area->summary_lsa);

  XFREE (MTYPE_OSPF_AREA, area);
}

struct ospf_area *
ospf_area_lookup_by_area_id (struct in_addr area_id)
{
  struct ospf_area *area;
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);
      if (!IPV4_ADDR_CMP (&area->area_id, &area_id))
	return area;
    }

  return NULL;
}

struct ospf_network *
ospf_network_new (struct in_addr area_id, int format)
{
  struct ospf_network *new;
  struct ospf_area *area;

  new = XMALLOC (MTYPE_OSPF_NETWORK, sizeof (struct ospf_network));
  bzero (new, sizeof (struct ospf_network));

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      /* sort should be applied. */
      list_add_node (ospf_top->areas, area);
    }

  new->area_id = area_id;
  area->format = format;
  area->count++;

  return new;
}

void
ospf_network_free (struct ospf_network *network)
{
  struct ospf_area *area;

  area = ospf_area_lookup_by_area_id (network->area_id);
  if (area)
    {
      area->count--;

      if (area->count == 0)
	if (area->auth_type == OSPF_AUTH_NULL)
	  {
	    ospf_area_free (area);
	    list_delete_by_val (ospf_top->areas, area);
	  }
    }

  XFREE (MTYPE_OSPF_NETWORK, network);
}

void
ospf_loopback_run (struct ospf *ospf)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;

  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->if_data;

      if (if_is_up (ifp))
	{
	  /* If interface is loopback, change state. */
	  if (if_is_loopback (ifp))
	    if (oi->flag == OSPF_IF_DISABLE)
	      {	      
		oi->flag = OSPF_IF_ENABLE;
		zlog (NULL, LOG_INFO, "OSPF ISM[%s] start.", ifp->name);
		OSPF_ISM_EVENT_ADD (ifp->if_data, ISM_LoopInd);
	      }
	}
    }
}

void
ospf_interface_run (struct ospf *ospf, struct prefix *p,
		    struct ospf_area *area)
{
  struct interface *ifp;
  listnode node;

  /* get target interface. */
  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      listnode cn;
      struct ospf_interface *oi;
      u_char flag = OSPF_IF_DISABLE;

      ifp = getdata (node);
      oi = ifp->if_data;

      /* is interface up? */
      if (! if_is_up (ifp))
	continue;

      if (oi->flag == OSPF_IF_ENABLE)
	continue;

      /* if interface prefix is match specified prefix,
	 then create socket and join multicast group. */
      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co;
	  struct in_addr addr;
	  int sock;

	  co = getdata (cn);

	  if (prefix_match (co->address, p))
	    {
	      /* get pointer of interface prefix. */
	      oi->address = co->address;
	      oi->area = ospf_area_lookup_by_area_id (area->area_id);

	      addr = co->address->u.prefix4;

	      /* create raw socket. */
	      sock = ospf_serv_sock (ifp, AF_INET);
	      if (sock < 0)
		{
		  zlog (NULL, LOG_WARNING,
			"interface %s can't create raw socket", ifp->name);
		  continue;
		}

	      /* join mcast group. */
	      ospf_if_add_allspfrouters (sock, co->address);

	      /* select interface. */
	      ospf_if_ipmulticast (sock, co->address);

	      /* create input/output buffer stream. */
	      ospf_if_stream_set (sock, oi);

	      /* Remember this interface is running. */
	      flag = OSPF_IF_ENABLE;

	      /* entry point of ISM. */
	      OSPF_ISM_EVENT_ADD (oi, ISM_InterfaceUp);
	      zlog (NULL, LOG_INFO, "OSPF ISM[%s] start.", ifp->name);

	      /* Add Pseudo Neighbor. */
	      ospf_nbr_add_myself (oi);

	      break;
	    }
	}
      oi->flag = flag;
    }
}

void
ospf_interface_down (struct ospf *ospf, struct prefix *p,
		     struct ospf_area *area)
{
  struct interface *ifp;
  listnode node;

  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      struct ospf_interface *oi;
      u_char flag = OSPF_IF_ENABLE;

      ifp = getdata (node);
      oi = ifp->if_data;

      if (oi->flag == OSPF_IF_DISABLE)
	continue;

      if (oi->area == area)
	{
	  /* close socket. */
	  close (oi->fd);

	  /* clear input/output buffer stream. */
	  ospf_if_stream_unset (oi);

	  /* Remember this interface is not running. */
	  flag = OSPF_IF_DISABLE;

	  /* This interface goes down. */
	  OSPF_ISM_EVENT_ADD (oi, ISM_InterfaceDown);
	}
    }
}

struct in_addr
ospf_get_router_id (list if_list)
{
  listnode node;
  struct in_addr router_id;
  struct interface *ifp;

  bzero (&router_id, sizeof (struct in_addr));

  for (node = listhead (if_list); node; nextnode (node))
    {
      listnode cn;

      ifp = getdata (node);

      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co;

	  co = getdata (cn);

	  if (co->address->family != AF_INET)
	    continue;

	  /* ignore loopback network. */
	  if (if_is_loopback (ifp))
	    continue;

	  if (ntohl (router_id.s_addr) < ntohl (co->address->u.prefix4.s_addr))
	    router_id = co->address->u.prefix4;
	}
    }

  return router_id;
}


void
ospf_if_update ()
{
  struct route_node *rn;
  struct ospf_network *network;
  struct ospf_area *area;

  if (ospf_top != NULL)
    {
      ospf_loopback_run (ospf_top);

      for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
	{
	  network = (struct ospf_network *) rn->info;
	  area = ospf_area_lookup_by_area_id (network->area_id);

	  ospf_interface_run (ospf_top, &rn->p, area);
	}
    }

  /* Update router_id. */
  if (ospf_top != NULL)
    ospf_top->router_id = ospf_get_router_id (ospf_top->iflist);
}

int
ospf_str2area_id (char *str, struct in_addr *area_id)
{
  int ret;
  int area_id_dec;
  int format;

  if (strchr (str, '.') != NULL)
    {
      ret = inet_aton (str, area_id);
      if (!ret)
	return 0;
      format = OSPF_AREA_ID_FORMAT_ADDRESS;
    }
  else
    {
      area_id_dec = strtol (str, NULL, 10);
      if (area_id_dec < 0)
	return 0;
      area_id->s_addr = htonl (area_id_dec);
      format = OSPF_AREA_ID_FORMAT_DECIMAL;
    }

  return format;
}


/* router ospf command */
DEFUN (router_ospf,
       router_ospf_cmd,
       "router ospf",
       "Enable a routing process\n"
       "Start OSPF configuration\n")
{
  /* There is already active ospf instance. */
  if (ospf_top != NULL)
    {
      vty->node = OSPF_NODE;
      vty->index = ospf_top;
      return CMD_SUCCESS;
    }

  /* Make new ospf instance. */
  ospf_top = ospf_new ();

  /* Set current ospf point. */
  vty->node = OSPF_NODE;
  vty->index = ospf_top;

  ospf_loopback_run (ospf_top);

  ospf_top->router_id = ospf_get_router_id (ospf_top->iflist);

  return CMD_SUCCESS;
}

DEFUN (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n")
{
  struct route_node *rn;
  listnode node;

  if (ospf_top == NULL)
    {
      vty_out (vty, "There isn't active ospf instance.\r\n");
      return CMD_WARNING;
    }

  /* Clear networks and Areas. */
  for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
    {
      struct ospf_network *network;
      struct ospf_area *area;

      if (rn->info == NULL)
	continue;

      network = rn->info;
      area = ospf_area_lookup_by_area_id (network->area_id);

      /* Add InterfaceDown event to appropriate interface. */
      ospf_interface_down (ospf_top, &rn->p, area);

      ospf_network_free (network);
      rn->info = NULL;
      route_unlock_node (rn);
    }

  /* reset interface. */
  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct route_node *rn;      

      ifp = getdata (node);
      oi = ifp->if_data;

      /* Clear neighbors. */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  struct ospf_neighbor *nbr;

	  if (!rn->info)
	    continue;

	  nbr = rn->info;
	  ospf_nbr_free (nbr);
	}
      /* Reset interface variables. */
      ospf_if_reset_variables (oi);
    }

  XFREE (MTYPE_OSPF_TOP, ospf_top);

  ospf_top = NULL;

  return CMD_SUCCESS;
}

DEFUN (network_area,
       network_area_cmd,
       "network IPV4_PREFIX area AREA_ID",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF Area ID\n")
{
  int ret;
  struct prefix p;
  struct in_addr area_id;
  struct ospf *ospf;
  struct ospf_network *network;
  struct ospf_area *area;
  struct route_node *rn;

  ospf = vty->index;

  /* get network prefix. */
  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (! ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask ((struct prefix_ipv4 *) &p);

  /* get Area ID. */
  ret = ospf_str2area_id (argv[1], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid\r\n");
      return CMD_WARNING;
    }

  network = ospf_network_new (area_id, ret);

  rn = route_node_get (ospf->networks, &p);
  if (rn->info)
    {
      vty_out (vty, "There is already same network statement.\r\n");
      route_unlock_node (rn);
      return CMD_WARNING;
    }
  rn->info = network;

  /* get area data structure. */
  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "There is no area data structure.\r\n");
      return CMD_WARNING;
    }

  /* Run Interface config now. */
  ospf_interface_run (ospf, &p, area);

  return CMD_SUCCESS;
}

DEFUN (no_network_area,
       no_network_area_cmd,
       "no network IPV4_PREFIX area AREA_ID",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF Area ID\n")
{
  int ret;
  struct ospf *ospf;
  struct prefix_ipv4 p;
  struct in_addr area_id;
  struct route_node *rn;
  struct ospf_network *network;
  struct ospf_area *area;

  ospf = (struct ospf *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  if (!ospf_str2area_id (argv[1], &area_id))
    {
      vty_out (vty, "OSPF Area ID is invalid\r\n");
      return CMD_WARNING;
    }

  apply_mask (&p);

  rn = route_node_get (ospf->networks, (struct prefix *) &p);
  if (!rn->info)
    {
      vty_out (vty, "Can't find specified network area configuration.\r\n");
      route_unlock_node (rn);
      return CMD_WARNING;
    }

  network = rn->info;
  area = ospf_area_lookup_by_area_id (network->area_id);

  /* Add InterfaceDown event to appropriate interface. */
  ospf_interface_down (ospf, &rn->p, area);

  ospf_network_free (rn->info);
  rn->info = NULL;
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

DEFUN (area_authentication_message_digest,
       area_authentication_message_digest_cmd,
       "area AREA_ID authentication message-digest",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid\r\n");
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
    }

  area->auth_type = OSPF_AUTH_CRYPTOGRAPHIC;

  return CMD_SUCCESS;
}

DEFUN (area_authentication,
       area_authentication_cmd,
       "area AREA_ID authentication",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid\r\n");
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
    }

  area->auth_type = OSPF_AUTH_SIMPLE;

  return CMD_SUCCESS;
}

DEFUN (no_area_authentication,
       no_area_authentication_cmd,
       "no area AREA_ID authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;

  if (!ospf_str2area_id (argv[0], &area_id))
    {
      vty_out (vty, "OSPF Area ID is invalid\r\n");
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area ID %s is not declared\r\n", inet_ntoa (area_id));
      return CMD_WARNING;
    }

  area->auth_type = OSPF_AUTH_NULL;

  return CMD_SUCCESS;
}

void
show_ip_ospf_interface_sub (struct vty *vty, struct interface *ifp)
{
  struct ospf_interface *oi;
  struct route_node *rn;
  struct prefix key;
  struct ospf_neighbor *nbr;
  char buf[9];

  /* is interface up? */
  if (if_is_up (ifp))
    vty_out (vty, "%s is up, line protocol is up\r\n", ifp->name);
  else
    vty_out (vty, "%s is down, line protocol is down\r\n", ifp->name);

  oi = ifp->if_data;

  /* is interface OSPF enabled? */
  if (oi == NULL)
    {
      vty_out (vty, "  OSPF not enabled on this interface\r\n");
      return;
    }
  if (oi->flag == OSPF_IF_DISABLE || oi->address == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface\r\n");
      return;
    }
      
  /* show OSPF interface information. */
  vty_out (vty, "  Internet Address %s/%d,",
	   inet_ntoa (oi->address->u.prefix4), oi->address->prefixlen);

  vty_out (vty, " Area %s\r\n", inet_ntoa (oi->area->area_id));

  vty_out (vty, "  Router ID %s, Network Type %s, Cost: %d\r\n",
	   inet_ntoa (ospf_top->router_id),
	   ospf_network_type_str[oi->type],
	   oi->output_cost);

  vty_out (vty, "  Transmit Delay is %d sec, State %s, Priority %d\r\n",
	   oi->transmit_delay,
	   LOOKUP (ospf_ism_status_msg, oi->status),
	   oi->priority);

  /* show DR information. */
  if (oi->d_router.s_addr == 0)
    vty_out (vty, "  No designated router on this network\r\n");
  else
    {
      key.family = AF_INET;
      key.prefixlen = 32;
      key.u.prefix4 = oi->d_router;

      rn = route_node_get (oi->nbrs, &key);
      if (rn == NULL)
	vty_out (vty, "  No designated router on this network\r\n");
      else if (rn->info == NULL)
	vty_out (vty, "  No designated router on this network\r\n");
      else
	{
	  nbr = (struct ospf_neighbor *) rn->info;

	  vty_out (vty, "  Designated Router (ID) %s,",
		   inet_ntoa (oi->d_router));
	  vty_out (vty, " Interface Address %s\r\n",
		   inet_ntoa (nbr->address.u.prefix4));
	}
      route_unlock_node (rn);
    }

  /* show BDR information. */
  if (oi->bd_router.s_addr == 0)
    vty_out (vty, "  No backup designated router on this network\r\n");
  else
    {
      key.family = AF_INET;
      key.prefixlen = 32;
      key.u.prefix4 = oi->bd_router;

      rn = route_node_get (oi->nbrs, &key);
      if (rn == NULL)
	vty_out (vty, "  No backup designated router on this network\r\n");
      else if (rn->info == NULL)
	vty_out (vty, "  No backup designated router on this network\r\n");
      else
	{
	  nbr = (struct ospf_neighbor *) rn->info;

	  vty_out (vty, "  Backup Designated Router (ID) %s,",
		   inet_ntoa (oi->bd_router));
	  vty_out (vty, " Interface Address %s\r\n",
		   inet_ntoa (nbr->address.u.prefix4));
	}
      route_unlock_node (rn);
    }

  vty_out (vty, "  Timer intarvals configured,");
  vty_out (vty, " Hello %d, Dead %d, Wait %d, Retransmit %d\r\n",
	   oi->v_hello, oi->v_wait, oi->v_wait, 0);

  vty_out (vty, "    Hello due in %s\r\n",
	   ospf_timer_dump (oi->t_hello, buf, 9));

  vty_out (vty, "  Neighbor Count is %d, Adjacent neighbor count is %d\r\n",
	   ospf_nbr_count (oi->nbrs), ospf_adjacent_count (oi->nbrs));
}

DEFUN (show_ip_ospf_interface,
       show_ip_ospf_interface_cmd,
       "show ip ospf interface [INTERFACE]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Interface information\n"
       "Interface name\n")
{
  struct interface *ifp;
  listnode node;

  /* show All Interfaces. */
  if (argc == 0)
    for (node = listhead (iflist); node; nextnode (node))
      {
	ifp = getdata (node);
	show_ip_ospf_interface_sub (vty, ifp);
      }
  /* Interface name is specified. */
  else
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL)
	vty_out (vty, "No such interface name\r\n");
      else
	show_ip_ospf_interface_sub (vty, ifp);
    }

  return CMD_SUCCESS;
}

void
show_ip_ospf_neighbor_sub (struct vty *vty, struct interface *ifp)
{
  struct route_node *rn;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  char msgbuf[16];
  char timebuf[9];

  oi = ifp->if_data;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if (!rn->info)
	continue;

      nbr = rn->info;

      if (!IPV4_ADDR_CMP (&nbr->router_id, &ospf_top->router_id))
	continue;

      ospf_nbr_state_message (nbr, msgbuf, 16);

      vty_out (vty, "%-15s %3d   %-15s %6s     %-15s %s\r\n",
	       inet_ntoa (nbr->router_id), nbr->priority,
	       msgbuf, ospf_timer_dump (nbr->t_inactivity, timebuf, 9),
	       nbr->host, ifp->name);
    }
}

DEFUN (show_ip_ospf_neighbor,
       show_ip_ospf_neighbor_cmd,
       "show ip ospf neighbor [INTERFACE]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n")
{
  listnode node;
  struct interface *ifp;

  /* show All neighbors. */
  if (argc == 0)
    {
      vty_out (vty, "\r\nNeighbor ID     Pri   State           Dead Time   Address         Interface\r\n");
      for (node = listhead (iflist); node; nextnode (node))
	{
	  ifp = getdata (node);
	  show_ip_ospf_neighbor_sub (vty, ifp);
	}
    }
  else
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL)
	vty_out (vty, "No such interface name\r\n");
      else
	{
	  vty_out (vty, "\r\nNeighbor ID     Pri   State           Dead Time   Address         Interface\r\n");
	  show_ip_ospf_neighbor_sub (vty, ifp);
	}
    }

  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  struct route_node *rn;
  listnode node;
  u_char buf[INET_ADDRSTRLEN];

  if (ospf_top != NULL)
    {
      /* router ospf print. */
      vty_out (vty, "router ospf%s", VTY_NEWLINE);

      if (! ospf_top->networks)
	return 0;

      /* network area print. */
      for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
	{
	  struct ospf_network *n;
	  struct ospf_area *a;

	  if (rn->info == NULL)
	    continue;

	  n = rn->info;
	  a = ospf_area_lookup_by_area_id (n->area_id);

	  bzero (&buf, INET_ADDRSTRLEN);

	  /* Create Area ID string by specified Area ID format. */
	  /* No Area Structure, is it error? */
	  if (!a)
	    strncpy (buf, inet_ntoa (n->area_id), INET_ADDRSTRLEN);
	  else if (a->format == OSPF_AREA_ID_FORMAT_ADDRESS)
	    strncpy (buf, inet_ntoa (n->area_id), INET_ADDRSTRLEN);
	  else
	    sprintf (buf, "%lu", ntohl (n->area_id.s_addr));

	  /* print network. */
	  vty_out (vty, " network %s/%d area %s%s",
		   inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		   buf, VTY_NEWLINE);
	}

      /* area configuration print. */
      for (node = listhead (ospf_top->areas); node; nextnode (node))
	{
	  struct ospf_area *a;
	  
	  a = getdata (node);
	  if (a->auth_type != OSPF_AUTH_NULL)
	    {
	      bzero (&buf, INET_ADDRSTRLEN);

	      if (a->format == OSPF_AREA_ID_FORMAT_ADDRESS)
		strncpy (buf, inet_ntoa (a->area_id), INET_ADDRSTRLEN);
	      else
		sprintf (buf, "%lu", ntohl (a->area_id.s_addr));

	      if (a->auth_type == OSPF_AUTH_SIMPLE)
		vty_out (vty, " area %s authentication%s",
			 buf, VTY_NEWLINE);
	      else
		vty_out (vty, " area %s authentication message-digest%s",
			 buf, VTY_NEWLINE);
	    }
	}
    }

  return 0;
}

struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# ",
};

/* Install ospf related commands. */
void
ospf_init ()
{
  /* Install ospf top node. */
  install_node (&ospf_node, ospf_config_write);

  /* Install ospf commands. */
  install_element (ENABLE_NODE, &show_ip_ospf_interface_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_cmd);
  install_element (CONFIG_NODE, &router_ospf_cmd);
  install_element (CONFIG_NODE, &no_router_ospf_cmd);

  install_element (OSPF_NODE, &config_end_cmd);
  install_element (OSPF_NODE, &config_exit_cmd);
  install_element (OSPF_NODE, &config_help_cmd);
  install_element (OSPF_NODE, &network_area_cmd);
  install_element (OSPF_NODE, &no_network_area_cmd);
  install_element (OSPF_NODE, &area_authentication_message_digest_cmd);
  install_element (OSPF_NODE, &area_authentication_cmd);
  install_element (OSPF_NODE, &no_area_authentication_cmd);
  /*
  install_element (OSPF_NODE, &neighbor_cmd);
  install_element (OSPF_NODE, &no_neighbor_cmd);
  */

  /* Make empty list of ospf list. */
  ospf_top = NULL;

  zebra_init ();
}
