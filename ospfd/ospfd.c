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
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
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

  new->if_list = iflist;
  new->network_area = (struct route_table *) route_table_init ();

  return new;
}


/* allocate new OSPF Area object */
struct area *
ospf_area_new (int format, struct in_addr area_id)
{
  struct area *new;

  /* Allocate new config_network. */
  new = XMALLOC (MTYPE_OSPF_AREA, sizeof (struct area));
  bzero (new, sizeof (struct area));

  new->area_id_format = format;
  new->area_id = area_id;

  return new;
}

void
ospf_area_free (struct area *area)
{
  XFREE (MTYPE_OSPF_AREA, area);
}

void
ospf_loopback_run (struct ospf *ospf)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;

  for (node = listhead (ospf->if_list); node; nextnode (node))
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
		OSPF_ISM_EVENT_ADD (ifp->if_data, ISM_LoopInd);
	      }
	}
    }
}

void
ospf_interface_run (struct ospf *ospf, struct prefix *p, struct area *a)
{
  struct interface *ifp;
  listnode node;

  /* get target interface. */
  for (node = listhead (ospf->if_list); node; nextnode (node))
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

	  /* get pointer of interface prefix. */
	  oi->address = co->address;
	  oi->area_id = a->area_id;

	  if (prefix_match (co->address, p))
	    {
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
	      ospf_if_stream_set (sock, ifp->if_data);

	      /* Remember this interface is running. */
	      flag = OSPF_IF_ENABLE;

	      OSPF_ISM_EVENT_ADD (ifp->if_data, ISM_InterfaceUp);
	    }
	}
      oi->flag = flag;
    }
}

struct in_addr
ospf_get_router_id (struct _list *if_list)
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

  if (ospf_top != NULL)
    {
      ospf_loopback_run (ospf_top);

      for (rn = route_top (ospf_top->network_area); rn; rn = route_next (rn))
	ospf_interface_run (ospf_top, &rn->p, rn->info);

    }
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

  ospf_top->router_id = ospf_get_router_id (ospf_top->if_list);

  return CMD_SUCCESS;
}

DEFUN (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n")
{
  if (ospf_top == NULL)
    {
      vty_out (vty, "There isn't active ospf instance.\r\n");
      return CMD_WARNING;
    }

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
  u_int32_t area_id_dec;
  int format;
  struct ospf *ospf;
  struct area *area;
  struct route_node *route_node;

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

  /* get Area ID as specified format */
  if (strchr (argv[1], '.') != NULL)
    {
      ret = inet_aton (argv[1], &area_id);
      if (!ret)
	{
	  vty_out (vty, "OSPF Area ID is invalid\r\n");
	  return CMD_WARNING;
	}
      format = OSPF_AREA_ID_FORMAT_ADDRESS;
    }
  else
    {
      area_id_dec = strtol (argv[1], NULL, 10);
      area_id.s_addr = htonl (area_id_dec);
      format = OSPF_AREA_ID_FORMAT_DECIMAL;
    }
  area = ospf_area_new (format, area_id);

  route_node = route_node_get (ospf->network_area, &p);
  if (route_node->info)
    {
      vty_out (vty, "There is already same network statement.\r\n");
      route_unlock_node (route_node);
      return CMD_WARNING;
    }
  route_node->info = area;

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
  u_int32_t area_id_dec;
  struct route_node *np;

  ospf = (struct ospf *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  if (strchr (argv[1], '.') != NULL)
    {
      ret = inet_aton (argv[1], &area_id);
      if (!ret)
	{
	  vty_out (vty, "OSPF Area ID is invalid\r\n");
	  return CMD_WARNING;
	}
    }
  else
    {
      area_id_dec = strtol (argv[1], NULL, 10);
      area_id.s_addr = htonl (area_id_dec);
    }

  apply_mask (&p);

  np = route_node_get (ospf->network_area, (struct prefix *) &p);
  if (!np->info)
    {
      vty_out (vty, "Can't find specified network area configuration.\r\n");
      route_unlock_node (np);
      return CMD_WARNING;
    }

  ospf_area_free (np->info);
  np->info = NULL;
  route_unlock_node (np);

  return CMD_SUCCESS;
}

void
show_ip_ospf_interface_sub (struct vty *vty, struct interface *ifp)
{
  struct ospf_interface *oi;
  struct route_node *rn;
  struct prefix key;
  struct ospf_neighbor *nbr;

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

  vty_out (vty, " Area %s\r\n", inet_ntoa (oi->area_id));

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

  vty_out (vty, "    Hello due in \r\n");

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
       "Interface name")
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

/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  struct route_node *rn;

  if (ospf_top != NULL)
    {
      /* router ospf print. */
      vty_out (vty, "router ospf%s", VTY_NEWLINE);

      if (! ospf_top->network_area)
	return 0;

      /* network area print. */
      for (rn = route_top (ospf_top->network_area); rn; rn = route_next (rn))
	{
	  struct area *area;
	  u_char area_id_buf[16];

	  if (rn->info == NULL)
	    continue;

	  area = rn->info;

	  /* print nework statement as specified Area ID format. */
	  if (area->area_id_format == OSPF_AREA_ID_FORMAT_ADDRESS)
	    {
	      bzero (&area_id_buf, 16);
	      strncpy (area_id_buf, inet_ntoa (area->area_id), 16);
	      vty_out (vty, " network %s/%d area %s%s",
		       inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		       area_id_buf, VTY_NEWLINE);
	    }
	  else
	    {
	      vty_out (vty, " network %s/%d area %u%s",
		       inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		       area->area_id.s_addr, VTY_NEWLINE);
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
  install_element (VIEW_NODE, &show_ip_ospf_interface_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_interface_cmd);
  install_element (CONFIG_NODE, &router_ospf_cmd);
  install_element (CONFIG_NODE, &no_router_ospf_cmd);

  install_element (OSPF_NODE, &config_end_cmd);
  install_element (OSPF_NODE, &config_exit_cmd);
  install_element (OSPF_NODE, &config_help_cmd);
  install_element (OSPF_NODE, &network_area_cmd);
  install_element (OSPF_NODE, &no_network_area_cmd);
  /*
  install_element (OSPF_NODE, &neighbor_cmd);
  install_element (OSPF_NODE, &no_neighbor_cmd);
  */

  /* Make empty list of ospf list. */
  ospf_top = NULL;

  zebra_init ();
}
