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
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_lsdb.h"

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

  new->router_id.s_addr = htonl (0);
  new->router_id_static.s_addr = htonl (0);

  new->abr_type = OSPF_ABR_STAND;
  new->iflist = iflist;
  new->vlinks = list_init ();
  new->areas = list_init ();
  new->networks = (struct route_table *) route_table_init ();

  new->external_lsa = ospf_lsdb_new(OSPF_LSDB_DEF);
  new->external_self = route_table_init ();
  new->maxage_lsa = list_init ();
  new->t_maxage_walker = thread_add_timer (master, ospf_lsa_maxage_walker,
					   NULL, OSPF_LSA_MAX_AGE_CHECK_INTERVAL);

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

  new->external_routing = OSPF_AREA_DEFAULT;
  new->default_cost = 1;
  new->auth_type = OSPF_AUTH_NULL;

  /* LSAs tables initialize. */
#ifdef OSPF_TABLE_TEST
  new->lsa[0] = ospf_lsdb_new (OSPF_LSDB_RT);
  new->lsa[1] = ospf_lsdb_new (OSPF_LSDB_RT);
  new->lsa[2] = ospf_lsdb_new (OSPF_LSDB_HASH);
  new->lsa[3] = ospf_lsdb_new (OSPF_LSDB_HASH);
#else
  new->lsa[0] = ospf_lsdb_new (OSPF_LSDB_DEF);
  new->lsa[1] = ospf_lsdb_new (OSPF_LSDB_DEF);
  new->lsa[2] = ospf_lsdb_new (OSPF_LSDB_DEF);
  new->lsa[3] = ospf_lsdb_new (OSPF_LSDB_DEF);
#endif /* OSPF_TABLE_TEST. */

  /* Self-originated LSAs initialize. */
  new->router_lsa_self = NULL;
  /* new->summary_lsa_self = route_table_init(); */
  /* new->summary_lsa_asbr_self = route_table_init(); */

  new->iflist = list_init();
  new->ranges = route_table_init();

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    ospf_top->backbone = new;

  return new;
}

void
ospf_area_free (struct ospf_area *area)
{
  /* Free each route table. */

  if (area->area_id.s_addr == OSPF_AREA_BACKBONE)
    ospf_top->backbone = NULL;

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
      if (IPV4_ADDR_SAME (&area->area_id, &area_id))
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
      ospf_check_abr_status ();
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

  ospf_schedule_abr_task ();
  XFREE (MTYPE_OSPF_NETWORK, network);
}

struct in_addr
ospf_get_router_id (list if_list)
{
  listnode node;
  struct in_addr router_id;
  struct interface *ifp;
  struct ospf_interface *oi;

  bzero (&router_id, sizeof (struct in_addr));

  for (node = listhead (if_list); node; nextnode (node))
    {
      listnode cn;

      ifp = getdata (node);
      oi = ifp->info;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK) 
	 continue;

      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co;

	  co = getdata (cn);

	  if (co->address->family != AF_INET)
	    continue;

	  /* ignore loopback network. */
	  if (if_is_loopback (ifp))
	    continue;

	  if (IPV4_ADDR_CMP (&router_id, &co->address->u.prefix4) < 0)
	    router_id = co->address->u.prefix4;
	}
    }

  return router_id;
}



void
ospf_update_router_id ()
{
  listnode node;
  struct interface *ifp;
  struct in_addr router_id;
  struct in_addr old_rid;

  zlog_info ("Z: ospf_update_router_id(): Start");
  zlog_info ("Z: ospf_update_router_id(): Old RID:%s",
	     inet_ntoa (ospf_top->router_id));

  old_rid = ospf_top->router_id;
  router_id = ospf_get_router_id (ospf_top->iflist);
  ospf_top->router_id = router_id;
  zlog_info ("Z: ospf_update_router_id(): New RID:%s",
	     inet_ntoa (ospf_top->router_id));

  if (old_rid.s_addr != router_id.s_addr)
    {
      for (node = listhead (ospf_top->iflist); node; nextnode (node))
	{
	  struct ospf_interface *oi;

	  ifp = getdata (node);
	  oi = ifp->info;

	  /* Is interface OSPF enable? */
	  if (!ospf_if_is_enable (ifp))
	    continue;

	  /* Update self-neighbor's router_id. */
	  oi->nbr_self->router_id = router_id;
	}
      ospf_schedule_update_router_lsas ();
    }
  zlog_info ("Z: ospf_update_router_id(): Stop");
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
      oi = ifp->info;

      if (if_is_up (ifp))
	{
	  /* If interface is loopback, change state. */
	  if (if_is_loopback (ifp))
	    if (oi->flag == OSPF_IF_DISABLE)
	      {	      
		oi->flag = OSPF_IF_ENABLE;
		zlog (NULL, LOG_INFO, "OSPF ISM[%s] start.", ifp->name);
		OSPF_ISM_EVENT_SCHEDULE (ifp->info, ISM_LoopInd);
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

  /* Update router_id. */
  if (ospf_top != NULL)
    if (ospf_top->router_id_static.s_addr == 0)
      ospf_update_router_id ();

  /* get target interface. */
  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      listnode cn;
      struct ospf_interface *oi;
      u_char flag = OSPF_IF_DISABLE;

      ifp = getdata (node);
      oi = ifp->info;

      /* is interface up? */
      if (! if_is_up (ifp))
	continue;

      if (oi->flag == OSPF_IF_ENABLE)
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
  	continue;

      /* if interface prefix is match specified prefix,
	 then create socket and join multicast group. */
      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co;
	  struct in_addr addr;
	  int ret;

	  co = getdata (cn);

	  if (prefix_match (p, co->address))
	    {
	      /* get pointer of interface prefix. */
	      oi->address = co->address;
	      oi->nbr_self->address = *oi->address;

              if ((oi->area == NULL) && (oi->status > ISM_Down))
                 area->act_ints++;

	      oi->area = area;

              if (area->external_routing != OSPF_AREA_DEFAULT)
                 UNSET_FLAG(oi->nbr_self->options, OSPF_OPTION_E);

	      addr = co->address->u.prefix4;

	      ret = ospf_serv_sock_init (ifp, co->address);
	      if (ret < 0)
		continue;

	      /* Remember this interface is running. */
	      flag = OSPF_IF_ENABLE;

	      /* entry point of ISM. */
	      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_InterfaceUp);
	      zlog (NULL, LOG_INFO, "OSPF ISM[%s] start.", ifp->name);

	      /* Add pseudo neighbor. */
	      ospf_nbr_add_self (oi);

	      /* Make sure pseudo neighbor's router_id. */
	      oi->nbr_self->router_id = ospf_top->router_id;

	      /* Relate ospf interface to ospf instance. */
	      oi->ospf = ospf_top;

	      /* update network type as interface flag */
	      if (ifp->flags & IFF_BROADCAST)
		oi->type = OSPF_IFTYPE_BROADCAST;
	      else if ((ifp->flags & IFF_POINTOPOINT) &&
		  (oi->type == OSPF_IFTYPE_BROADCAST))
		oi->type = OSPF_IFTYPE_POINTOPOINT;

	      list_add_node (oi->area->iflist, ifp);

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
  listnode node, next;

  for (node = listhead (area->iflist); node; node = next)
    {
      struct ospf_interface *oi;
      listnode cn;
      u_char flag = OSPF_IF_ENABLE;

      next = node->next;

      ifp = getdata (node);
      oi = ifp->info;

      if (oi->flag == OSPF_IF_DISABLE)
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	continue;

      LIST_ITERATOR (ifp->connected, cn)
        {
	  struct connected *co;

	  co = getdata (cn);

	  if (p->family != co->address->family)
	    continue;

	  if (prefix_match (p, co->address))
	    {
	      /* Close socket. */
	      close (oi->fd);

	      /* clear input/output buffer stream. */
	      ospf_if_stream_unset (oi);

	      /* Remember this interface is not running. */
	      flag = OSPF_IF_DISABLE;

	      /* This interface goes down. */
	      OSPF_ISM_EVENT_EXECUTE (oi, ISM_InterfaceDown);

	      list_delete_by_val (oi->area->iflist, ifp);
	    }
	}
    }
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
	  if (rn->info == NULL)
	    continue;
	  network = (struct ospf_network *) rn->info;

	  area = ospf_area_lookup_by_area_id (network->area_id);

	  ospf_interface_run (ospf_top, &rn->p, area);
	}
    }
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

  if (ospf_top->router_id_static.s_addr == 0)
    ospf_update_router_id ();

  /* I'm not sure where is proper to start SPF calc timer. -- Kunihiro */
  ospf_spf_calculate_timer_add ();

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
      vty_out (vty, "There isn't active ospf instance.%s", VTY_NEWLINE);
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

  /* Reset interface. */
  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct route_node *rn;      

      ifp = getdata (node);
      oi = ifp->info;

      /* Clear neighbors. */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  struct ospf_neighbor *nbr;

	  if (!rn->info)
	    continue;

	  nbr = rn->info;
	  ospf_nbr_delete (nbr);
	  /*	  ospf_nbr_free (nbr); 
		  rn->info = NULL; */
	}
      /* Reset interface variables. */
      ospf_if_reset_variables (oi);
    }

  OSPF_TIMER_OFF (ospf_top->t_maxage_walker);

  XFREE (MTYPE_OSPF_TOP, ospf_top);

  ospf_top = NULL;

  return CMD_SUCCESS;
}

DEFUN (ospf_router_id,
       ospf_router_id_cmd,
       "ospf router-id A.B.C.D",
       "OSPF specific commands\n"
       "Set the OSPF Router ID\n"
       "OSPF Router ID\n")
{
  int ret;
  struct in_addr router_id;

  ret = inet_aton (argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "Please specify Router ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf_top->router_id = router_id;
  ospf_top->router_id_static = router_id;

  return CMD_SUCCESS;
}

DEFUN (no_ospf_router_id,
       no_ospf_router_id_cmd,
       "no ospf router-id",
       NO_STR
       "OSPF specific commands\n"
       "Set the OSPF Router ID\n")
{
  ospf_top->router_id_static.s_addr = 0;

  ospf_update_router_id ();

  return CMD_SUCCESS;
}


DEFUN (network_area,
       network_area_cmd,
       "network A.B.C.D/M area A.B.C.D",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n")
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
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  /* get Area ID. */
  ret = ospf_str2area_id (argv[1], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  network = ospf_network_new (area_id, ret);

  rn = route_node_get (ospf->networks, &p);
  if (rn->info)
    {
      vty_out (vty, "There is already same network statement.%s", VTY_NEWLINE);
      route_unlock_node (rn);
      return CMD_WARNING;
    }
  rn->info = network;

  /* get area data structure. */
  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "There is no area data structure.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Run Interface config now. */
  ospf_interface_run (ospf, &p, area);

  return CMD_SUCCESS;
}

ALIAS (network_area,
       network_area_decimal_cmd,
       "network A.B.C.D/M area <0-4294967295>",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")

void
ospf_remove_vls_through_area (struct ospf_area *area)
{
  listnode node, next;
  struct ospf_vl_data * vl_data;

  for (node = listhead (ospf_top->vlinks); node; node = next) 
    {
      next = node->next;

      vl_data = getdata (node);
      if (vl_data == NULL)
	continue;

      if (vl_data->vl_area == area)
	ospf_vl_delete (vl_data);
    }
}


DEFUN (no_network_area,
       no_network_area_cmd,
       "no network A.B.C.D/M area A.B.C.D",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n")
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
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!ospf_str2area_id (argv[1], &area_id))
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask_ipv4 (&p);

  rn = route_node_get (ospf->networks, (struct prefix *) &p);
  if (!rn->info)
    {
      vty_out (vty, "Can't find specified network area configuration.%s",
	       VTY_NEWLINE);
      route_unlock_node (rn);
      return CMD_WARNING;
    }

  network = rn->info;
  area = ospf_area_lookup_by_area_id (network->area_id);

  ospf_remove_vls_through_area (area);

  /* Add InterfaceDown event to appropriate interface. */
  ospf_interface_down (ospf, &rn->p, area);

  ospf_network_free (rn->info);
  rn->info = NULL;
  route_unlock_node (rn);

  return CMD_SUCCESS;
}

ALIAS (no_network_area,
       no_network_area_decimal_cmd,
       "no network A.B.C.D/M area <0-4294967295>",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")

struct ospf_area_range *
ospf_new_area_range (struct ospf_area * area,
		     struct prefix_ipv4 *p)
{
  struct ospf_area_range *range;
  struct route_node * node;

  node = route_node_get (area->ranges, (struct prefix *) p);
  if (node->info)
    {
      route_unlock_node (node);
      return node->info;
    }

  range = XMALLOC (MTYPE_OSPF_AREA_RANGE, sizeof (struct ospf_area_range));
  bzero (range, sizeof (struct ospf_area_range));
  range->node = node;
  node->info = range;

  return range;
}


DEFUN (area_range,
       area_range_cmd,
       "area A.B.C.D range A.B.C.D/M",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf_new_area_range (area, &p);
  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}

ALIAS (area_range,
       area_range_decimal_cmd,
       "area <0-4294967295> range A.B.C.D/M",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFUN (no_area_range,
       no_area_range_cmd,
       "no area A.B.C.D range A.B.C.D/M",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix*) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  XFREE (MTYPE_OSPF_AREA_RANGE, node->info);
  node->info = NULL;

  route_unlock_node (node);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


ALIAS (no_area_range,
       no_area_range_decimal_cmd,
       "no area <0-4294967295> range A.B.C.D/M",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFUN (area_range_suppress,
       area_range_suppress_cmd,
       "area A.B.C.D range IPV4_PREFIX suppress",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = ospf_new_area_range (area, &p);
  SET_FLAG (range->flags, OSPF_RANGE_SUPPRESS);
  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}


DEFUN (no_area_range_suppress,
       no_area_range_suppress_cmd,
       "no area A.B.C.D range IPV4_PREFIX suppress",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix *) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = (struct ospf_area_range *) node->info;
  UNSET_FLAG (range->flags, OSPF_RANGE_SUPPRESS);

  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}



DEFUN (area_range_subst,
       area_range_subst_cmd,
       "area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "announce area range as another prefix\n"
       "network prefix to be announced instead of range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p, subst;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_ipv4 (argv[2], &subst);
  if (! ret)
    {
      vty_out (vty, "Please specify network prefix as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = ospf_new_area_range (area, &p);

  if (CHECK_FLAG (range->flags, OSPF_RANGE_SUPPRESS))
    {
      vty_out (vty, "The same area range is configured as suppress%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  SET_FLAG (range->flags, OSPF_RANGE_SUBST);
  range->substitute = subst;

  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}


DEFUN (no_area_range_subst,
       no_area_range_subst_cmd,
       "no area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "Do not advertise this range\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p, subst;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (! ret)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix *) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = (struct ospf_area_range *) node->info;

  ret = str2prefix_ipv4 (argv[2], &subst);
  if (! ret)
    {
      vty_out (vty, "Please specify network prefix as a.b.c.d/mask%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  UNSET_FLAG (range->flags, OSPF_RANGE_SUBST);

  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


DEFUN (area_vlink,
       area_vlink_cmd,
       "area A.B.C.D virtual-link A.B.C.D",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")
{
  struct ospf_area *area;
  struct in_addr area_id, vl_peer;
  struct ospf_vl_data *vl_data;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "Configuring VLs over the backbone is not allowed%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }


  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  vl_data = ospf_vl_lookup (area, vl_peer);

  if (vl_data)
    return CMD_SUCCESS;

  vl_data = ospf_vl_data_new (area, vl_peer);

  if (vl_data->vl_oi == NULL)
    {
      vl_data->vl_oi = ospf_vl_new (vl_data);
      ospf_vl_add (vl_data);
      ospf_spf_calculate_schedule ();
    }

  return CMD_SUCCESS;
}

ALIAS (area_vlink,
       area_vlink_decimal_cmd,
       "area <0-4294967295> virtual-link A.B.C.D",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFUN (no_area_vlink,
       no_area_vlink_cmd,
       "no area A.B.C.D virtual-link A.B.C.D",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")
{
  struct ospf_area *area;
  struct in_addr area_id, vl_peer;
  struct ospf_vl_data *vl_data = NULL;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  vl_data = ospf_vl_lookup (area, vl_peer);
  if (vl_data)
    ospf_vl_delete (vl_data);

  return CMD_SUCCESS;
}

ALIAS (no_area_vlink,
       no_area_vlink_decimal_cmd,
       "no area <0-4294967295> virtual-link A.B.C.D",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")


DEFUN (area_shortcut,
       area_shortcut_cmd,
       "area A.B.C.D shortcut",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as Shortcut\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  if (!area->shortcut_configured)
    {
      area->shortcut_configured = 1;
      if (ospf_top->abr_type != OSPF_ABR_SHORTCUT)
        vty_out (vty, "Shortcut area setting will take effect "
		 "only when the router is configured as "
		 "Shortcut ABR%s", VTY_NEWLINE);
      ospf_schedule_router_lsa_originate (area);
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

ALIAS (area_shortcut,
       area_shortcut_decimal_cmd,
       "area <0-4294967295> shortcut",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as Shortcut\n")

DEFUN (no_area_shortcut,
       no_area_shortcut_cmd,
       "no area A.B.C.D shortcut",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF area as Shortcut\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
     return CMD_SUCCESS;

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  if (area->shortcut_configured)
    {
      area->shortcut_configured = 0;
      ospf_schedule_router_lsa_originate (area);
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

ALIAS (no_area_shortcut,
       no_area_shortcut_decimal_cmd,
       "no area <0-4294967295> shortcut",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as Shortcut\n")


void
ospf_area_set_type (struct ospf_area *area, int type)
{
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;

  if (area->external_routing != type)
    {
      area->external_routing = type;

      switch (area->external_routing)
	{
	case OSPF_AREA_DEFAULT:
          zlog_info ("Z: Area %s configured as normal",
		    inet_ntoa(area->area_id));

          LIST_ITERATOR (area->iflist, node)
	    {
	      ifp = getdata (node);
	      if (ifp == NULL)
		continue;
	      oi = ifp->info;
	      if (oi == NULL)
		continue;
	      if (oi->nbr_self == NULL)
		continue;
	      SET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
	    }
          break;

	case OSPF_AREA_STUB:
          zlog_info ("Z: Area %s configured as stub",
		     inet_ntoa (area->area_id));

          LIST_ITERATOR (area->iflist, node)
	    {
	      ifp = getdata (node);
	      if (ifp == NULL)
		continue;
	      oi = ifp->info;
	      if (oi == NULL)
		continue;
	      if (oi->nbr_self == NULL)
		continue;
  
	      zlog_info ("Z: setting options on %s accordingly", ifp->name);
	      UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
	      zlog_info ("Z: options set on %s: %x", ifp->name, OPTIONS (oi));
	    }
          break;

	case OSPF_AREA_NSSA:
	  break;
	default:
	  ;
     }

     ospf_schedule_router_lsa_originate (area);
     ospf_schedule_abr_task ();
  }
}


int
ospf_area_stub_cmd (struct vty *vty, int argc, char **argv, int no_summary)
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ospf_vls_in_area (area))
    {
      vty_out (vty, "First deconfigure all VLs through this area%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf_area_set_type (area, OSPF_AREA_STUB);
  area->no_summary = no_summary;

  return CMD_SUCCESS;
}


DEFUN (area_stub,
       area_stub_cmd,
       "area A.B.C.D stub",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 0);
}

ALIAS (area_stub,
       area_stub_decimal_cmd,
       "area <0-4294967295> stub",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

DEFUN (area_stub_nosum,
       area_stub_nosum_cmd,
       "area A.B.C.D stub no-summary",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 1);
}

ALIAS (area_stub_nosum,
       area_stub_nosum_decimal_cmd,
       "area <0-4294967295> stub no-summary",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")

int
ospf_no_area_stub_cmd (struct vty *vty, int argc, char **argv, int no_summary)
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
     return CMD_SUCCESS;

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
     vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
     return CMD_WARNING;
    }

  if (no_summary)
    {
      area->no_summary = 0;
      return CMD_SUCCESS;
    }

  if (area->external_routing == OSPF_AREA_STUB)
    ospf_area_set_type (area, OSPF_AREA_DEFAULT);
  else
    {
      vty_out (vty, "Area is not stub%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}


DEFUN (no_area_stub,
       no_area_stub_cmd,
       "no area A.B.C.D stub",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 0);
}

ALIAS (no_area_stub,
       no_area_stub_decimal_cmd,
       "no area <0-4294967295> stub",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

DEFUN (no_area_stub_nosum,
       no_area_stub_nosum_cmd,
       "no area A.B.C.D stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 1);
}

ALIAS (no_area_stub_nosum,
       no_area_stub_nosum_decimal_cmd,
       "no area <0-4294967295> stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")

DEFUN (area_default_cost,
       area_default_cost_cmd,
       "area A.B.C.D default-cost <0-16777215>",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  u_int32_t cost;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area->external_routing == OSPF_AREA_DEFAULT)
    {
      vty_out (vty, "The area is neither stub, nor NSSA%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  cost = atol (argv[1]);

  if (cost > 16777215)
    {
      vty_out (vty, "Invalid cost value, expected <0-16777215>%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area->default_cost = cost;

  return CMD_SUCCESS;
}

DEFUN (no_area_default_cost,
       no_area_default_cost_cmd,
       "no area A.B.C.D default-cost <0-16777215>",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  u_int32_t cost;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
     vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
     return CMD_WARNING;
    }

  if (area->external_routing == OSPF_AREA_DEFAULT)
    {
     vty_out (vty, "The area is neither stub, nor NSSA%s", VTY_NEWLINE);
     return CMD_WARNING;
    }

  cost = atol (argv[1]);

  if (cost > 16777215)
    {
      vty_out (vty, "Invalid cost value, expected <0-16777215>%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (cost != area->default_cost)
    {
      vty_out (vty, "Specified cost value is not equal to the configured one%s", VTY_NEWLINE);
     return CMD_WARNING;
  }

  area->default_cost = 1;

  return CMD_SUCCESS;
}


int
ospf_set_area_export_list (struct ospf_area * area, char * list_name)
{
  struct access_list *list;
  list = access_list_lookup(AF_INET, list_name);

  EXP_LIST_PTR(area) = list;

  if (EXP_LIST_NAME(area))
    free (EXP_LIST_NAME(area));

  EXP_LIST_NAME(area) = strdup (list_name);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}

int
ospf_unset_area_export_list (struct ospf_area * area)
{

  EXP_LIST_PTR(area) = 0;

  if (EXP_LIST_NAME(area))
    free (EXP_LIST_NAME(area));

  EXP_LIST_NAME(area) = NULL;
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


DEFUN (area_export_list,
       area_export_list_cmd,
       "area A.B.C.D export-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  return ospf_set_area_export_list(area, argv[1]);
}

ALIAS (area_export_list,
       area_export_list_decimal_cmd,
       "area <0-4294967295> export-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFUN (no_area_export_list,
       no_area_export_list_cmd,
       "no area A.B.C.D export-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
     vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
     return CMD_WARNING;
    }

  return ospf_unset_area_export_list(area);
}

ALIAS (no_area_export_list,
       no_area_export_list_decimal_cmd,
       "no area <0-4294967295> export-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")


int
ospf_set_area_import_list (struct ospf_area * area, char * list_name)
{
  struct access_list *list;
  list = access_list_lookup(AF_INET, list_name);

  IMP_LIST_PTR(area) = list;

  if (IMP_LIST_NAME(area))
    free (IMP_LIST_NAME(area));

  IMP_LIST_NAME(area) = strdup (list_name);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}

int
ospf_unset_area_import_list (struct ospf_area * area)
{

  IMP_LIST_PTR(area) = 0;

  if (IMP_LIST_NAME(area))
    free (IMP_LIST_NAME(area));

  IMP_LIST_NAME(area) = NULL;
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


DEFUN (area_import_list,
       area_import_list_cmd,
       "area A.B.C.D import-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  return ospf_set_area_import_list(area, argv[1]);
}

ALIAS (area_import_list,
       area_import_list_decimal_cmd,
       "area <0-4294967295> import-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")

DEFUN (no_area_import_list,
       no_area_import_list_cmd,
       "no area A.B.C.D import-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
     vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
     return CMD_WARNING;
    }

  return ospf_unset_area_import_list(area);
}

ALIAS (no_area_import_list,
       no_area_import_list_decimal_cmd,
       "no area <0-4294967295> import-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")





DEFUN (area_authentication_message_digest,
       area_authentication_message_digest_cmd,
       "area A.B.C.D authentication message-digest",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  area->auth_type = OSPF_AUTH_CRYPTOGRAPHIC;

  return CMD_SUCCESS;
}

ALIAS (area_authentication_message_digest,
       area_authentication_message_digest_decimal_cmd,
       "area <0-4294967295> authentication message-digest",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")

DEFUN (area_authentication,
       area_authentication_cmd,
       "area A.B.C.D authentication",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = ret;
      list_add_node (ospf_top->areas, area);
      ospf_check_abr_status ();
    }

  area->auth_type = OSPF_AUTH_SIMPLE;

  return CMD_SUCCESS;
}

ALIAS (area_authentication,
       area_authentication_decimal_cmd,
       "area <0-4294967295> authentication",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")

DEFUN (no_area_authentication,
       no_area_authentication_cmd,
       "no area A.B.C.D authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;

  if (!ospf_str2area_id (argv[0], &area_id))
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area ID %s is not declared%s", inet_ntoa (area_id),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area->auth_type = OSPF_AUTH_NULL;

  return CMD_SUCCESS;
}

ALIAS (no_area_authentication,
       no_area_authentication_decimal_cmd,
       "no area <0-4294967295> authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")


DEFUN (ospf_abr_type_stand,
       ospf_abr_type_stand_cmd,
       "ospf abr-type standard",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Standard behavior (RFC2328)\n")
{

  if (ospf_top->abr_type != OSPF_ABR_STAND)
    {
      ospf_top->abr_type = OSPF_ABR_STAND;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (ospf_abr_type_ibm,
       ospf_abr_type_ibm_cmd,
       "ospf abr-type ibm",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, IBM implementation\n")
{
  if (ospf_top->abr_type != OSPF_ABR_IBM)
    {
      ospf_top->abr_type = OSPF_ABR_IBM;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type_ibm,
       no_ospf_abr_type_ibm_cmd,
       "no ospf abr-type ibm",
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, IBM implementation\n")
{
  if (ospf_top->abr_type == OSPF_ABR_IBM)
    {
      ospf_top->abr_type = OSPF_ABR_STAND;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (ospf_abr_type_cisco,
       ospf_abr_type_cisco_cmd,
       "ospf abr-type cisco",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n")
{
  if (ospf_top->abr_type != OSPF_ABR_CISCO)
    {
      ospf_top->abr_type = OSPF_ABR_CISCO;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type_cisco,
       no_ospf_abr_type_cisco_cmd,
       "no ospf abr-type cisco",
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n")
{
  if (ospf_top->abr_type == OSPF_ABR_CISCO)
    {
      ospf_top->abr_type = OSPF_ABR_STAND;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (ospf_abr_type_shortcut,
       ospf_abr_type_shortcut_cmd,
       "ospf abr-type shortcut",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Shortcut ABR\n")
{
  if (ospf_top->abr_type != OSPF_ABR_SHORTCUT)
    {
      ospf_top->abr_type = OSPF_ABR_SHORTCUT;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type_shortcut,
       no_ospf_abr_type_shortcut_cmd,
       "no ospf abr-type shortcut",
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Shortcut ABR\n")
{
  if (ospf_top->abr_type == OSPF_ABR_SHORTCUT)
    {
      ospf_top->abr_type = OSPF_ABR_STAND;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

char *ospf_abr_type_descr_str[] = 
{
  "Unknown",
  "Standard (RFC2328)",
  "Alternative IBM",
  "Alternative Cisco",
  "Alternative Shortcut"
};


DEFUN (show_ip_ospf,
       show_ip_ospf_cmd,
       "show ip ospf",
       SHOW_STR
       IP_STR
       "OSPF information\n")
{
  listnode node;
  struct ospf_area * area;

  if (ospf_top == NULL)
    {
      vty_out (vty, " OSPF Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  vty_out (vty, " OSPF Routing Process, Router ID: %s%s",
	   inet_ntoa (ospf_top->router_id),
	   VTY_NEWLINE);
  vty_out (vty, " Supports only single TOS (TOS0) routes%s", VTY_NEWLINE);

  if (CHECK_FLAG (ospf_top->flags, OSPF_FLAG_ABR))
    {
      vty_out (vty, " This router is an ABR, ABR type is: %s%s",
	       ospf_abr_type_descr_str[ospf_top->abr_type],
	       VTY_NEWLINE);
    }

  if (CHECK_FLAG (ospf_top->flags, OSPF_FLAG_ASBR))
    {
      vty_out (vty, " This router is an ASBR "
	       "(injecting external routing information)%s", VTY_NEWLINE);
    }

  vty_out (vty, " Number of areas attached to this router: %d%s%s",
	   listcount (ospf_top->areas),
	   VTY_NEWLINE,
	   VTY_NEWLINE);

  LIST_ITERATOR (ospf_top->areas, node)
    {
      area = getdata (node);
      if (area == NULL)
	continue;

      vty_out (vty, " Area ID: %s", inet_ntoa (area->area_id));

      if (area->area_id.s_addr == OSPF_AREA_BACKBONE)
	vty_out (vty, " (Backbone)%s", VTY_NEWLINE);
      else
	{
	  if (area->shortcut_configured || 
	      (area->external_routing == OSPF_AREA_STUB))
	    {

	      vty_out (vty, " (");

	      if (area->external_routing == OSPF_AREA_STUB)
		{
		  vty_out (vty, "Stub");

		  if (area->no_summary)
		    vty_out (vty, ", no summary");
		  if (area->shortcut_configured)
		    vty_out (vty, "; ");
		}

	      if (area->shortcut_configured)
		{
		  vty_out (vty, "Shortcut configured");

		  if (area->shortcut_capability == 0)
		    vty_out (vty, ", but not active");
		  else
		    vty_out (vty, " and active");
		}

	      vty_out (vty, ")");
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	}


      vty_out (vty, "   Number of interfaces in this area: Total:"
	       " %d, Active: %d%s",
	       listcount(area->iflist),
	       area->act_ints,
	       VTY_NEWLINE);

      vty_out (vty, "   Number of fully adjacent neighbors in this area:"
	       " %d%s", area->full_nbrs,
	       VTY_NEWLINE);

      if (area->area_id.s_addr != OSPF_AREA_BACKBONE)
	vty_out (vty, "   Number of full virtual adjacencies going through"
		 " this area: %d%s", area->full_vls,
		 VTY_NEWLINE);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

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
    vty_out (vty, "%s is up, line protocol is up%s", ifp->name, VTY_NEWLINE);
  else
    vty_out (vty, "%s is down, line protocol is down%s", ifp->name,
	     VTY_NEWLINE);

  oi = ifp->info;

  /* is interface OSPF enabled? */
  if (oi == NULL)
    {
      vty_out (vty, "  OSPF not enabled on this interface%s", VTY_NEWLINE);
      return;
    }
  if (oi->flag == OSPF_IF_DISABLE || oi->address == NULL)
    {
      vty_out (vty, "  OSPF not enabled on this interface%s", VTY_NEWLINE);
      return;
    }
      
  /* show OSPF interface information. */
  vty_out (vty, "  Internet Address %s/%d,",
	   inet_ntoa (oi->address->u.prefix4), oi->address->prefixlen);

  vty_out (vty, " Area %s%s", inet_ntoa (oi->area->area_id),
	   VTY_NEWLINE);

  vty_out (vty, "  Router ID %s, Network Type %s, Cost: %d%s",
	   inet_ntoa (ospf_top->router_id),
	   ospf_network_type_str[oi->type],
	   oi->output_cost,
	   VTY_NEWLINE);

  vty_out (vty, "  Transmit Delay is %d sec, State %s, Priority %d%s",
	   oi->transmit_delay,
	   LOOKUP (ospf_ism_status_msg, oi->status),
	   PRIORITY (oi),
	   VTY_NEWLINE);

  /* show DR information. */
  if (DR (oi).s_addr == 0)
    vty_out (vty, "  No designated router on this network%s", VTY_NEWLINE);
  else
    {
      key.family = AF_INET;
      key.prefixlen = 32;
      key.u.prefix4 = DR (oi);

      rn = route_node_get (oi->nbrs, &key);
      if (rn == NULL)
	vty_out (vty, "  No designated router on this network%s", VTY_NEWLINE);
      else if (rn->info == NULL)
	vty_out (vty, "  No designated router on this network%s", VTY_NEWLINE);
      else
	{
	  nbr = (struct ospf_neighbor *) rn->info;

	  vty_out (vty, "  Designated Router (ID) %s,",
		   inet_ntoa (DR (oi)));
	  vty_out (vty, " Interface Address %s%s",
		   inet_ntoa (nbr->address.u.prefix4),
		   VTY_NEWLINE);
	}
      route_unlock_node (rn);
    }

  /* show BDR information. */
  if (BDR (oi).s_addr == 0)
    vty_out (vty, "  No backup designated router on this network%s",
	     VTY_NEWLINE);
  else
    {
      key.family = AF_INET;
      key.prefixlen = 32;
      key.u.prefix4 = BDR (oi);

      rn = route_node_get (oi->nbrs, &key);
      if (rn == NULL)
	vty_out (vty, "  No backup designated router on this network%s",
		 VTY_NEWLINE);
      else if (rn->info == NULL)
	vty_out (vty, "  No backup designated router on this network%s",
		 VTY_NEWLINE);
      else
	{
	  nbr = (struct ospf_neighbor *) rn->info;

	  vty_out (vty, "  Backup Designated Router (ID) %s,",
		   inet_ntoa (BDR (oi)));
	  vty_out (vty, " Interface Address %s%s",
		   inet_ntoa (nbr->address.u.prefix4),
		   VTY_NEWLINE);
	}
      route_unlock_node (rn);
    }

  vty_out (vty, "  Timer intarvals configured,");
  vty_out (vty, " Hello %d, Dead %d, Wait %d, Retransmit %d%s",
	   oi->v_hello,
	   oi->v_wait,
	   oi->v_wait, oi->retransmit_interval,
	   VTY_NEWLINE);

  vty_out (vty, "    Hello due in %s%s",
	   ospf_timer_dump (oi->t_hello, buf, 9),
	   VTY_NEWLINE);

  vty_out (vty, "  Neighbor Count is %d, Adjacent neighbor count is %d%s",
	   ospf_nbr_count (oi->nbrs, 0),
	   ospf_nbr_count (oi->nbrs, NSM_Full),
	   VTY_NEWLINE);
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
	vty_out (vty, "No such interface name%s", VTY_NEWLINE);
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

  oi = ifp->info;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if (!rn->info)
	continue;

      nbr = rn->info;

      /* Do not show myself. */
      /*      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	      continue; */
      if (nbr == nbr->oi->nbr_self)
	continue;

      /* Down state is not shown. */
      if (nbr->status == NSM_Down)
	continue;

      ospf_nbr_state_message (nbr, msgbuf, 16);

      vty_out (vty, "%-15s %3d   %-15s %8s    %-15s %-15s %5d %5d %5d%s",
	       inet_ntoa (nbr->router_id), nbr->priority,
	       msgbuf, ospf_timer_dump (nbr->t_inactivity, timebuf, 9),
	       nbr->host, ifp->name, listcount(nbr->ls_retransmit),
	       listcount(nbr->ls_request), listcount(nbr->db_summary),
	       VTY_NEWLINE);
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
      vty_out (vty, "%sNeighbor ID     Pri   State           Dead "
                    "Time   Address         Interface           RXmtL "
                    "RqstL DBsmL%s", VTY_NEWLINE, VTY_NEWLINE);
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
	vty_out (vty, "No such interface name%s", VTY_NEWLINE);
      else
	{
	  vty_out (vty, "%sNeighbor ID     Pri   State           Dead "
                        "Time   Address         Interface           RXmtL "
                        "RqstL DBsmL%s", VTY_NEWLINE,
		   VTY_NEWLINE);
	  show_ip_ospf_neighbor_sub (vty, ifp);
	}
    }

  return CMD_SUCCESS;
}

char *ospf_abr_type_str[] = 
{
  "unknown",
  "standard",
  "ibm",
  "cisco",
  "shortcut"
};



/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  struct route_node *rn;
  listnode node;
  u_char buf[INET_ADDRSTRLEN];
  int write = 0;

  if (ospf_top != NULL)
    {
      /* router ospf print. */
      vty_out (vty, "router ospf%s", VTY_NEWLINE);

      write++;

      if (! ospf_top->networks)
	return write;

      /* Router ID print. */
      if (ospf_top->router_id_static.s_addr != 0)
	vty_out (vty, " ospf router-id %s%s",
		 inet_ntoa (ospf_top->router_id_static),
		 VTY_NEWLINE);

      if (ospf_top->abr_type != OSPF_ABR_STAND)
        vty_out (vty, " ospf abr-type %s%s", 
		 ospf_abr_type_str[ospf_top->abr_type],
		 VTY_NEWLINE);

      /* Redistribute information print. */
      config_write_ospf_redistribute (vty);

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
	    sprintf (buf, "%lu", 
		     (unsigned long int) ntohl (n->area_id.s_addr));

	  /* print network. */
	  vty_out (vty, " network %s/%d area %s%s",
		   inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		   buf,
		   VTY_NEWLINE);
	}

      /* area configuration print. */
      for (node = listhead (ospf_top->areas); node; nextnode (node))
	{
	  struct ospf_area *a;
	  struct route_node *rn1;
	  
	  a = getdata (node);

          bzero (&buf, INET_ADDRSTRLEN);

	  if (a->format == OSPF_AREA_ID_FORMAT_ADDRESS)
	      strncpy (buf, inet_ntoa (a->area_id), INET_ADDRSTRLEN);
	  else
	      sprintf (buf, "%lu", (unsigned long int) ntohl (a->area_id.s_addr));

	  if (a->auth_type != OSPF_AUTH_NULL)
	    {

	      if (a->auth_type == OSPF_AUTH_SIMPLE)
		vty_out (vty, " area %s authentication%s",
			 buf,
			 VTY_NEWLINE);
	      else
		vty_out (vty, " area %s authentication message-digest%s",
			 buf,
			 VTY_NEWLINE);
	    }

          if (a->shortcut_configured)
 	     vty_out (vty, " area %s shortcut%s", buf,
		      VTY_NEWLINE);

          if (a->external_routing == OSPF_AREA_STUB)
	    {
	      vty_out (vty, " area %s stub", buf);

	      if (a->no_summary)
  	        vty_out (vty, " no-summary");

	      vty_out (vty, "%s", VTY_NEWLINE);

	      if (a->default_cost != 1)
  	        vty_out (vty, " area %s default-cost %lu%s", buf, 
		         a->default_cost, VTY_NEWLINE);
	    }

          for (rn1 = route_top (a->ranges); rn1; rn1 = route_next (rn1))
	    {
	      struct ospf_area_range *range;

	      if (rn1->info == NULL)
		continue;

	      range = rn1->info;

	      vty_out (vty, " area %s range %s/%d", buf,
		       inet_ntoa (rn1->p.u.prefix4), rn1->p.prefixlen);

	      if (CHECK_FLAG(range->flags, OSPF_RANGE_SUPPRESS))
		vty_out (vty, " suppress");

	      if (CHECK_FLAG(range->flags, OSPF_RANGE_SUBST))
		vty_out (vty, " substitute %s/%d",
			 inet_ntoa (range->substitute.prefix), 
			 range->substitute.prefixlen);

	      vty_out (vty, "%s", VTY_NEWLINE);
	    }

           if (EXP_LIST_NAME(a))
 	      vty_out (vty, " area %s export-list %s%s", buf, EXP_LIST_NAME(a),
                       VTY_NEWLINE);

           if (IMP_LIST_NAME(a))
 	      vty_out (vty, " area %s import-list %s%s", buf, IMP_LIST_NAME(a),
                       VTY_NEWLINE);

	}

      /* virtual link print */
      LIST_ITERATOR (ospf_top->vlinks, node)
	{
	  struct ospf_vl_data *vl_data;
	  struct ospf_area *area;

	  vl_data = getdata (node);
	  if (vl_data == NULL)
	    continue;

	  area = vl_data->vl_area;
	  if (area == NULL)
	    continue;

	  bzero (&buf, INET_ADDRSTRLEN);

	  if (area->format == OSPF_AREA_ID_FORMAT_ADDRESS)
	    strncpy (buf, inet_ntoa (area->area_id), INET_ADDRSTRLEN);
	  else
	    sprintf (buf, "%lu", 
		     (unsigned long int) ntohl (area->area_id.s_addr));

	  vty_out(vty, " area %s virtual-link %s%s", buf,
		  inet_ntoa (vl_data->vl_peer),
		  VTY_NEWLINE);

	}
    }

  return write;
}

struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# ",
};

/* Install OSPF related commands. */
void
ospf_init ()
{
  /* Install ospf top node. */
  install_node (&ospf_node, ospf_config_write);

  /* Install ospf commands. */
  install_element (VIEW_NODE, &show_ip_ospf_interface_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_cmd);
  /* install_element (VIEW_NODE, &show_ip_ospf_cmd); */
  install_element (ENABLE_NODE, &show_ip_ospf_interface_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_cmd);
  /* install_element (ENABLE_NODE, &show_ip_ospf_cmd); */
  install_element (CONFIG_NODE, &router_ospf_cmd);
  install_element (CONFIG_NODE, &no_router_ospf_cmd);

  install_default (OSPF_NODE);
  install_element (OSPF_NODE, &ospf_router_id_cmd);
  install_element (OSPF_NODE, &no_ospf_router_id_cmd);
  install_element (OSPF_NODE, &ospf_abr_type_stand_cmd);
  install_element (OSPF_NODE, &ospf_abr_type_ibm_cmd);
  install_element (OSPF_NODE, &no_ospf_abr_type_ibm_cmd);
  install_element (OSPF_NODE, &ospf_abr_type_cisco_cmd);
  install_element (OSPF_NODE, &no_ospf_abr_type_cisco_cmd);
  install_element (OSPF_NODE, &ospf_abr_type_shortcut_cmd);
  install_element (OSPF_NODE, &no_ospf_abr_type_shortcut_cmd);

  install_element (OSPF_NODE, &network_area_decimal_cmd);
  install_element (OSPF_NODE, &network_area_cmd);
  install_element (OSPF_NODE, &no_network_area_decimal_cmd);
  install_element (OSPF_NODE, &no_network_area_cmd);

  install_element (OSPF_NODE, &area_authentication_message_digest_decimal_cmd);
  install_element (OSPF_NODE, &area_authentication_message_digest_cmd);

  install_element (OSPF_NODE, &area_authentication_decimal_cmd);
  install_element (OSPF_NODE, &area_authentication_cmd);
  install_element (OSPF_NODE, &no_area_authentication_decimal_cmd);
  install_element (OSPF_NODE, &no_area_authentication_cmd);

  install_element (OSPF_NODE, &area_range_decimal_cmd);
  install_element (OSPF_NODE, &area_range_cmd);
  install_element (OSPF_NODE, &no_area_range_decimal_cmd);
  install_element (OSPF_NODE, &no_area_range_cmd);
  install_element (OSPF_NODE, &area_range_suppress_cmd);
  install_element (OSPF_NODE, &no_area_range_suppress_cmd);
  install_element (OSPF_NODE, &area_range_subst_cmd);
  install_element (OSPF_NODE, &no_area_range_subst_cmd);

  install_element (OSPF_NODE, &area_vlink_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_cmd);
  install_element (OSPF_NODE, &no_area_vlink_decimal_cmd);
  install_element (OSPF_NODE, &no_area_vlink_cmd);

  install_element (OSPF_NODE, &area_stub_nosum_cmd);
  install_element (OSPF_NODE, &area_stub_nosum_decimal_cmd);
  install_element (OSPF_NODE, &area_stub_cmd);
  install_element (OSPF_NODE, &area_stub_decimal_cmd);
  install_element (OSPF_NODE, &no_area_stub_nosum_cmd);
  install_element (OSPF_NODE, &no_area_stub_nosum_decimal_cmd);
  install_element (OSPF_NODE, &no_area_stub_cmd);
  install_element (OSPF_NODE, &no_area_stub_decimal_cmd);
  install_element (OSPF_NODE, &area_default_cost_cmd);
  install_element (OSPF_NODE, &no_area_default_cost_cmd);

  install_element (OSPF_NODE, &area_shortcut_decimal_cmd);
  install_element (OSPF_NODE, &area_shortcut_cmd);
  install_element (OSPF_NODE, &no_area_shortcut_decimal_cmd);
  install_element (OSPF_NODE, &no_area_shortcut_cmd);

  install_element (OSPF_NODE, &area_export_list_cmd);
  install_element (OSPF_NODE, &area_export_list_decimal_cmd);
  install_element (OSPF_NODE, &no_area_export_list_cmd);
  install_element (OSPF_NODE, &no_area_export_list_decimal_cmd);

  install_element (OSPF_NODE, &area_import_list_cmd);
  install_element (OSPF_NODE, &area_import_list_decimal_cmd);
  install_element (OSPF_NODE, &no_area_import_list_cmd);
  install_element (OSPF_NODE, &no_area_import_list_decimal_cmd);


  /*
  install_element (OSPF_NODE, &neighbor_cmd);
  install_element (OSPF_NODE, &no_neighbor_cmd);
  */

  /* Make empty list of ospf list. */
  ospf_top = NULL;

  zebra_init ();
}

void
ospf_init_end ()
{
  install_element (VIEW_NODE, &show_ip_ospf_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_cmd);
}
