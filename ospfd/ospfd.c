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
#include "ospfd/ospf_zebra.h"

/* List head of ospf instance list. */
list ospf_list;


/* Allocate new ospf structure. */
struct ospf *
ospf_new (u_int16_t process_id)
{
  struct ospf *new = (struct ospf *) malloc (sizeof (struct ospf));
  bzero (new, sizeof (struct ospf));

  new->process_id = process_id;
  new->if_list = iflist;
  new->neighbor = NULL;
  new->network_area = (struct route_table *) route_table_init ();

  list_add_node (ospf_list, new);

  return new;
}

/* OSPF structure specify by process_id. */
struct ospf *
ospf_lookup_by_process_id (u_int16_t process_id)
{
  struct ospf *ospf;
  listnode node;

  node = listhead (ospf_list);
  while (node)
    {
      ospf = getdata (node);
      if (ospf->process_id == process_id)
	return ospf;
      nextnode (node);
    }
  return NULL;
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
	    if (oi->flag == OSPF_FLAG_SLEEP)
	      {	      
		oi->flag = OSPF_FLAG_RUNNING;
		OSPF_ISM_EVENT_ADD (ifp->if_data, ISM_LoopInd);
	      }
	}
    }
}

void
ospf_interface_run (struct ospf *ospf, struct prefix *p)
{
  struct interface *ifp;
  listnode node;

  /* get target interface. */
  for (node = listhead (ospf->if_list); node; nextnode (node))
    {
      listnode cn;
      struct ospf_interface *oi;
      u_char flag = OSPF_FLAG_SLEEP;

      ifp = getdata (node);
      oi = ifp->if_data;

      /* is interface up? */
      if (! if_is_up (ifp))
	continue;

      if (oi->flag == OSPF_FLAG_RUNNING)
	continue;

      /* if interface prefix is match specified prefix,
	 then create socket and join multicast group. */
      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co;
	  struct sockaddr_in sa;
	  struct in_addr addr;
	  int sock;

	  co = getdata (cn);
	  /* get pointer of interface prefix. */
	  oi->address = co->address;

	  if (prefix_match (co->address, p))
	    {
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

	      /* */
	      bzero ((char *) &sa, sizeof (sa));
	      inet_aton (OSPF_ALLSPFROUTERS, &addr);
	      sa.sin_family = AF_INET;
	      sa.sin_addr = addr;
	      sa.sin_port = htons (0);
/* 	      if (bind (sock, (struct sockaddr *) &sa, sizeof (sa)) < 0)
		{
		  zlog (NULL, LOG_WARNING,
			"interface %s can't bind socket", ifp->name);
		  continue;
		}
*/
	      /* create input/output buffer stream. */
	      ospf_if_stream_set (sock, ifp->if_data);

	      /* Remember this interface is running. */
	      flag = OSPF_FLAG_RUNNING;

	      OSPF_ISM_EVENT_ADD (ifp->if_data, ISM_InterfaceUp);
	    }
	}
      oi->flag = flag;
    }
}

void
ospf_if_update ()
{
  struct ospf *ospf;
  listnode node;
  struct route_node *rn;

  for (node = listhead (ospf_list); node; nextnode (node))
    if ((ospf = getdata (node)) != NULL)
      {
	ospf_loopback_run (ospf);

	for (rn = route_top (ospf->network_area); rn; rn = route_next (rn))
	  ospf_interface_run (ospf, &rn->p);
      }
}

/* router ospf command */
DEFUN (router_ospf,
       router_ospf_cmd,
       "router ospf PROCESS_ID",
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "OSPF Process ID\n")
{
  u_int16_t process_id;
  struct ospf *ospf;

  process_id = strtol (argv[0], NULL, 10);
  if (!process_id)
    {
      vty_out (vty, "OSPF Process ID is invalid\r\n");
      return CMD_WARNING;
    }

  ospf = ospf_lookup_by_process_id (process_id);

  /* There is already active ospf instance. */
  if (ospf != NULL)
    {
      vty->node = OSPF_NODE;
      vty->index = ospf;
      return CMD_SUCCESS;
    }

  /* Make new ospf instance. */
  ospf = ospf_new (process_id);

  /* Set current ospf point. */
  vty->node = OSPF_NODE;
  vty->index = ospf;

  ospf_loopback_run (ospf);

  return CMD_SUCCESS;
}

DEFUN (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf PROCESS_ID",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "OSPF Process ID\n")
{
  struct ospf *ospf;
  u_int16_t process_id;

  process_id = strtol (argv[0], NULL, 10);

  /* Check existing ospf. */
  ospf = ospf_lookup_by_process_id (process_id);

  if (ospf == NULL)
    {
      vty_out (vty, "There isn't active ospf instance under process ID %d.\r\n", process_id);
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

  ospf_interface_run (ospf, &p);

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

/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  struct route_node *node;
  struct ospf *ospf;

  ospf = vty->index;

  /* no ospf instance. */
  if (! ospf)
    return 0;

  /* router ospf print. */
  vty_out (vty, "router ospf %u%s", ospf->process_id, VTY_NEWLINE);

  /* network area print. */
  for (node = route_top (ospf->network_area); node; node = route_next (node))
    {
      struct area *area;
      u_char area_id_buf[16];

      if (node->info == NULL)
	continue;

      area = node->info;

      /* print nework statement as specified Area ID format. */
      if (area->area_id_format == OSPF_AREA_ID_FORMAT_ADDRESS)
	{
	  bzero (&area_id_buf, 16);
	  strncpy (area_id_buf, inet_ntoa (area->area_id), 16);
	  vty_out (vty, " network %s/%d area %s%s",
		   inet_ntoa (node->p.u.prefix4), node->p.prefixlen,
		   area_id_buf, VTY_NEWLINE);
	}
      else
	{
	  vty_out (vty, " network %s/%d area %u%s",
		   inet_ntoa (node->p.u.prefix4), node->p.prefixlen,
		   area->area_id.s_addr, VTY_NEWLINE);
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
  ospf_list = list_init ();

  zebra_init ();
}
