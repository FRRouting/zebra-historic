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

#include "ospfd.h"

/* Thread master. */
extern struct thread_master *master;
extern FILE *logfp;

/* global ospfd variable */
list ospf_list;
list ospf_iflist;

char *autype_name[] = 
{
  "null",
  "simplepasswd",
  "crypto",
  "other",
};

char *ifs_name[] =
{
  "NONE",
  "DOWN",
  "LOOPBACK",
  "WAITING",
  "POINTTOPOINT",
  "DROTHER",
  "BDR",
  "DR",
  NULL
};

char *nbs_name[] =
{
  "NONE",
  "DOWN",
  "ATTEMPT",
  "INIT",
  "TWOWAY",
  "EXSTART",
  "EXCHANGE",
  "LOADING",
  "FULL",
  NULL
};

/* Allocate new ospf structure. */
struct ospf *
ospf_new ()
{
  struct ospf *new = (struct ospf *)
                 XMALLOC (MTYPE_OSPF_TOP, sizeof (struct ospf));
  if (new)
    bzero (new, sizeof (struct ospf));
  return new;
}

/* Allocate new area structure. */
struct area *
area_new ()
{
  struct area *new = (struct area *)
                 XMALLOC (MTYPE_OSPF_AREA, sizeof (struct area));
  if (new)
    bzero (new, sizeof (struct area));
  return new;
}

/* Allocate new interface structure */
struct ospf_if *
ospf_if_new ()
{
  struct ospf_if *new = (struct ospf_if *)
                 XMALLOC (MTYPE_OSPF_IF, sizeof (struct ospf_if));
  if (new)
    bzero (new, sizeof (struct ospf_if));
  return new;
}

#if 0
set_ospf_if_default_val (struct ospf_if *)
{
  interface->inf_trans_delay = 1;
  interface->rtr_pri = 1;
  interface->hello_interval = 10;
  interface->rtr_dead_interval = 40;
  interface->rxmt_interval = 5;
  interface->cost = 1;
}
#else
#define set_ospf_if_default_val(X) \
{ \
            (X)->inf_trans_delay = 1; \
            (X)->rtr_pri = 1; \
            (X)->hello_interval = 10; \
            (X)->rtr_dead_interval = 40; \
            (X)->rxmt_interval = 5; \
            (X)->cost = 1; \
} 
#endif

/* Allocate new Neighbor data structure */
struct neighbor *
neighbor_new ()
{
  struct neighbor *new = (struct neighbor *)
    XMALLOC (MTYPE_OSPF_NEIGHBOR, sizeof (struct neighbor));
  if (new)
    bzero (new, sizeof (struct neighbor));

  return new;
}

/* Make new neighbor structure */
struct neighbor *
make_neighbor (rtr_id_t rtr_id, struct ospf_if *iface)
{
  struct neighbor *nbp = neighbor_new ();

  if (!nbp)
    return NULL;
  nbp->state = NBS_DOWN;
  nbp->interface = iface;
  id_val (nbp->rtr_id) = id_val (rtr_id);
  nbp->inactivity_timer = NULL;
  nbp->dd_retrans = list_init ();
  nbp->summarylist = list_init ();
  nbp->retranslist = list_init ();
  nbp->requestlist = list_init ();
  list_add_node (iface->nb_list, nbp);

  return nbp;
}

/* Make new interface structure */
struct ospf_if *
make_ospf_if (char *ifname)
{
  struct ospf_if *ospf_if;
  struct interface *interface;

  interface = if_lookup_by_name (ifname);
  if (!interface)
    {
      zlog (NULL, LOG_ERR, "Can't find Interface: %s\n", ifname);
      return (struct ospf_if *)NULL;
    }

  ospf_if = ospf_if_new ();
  if (!ospf_if)
    {
      zlog (NULL, LOG_ERR, "Can't allocate ospf_if for %s\n", ifname);
      return (struct ospf_if *)NULL;
    }

  ospf_if->interface = interface;
  ospf_if->ifname = interface->name;
  ospf_if->ifid = interface->index;

  ospf_if->area = (struct area *)NULL;
  ospf_if->state = IFS_DOWN;
  ospf_if->nb_list = list_init ();

  ospf_if->linklocal_lsa = list_init ();

  set_ospf_if_default_val (ospf_if);

  return ospf_if;
}

/* Make new area structure */
struct area *
make_area (area_id_t area_id, struct ospf *ospf)
{
  int i, j;
  struct area *area = area_new ();

  if (!area)
    {
      /* AREA 
      zlog (NULL, LOG_ERR, "Can't allocate area for %s\n",
	    area_id_str (area_id));
      */
      return (struct area *)NULL;
    }

  id_val(area->area_id) = id_val(area_id);
  area->ospf_if_list = list_init ();

  area->router_lsa_seqnum = INITIAL_SEQUENCE_NUMBER;
  area->network_lsa_seqnum = INITIAL_SEQUENCE_NUMBER;
  area->link_lsa_seqnum = INITIAL_SEQUENCE_NUMBER;
  area->intra_prefix_seqnum = INITIAL_SEQUENCE_NUMBER;

  for (i = 0; i < AREALSTYPESIZE; i++)
    {
      for (j = 0; j < HASHVAL; j++)
	{
	  area->lsdb[i][j] = list_init ();
	}
    }

  switch (ospf->version)
    {
    case OSPF_V3:
      V3_EBIT_SET (area->options);
      V3_V6BIT_SET (area->options);
      V3_RBIT_SET (area->options);
      break;
    case OSPF_V2:
      EBITSET(area->options);
      break;
    default:
      log ("Unknown version in make_area()\n");
      free (area);
      return NULL;
    }

  list_add_node (ospf->area_list, area);
  area->ospf = ospf;
  return area;
}

/* Make new ospf structure */
struct ospf *
make_ospf (vers_t vers, instance_id_t i_id, rtr_id_t r_id)
{
  struct ospf *ospf = ospf_new ();

  if (!ospf)
    return NULL;

  ospf->version = vers;
  ospf->instance_id = i_id;
  id_val(ospf->router_id) = id_val(r_id);
  ospf->area_list = list_init ();
  list_add_node (ospf_list, ospf);
  return ospf;
}

/* delete neighbor from interface neighbor_list */
void
delete_all_neighbors (struct ospf_if *interface)
{
  return;
}

/* delete interface from area interface_list */
void
delete_interface (struct ospf_if *interface, struct area *area)
{
  delete_all_neighbors (interface);
  list_delete_by_val (area->ospf_if_list, interface);
  return;
}

void
delete_all_interface (struct area *area)
{
  listnode node;

  for (node = listhead (area->ospf_if_list);
       !list_isempty (area->ospf_if_list);
       node = listhead (area->ospf_if_list))
    {
      delete_interface (getdata (node), area);
    }

  return;
}

void
detach_interface (struct ospf_if *iface, struct area *area)
{
  list_delete_by_val (area->ospf_if_list, iface);
  iface->state = IFS_DOWN;
  iface->area = NULL;
}

void
detach_all_interface (struct area *area)
{
  listnode node;

  for (node = listhead (area->ospf_if_list);
       !list_isempty (area->ospf_if_list);
       node = listhead (area->ospf_if_list))
    {
      detach_interface (getdata (node), area);
    }

  return;
}

int
related_thread_cancel (struct area *area)
{
  struct thread *thread;

  /* Cancel related thread */
  for (thread = master->read.head; thread; thread = thread->next)
    {
      void *arg = THREAD_ARG (thread);
      if (((struct neighbor *)arg)->interface->area == area)
	{
	  thread_cancel (thread);
	  thread = master->read.head;
	}
      if (((struct ospf_if *)arg)->area == area)
	{
	  thread_cancel (thread);
	  thread = master->read.head;
	}
    }
  for (thread = master->write.head; thread; thread = thread->next)
    {
      void *arg = THREAD_ARG (thread);
      if (((struct neighbor *)arg)->interface->area == area)
	{
	  thread_cancel (thread);
	  thread = master->write.head;
	}
      if (((struct ospf_if *)arg)->area == area)
	{
	  thread_cancel (thread);
	  thread = master->write.head;
	}
    }
  for (thread = master->timer.head; thread; thread = thread->next)
    {
      void *arg = THREAD_ARG (thread);
      if (((struct neighbor *)arg)->interface->area == area)
	{
	  thread_cancel (thread);
	  thread = master->timer.head;
	}
      if (((struct ospf_if *)arg)->area == area)
	{
	  thread_cancel (thread);
	  thread = master->timer.head;
	}
    }
  for (thread = master->event.head; thread; thread = thread->next)
    {
      void *arg = THREAD_ARG (thread);
      if (((struct neighbor *)arg)->interface->area == area)
	{
	  thread_cancel (thread);
	  thread = master->event.head;
	}
      if (((struct ospf_if *)arg)->area == area)
	{
	  thread_cancel (thread);
	  thread = master->event.head;
	}
    }
  return 0;
}

/* delete area from ospf area_list */
void
delete_area (struct area *area, struct ospf *ospf)
{
  /* related_thread_cancel (area); */
  detach_all_interface (area);
  list_delete_by_val (ospf->area_list, area);
  XFREE (MTYPE_OSPF_AREA, area);
}

/* delete ospf from ospf_list */
int
delete_ospf (struct ospf *ospf)
{
  listnode node;

  for (node = listhead (ospf->area_list); !list_isempty (ospf->area_list);
       node = listhead (ospf->area_list))
    {
      delete_area(getdata(node), ospf);
    }
  list_delete_by_val (ospf_list, ospf);
  XFREE (MTYPE_OSPF_TOP, ospf);
  return 0;
}

/* Lookup functions. */
/* OSPF structure specified by instance_id. */
struct ospf *
ospf_lookup_by_instance_id (instance_id_t id)
{
  struct ospf *ospf;
  listnode node;

  for (node = listhead (ospf_list); node; nextnode (node))
    {
      ospf = getdata (node);
      if (ospf->instance_id == id)
        return ospf;
    }
  return NULL;
}

/* OSPF structure specified by router_id. */
struct ospf *
ospf_lookup_by_router_id (rtr_id_t id)
{
  struct ospf *ospf;
  listnode node;

  for (node = listhead (ospf_list); node; nextnode (node))
    {
      ospf = getdata (node);
      if (id_val (ospf->router_id) == id_val (id))
        return ospf;
    }
  return NULL;
}

/* area structure specified by area_id. */
struct area *
area_lookup_by_area_id (area_id_t id, struct ospf *ospf)
{
  struct area *area;
  listnode node;

  for (node = listhead (ospf->area_list); node; nextnode (node))
    {
      area = getdata (node);
      if (id_val (area->area_id) == id_val (id))
        return area;
    }
  return NULL;
}

/* interface structure specified by name. */
struct ospf_if *
if_lookup_by_ifname (char *ifname, list ospf_iflist)
{
  struct ospf_if *interface;
  listnode node;

  for (node = listhead (ospf_iflist); node; nextnode (node))
    {
      interface = getdata (node);
      if (strcmp (interface->ifname, ifname) == 0)
        return interface;
    }
  return NULL;
}

struct ospf_if *
if_lookup_by_addr (struct prefix *addr, list ospf_iflist)
{
  struct ospf_if *iface;
  listnode i, j;
  struct prefix *p;
  struct connected *c;

  for (i = listhead (ospf_iflist); i; nextnode (i))
    {
      iface = getdata (i);
      for (j = listhead (iface->interface->connected); j; nextnode (j))
	{
	  c = getdata (j);
	  p = c->address;
	  if (prefix_same (addr, p))
	    return iface;
	}
    }
  return NULL;
}

struct ospf_if *
if_lookup_by_addr_in_net (struct prefix *addr, list ospf_iflist)
{
  struct ospf_if *iface;
  listnode i, j;
  struct prefix *p;
  struct connected *c;

  for (i = listhead (ospf_iflist); i; nextnode (i))
    {
      iface = getdata (i);
      for (j = listhead (iface->interface->connected); j; nextnode (j))
	{
	  c = getdata (j);
	  p = c->address;
	  if (prefix_match (addr, p))
	    return iface;
	}
    }
  return NULL;
}

/* Neighbor lookup by Neighbor ID (Neighbor Router ID) */
struct neighbor *
nb_lookup_by_nb_id (rtr_id_t id, list nblist)
{
  struct neighbor *nbp;
  listnode node;

  for (node = listhead (nblist); node; nextnode (node))
    {
      nbp = getdata (node);
      if (IS_ROUTER_ID_EQUAL (id, nbp->rtr_id))
	return nbp;
    }

  return NULL;
}

/* Called when SIGINT signal is received */
/* Close all ospf instance. */
void
ospf_terminate ()
{
  listnode node;

  for (node = listhead (ospf_list); !list_isempty (ospf_list);
       node = listhead (ospf_list))
    {
      delete_ospf (getdata (node));
    }

  list_free (ospf_list);
  list_free (ospf_iflist);

  return;
}



/* show ospf area list */
int
show_ospf_area_all (struct vty *vty, list areas)
{
  listnode node;

  for (node = listhead (areas); node; nextnode (node))
    {
      show_area (vty, getdata (node));
    }
  return 0;
}

/* show all of ospf top level structure */
int
show_ospf_top_all (struct vty *vty)
{
  listnode node;

  for (node = listhead (ospf_list); node; nextnode (node))
    {
      show_ospf_top (vty, getdata (node));
    }
  return 0;
}

/* show specified ospf top level structure */
int
show_ospf_top (struct vty *vty, struct ospf *ospf)
{
  vty_out (vty, "Instance-ID: %d\tVersion: %d\tRouter-ID: %s\r\n",
                 ospf->instance_id, ospf->version, inet_ntoa (ospf->router_id));
  show_ospf_area_all (vty, ospf->area_list);
  return 0;
}

/* show specified ospf_if structure */
int
show_int (struct vty *vty, struct ospf_if *interface)
{
  char *area, *type;

  if (interface->area == NULL)
      area = "NOT ATTACHED TO AREA";
  else
      area = inet_ntoa(interface->area->area_id);

  if (if_is_up (interface->interface))
    {
      if (if_is_broadcast (interface->interface))
	{
	  if (if_is_pointopoint (interface->interface))
	    {
	      type = "UP,BROADCAST,POINTTOPOINT";
	    }
	  else
	    {
	      type = "UP,BROADCAST";
	    }
	}
      else if (if_is_pointopoint (interface->interface))
	{
	  type = "UP,POINTTOPOINT";
	}
      else if (if_is_loopback (interface->interface))
	{
	  type = "UP,LOOPBACK";
	}
      else
	{
	  type = "UP,UNKNOWN";
	}
    }
  else
    {
      if (if_is_broadcast (interface->interface))
	{
	  if (if_is_pointopoint (interface->interface))
	    {
	      type = "DOWN,BROADCAST,POINTTOPOINT";
	    }
	  else
	    {
	      type = "DOWN,BROADCAST";
	    }
	}
      else if (if_is_pointopoint (interface->interface))
	{
	  type = "DOWN,POINTTOPOINT";
	}
      else
	{
	  type = "DOWN,LOOPBACK";
	}
    }
	    
  vty_out (vty, "\r\n");
  vty_out (vty, "   %s:[%s]\tArea-ID: %s\tState:\t%s\r\n",
	   interface->ifname,
	   type,
	   area,
	   ifs_name[interface->state]);
  vty_out (vty, "      InfTransDelay:\t%dsec\tRouterPriority:\t%d\r\n",
	   interface->inf_trans_delay, interface->rtr_pri);
  vty_out (vty, "      HelloInterval:\t%dsec\tRouterDeadInterval:\t%dsec\r\n",
	   interface->hello_interval, interface->rtr_dead_interval);
  vty_out (vty, "      Cost:\t%d\t\tRxmtInterval:\t%dsec\r\n",
	   interface->cost, interface->rxmt_interval);
  vty_out (vty, "      AuType:\t%s\tAuKey:\t%s\r\n",
	   autype_name[interface->autype], (char *)interface->auth_data);
  show_address (vty, interface);

  return 0;
}

/* show ospf_if list */
int
show_area_if_all (struct vty *vty, list ospf_if_list)
{
  listnode node;

  for (node = listhead (ospf_if_list); node; nextnode (node))
    {
      show_int (vty, getdata (node));
    }
  return 0;
}

/* show specified area structure */
int
show_area (struct vty *vty, struct area *area)
{
  vty_out (vty, "  Area-ID: %s\r\n", inet_ntoa (area->area_id));
  show_area_if_all (vty, area->ospf_if_list);
  return 0;
}

/* show all neighbor structure */
int
show_all_neighbor (struct vty *vty)
{
  listnode i, j;
  struct ospf_if *iface;
  struct neighbor *nb;

  vty_out (vty, "%-15s %-15s %-8s %-15s %-15s %s[%s]\r\n",
	   "RouterID", "InterfaceID", "State", "DR", "BDR", "I/F", "State");

  for (i = listhead (ospf_iflist); i; nextnode (i))
    {
      iface = getdata (i);
      for (j = listhead (iface->nb_list); j; nextnode (j))
	{
	  char rtrid[16], ifid[16], dr[16], bdr[16];
	  nb = getdata (j);
	  bcopy (inet_ntoa (nb->rtr_id), rtrid, sizeof (rtrid));
	  bcopy (inet_ntoa (*(rtr_id_t *)&nb->ifid), ifid, sizeof (ifid));
	  bcopy (inet_ntoa (*(rtr_id_t *)&nb->dr), dr, sizeof (dr));
	  bcopy (inet_ntoa (*(rtr_id_t *)&nb->bdr), bdr, sizeof (bdr));
	  vty_out (vty, "%-15s %-15s %-8s %-15s %-15s %s[%s]\r\n",
		   rtrid, ifid, nbs_name[nb->state], dr, bdr,
		   iface->ifname, ifs_name[iface->state]);
	}
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return 0;
}

DEFUN (show_neighbor,
       show_neighbor_cmd,
       "show neighbor",
       SHOW_STR
       OSPF_NEIGHBOR_STR)
{
  show_all_neighbor (vty);
  return CMD_SUCCESS;
}

/* make ospf instance by INSTANCE_ID. */
DEFUN (router_ospf_instance,
       router_ospf_instance_cmd,
       /* "router ospf [instance INSTANCE_ID]", */
       "router ospf",
       OSPF_ROUTER_STR
       "enter OSPF top node\n")
{
  struct ospf *ospf;
  instance_id_t instance_id;
  rtr_id_t router_id;

  if (argc != 0)
    instance_id = strtol (argv[0], NULL, 10);
  else
    instance_id = 1;

  /* lookup existing ospf structure */
  ospf = ospf_lookup_by_instance_id (instance_id);
  if (ospf == NULL)       /* Make new ospf instance. */
    {
      inet_aton ("0.0.0.0", &router_id); /* invalid default value */
      ospf = make_ospf(OSPF_V3, instance_id, router_id);
    }

  /* Set current ospf point. */
  vty->node = OSPF_NODE;
  vty->index = ospf;
  return CMD_SUCCESS;
}

/* Delete ospf instance by INSTANCE_ID. */
DEFUN (no_router_ospf_instance,
       no_router_ospf_instance_cmd,
       /* "no router ospf [instance INSTANCE_ID]", */
       "no router ospf",
       NO_STR
       OSPF_ROUTER_STR
       "Delete OSPF instance(by INSTANCE_ID is not supported).")
{
  struct ospf *ospf;
  instance_id_t id;

  if (argc != 0)
    {
      id = strtol (argv[0], NULL, 10);
      ospf = ospf_lookup_by_instance_id (id);
    }
  else
    {
      ospf = ospf_lookup_by_instance_id (1);
    }

  if (ospf == NULL)
    {
      vty_out (vty, "No match by INSTANCE_ID.\r\n");
      vty_out (vty, "\r\n");
      return CMD_SUCCESS;
    }
  delete_ospf (ospf);
  return CMD_SUCCESS;
}

/* make ospf ospf_if */
DEFUN (interface,
       interface_cmd,
       "interface IFNAME area AREA_ID [IFSTATE]",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "Specify AREA\n"
       V4NOTATION_STR
       "up or down\n")
{
  char *ifname;
  area_id_t area_id;
  struct area *area;
  struct ospf_if *interface;

  ifname = argv[0];
  inet_aton (argv[1], &area_id);

  interface = if_lookup_by_ifname (ifname, ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No such interface: %s\r\n", ifname);
      return CMD_WARNING;
    }
  area = area_lookup_by_area_id (area_id, (struct ospf *)(vty->index));
  if (!area)
    area = make_area (area_id, (struct ospf *)(vty->index));
  list_add_node (area->ospf_if_list, interface);
  interface->area = area;

  if (argc == 3)
    {
      if (strcmp (argv[2], "up") == 0)
	thread_add_event (master, interface_up, interface, 0);
      else if (strcmp (argv[2], "down") == 0)
	thread_add_event (master, interface_down, interface, 0);
      else
        vty_out (vty, "Invalid argument: %s\r\n", argv[2]);
      vty_out (vty, "\r\n");
    }

  return CMD_SUCCESS;
}

DEFUN (no_interface,
       no_interface_cmd,
       "no interface IFNAME [area AREA_ID]",
       OSPF_INTERFACE_STR
       "Delete Interface.")
{
  struct area *area;
  area_id_t area_id;
  struct ospf_if *interface;

  if (argc == 1)
    {
      interface = if_lookup_by_ifname (argv[0], ospf_iflist);
      if (!interface)
        {
          vty_out (vty, "No match by IFNAME: %s\r\n",
                         argv[0]);
          vty_out (vty, "\r\n");
          return CMD_SUCCESS;
        }
      delete_interface (interface, interface->area);
      return CMD_SUCCESS;
    }

  inet_aton (argv[1], &area_id);
  area = area_lookup_by_area_id (area_id, (struct ospf *)vty->index);
  if (!area)
    {
      vty_out (vty, "No match by AREA_ID: %s\r\n", inet_ntoa (area_id));
      vty_out (vty, "\r\n");
      return CMD_SUCCESS;
    }
  interface = if_lookup_by_ifname (argv[0], area->ospf_if_list);
  if (!interface)
    {
      vty_out (vty, "No match by IFNAME: %s in AREA: %s\r\n",
                     argv[0], inet_ntoa (area_id));
      vty_out (vty, "\r\n");
      return CMD_SUCCESS;
    }
  delete_interface (interface, area);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_cost,
       interface_cost_cmd,
       "interface IFNAME cost COST",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "cost setting command.\n"
       "Specify by number\n")
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->cost = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_hello_interval,
       interface_hello_interval_cmd,
       "interface IFNAME hellointerval HELLO_INTERVAL",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "Hello Interval setting command.\n"
       "Specify by number\n")
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->hello_interval = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_router_dead_interval,
       interface_router_dead_interval_cmd,
       "interface IFNAME routerdeadinterval ROUTER_DEAD_INTERVAL",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "Router Dead Interval setting command.\n"
       "Specify by number\n")
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->rtr_dead_interval = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_inf_trans_delay,
       interface_inf_trans_delay_cmd,
       "interface IFNAME inftransdelay INFTRANSDELAY",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "InfTransDelay setting command.\n"
       OSPF_NUMBER_STR
       )
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->inf_trans_delay = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_rxmt_interval,
       interface_rxmt_interval_cmd,
       "interface IFNAME rxmtinterval RXMTINTERVAL",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "RxmtInterval setting command.\n"
       OSPF_NUMBER_STR
       )
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->rxmt_interval = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_autype,
       interface_autype_cmd,
       "interface IFNAME autype AUTYPE [AUDATA]",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "Authentication Type set command.\n"
       "Only simplepasswd is supported.\n"
       "Specify Authentication Data\n")
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }

  if (strcmp(argv[1], autype_name[AUTYPE_SIMPLE_PASSWD]) == 0 && argc == 3)
    {
      interface->autype = AUTYPE_SIMPLE_PASSWD;
      bcopy (argv[2], interface->auth_data, sizeof (interface->auth_data));
    }
  else
    {
      interface->autype = AUTYPE_NULL;
      bzero (interface->auth_data, sizeof (interface->auth_data));
    }

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (interface_router_priority,
       interface_router_priority_cmd,
       "interface IFNAME routerpriority ROUTERPRIORITY",
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR
       "Router Priority setting command.\n"
       OSPF_NUMBER_STR)
{
  struct ospf_if *interface;

  interface = if_lookup_by_ifname (argv[0], ospf_iflist);
  if (!interface)
    {
      vty_out (vty, "No match interface: %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  interface->rtr_pri = strtol (argv[1], NULL, 10);
  return CMD_SUCCESS;
}

/* show top level structures */
DEFUN (show_ospf,
       show_ospf_cmd,
       /* "show ospf [INSTANCE_ID]", */
       "show ospf",
       SHOW_STR
       OSPF_STR
       "Show ospf top level structures.")
{
  struct ospf *ospf;
  instance_id_t id;

  if (argc)
    {
      id = strtol (argv[0], NULL, 10);
      ospf = ospf_lookup_by_instance_id (id);
      if (!ospf)
        vty_out (vty, "No match by Instance-ID: %d\r\n", id);
      else
        show_ospf_top(vty, ospf);
      vty_out (vty, "\r\n");
      return CMD_SUCCESS;
    }
  show_ospf_top_all (vty);
  vty_out (vty, "\r\n");
  return CMD_SUCCESS;
}

/* show interface */
DEFUN (show_interface,
       show_interface_cmd,
       "show interface [IFNAME]",
       SHOW_STR
       OSPF_INTERFACE_STR
       OSPF_IFNAME_STR)
{
  struct ospf_if *interface;
  listnode node;

  if (argc)
    {
      interface = if_lookup_by_ifname (argv[0], ospf_iflist);
      if (interface)
	show_int (vty, interface);
      else
	vty_out (vty, "No such Interface: %s\r\n", argv[0]);
      return CMD_SUCCESS;
    }
  for (node = listhead (ospf_iflist); node; nextnode (node))
    {
      show_int (vty, getdata (node));
    }
  vty_out (vty, "\r\n");
  return CMD_SUCCESS;
}

DEFUN (show_lsa,
       show_lsa_cmd,
       "show lsa",
       SHOW_STR
       "show LSA list all\n")
{
  struct area *area;
  area_id_t area_id;

  if (argc)
    {
      inet_aton (argv[0], &area_id);
      area = area_lookup_by_area_id (area_id, (struct ospf *)(getdata (listhead (ospf_list))));
      if (!area)
	{
	  vty_out (vty, "No match by AREA_ID: %s\r\n", inet_ntoa (area_id));
	  vty_out (vty, "\r\n");
	  return CMD_SUCCESS;
	}
    }
  else
    {
      area = (struct area *)getdata (listhead
	(((struct ospf *)getdata (listhead (ospf_list)))->area_list));
    }

  vty_lsdb (vty, area);

  return CMD_SUCCESS;
}

DEFUN (show_table,
       show_table_cmd,
       "show table",
       SHOW_STR
       "show routing table all\n")
{
  struct area *area;
  area_id_t area_id;
  int i;
  char ifname[64];
  char ntop_buf[2][INET6_ADDRSTRLEN];

  if (argc)
    {
      inet_aton (argv[0], &area_id);
      area = area_lookup_by_area_id
	(area_id, (struct ospf *)(getdata (listhead (ospf_list))));
      if (!area)
	{
	  vty_out (vty, "No match by AREA_ID: %s\r\n", inet_ntoa (area_id));
	  vty_out (vty, "\r\n");
	  return CMD_SUCCESS;
	}
    }
  else
    {
      area = (struct area *)getdata (listhead
	(((struct ospf *)getdata (listhead (ospf_list)))->area_list));
    }

  vty_out (vty, "Routing Table\r\n");
  vty_out (vty, "%-22s/%3s %-39s %-3s %5s\r\n",
	   "DESTINATION", "LEN", "NEXTHOP", "IF", "COST");
  vty_out (vty, "----------\r\n");
  for (i = 0; i < area->tablesize; i++)
    {
      inet_ntop (AF_INET6, &area->rt_table[i].destination, ntop_buf[0],
		 sizeof (ntop_buf[0]));
      inet_ntop (AF_INET6, &area->rt_table[i].next_hop, ntop_buf[1],
		 sizeof (ntop_buf[1]));
      if_indextoname (area->rt_table[i].ifindex, ifname);
      vty_out (vty, "%-22s/%3d %-39s %-3s %5d\r\n",
	       ntop_buf[0], area->rt_table[i].prefixlength, 
	       ntop_buf[1], ifname, area->rt_table[i].cost);
    }

  return CMD_SUCCESS;
}

/* change OSPF_VERSION commands. */
DEFUN (ospf_version,
       ospf_version_cmd,
       "ospf version VERSION",
       OSPF_STR
       "Configure ospf version.\n"
       "2 or 3.\n")
{
  vers_t vers;
  struct ospf *ospfp;
  listnode i, j;
  struct area *area;
  struct ospf_if *iface;

  vers = strtol (argv[0], NULL, 10);
  if (vers != OSPF_V2 && vers != OSPF_V3)
    {
      ((struct ospf *)vty->index)->version = OSPF_V3;
      vty_out (vty, "invalid version number.\r\n");
      vty_out (vty, "default version 3.\r\n");
      vty_out (vty, "\r\n");
      return CMD_WARNING;
    }
  ospfp = (struct ospf *)vty->index;
  if (ospfp->version != vers)
    {
      log ("OSPF version changed: %d -> %d\n",
	   ospfp->version,
	   vers);
      ospfp->version = vers;

      for (i = listhead (ospfp->area_list); i; nextnode (i))
	{
	  area = getdata (i);
	  for (j = listhead (area->ospf_if_list); j; nextnode (j))
	    {
	      iface = getdata (j);
	      thread_add_event (master, interface_down, iface, 0);
	      thread_add_event (master, interface_up, iface, 0);
	    }
	}
    }
  return CMD_SUCCESS;
}

/* change Router_ID commands. */
DEFUN (ospf_router_id,
       ospf_router_id_cmd,
       "ospf router id ROUTER_ID",
       OSPF_STR
       OSPF_ROUTER_STR
       "Configure ospf Router-ID.\n"
       V4NOTATION_STR)
{
  int ret;
  rtr_id_t router_id;

  ret = inet_aton (argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "malformed ospf router identifier\r\n");
      vty_out (vty, "\r\n");
      return CMD_WARNING;
    }

  id_val (((struct ospf *)(vty->index))->router_id) = id_val (router_id);
  return CMD_SUCCESS;
}

DEFUN (show_ospf_memory,
       show_ospf_memory_cmd,
       "show ospf memory",
       SHOW_STR
       OSPF_STR
       "Display ospf memory allocation status.")
{
  vty_out (vty, "Top Level Structure alloced : %ld\r\n",
           mstat[MTYPE_OSPF_TOP].alloc);
  vty_out (vty, "Area Structure alloced : %ld\r\n",
           mstat[MTYPE_OSPF_AREA].alloc);
  vty_out (vty, "Interface Structure alloced: %ld\r\n",
           mstat[MTYPE_OSPF_IF].alloc);
  vty_out (vty, "Neighbor Structure alloced: %ld\r\n",
           mstat[MTYPE_OSPF_NEIGHBOR].alloc);
  vty_out (vty, "linklist alloced : %ld\r\n",
           mstat[MTYPE_LINK_LIST].alloc);
  vty_out (vty, "linknode alloced : %ld\r\n",
           mstat[MTYPE_LINK_NODE].alloc);
  vty_out (vty, "\r\n");

  return CMD_SUCCESS;
}

DEFUN (ospf_exit,
       ospf_exit_cmd,
       "exit",
       "Exit current mode and down to previous mode\n")
{
  vty->node = CONFIG_NODE;
  return CMD_SUCCESS;
}

DEFUN (ospf_end,
       ospf_end_cmd,
       "end",
       "End current mode and change to enable mode.")
{
  vty->node = ENABLE_NODE;
  return CMD_SUCCESS;
}

/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  listnode i, j, k;
  struct ospf *ospf;
  struct area *area;
  struct ospf_if *interface;

  /* OSPF instance configuration. */
  for (i = listhead (ospf_list); i; nextnode (i))
    {
      ospf = getdata (i);

      vty_out (vty, "router ospf%s", VTY_NEWLINE);
      vty_out (vty, " ospf version %d%s", ospf->version, VTY_NEWLINE);
      vty_out (vty, " ospf router id %s%s",
                     inet_ntoa(ospf->router_id), VTY_NEWLINE);
      for (j = listhead (ospf->area_list); j; nextnode (j))
        {
          area = getdata (j);
          for (k = listhead (area->ospf_if_list); k; nextnode (k))
            {
              interface = getdata (k);
              vty_out (vty, "  interface %s area %s",
                             interface->ifname,
                             inet_ntoa (area->area_id));
              if (interface->state != IFS_DOWN)
                vty_out (vty, " up");
              vty_out (vty, "%s", VTY_NEWLINE);
              vty_out (vty, "  interface %s cost %d%s",
                             interface->ifname,
                             interface->cost,
                             VTY_NEWLINE);
              vty_out (vty, "  interface %s hellointerval %d%s",
                             interface->ifname,
                             interface->hello_interval,
                             VTY_NEWLINE);
              vty_out (vty, "  interface %s routerdeadinterval %d%s",
                             interface->ifname,
                             interface->rtr_dead_interval,
                             VTY_NEWLINE);
              vty_out (vty, "  interface %s rxmtinterval %d%s",
                             interface->ifname,
                             interface->rxmt_interval,
                             VTY_NEWLINE);
              vty_out (vty, "  interface %s routerpriority %d%s",
                             interface->ifname,
                             interface->rtr_pri,
                             VTY_NEWLINE);
              vty_out (vty, "  interface %s inftransdelay %d%s",
                             interface->ifname,
                             interface->inf_trans_delay,
                             VTY_NEWLINE);
	      vty_out (vty, "  interface %s autype %s",
		       interface->ifname,
		       autype_name[interface->autype]);
	      if (interface->autype == AUTYPE_SIMPLE_PASSWD)
		{
		  char auth_data[16];
		  bzero (auth_data, sizeof (auth_data));
		  bcopy (interface->auth_data, auth_data,
			 sizeof (interface->auth_data));
		  vty_out (vty, " %s", auth_data);
		}
              vty_out (vty, "%s!%s", VTY_NEWLINE, VTY_NEWLINE);
            }
        }
      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

/* OSPF node structure. */
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
  install_element (VIEW_NODE, &show_ospf_cmd);
  install_element (VIEW_NODE, &show_interface_cmd);
  install_element (VIEW_NODE, &show_ospf_memory_cmd);
  install_element (VIEW_NODE, &show_neighbor_cmd);
  install_element (VIEW_NODE, &show_lsa_cmd);
  install_element (VIEW_NODE, &show_table_cmd);
  install_element (ENABLE_NODE, &show_ospf_cmd);
  install_element (ENABLE_NODE, &show_interface_cmd);
  install_element (ENABLE_NODE, &show_ospf_memory_cmd);
  install_element (ENABLE_NODE, &show_neighbor_cmd);
  install_element (CONFIG_NODE, &router_ospf_instance_cmd);
  install_element (CONFIG_NODE, &no_router_ospf_instance_cmd);
  install_element (CONFIG_NODE, &show_ospf_cmd);
  install_element (CONFIG_NODE, &show_interface_cmd);
  install_element (CONFIG_NODE, &show_neighbor_cmd);
  install_element (OSPF_NODE, &ospf_end_cmd);
  install_element (OSPF_NODE, &ospf_exit_cmd);
  install_element (OSPF_NODE, &config_help_cmd);
  install_element (OSPF_NODE, &show_ospf_cmd);
  install_element (OSPF_NODE, &show_interface_cmd);
  install_element (OSPF_NODE, &ospf_router_id_cmd);
  install_element (OSPF_NODE, &ospf_version_cmd);
  install_element (OSPF_NODE, &interface_cmd);
  install_element (OSPF_NODE, &interface_cost_cmd);
  install_element (OSPF_NODE, &interface_hello_interval_cmd);
  install_element (OSPF_NODE, &interface_router_dead_interval_cmd);
  install_element (OSPF_NODE, &interface_rxmt_interval_cmd);
  install_element (OSPF_NODE, &interface_router_priority_cmd);
  install_element (OSPF_NODE, &interface_inf_trans_delay_cmd);
  install_element (OSPF_NODE, &interface_autype_cmd);
  install_element (OSPF_NODE, &show_neighbor_cmd);
  install_element (OSPF_NODE, &config_help_cmd);
  /*  install_element (OSPF_NODE, &no_interface_cmd); */

#if 0
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_cmd);
  install_element (ENABLE_NODE, &clear_ip_ospf_interface_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_area_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_interface_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_cmd);

  install_element (VIEW_NODE, &show_ip_ospf_route_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_route_cmd);

#ifdef HAVE_IPV6
  install_element (VIEW_NODE, &show_ip6_ospf_cmd);
  install_element (VIEW_NODE, &show_ip6_ospf_area_cmd);
  install_element (VIEW_NODE, &show_ip6_ospf_interface_cmd);
  install_element (VIEW_NODE, &show_ip6_ospf_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ip6_ospf_cmd);
  install_element (ENABLE_NODE, &show_ip6_ospf_area_cmd);
  install_element (ENABLE_NODE, &show_ip6_ospf_interface_cmd);
  install_element (ENABLE_NODE, &show_ip6_ospf_neighbor_cmd);
  install_element (ENABLE_NODE, &clear_ip6_ospf_interface_cmd);

  install_element (VIEW_NODE, &show_ip6_ospf_route_cmd);
  install_element (ENABLE_NODE, &show_ip6_ospf_route_cmd);
#endif /* 0 */
#endif /* HAVE_IPV6 */

  /* Make empty list of top list. */
  ospf_list = list_init ();
  ospf_iflist = list_init ();

}

