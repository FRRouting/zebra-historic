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
  int i, j;
  struct area *area = area_new ();

  if (!area)
    {
      /* xxx */
      zlog (NULL, LOG_WARNING,"Can't alloc area for %lu.", area_id);
      return (struct area *)NULL;
    }

  area->area_id = area_id;
  area->ospf6_if_list = list_init ();

  area->router_lsa_seqnum = area->network_lsa_seqnum
                          = area->link_lsa_seqnum
                          = area->intra_prefix_seqnum
                          = INITIAL_SEQUENCE_NUMBER;

  /* XXX Initialize LSDB */
  for (i = 0; i < AREALSTYPESIZE; i++)
    {
      for (j = 0; j < HASHVAL; j++)
        {
          area->lsdb[i][j] = list_init ();
        }
    }

  assert (ospf6->version == OSPF_V3);

  V3OPT_SET (area->options, V3OPT_V6);
  V3OPT_SET (area->options, V3OPT_E);
  V3OPT_SET (area->options, V3OPT_R);

  list_add_node (ospf6->area_list, area);
  area->ospf6 = ospf6;
  return area;
}



/* OSPF6 Interface section */
/* Allocate new interface structure */
static struct ospf6_if *
ospf6_if_new ()
{
  struct ospf6_if *new = (struct ospf6_if *)
      XMALLOC (MTYPE_OSPF6_IF, sizeof (struct ospf6_if));
  if (new)
    memset (new, 0, sizeof (struct ospf6_if));
  else
    zlog (NULL, LOG_WARNING,"Can't malloc ospf6_if");

  return new;
}

#if 0
static set_ospf6_if_default_val (struct ospf6_if *ospf6_if)
{
  ospf6_if->inf_trans_delay = 1;
  ospf6_if->rtr_pri = 1;
  ospf6_if->hello_interval = 10;
  ospf6_if->rtr_dead_interval = 40;
  ospf6_if->rxmt_interval = 5;
  ospf6_if->cost = 1;
}
#else
#define set_ospf6_if_default_val(X) \
{ \
  (X)->inf_trans_delay = 1; \
  (X)->rtr_pri = 1; \
  (X)->hello_interval = 10; \
  (X)->rtr_dead_interval = 40; \
  (X)->rxmt_interval = 5; \
  (X)->cost = 1; \
} 
#endif

/* Make new ospf6 interface structure */
struct ospf6_if *
make_ospf6_if (char *ifname)
{
  struct ospf6_if *ospf6_if;
  struct interface *interface;

  interface = if_lookup_by_name (ifname);
  if (!interface)
    {
      zvlog_err ("Can't find Interface: %s", ifname);
      return (struct ospf6_if *)NULL;
    }
  if (interface->if_data)
    {
      zvlog_err ("Already have ospf6_if");
      return (struct ospf6_if *)NULL;
    }

  ospf6_if = ospf6_if_new ();
  if (!ospf6_if)
    {
      zvlog_err ("Can't allocate ospf6_if for %s", ifname);
      return (struct ospf6_if *)NULL;
    }

  ospf6_if->interface = interface;
  ospf6_if->ifid = interface->index;
  ospf6_if->area = (struct area *)NULL; /* not yet attached to Area. */
  ospf6_if->state = IFS_DOWN;
  ospf6_if->nbr_list = list_init ();
  ospf6_if->linklocal_lsa = list_init ();
  ospf6_if->delayed_ack = list_init ();
  interface->if_data = ospf6_if;

  set_ospf6_if_default_val (ospf6_if);

  return ospf6_if;
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
    zlog (NULL, LOG_WARNING, "Can't malloc neighbor");

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

struct ospf6_if *
ospf6_if_lookup (char *ifname)
{
  struct interface *ifp;
  struct ospf6_if *ospf6_if;

  ifp = if_lookup_by_name (ifname);
  if (!ifp)
    {
      zlog (NULL, LOG_WARNING, "no such interface: %s", ifname);
      return (struct ospf6_if *)NULL;
    }
  ospf6_if = (struct ospf6_if *)ifp->if_data;
  if (!ospf6_if)
    {
      zlog (NULL, LOG_WARNING, "no such ospf6 interface: %s", ifname);
      return (struct ospf6_if *)NULL;
    }

  return ospf6_if;
}

struct ospf6_if *
ospf6_if_lookup_by_addr (struct prefix *addr)
{
  struct interface *iface;
  listnode i, j;
  struct prefix *p;
  struct connected *c;

  for (i = listhead (iflist); i; nextnode (i))
    {
      iface = (struct interface *)getdata (i);
      for (j = listhead (iface->connected); j; nextnode (j))
        {
          c = getdata (j);
          p = c->address;
          if (prefix_same (addr, p) && iface->if_data != NULL)
            return (struct ospf6_if *)iface->if_data;
        }
    }
  return (struct ospf6_if *)NULL;
}

struct ospf6_if *
ospf6_if_lookup_by_addr_in_net (struct prefix *addr)
{
  struct interface *iface;
  listnode i, j;
  struct prefix *p;
  struct connected *c;

  for (i = listhead (iflist); i; nextnode (i))
    {
      iface = (struct interface *)getdata (i);
      for (j = listhead (iface->connected); j; nextnode (j))
        {
          c = getdata (j);
          p = c->address;
          if (prefix_match (addr, p) && iface->if_data != NULL)
            return (struct ospf6_if *)iface->if_data;
        }
    }
  return (struct ospf6_if *)NULL;
}

/* lookup neighbor from instance.
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

/* Called when SIGINT signal is received */
/* Close all ospf instance. */
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

/* show specified interface structure */
int
show_if (struct vty *vty, struct interface *iface)
{
  struct ospf6_if *ospf6_if;
  struct connected *c;
  struct prefix *p;
  listnode i;
  char strbuf[64];
  char *updown[3] = {"down", "up", NULL};
  char *type;

  /* check interface type */
  if (if_is_loopback (iface))
    type = "LOOPBACK";
  else if (if_is_broadcast (iface))
    type = "BROADCAST";
  else if (if_is_pointopoint (iface))
    type = "POINTOPOINT";
  else
    type = "UNKNOWN";

  vty_out (vty, "%s is %s, type %s\r\n",
           iface->name, updown[if_is_up (iface)], type);

  if (iface->if_data == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface\r\n");
      return 0;
    }
  else
    ospf6_if = (struct ospf6_if *)iface->if_data;

  vty_out (vty, "  Internet Address:\r\n");
  for (i = listhead (iface->connected); i; nextnode (i))
    {
      c = (struct connected *)getdata (i);
      p = c->address;
      prefix2str (p, strbuf, sizeof (strbuf));
      switch (p->family)
        {
        case AF_INET:
          vty_out (vty, "   inet : %s\r\n", strbuf);
          break;
        case AF_INET6:
          vty_out (vty, "   inet6: %s\r\n", strbuf);
          break;
        default:
          vty_out (vty, "   ???  : %s\r\n", strbuf);
          break;
        }
    }

  if (ospf6_if->area)
    {
      vty_out (vty, "  Instance ID %lu, Router ID %s\r\n",
           ospf6_if->area->ospf6->instance_id,
           inet4str (ospf6_if->area->ospf6->router_id));
      vty_out (vty, "  Area ID %s, Cost %hu\r\n",
           inet4str (ospf6_if->area->area_id), 
           ospf6_if->cost);
    }
  else
    vty_out (vty, "  Not Attached to Area\r\n");

  vty_out (vty, "  State %s, Transmit Delay %lu sec\r\n",
           ifs_name[ospf6_if->state],
           ospf6_if->inf_trans_delay);
  vty_out (vty, "  Timers:\r\n");
  vty_out (vty, "   Hello %lu, Dead %lu, Retransmit %lu\r\n",
           ospf6_if->hello_interval,
           ospf6_if->rtr_dead_interval,
           ospf6_if->rxmt_interval);
  vty_out (vty, "  DR %s\r\n",
           inet4str (ospf6_if->dr));
  vty_out (vty, "  BDR %s\r\n",
           inet4str (ospf6_if->bdr));

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

DEFUN (no_interface,
       no_interface_cmd,
       "no interface IFNAME [area AREA_ID]",
       INTERFACE_STR
       "Delete Interface.")
{
  char *ifname;
  area_id_t area_id;
  struct area *area;
  struct ospf6_if *ospf6_if;
  struct interface *ifp;
  struct ospf6 *ospf6 = (struct ospf6 *)vty->index;

  ifname = argv[0];
  inet_pton (AF_INET, argv[1], &area_id);

  if (area_id != 0)
    {
      vty_out (vty, "Area ID other than Backbone(0.0.0.0), not yet implimented\r\n");
      return CMD_WARNING;
    }

  ifp = if_lookup_by_name (ifname);
  if (!ifp)
    {
      vty_out (vty, "No such interface: %s\r\n", ifname);
      return CMD_WARNING;
    }

  area = area_lookup (area_id, ospf6);
  if (!area)
    {
      vty_out (vty, "No such area: %s\r\n",
               inet4str (area_id));
      return CMD_WARNING;
    }

  ospf6_if = ospf6_if_lookup (ifname);
  if (!ospf6_if)
    {
      vty_out (vty, "No such ospf6 interface: %s\r\n", ifname);
      return CMD_WARNING;
    }

  /* xxx delete_ospf6_if (ospf6_if, area); */
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_cost,
       ip6_ospf6_cost_cmd,
       "ip6 ospf6 cost COST",
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "<1-65535> Cost\n"
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  ospf6_if = (struct ospf6_if *)ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->cost = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_hellointerval,
       ip6_ospf6_hellointerval_cmd,
       "ip6 ospf6 hello-interval HELLO_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_if = (struct ospf6_if *) ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->hello_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_deadinterval,
       ip6_ospf6_deadinterval_cmd,
       "ip6 ospf6 dead-interval ROUTER_DEAD_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Interval after which a neighbor is declared dead\n"
       SECONDS_STR
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_if = (struct ospf6_if *) ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->rtr_dead_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_transmitdelay,
       ip6_ospf6_transmitdelay_cmd,
       "ip6 ospf6 transmit-delay TRANSMITDELAY",
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_if = (struct ospf6_if *) ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->inf_trans_delay = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_retransmitinterval,
       ip6_ospf6_retransmitinterval_cmd,
       "ip6 ospf6 retransmit-interval RXMTINTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_if = (struct ospf6_if *) ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->rxmt_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_priority,
       ip6_ospf6_priority_cmd,
       "ip6 ospf6 priority PRIORITY",
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "<0-255> Priority\n"
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_if = (struct ospf6_if *)ifp->if_data;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp->name);
  assert (ospf6_if);

  ospf6_if->rtr_pri = strtol (argv[0], NULL, 10);
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
  struct lsa_internal *lsi;

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
      lsi = (struct lsa_internal *) getdata (n);
      vty_out (vty, "%s\r\n", print_lsahdr (lsi->lsh));
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
  int x;
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
          for (x = 0; x < HASHVAL; x++)
            {
              l = area->lsdb[typeindex (htons (LST_ROUTER_LSA))][x];
              for (k = listhead (l); k; nextnode (k))
                {
                  vty_lsa (vty, (struct lsa_internal *) getdata (k));
                }
            }
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
  int x;
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
          for (x = 0; x < HASHVAL; x++)
            {
              l = area->lsdb[typeindex (htons (LST_NETWORK_LSA))][x];
              for (k = listhead (l); k; nextnode (k))
                {
                  vty_lsa (vty, (struct lsa_internal *) getdata (k));
               }
            }
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
  listnode i, j, k, l;
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
              for (l = listhead (ospf6_if->linklocal_lsa); l; nextnode (l))
                {
                  vty_lsa (vty, (struct lsa_internal *) getdata (l));
                }
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
  int x;
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
          for (x = 0; x < HASHVAL; x++)
            {
              l = area->lsdb[typeindex (htons (LST_INTRA_AREA_PREFIX_LSA))][x];
              for (k = listhead (l); k; nextnode (k))
                {
                  vty_lsa (vty, (struct lsa_internal *) getdata (k));
                }
            }
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
       show_ipv6_route_ospf6_cmd,
       "show ipv6 route ospf6",
/*       "show ipv6 route ospf6 [INSTANCE AREA]", */
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
/*       OSPF6_INSTANCE_STR
       "A.B.C.D OSPF6 area ID in IP address format\n"
*/
       )
{
  struct ospf6 *ospf6;
  struct area *area;
  instance_id_t instance_id;
  area_id_t area_id;
  int i;
  char ifname[64];
  char ntop_buf[2][INET6_ADDRSTRLEN];

  if (argc)
    {
      instance_id = strtol (argv[0], NULL, 10);
      inet_pton (AF_INET, argv[1], &area_id);
    }
  else
    {
      instance_id = 1;
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
    ospf6_if = make_ospf6_if (ifp->name);
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
  ospf6_if->area = area;
  list_add_node (area->ospf6_if_list, ospf6_if);
  return CMD_SUCCESS;
}

DEFUN (zebra_install,
       zebra_install_cmd,
       "zebra install",
       "information about zebra\n"
       "install OSPF6 route to zebra\n"
       )
{
  listnode n;

  struct ospf6 *ospf6 = (struct ospf6 *)vty->index;
  ospf6->isinstall = INSTALL;
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    install_route ((struct area *) getdata (n));
  return CMD_SUCCESS;
}

DEFUN (zebra_noinstall,
       zebra_noinstall_cmd,
       "zebra noinstall",
       "information about zebra\n"
       "install *NO* OSPF6 route to zebra\n"
       )
{
  listnode n;

  struct ospf6 *ospf6 = (struct ospf6 *)vty->index;
  ospf6->isinstall = NOINSTALL;
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    noinstall_route ((struct area *) getdata (n));
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

      switch (ospf6->isinstall)
        {
        case INSTALL:
          vty_out (vty, " zebra install%s", VTY_NEWLINE);
          break;
        case NOINSTALL:
        default:
          vty_out (vty, " zebra noinstall%s", VTY_NEWLINE);
          break;
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

int
ospf6_if_config_write (struct vty *vty)
{
  listnode i,j,k;
  struct ospf6 *ospf6;
  struct ospf6_if *ospf6_if;
  struct area *area;

  for (i = listhead (ospf6_list); i; nextnode (i))
    {
      ospf6 = (struct ospf6 *) getdata (i);
      for (j = listhead (ospf6->area_list); j; nextnode (j))
        {
          area = (struct area *) getdata (j);
          for (k = listhead (area->ospf6_if_list); k; nextnode (k))
            {
              ospf6_if = (struct ospf6_if *) getdata (k);
              vty_out (vty, "interface %s%s",
                       ospf6_if->interface->name, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 cost %d%s",
                       ospf6_if->cost, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 hello-interval %d%s",
                       ospf6_if->hello_interval, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 dead-interval %d%s",
                       ospf6_if->rtr_dead_interval, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 retransmit-interval %d%s",
                       ospf6_if->rxmt_interval, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 priority %d%s",
                       ospf6_if->rtr_pri, VTY_NEWLINE);
              vty_out (vty, " ip6 ospf6 transmit-delay %d%s",
                       ospf6_if->inf_trans_delay, VTY_NEWLINE);
              vty_out (vty, "!%s", VTY_NEWLINE);
            }
        }
    }

  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Install ospf related commands. */
void
ospf6_init ()
{
  /* Install ospf6 top node. */
  install_node (&ospf6_node, ospf6_config_write);
  /* Install interface node. */
  install_node (&interface_node, ospf6_if_config_write);

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

  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &router_ospf6_instance_cmd);
  install_element (CONFIG_NODE, &interface_cmd);

  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_transmitdelay_cmd);

  install_element (OSPF6_NODE, &config_end_cmd);
  install_element (OSPF6_NODE, &config_exit_cmd);
  install_element (OSPF6_NODE, &config_help_cmd);
  install_element (OSPF6_NODE, &router_id_cmd);
  install_element (OSPF6_NODE, &interface_area_cmd);
  install_element (OSPF6_NODE, &zebra_install_cmd);
  install_element (OSPF6_NODE, &zebra_noinstall_cmd);

  /* Make empty list of top list. */
  ospf6_list = list_init ();
  if_init ();

  ospf6_zebra_init ();
  access_list_init ();
}

