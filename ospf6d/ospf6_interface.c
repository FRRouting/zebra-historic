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
    zvlog_warn ("Can't malloc ospf6_if");

  return new;
}

static void
ospf6_if_free (struct ospf6_if *o6if)
{
  XFREE (MTYPE_OSPF6_IF, o6if);
  return;
}

#if 0
static void
set_ospf6_if_default_val (struct ospf6_if *ospf6_if)
{
  ospf6_if->inf_trans_delay = 1;
  ospf6_if->rtr_pri = 1;
  ospf6_if->hello_interval = 10;
  ospf6_if->rtr_dead_interval = 40;
  ospf6_if->rxmt_interval = 5;
  ospf6_if->cost = 1;
  return;
}
#else
#define set_ospf6_if_default_val(X) \
{ \
  (X)->inf_trans_delay = 1; \
  (X)->rtr_pri = 1; \
  (X)->hello_interval = 10; \
  (X)->rtr_dead_interval = 40; \
  (X)->rxmt_interval = 5; \
  (X)->ifmtu = DEFAULT_INTERFACE_MTU; \
  (X)->cost = 1; \
} 
#endif


struct in6_addr *
ospf6_if_linklocal_addr (struct interface *ifp)
{
  listnode n;
  struct connected *c;
  struct in6_addr *linklocal = (struct in6_addr *) NULL;

  /* for each connected address */
  for (n = listhead (ifp->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* linklocal scope check */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        linklocal = &c->address->u.prefix6;
    }
  return linklocal;
}

/* Make new ospf6 interface structure */
struct ospf6_if *
make_ospf6_if (struct interface *ifp)
{
  struct ospf6_if *ospf6_if;

  assert (ifp);

  ospf6_if = ospf6_if_new ();
  if (!ospf6_if)
    {
      zvlog_err ("Can't allocate ospf6_if for %s", ifp->name);
      return (struct ospf6_if *)NULL;
    }

  ospf6_if->instance_id = 1; /* XXX multiple instance not yet */
  ospf6_if->ifid =  ifp->ifindex;
  ospf6_if->myaddr = ospf6_if_linklocal_addr (ifp);
  ospf6_if->area = (struct area *)NULL; /* not yet attached to Area. */
  ospf6_if->state = IFS_DOWN;
  ospf6_if->nbr_list = list_init ();
  ospf6_lsdb_init_interface (ospf6_if);

  ospf6_if->prefix_connected = list_init ();

  ospf6_if->link_lsa_seqnum = ospf6_if->network_lsa_seqnum
                            = ospf6_if->intra_prefix_seqnum
                            = INITIAL_SEQUENCE_NUMBER;

  /* make double link */
  ospf6_if->interface = ifp;
  ifp->info = ospf6_if;

  set_ospf6_if_default_val (ospf6_if);

  return ospf6_if;
}

void
delete_ospf6_if (struct ospf6_if *o6if)
{
  listnode n;

  for (n = listhead (o6if->nbr_list); n; nextnode (n))
    delete_ospf6_nbr (getdata (n));
  list_delete_all (o6if->nbr_list);

  thread_cancel (o6if->send_hello);
  thread_cancel (o6if->send_ack);

  ospf6_lsdb_finish_interface (o6if);

  list_delete_by_val (o6if->area->if_list, o6if);
  ospf6_if_free (o6if);

  return;
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
  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    {
      zlog (NULL, LOG_WARNING, "no such ospf6 interface: %s", ifname);
      return (struct ospf6_if *)NULL;
    }

  return ospf6_if;
}

struct ospf6_if *
ospf6_if_lookup_by_index (int ifindex)
{
  struct interface *ifp;
  struct ospf6_if *ospf6_if;

  ifp = if_lookup_by_index (ifindex);
  if (!ifp)
    {
      zlog (NULL, LOG_WARNING, "no such interface: %d", ifindex);
      return (struct ospf6_if *)NULL;
    }
  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    {
      zlog (NULL, LOG_WARNING, "no such ospf6 interface: %s",
            ifp->name);
      return (struct ospf6_if *)NULL;
    }

  return ospf6_if;
}

/* count number of full neighbor */
int
ospf6_if_count_full_nbr (struct ospf6_if *o6if)
{
  listnode n;
  struct neighbor *nbr;
  int count = 0;

  for (n = listhead (o6if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state == NBS_FULL)
        count++;
    }

  return count;
}

/* write linklocal address to buf. if linklocal not found, return -1 */
int
ospf6_if_get_linklocal (struct in6_addr *buf, struct ospf6_if *o6if)
{
  listnode n;
  struct connected *c;
  struct in6_addr *linklocal = (struct in6_addr *) NULL;

  /* for each connected address */
  for (n = listhead (o6if->interface->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* linklocal scope check */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        linklocal = &c->address->u.prefix6;
    }

  /* if no linklocal address, return -1 */
  if (!linklocal)
    return -1;

  /* copy linklocal to buf */
  memcpy (buf, linklocal, sizeof (struct in6_addr));

#ifdef KAME
  /* if KAME, clear ifindex included in address */
  if (buf->s6_addr[3] & 0x0f)
    {
      char linklocal_str[64];
      buf->s6_addr[3] &= ~((char)0x0f);
      inet_ntop (AF_INET6, buf, linklocal_str, sizeof (linklocal_str));
      o6log.interface ("clear kame ifindex, %s", linklocal_str);
    }
#endif /* KAME */

  return 0;
}

int
ospf6_if_is_enabled (struct ospf6_if *o6i)
{
  assert (o6i);
  if (o6i->state > IFS_DOWN)
    {
      assert (o6i->area);
      return 1;
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
  char strbuf[64], dr[32], bdr[32];
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

  vty_out (vty, "%s is %s, type %s%s",
           iface->name, updown[if_is_up (iface)], type,
	   VTY_NEWLINE);

  if (iface->info == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface%s", VTY_NEWLINE);
      return 0;
    }
  else
    ospf6_if = (struct ospf6_if *)iface->info;

  vty_out (vty, "  Internet Address:%s", VTY_NEWLINE);
  for (i = listhead (iface->connected); i; nextnode (i))
    {
      c = (struct connected *)getdata (i);
      p = c->address;
      prefix2str (p, strbuf, sizeof (strbuf));
      switch (p->family)
        {
        case AF_INET:
          vty_out (vty, "   inet : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        case AF_INET6:
          vty_out (vty, "   inet6: %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        default:
          vty_out (vty, "   ???  : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        }
    }

  if (ospf6_if->area)
    {
      vty_out (vty, "  Instance ID %lu, Router ID %s%s",
	       ospf6_if->instance_id,
	       inet4str (ospf6_if->area->ospf6->router_id),
	       VTY_NEWLINE);
      vty_out (vty, "  Area ID %s, Cost %hu%s",
	       inet4str (ospf6_if->area->area_id), 
	       ospf6_if->cost, VTY_NEWLINE);
    }
  else
    vty_out (vty, "  Not Attached to Area%s", VTY_NEWLINE);

  vty_out (vty, "  State %s, Transmit Delay %lu sec%s",
           ifs_name[ospf6_if->state],
           ospf6_if->inf_trans_delay,
	   VTY_NEWLINE);
  vty_out (vty, "  Timer intervals configured:%s", VTY_NEWLINE);
  vty_out (vty, "   Hello %lu, Dead %lu, Retransmit %lu%s",
           ospf6_if->hello_interval,
           ospf6_if->rtr_dead_interval,
           ospf6_if->rxmt_interval,
	   VTY_NEWLINE);

  inet_ntop (AF_INET, &ospf6_if->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &ospf6_if->bdr, bdr, sizeof (bdr));
  vty_out (vty, "  DR:%s BDR:%s%s", dr, bdr, VTY_NEWLINE);

  vty_out (vty, "  Number of I/F scoped LSAs is %u%s",
           listcount (ospf6_if->linklocal_lsa), VTY_NEWLINE);
  vty_out (vty, "  %-16s %5d times, %-16s %5d times%s",
                "DRElection", ospf6_if->ospf6_stat_dr_election,
                "DelayedLSAck", ospf6_if->ospf6_stat_delayed_lsack,
                VTY_NEWLINE);

  return 0;
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

  ifname = argv[0];
  inet_pton (AF_INET, argv[1], &area_id);

  if (area_id != 0)
    {
      vty_out (vty, "Area ID other than Backbone(0.0.0.0), "
               "not yet implimented%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ifp = if_lookup_by_name (ifname);
  if (!ifp)
    {
      vty_out (vty, "No such interface: %s%s", ifname,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf6_area_lookup (area_id);
  if (!area)
    {
      vty_out (vty, "No such area: %s%s",
               inet4str (area_id),
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf6_if = ospf6_if_lookup (ifname);
  if (!ospf6_if)
    {
      vty_out (vty, "No such ospf6 interface: %s%s", ifname,
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* xxx delete_ospf6_if (ospf6_if, area); */
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_cost,
       ip6_ospf6_cost_cmd,
       "ipv6 ospf6 cost COST",
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

  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->cost = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_hellointerval,
       ip6_ospf6_hellointerval_cmd,
       "ipv6 ospf6 hello-interval HELLO_INTERVAL",
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
  ospf6_if = (struct ospf6_if *) ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->hello_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_deadinterval,
       ip6_ospf6_deadinterval_cmd,
       "ipv6 ospf6 dead-interval ROUTER_DEAD_INTERVAL",
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
  ospf6_if = (struct ospf6_if *) ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->rtr_dead_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_transmitdelay,
       ip6_ospf6_transmitdelay_cmd,
       "ipv6 ospf6 transmit-delay TRANSMITDELAY",
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
  ospf6_if = (struct ospf6_if *) ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->inf_trans_delay = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_retransmitinterval,
       ip6_ospf6_retransmitinterval_cmd,
       "ipv6 ospf6 retransmit-interval RXMTINTERVAL",
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
  ospf6_if = (struct ospf6_if *) ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->rxmt_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ip6_ospf6_priority,
       ip6_ospf6_priority_cmd,
       "ipv6 ospf6 priority PRIORITY",
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
  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->rtr_pri = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (ip6_ospf6_instance,
       ip6_ospf6_instance_cmd,
       "ipv6 ospf6 instance-id COST",
       IP6_STR
       OSPF6_STR
       "Instance ID\n"
       "<0-255> Instance ID\n"
       )
{
  struct ospf6_if *ospf6_if;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  ospf6_if = (struct ospf6_if *)ifp->info;
  if (!ospf6_if)
    ospf6_if = make_ospf6_if (ifp);
  assert (ospf6_if);

  ospf6_if->instance_id = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

int
ospf6_if_config_write (struct vty *vty)
{
  listnode j,k;
  struct ospf6_if *ospf6_if;
  struct area *area;

  for (j = listhead (ospf6->area_list); j; nextnode (j))
    {
      area = (struct area *) getdata (j);
      for (k = listhead (area->if_list); k; nextnode (k))
        {
          ospf6_if = (struct ospf6_if *) getdata (k);
          vty_out (vty, "interface %s%s",
		   ospf6_if->interface->name,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 cost %d%s",
		   ospf6_if->cost,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 hello-interval %d%s",
		   ospf6_if->hello_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 dead-interval %d%s",
                   ospf6_if->rtr_dead_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 retransmit-interval %d%s",
                   ospf6_if->rxmt_interval,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 priority %d%s",
                   ospf6_if->rtr_pri,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 transmit-delay %d%s",
                   ospf6_if->inf_trans_delay,
		   VTY_NEWLINE);
          vty_out (vty, " ipv6 ospf6 instance-id %d%s",
                   ospf6_if->instance_id,
		   VTY_NEWLINE);
          vty_out (vty, "!%s", VTY_NEWLINE);
        }
    }

  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

void
ospf6_if_init ()
{
  /* Install interface node. */
  install_node (&interface_node, ospf6_if_config_write);

  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_transmitdelay_cmd);
  install_element (INTERFACE_NODE, &ip6_ospf6_instance_cmd);
}

