/*
 * OSPF Interface functions.
 * Copyright (C) 1999 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospfd.h"

void
ospf_if_reset_variables (struct ospf_interface *oi)
{
  /* file descriptor reset. */
  oi->fd = -1;

  /* Set default values. */
  oi->flag = OSPF_IF_DISABLE;

  if (oi->vl_data)
    oi->type = OSPF_IFTYPE_VIRTUALLINK;
  else 
    oi->type = OSPF_IFTYPE_BROADCAST;

  oi->status = ISM_Down;

  bzero (oi->auth_data, OSPF_AUTH_MD5_SIZE);
  oi->auth_md5 = 0;
  oi->auth_seq = 0;

  oi->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;
  oi->output_cost = OSPF_OUTPUT_COST_DEFAULT;
  oi->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;

  /* Timer values. */
  oi->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;
  oi->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
  oi->v_ls_ack = OSPF_RETRANSMIT_INTERVAL_DEFAULT;
}

struct ospf_interface *
ospf_if_new (struct interface *ifp)
{
  struct ospf_interface *oi;

  oi = XMALLOC (MTYPE_OSPF_IF, sizeof (struct ospf_interface));
  bzero (oi, sizeof (struct ospf_interface));

  /* Set zebra interface pointer. */
  oi->ifp = ifp;

  /* Set default values. */
  ospf_if_reset_variables (oi);

  /* Clear self-originated network-LSA. */
  oi->network_lsa_self = NULL;

  /* Initialize neighbor list. */
  oi->nbrs = route_table_init ();

  /* Initialize Link State Acknowledgment list. */
  oi->ls_ack = list_init ();

  /* Add pseudo neighbor. */
  oi->nbr_self = ospf_nbr_new (oi);
  oi->nbr_self->status = NSM_TwoWay;
  /*  oi->nbr_self->router_id = ospf_top->router_id; */
  oi->nbr_self->priority = OSPF_ROUTER_PRIORITY_DEFAULT;

  if (oi->area)
    {
      if (oi->area->external_routing == OSPF_AREA_DEFAULT)
        oi->nbr_self->options = OSPF_OPTION_E;
    }
  else
    oi->nbr_self->options = OSPF_OPTION_E;

  /* Set LS Ack timer. */
  OSPF_ISM_TIMER_ON (oi->t_ls_ack, ospf_ls_ack_timer, oi->v_ls_ack);

  return oi;
}

void
ospf_if_free (struct ospf_interface *oi)
{
  struct route_node *rn;
  struct prefix p;

  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    list_delete_by_val (oi->area->iflist, oi->ifp);
  else
    {
      p.family = AF_INET;
      p.u.prefix4 = oi->address->u.prefix4;
      p.prefixlen = IPV4_MAX_BITLEN;

      ospf_interface_down (ospf_top, &p, oi->area);
    }

  OSPF_ISM_EVENT_EXECUTE (oi, ISM_InterfaceDown);
  OSPF_ISM_TIMER_OFF (oi->t_ls_ack);

  if (oi->t_network_lsa_self)
     OSPF_TIMER_OFF (oi->t_network_lsa_self);

  RT_ITERATOR (oi->nbrs, rn)
    {
      if (rn->info == NULL)
	continue;

      ospf_nbr_free ((struct ospf_neighbor *) rn->info);
    }

  route_table_finish (oi->nbrs);

  list_delete_all (oi->ls_ack);

  XFREE (MTYPE_OSPF_IF, oi);
}

struct ospf_interface *
ospf_if_lookup_by_addr (struct in_addr *address)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      if ((ifp = getdata (node)) == NULL)
	continue;

      if ((oi = ifp->info) == NULL)
	continue;

      if (!ospf_if_is_enable (ifp))
	continue;

      if (IPV4_ADDR_SAME (address, &oi->address->u.prefix4))
	return oi;
    }

  return NULL;
}

struct ospf_interface *
ospf_if_lookup_by_prefix (struct prefix_ipv4 *p)
{
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;
  struct prefix_ipv4 ip;

  zlog_info ("Z: ospf_if_lookup_by_prefix(): Start");

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      if ((ifp = getdata (node)) == NULL)
	continue;

      zlog_info ("Z: ospf_if_lookup_by_prefix(): looking at %s", ifp->name);

      if ((oi = ifp->info) == NULL)
	continue;

      if (oi->address == NULL)
	continue;

      prefix_copy ((struct prefix *) &ip, oi->address);

      zlog_info ("Z: ospf_if_lookup_by_prefix(): its prefix is %s/%d", 
		 inet_ntoa (ip.prefix), ip.prefixlen);

      apply_mask_ipv4 (&ip);

      if (prefix_same ((struct prefix *) &ip, (struct prefix *) p))
	return oi;
    }

  zlog_info ("Z: ospf_if_lookup_by_prefix(): I didn't find it");
  return NULL;
}

void
ospf_if_stream_set (struct ospf_interface *oi)
{
  /* set input buffer. */

  if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
    {
      oi->ibuf = stream_new (oi->ifp->mtu * 2);
      OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);
    }

  /* set output fifo queue. */
  oi->obuf = ospf_fifo_new ();
}

void
ospf_if_stream_unset (struct ospf_interface *oi)
{
  /* unset input buffer. */
  stream_free (oi->ibuf);
  OSPF_ISM_READ_OFF (oi->t_read);

  /*
  stream_free (oi->obuf);
  OSPF_ISM_WRITE_OFF (oi->t_write);
  */
}

int
ospf_if_new_hook (struct interface *ifp)
{
  ifp->info = ospf_if_new (ifp);

  return 0;
}

int
ospf_if_delete_hook (struct interface *ifp)
{
  ospf_if_free ((struct ospf_interface *) ifp->info);

  return 0;
}


int
ospf_if_is_enable (struct interface *ifp)
{
  struct ospf_interface *oi = ifp->info;

  if (if_is_loopback (ifp))
    return 0;

  if (!if_is_up (ifp))
    return 0;

  if (oi->flag != OSPF_IF_ENABLE)
    return 0;

  return 1;
}


struct ospf_vl_data *
ospf_vl_data_new (struct ospf_area * area, struct in_addr vl_peer)
{
  struct ospf_vl_data *vl_data;

  vl_data = XMALLOC (MTYPE_OSPF_VL_DATA, sizeof (struct ospf_vl_data));
  bzero (vl_data, sizeof (struct ospf_vl_data));

  vl_data->vl_peer.s_addr = vl_peer.s_addr;
  vl_data->vl_area = area;

  return vl_data;
}

void
ospf_vl_data_free (struct ospf_vl_data *vl_data)
{
  XFREE (MTYPE_OSPF_VL_DATA, vl_data);
}

u_int vlink_count = 0;

void
ospf_vl_set_variables (struct ospf_interface *voi)
{
  voi->ifp->mtu = OSPF_VL_MTU;
  voi->flag = OSPF_IF_ENABLE;
  voi->type = OSPF_IFTYPE_VIRTUALLINK;
}

struct ospf_interface * 
ospf_vl_new (struct ospf_vl_data *vl_data)
{
  struct ospf_interface * voi;
  struct interface * vi;
  char   ifname[INTERFACE_NAMSIZ + 1];
  struct in_addr area_id;

  zlog_info ("Z: ospf_vl_new(): Start");

  if (vlink_count == OSPF_VL_MAX_COUNT)
    {
      zlog_info ("Z: ospf_vl_new(): Alarm: "
		 "cannot create more than OSPF_MAX_VL_COUNT virtual links");
      return NULL;
    }

  zlog_info ("Z: ospf_vl_new(): creating pseudo zebra interface");

  vi = if_create ();
  voi = vi->info;

  if (voi == NULL)
    {
      zlog_info ("Z: ospf_vl_new(): Alarm: OSPF int structure is not created");
      return NULL;
    }

  voi->address = (struct prefix *) prefix_ipv4_new ();
  voi->address->family = AF_INET;
  voi->address->u.prefix4.s_addr = 0;
  voi->address->prefixlen = 0;
  voi->vl_data = vl_data;

  ospf_vl_set_variables (voi);

  sprintf (ifname, "VLINK%d", vlink_count++);
  zlog_info ("Z: ospf_vl_new(): Created name: %s", ifname);

  strncpy (vi->name, ifname, IFNAMSIZ);
  zlog_info ("Z: ospf_vl_new(): set if->name to %s", vi->name);

  area_id.s_addr = 0;
  voi->area = ospf_area_lookup_by_area_id (area_id);
  zlog_info ("Z: ospf_vl_new(): set associated area to the backbone");

  list_add_node (voi->area->iflist, vi);

  ospf_if_stream_set (voi);

  zlog_info ("Z: ospf_vl_new(): Stop");
  return voi;
}

void
ospf_vl_if_delete (struct ospf_vl_data *vl_data)
{
  if_delete (vl_data->vl_oi->ifp);
}

struct ospf_vl_data *
ospf_vl_lookup (struct ospf_area *area, struct in_addr vl_peer)
{
  struct ospf_vl_data *vl_data;
  listnode node;

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      if (vl_data->vl_peer.s_addr == vl_peer.s_addr &&
	  vl_data->vl_area == area)
	return vl_data;
    }

  return NULL;
}

void
ospf_vl_add (struct ospf_vl_data *vl_data)
{
  list_add_node (ospf_top->vlinks, vl_data);
}

void
ospf_vl_delete (struct ospf_vl_data *vl_data)
{
  list_delete_by_val (ospf_top->vlinks, vl_data);

  ospf_vl_if_delete (vl_data);
  ospf_vl_data_free (vl_data);
}

void
ospf_vl_set_params (struct ospf_vl_data *vl_data, struct vertex *v)
{
  int changed = 0;
  struct ospf_interface *voi;
  listnode node;
  struct ospf_nexthop *nh;
  int ret;

  voi = vl_data->vl_oi;

  if (voi->output_cost != v->distance)
    {
      voi->output_cost = v->distance;
      changed = 1;
    }

  /* Associate the VL with a physical interface. */
  ospf_vl_set_variables (voi);

  LIST_ITERATOR (v->nexthop, node)
    {
      if ((nh = getdata (node)) == NULL)
	continue;

      vl_data->out_oi = (struct ospf_interface *) nh->ifp->info;

      voi->address->u.prefix4 = vl_data->out_oi->address->u.prefix4;
      voi->address->prefixlen = vl_data->out_oi->address->prefixlen;

      break; /* We take the first interface. */
    }

  if (voi->fd == -1)
    ret = ospf_serv_sock_init (voi->ifp, voi->address);

  vl_data->peer_addr = v->address;
}


void
ospf_vl_up_check (struct ospf_area * area, struct in_addr rid,
		  struct vertex *v)
{
  listnode node;
  struct ospf_vl_data *vl_data;
  struct ospf_interface *oi;

  zlog_info ("Z: ospf_vl_up_check(): Start");
  zlog_info ("Z: ospf_vl_up_check(): Router ID is %s", inet_ntoa (rid));
  zlog_info ("Z: ospf_vl_up_check(): Area is %s", inet_ntoa (area->area_id));

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;
  
      zlog_info ("Z: ospf_vl_up_check(): considering VL, name: %s", 
		 vl_data->vl_oi->ifp->name);
      zlog_info ("Z: ospf_vl_up_check(): VL area: %s, peer ID: %s", 
		 inet_ntoa (vl_data->vl_area->area_id),
		 inet_ntoa (vl_data->vl_peer));

      /*
      if (vl_data->vl_peer.s_addr == rid.s_addr &&
	  vl_data->vl_area == area)
      */

      if (IPV4_ADDR_SAME (&vl_data->vl_peer, &rid) &&
	  vl_data->vl_area == area)
	{
	  oi = vl_data->vl_oi;
	  SET_FLAG (vl_data->flags, OSPF_VL_FLAG_APPROVED);

	  zlog_info ("Z: ospf_vl_up_check(): this VL matched");

	  if (oi->status == ISM_Down)
	    {
	      zlog_info ("Z: ospf_vl_up_check(): VL is down, waking it up");
	      SET_FLAG (oi->ifp->flags, IFF_UP);
	      OSPF_ISM_EVENT_SCHEDULE (oi, ISM_InterfaceUp);
	    }

	  ospf_vl_set_params (vl_data, v);
	}
    }
}

void 
ospf_vl_shutdown (struct ospf_vl_data *vl_data)
{
  struct ospf_interface *oi;

  oi = vl_data->vl_oi;
  if (oi == NULL)
    return;

  oi->address->u.prefix4.s_addr = 0;
  oi->address->prefixlen = 0;

  UNSET_FLAG (oi->ifp->flags, IFF_UP);
  OSPF_ISM_EVENT_SCHEDULE (oi, ISM_InterfaceDown);
}

void
ospf_vl_unapprove ()
{
  listnode node;
  struct ospf_vl_data *vl_data;

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      UNSET_FLAG (vl_data->flags, OSPF_VL_FLAG_APPROVED);
    }
}

void
ospf_vl_shut_unapproved ()
{
  listnode node;
  struct ospf_vl_data *vl_data;

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      if (!CHECK_FLAG (vl_data->flags, OSPF_VL_FLAG_APPROVED))
	ospf_vl_shutdown (vl_data);
    }
}

int
ospf_full_virtual_nbrs (struct ospf_area *area)
{
#if 0
  listnode node;
  struct ospf_vl_data *vl_data;
  int c;
#endif /* 0 */

  zlog_info ("Z: counting fully adjacent virtual neighbors in area %s",
	     inet_ntoa (area->area_id));
  zlog_info ("Z: there are %d of them", area->full_vls);

  return area->full_vls;

#if 0
  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      if (vl_data->vl_area != area)
	continue;

      c = ospf_nbr_count (vl_data->vl_oi->nbrs, NSM_Full);
 
      zlog_info ("Z: the number is %d", c);
      return c;

    }
  return 0;
#endif
}

int
ospf_vls_in_area (struct ospf_area *area)
{
  listnode node;
  struct ospf_vl_data *vl_data;
  int c = 0;

  LIST_ITERATOR (ospf_top->vlinks, node)
    {
      if ((vl_data = getdata (node)) == NULL)
	continue;

      if (vl_data->vl_area == area)
	c++;
    }
  return c;
}


char *ospf_int_type_str[] = 
{
  "unknown",               /*should never be used*/
  "point-to-point",
  "broadcast",
  "nbma",
  "point-to-multipoint",
  "virtual-link"           /*should never be used*/
};

/* Configuration write function for ospfd. */
int
interface_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;
  int write = 0;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (!if_is_up (ifp))
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
        continue;

      vty_out (vty, "!%s", VTY_NEWLINE);
      vty_out (vty, "interface %s%s", ifp->name,
	       VTY_NEWLINE);

      write++;

      /* Interface Output Cost print. */
      if (oi->type != OSPF_IFTYPE_BROADCAST)
	vty_out (vty, " ospf network %s%s", ospf_int_type_str[oi->type], 
                 VTY_NEWLINE);

      /* Authentication Key print. */
      if (strlen (oi->auth_data) && oi->auth_md5 == 0)
	vty_out (vty, " ospf authentication-key %s%s", oi->auth_data,
		 VTY_NEWLINE);

      if (strlen (oi->auth_data) && oi->auth_md5 == 1)
	vty_out (vty, " ospf message-digest-key %d md5 %s%s",
                 oi->auth_key_id, oi->auth_data, VTY_NEWLINE);

      /* Interface Output Cost print. */
      if (oi->output_cost != OSPF_OUTPUT_COST_DEFAULT)
	vty_out (vty, " ospf cost %u%s", oi->output_cost, VTY_NEWLINE);

      /* Hello Interval print. */
      if (oi->v_hello != OSPF_HELLO_INTERVAL_DEFAULT)
	vty_out (vty, " ospf hello-interval %u%s", oi->v_hello, VTY_NEWLINE);

      /* Router Dead Interval print. */
      if (oi->v_wait != OSPF_ROUTER_DEAD_INTERVAL_DEFAULT)
	vty_out (vty, " ospf dead-interval %u%s", oi->v_wait, VTY_NEWLINE);

      /* Router Priority print. */
      if (oi->nbr_self)
	if (PRIORITY (oi) != OSPF_ROUTER_PRIORITY_DEFAULT)
	  vty_out (vty, " ospf priority %u%s", PRIORITY (oi), VTY_NEWLINE);

      /* Retransmit Interval print. */
      if (oi->retransmit_interval != OSPF_RETRANSMIT_INTERVAL_DEFAULT)
	vty_out (vty, " ospf retransmit-interval %u%s",
		 oi->retransmit_interval, VTY_NEWLINE);

      /* Transmit Delay print. */
      if (oi->transmit_delay != OSPF_TRANSMIT_DELAY_DEFAULT)
	vty_out (vty, " ospf transmit-delay %u%s", oi->transmit_delay,
		 VTY_NEWLINE);
    }

  return write;
}


DEFUN (if_ospf_authentication_key,
       if_ospf_authentication_key_cmd,
       "ospf authentication-key AUTH_KEY",
       "OSPF interface commands\n"
       "Authentication password (key)")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  bzero (oi->auth_data, OSPF_AUTH_MD5_SIZE);
  strncpy (oi->auth_data, argv[0], OSPF_AUTH_SIMPLE_SIZE);
  oi->auth_md5 = 0;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_authentication_key,
       no_if_ospf_authentication_key_cmd,
       "ospf authentication-key",
       NO_STR
       "OSPF interface commands\n")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  bzero (oi->auth_data, OSPF_AUTH_MD5_SIZE);

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_message_digest_key,
       no_if_ospf_message_digest_key_cmd,
       "ospf message-digest-key",
       NO_STR
       "OSPF interface commands\n")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  bzero (oi->auth_data, OSPF_AUTH_MD5_SIZE);
  oi->auth_md5 = 0;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_message_digest_key,
       if_ospf_message_digest_key_cmd,
       "ospf message-digest-key KEYID md5 KEY",
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int8_t keyid;

  ifp = vty->index;
  oi = ifp->info;

  keyid = strtol (argv[0], NULL, 10);
  oi->auth_key_id = keyid;

  bzero (oi->auth_data, OSPF_AUTH_MD5_SIZE);
  strncpy (oi->auth_data, argv[1], OSPF_AUTH_SIMPLE_SIZE);
  oi->auth_md5 = 1;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_cost,
       if_ospf_cost_cmd,
       "ospf cost <1-65535>",
       "OSPF interface commands\n"
       "Interface cost\n"
       "Cost")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t cost;

  ifp = vty->index;
  oi = ifp->info;

  cost = strtol (argv[0], NULL, 10);

  /* cost range is <1-65535>. */
  if (cost < 1 || cost > 65535)
    {
      vty_out (vty, "Interface output cost is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->output_cost = cost;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_cost,
       no_if_ospf_cost_cmd,
       "no ospf cost",
       NO_STR
       "OSPF interface commands\n"
       "Interface cost")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->output_cost = OSPF_OUTPUT_COST_DEFAULT;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_dead_interval,
       if_ospf_dead_interval_cmd,
       "ospf dead-interval <1-65535>",
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t seconds;

  ifp = vty->index;
  oi = ifp->info;

  seconds = strtol (argv[0], NULL, 10);

  /* dead_interval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Router Dead Interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->v_wait = seconds;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_dead_interval,
       no_if_ospf_dead_interval_cmd,
       "no ospf dead-interval",
       NO_STR
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_hello_interval,
       if_ospf_hello_interval_cmd,
       "ospf hello-interval <1-65535>",
       "OSPF interface commands\n"
       "Time between HELLO packets\n"
       "Seconds")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t seconds;

  ifp = vty->index;
  oi = ifp->info;

  seconds = strtol (argv[0], NULL, 10);

  /* HelloInterval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Hello Interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->v_hello = seconds;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_hello_interval,
       no_if_ospf_hello_interval_cmd,
       "no ospf hello-interval",
       NO_STR
       "OSPF interface commands\n"
       "Time between HELLO packets")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_network,
       if_ospf_network_cmd,
       "ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point",
       "OSPF interface commands\n"
       "Network type\n"
       "Specify OSPF broadcast multi-access network\n"
       "Specify OSPF NBMA network\n"
       "Specify OSPF point-to-multipoint network\n"
       "Specify OSPF point-to-point network\n")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  if (strncmp (argv[0], "b", 1) == 0)
    oi->type = OSPF_IFTYPE_BROADCAST;
  else if (strncmp (argv[0], "n", 1) == 0)
    oi->type = OSPF_IFTYPE_NBMA;
  else if (strncmp (argv[0], "point-to-m", 10) == 0)
    oi->type = OSPF_IFTYPE_POINTOMULTIPOINT;
  else if (strncmp (argv[0], "point-to-p", 10) == 0)
    oi->type = OSPF_IFTYPE_POINTOPOINT;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_network,
       no_if_ospf_network_cmd,
       "no ospf network",
       NO_STR
       "OSPF interface commands\n"
       "Network type")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->type = OSPF_IFTYPE_BROADCAST;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_priority,
       if_ospf_priority_cmd,
       "ospf priority <0-255>",
       "OSPF interface commands\n"
       "Router priority\n"
       "Priority")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t priority;

  ifp = vty->index;
  oi = ifp->info;

  priority = strtol (argv[0], NULL, 10);

  /* Router Priority range is <0-255>. */
  if (priority < 0 || priority > 255)
    {
      vty_out (vty, "Router Priority is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  PRIORITY (oi) = priority;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_priority,
       no_if_ospf_priority_cmd,
       "no ospf priority",
       NO_STR
       "OSPF interface commands\n"
       "Router priority")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  PRIORITY (oi) = OSPF_ROUTER_PRIORITY_DEFAULT;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_retransmit_interval,
       if_ospf_retransmit_interval_cmd,
       "ospf retransmit-interval <1-65535>",
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t seconds;

  ifp = vty->index;
  oi = ifp->info;

  seconds = strtol (argv[0], NULL, 10);

  /* Retransmit Interval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Retransmit Interval is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->retransmit_interval = seconds;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_retransmit_interval,
       no_if_ospf_retransmit_interval_cmd,
       "no ospf retransmit-interval",
       NO_STR
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

DEFUN (if_ospf_transmit_delay,
       if_ospf_transmit_delay_cmd,
       "ospf transmit-delay <1-65535>",
       "OSPF interface commands\n"
       "Link state transmit delay\n"
       "Seconds")
{
  struct interface *ifp;
  struct ospf_interface *oi;
  u_int32_t seconds;

  ifp = vty->index;
  oi = ifp->info;

  seconds = strtol (argv[0], NULL, 10);

  /* Transmit Delay range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Transmit Delay is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->transmit_delay = seconds;

  return CMD_SUCCESS;
}

DEFUN (no_if_ospf_transmit_delay,
       no_if_ospf_transmit_delay_cmd,
       "no ospf transmit-delay",
       NO_STR
       "OSPF interface commands\n"
       "Link state transmit delay")
{
  struct interface *ifp;
  struct ospf_interface *oi;

  ifp = vty->index;
  oi = ifp->info;

  oi->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;

  return CMD_SUCCESS;
}


/* ospfd's interface node. */
struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Initialization of interface. */
void
ospf_if_init ()
{
  /* Initialize interface data structure. */
  if_init ();
  if_add_hook (IF_NEW_HOOK, ospf_if_new_hook);
  if_add_hook (IF_DELETE_HOOK, ospf_if_delete_hook);

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &if_ospf_authentication_key_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_authentication_key_cmd);
  install_element (INTERFACE_NODE, &if_ospf_message_digest_key_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_message_digest_key_cmd);
  install_element (INTERFACE_NODE, &if_ospf_cost_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_cost_cmd);
  install_element (INTERFACE_NODE, &if_ospf_dead_interval_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_dead_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_hello_interval_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_hello_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_network_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_network_cmd);
  install_element (INTERFACE_NODE, &if_ospf_priority_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_priority_cmd);
  install_element (INTERFACE_NODE, &if_ospf_retransmit_interval_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_retransmit_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_transmit_delay_cmd);
  install_element (INTERFACE_NODE, &no_if_ospf_transmit_delay_cmd);
}
