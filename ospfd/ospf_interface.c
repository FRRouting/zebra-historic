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

#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospfd.h"

#include "zebra/zebra.h"

void
ospf_if_reset_variables (struct ospf_interface *oi)
{
  /* file descriptor reset. */
  oi->fd = -1;

  /* Set default values. */
  oi->flag = OSPF_IF_DISABLE;
  oi->type = OSPF_IFTYPE_BROADCAST;
  oi->status = ISM_Down;

  /* Interface configurable values. */
  oi->priority = OSPF_ROUTER_PRIORITY_DEFAULT;
  oi->options = OSPF_OPTION_E;

  bzero (oi->auth_data, OSPF_AUTH_SIZE);

  oi->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;
  oi->output_cost = OSPF_OUTPUT_COST_DEFAULT;
  oi->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;

  /* Timer values. */
  oi->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;
  oi->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
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

  return oi;
}

struct ospf_interface *
ospf_if_lookup_by_addr (struct in_addr *address)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->if_data;

      if (if_is_loopback (ifp))
	continue;

      if (!if_is_up (ifp))
	continue;

      if (oi->flag != OSPF_IF_ENABLE)
	continue;

      if (IPV4_ADDR_SAME (address, &oi->address->u.prefix4))
	return oi;
    }

  return NULL;
}

void
ospf_if_stream_set (int sock, struct ospf_interface *oi)
{
  /* set input buffer. */
  oi->ibuf = stream_new (oi->ifp->mtu);
  OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);

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
  ifp->if_data = ospf_if_new (ifp);
  return 0;
}

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
      oi = ifp->if_data;

      if (!if_is_up (ifp))
	continue;

      vty_out (vty, "!%s", VTY_NEWLINE);
      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);

      write++;

      /* Authentication Key print. */
      if (strlen (oi->auth_data))
	vty_out (vty, " ospf authentication-key %s%s",
		 oi->auth_data, VTY_NEWLINE);

      /* Interface Output Cost print. */
      if (oi->output_cost != OSPF_OUTPUT_COST_DEFAULT)
	vty_out (vty, " ospf cost %u%s", oi->output_cost, VTY_NEWLINE);

      /* Hello Interval print. */
      if (oi->v_hello != OSPF_HELLO_INTERVAL_DEFAULT)
	vty_out (vty, " ospf hello-interval %u%s",
		 oi->v_hello, VTY_NEWLINE);

      /* Router Dead Interval print. */
      if (oi->v_wait != OSPF_ROUTER_DEAD_INTERVAL_DEFAULT)
	vty_out (vty, " ospf dead-interval %u%s",
		 oi->v_wait, VTY_NEWLINE);

      /* Router Priority print. */
      if (oi->priority != OSPF_ROUTER_PRIORITY_DEFAULT)
	vty_out (vty, " ospf priority %u%s",
		 oi->priority, VTY_NEWLINE);

      /* Retransmit Interval print. */
      if (oi->retransmit_interval != OSPF_RETRANSMIT_INTERVAL_DEFAULT)
	vty_out (vty, " ospf retransmit-interval %u%s",
		 oi->retransmit_interval, VTY_NEWLINE);

      /* Transmit Delay print. */
      if (oi->transmit_delay != OSPF_TRANSMIT_DELAY_DEFAULT)
	vty_out (vty, " ospf transmit-delay %u%s",
		 oi->transmit_delay, VTY_NEWLINE);
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
  oi = ifp->if_data;

  bzero (oi->auth_data, OSPF_AUTH_SIZE);
  strncpy (oi->auth_data, argv[0], OSPF_AUTH_SIZE);

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
  oi = ifp->if_data;

  bzero (oi->auth_data, OSPF_AUTH_SIZE);

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
  /* not yet implemented. */
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
  oi = ifp->if_data;

  cost = strtol (argv[0], NULL, 10);

  /* cost range is <1-65535>. */
  if (cost < 1 || cost > 65535)
    {
      vty_out (vty, "Interface output cost is invalid\r\n");
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
  oi = ifp->if_data;

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
  oi = ifp->if_data;

  seconds = strtol (argv[0], NULL, 10);

  /* dead_interval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Router Dead Interval is invalid\r\n");
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
  oi = ifp->if_data;

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
  oi = ifp->if_data;

  seconds = strtol (argv[0], NULL, 10);

  /* HelloInterval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Hello Interval is invalid\r\n");
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
  oi = ifp->if_data;

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
  oi = ifp->if_data;

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
  oi = ifp->if_data;

  oi->type = OSPF_IFTYPE_POINTOPOINT;

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
  oi = ifp->if_data;

  priority = strtol (argv[0], NULL, 10);

  /* Router Priority range is <0-255>. */
  if (priority < 0 || priority > 255)
    {
      vty_out (vty, "Router Priority is invalid\r\n");
      return CMD_WARNING;
    }

  oi->priority = priority;

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
  oi = ifp->if_data;

  oi->priority = OSPF_ROUTER_PRIORITY_DEFAULT;

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
  oi = ifp->if_data;

  seconds = strtol (argv[0], NULL, 10);

  /* Retransmit Interval range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Retransmit Interval is invalid\r\n");
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
  oi = ifp->if_data;

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
  oi = ifp->if_data;

  seconds = strtol (argv[0], NULL, 10);

  /* Transmit Delay range is <1-65535>. */
  if (seconds < 1 || seconds > 65535)
    {
      vty_out (vty, "Transmit Delay is invalid\r\n");
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
  oi = ifp->if_data;

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

