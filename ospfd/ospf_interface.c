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

#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "command.h"
#include "thread.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospfd.h"

#include "zebra/zebra.h"

struct ospf_interface *
ospf_if_new (struct interface *ifp)
{
  struct ospf_interface *oi;

  oi = XMALLOC (MTYPE_IF, sizeof (struct ospf_interface));
  bzero (oi, sizeof (struct ospf_interface));

  /* Set zebra interface pointer. */
  oi->ifp = ifp;

  /* file descriptor reset. */
  oi->fd = -1;

  /* Set default values. */
  oi->flag = OSPF_IF_DISABLE;
  oi->type = OSPF_IFTYPE_BROADCAST;
  oi->status = ISM_Down;

  oi->auth_type = OSPF_AUTH_NULL;

  /* Interface configurable values. */
  oi->priority = OSPF_ROUTER_PRIORITY_DEFAULT;
  oi->options = 2;

  oi->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;
  oi->output_cost = OSPF_OUTPUT_COST_DEFAULT;
  oi->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;

  /* Timer values. */
  oi->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;
  oi->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;

  /* Initialize neighbor list. */
  oi->nbrs = route_table_init ();

  /* Kick ospf process if it is needed. */
  ospf_if_update ();

  return oi;
}

void
ospf_if_stream_set (int sock, struct ospf_interface *oi)
{
  oi->fd = sock;

  /* set buffer. */
  oi->ibuf = stream_new (oi->ifp->mtu);
  OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);

  /*
  oi->obuf = stream_new (oi->ifp->mtu);
  OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd);
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

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->if_data;

      if (oi->flag == OSPF_IF_DISABLE)
	continue;

      vty_out (vty, "!%s", VTY_NEWLINE);
      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);

      /* Interface Output Cost print. */
      vty_out (vty, " ip ospf cost %u%s", oi->output_cost, VTY_NEWLINE);

      /* Hello Interval print. */
      vty_out (vty, " ip ospf hello-interval %u%s",
	       oi->v_hello, VTY_NEWLINE);

      /* Router Dead Interval print. */
      vty_out (vty, " ip ospf dead-interval %u%s",
	       oi->v_wait, VTY_NEWLINE);

      /* Router Priority print. */
      vty_out (vty, " ip ospf priority %u%s",
	       oi->priority, VTY_NEWLINE);

      /* Retransmit Interval print. */
      vty_out (vty, " ip ospf retransmit-interval %u%s",
	       oi->retransmit_interval, VTY_NEWLINE);

      /* Transmit Delay print. */
      vty_out (vty, " ip ospf transmit-delay %u%s",
	       oi->transmit_delay, VTY_NEWLINE);
    }

  return 0;
}


DEFUN (if_ospf_authentication_key,
       if_ospf_authentication_key_cmd,
       "ospf authentication-key AUTH_KEY",
       "OSPF interface commands\n"
       "Authentication password (key)")
{
  /* not yet implemented. */
  return CMD_SUCCESS;
}

DEFUN (if_ospf_cost,
       if_ospf_cost_cmd,
       "ospf cost COST",
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

DEFUN (if_ospf_dead_interval,
       if_ospf_dead_interval_cmd,
       "ospf dead-interval INTERVAL",
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

DEFUN (if_ospf_hello_interval,
       if_ospf_hello_interval_cmd,
       "ospf hello-interval INTERVAL",
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

DEFUN (if_ospf_network,
       if_ospf_network_cmd,
       "ospf network TYPE",
       "OSPF interface commands\n"
       "Network type")
{
  /* not yet implemented. */
  return CMD_SUCCESS;
}

DEFUN (if_ospf_priority,
       if_ospf_priority_cmd,
       "ospf priority NUMBER",
       "OSPF interface commands\n"
       "Router priority"
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

DEFUN (if_ospf_retransmit_interval,
       if_ospf_retransmit_interval_cmd,
       "ospf retransmit-interval INTERVAL",
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

DEFUN (if_ospf_transmit_delay,
       if_ospf_transmit_delay_cmd,
       "ospf transmit-delay DELAY",
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
  /*  install_element (INTERFACE_NODE, &if_ospf_authentication_key_cmd); */
  install_element (INTERFACE_NODE, &if_ospf_cost_cmd);
  install_element (INTERFACE_NODE, &if_ospf_dead_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_hello_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_network_cmd);
  install_element (INTERFACE_NODE, &if_ospf_priority_cmd);
  install_element (INTERFACE_NODE, &if_ospf_retransmit_interval_cmd);
  install_element (INTERFACE_NODE, &if_ospf_transmit_delay_cmd);
}

