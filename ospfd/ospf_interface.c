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

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_packet.h"

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
  oi->flag = OSPF_FLAG_SLEEP;
  oi->type = OSPF_IFTYPE_BROADCAST;
  oi->status = ISM_Down;

  oi->auth_type = OSPF_AUTH_NULL;
  inet_aton ("0.0.0.0", &oi->d_router);
  inet_aton ("0.0.0.0", &oi->bd_router);

  /* Interface configurable values. */
  oi->router_priority = OSPF_ROUTER_PRIORITY_DEFAULT;
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
  /*
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;
  */

  return 0;
}

DEFUN (if_authentication_key,
       if_authentication_key_cmd,
       "authentication-key AUTH_KEY",
       "help")
{
  return CMD_SUCCESS;
}

DEFUN (if_cost,
       if_cost_cmd,
       "cost COST",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_dead_interval,
       if_dead_interval_cmd,
       "dead-interval INTERVAL",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_hello_interval,
       if_hello_interval_cmd,
       "hello-interval INTERVAL",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_network,
       if_network_cmd,
       "network TYPE",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_priority,
       if_priority_cmd,
       "priority NUMBER",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_retransmit_interval,
       if_retransmit_interval_cmd,
       "retransmit-interval NUMBER",
       "help")
{
  return CMD_SUCCESS;

}

DEFUN (if_transmit_delay,
       if_transmit_delay_cmd,
       "transmit-delay NUMBER",
       "help")
{
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
  /*
  install_element (INTERFACE_NODE, &authentication_key_cmd);
  install_element (INTERFACE_NODE, &cost_cmd);
  install_element (INTERFACE_NODE, &dead_interval_cmd);
  install_element (INTERFACE_NODE, &hello_interval_cmd);
  install_element (INTERFACE_NODE, &network_cmd);
  install_element (INTERFACE_NODE, &priority_cmd);
  install_element (INTERFACE_NODE, &retransmit_interval_cmd);
  install_element (INTERFACE_NODE, &transmit_delay_cmd);
  */
}

