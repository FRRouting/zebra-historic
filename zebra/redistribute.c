/*
 * Redistribution Handler
 * Copyright (C) 1998 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "vector.h"
#include "vty.h"
#include "command.h"

struct rip_config
{
  int router_rip;
  int redistribute_bgp;

  struct access_list *in;
  struct access_list *out;
} rip_config;

/* Redistribute function generates a thread for each protocol
   redistribution */
void
redistribute ()
{
  return;
}

/* Change to rip interface node. */
DEFUN (router_rip, router_rip_cmd,
       "router rip", "RIP interface")
{
  vty->node = RIP_NODE;
  return CMD_SUCCESS;
}

/* Redistribution from bgp to rip. */
DEFUN (redistribute_bgp, redistribute_bgp_cmd,
       "redistribute bgp", "Redistribute bgp route to rip.")
{
  rip_config.redistribute_bgp = 1;
  return CMD_SUCCESS;
}

/* Redistribution from bgp to rip. */
DEFUN (no_redistribute_bgp, no_redistribute_bgp_cmd,
       "no redistribute bgp", "Delete redistribution of bgp route to rip.")
{
  rip_config.redistribute_bgp = 0;
  return CMD_SUCCESS;
}

/**/
DEFUN (filter_list, filter_list_cmd,
       "filter-list NAME DIRECTION",
       "Apply filter to the rip connection.")
{
  return CMD_SUCCESS;
}

/**/
int
rip_config_write (struct vty *vty)
{
  if (rip_config.redistribute_bgp)
    vty_out (vty, " redistribute bgp%s", VTY_NEWLINE);
  return 0;
}

/* RIP node structure. */
struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

/* Change to rip interface node. */
DEFUN (router_bgp, router_bgp_cmd,
       "router bgp", "RIP interface")
{
  vty->node = BGP_NODE;
  return CMD_SUCCESS;
}

/* Redistribution from rip to bgp. */
DEFUN (redistribute_rip, redistribute_rip_cmd,
       "redistribute rip", "Redistribute rip route to bgp.")
{
  return CMD_SUCCESS;
}

/**/
int
bgp_config_write (struct vty *vty)
{
  return 0;
}

/* BGP node structure. */
struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

void
redistribute_init ()
{
  bzero (&rip_config, sizeof rip_config);

  install_node (&rip_node, rip_config_write);
  install_node (&bgp_node, bgp_config_write);

  install_element (CONFIG_NODE, &router_rip_cmd);
  install_element (CONFIG_NODE, &router_bgp_cmd);

  install_element (RIP_NODE, &config_help_cmd);
  install_element (RIP_NODE, &config_exit_cmd);
  install_element (RIP_NODE, &redistribute_bgp_cmd);
  install_element (RIP_NODE, &no_redistribute_bgp_cmd);
  install_element (RIP_NODE, &filter_list_cmd);

  install_element (BGP_NODE, &config_help_cmd);
  install_element (BGP_NODE, &config_exit_cmd);
  install_element (RIP_NODE, &redistribute_rip_cmd);
}
