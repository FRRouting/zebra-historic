/*
 * RIPng debug output routines
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

#include "ripngd/ripng_debug.h"

/* For debug statement. */
unsigned long ripng_debug_option;

void
debug_set (unsigned int option)
{
  ripng_debug_option |= option;
}

void
debug_unset (unsigned int option)
{
  ripng_debug_option &= ~option;
}

int
debug (unsigned int option)
{
  return ripng_debug_option & option;
}

/* VTY related functions.*/
#include "vector.h"
#include "vty.h"
#include "command.h"

DEFUN (show_debug_ripng,
       show_debug_ripng_cmd,
       "show debug ripng",
       SHOW_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Show debug option for ripng\n")
{
  vty_out (vty, "debug ripng event  : %s\r\n", 
	   debug (DEBUG_EVENT) ? "set" : "unset");
  vty_out (vty, "debug ripng packet : %s\r\n",
	   debug (DEBUG_PACKET) ? "set" : "unset");

  return CMD_SUCCESS;
}

DEFUN (debug_ripng,
       debug_ripng_cmd,
       "debug ripng [DEBUG_OPT]",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng\n")
{
  if (argc == 0)
    {
      vty_out (vty, "Debug option for ripng\r\n");
      vty_out (vty, "------------------------\r\n");
      vty_out (vty, "debug ripng event -- Event of ripng.\r\n");
      vty_out (vty, "debug ripng packet -- Packet dump.\r\n");
      vty_out (vty, "------------------------\r\n");
      return CMD_SUCCESS;
     }

  if (strcmp (argv[0], "event") == 0)
    debug_set (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_set (DEBUG_PACKET);

  return CMD_SUCCESS;
}

DEFUN (no_debug_ripng,
       no_debug_ripng_cmd,
       "no debug ripng [DEBUG_OPT]",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option unset for ripng\n")
{
  if (argc == 0)
    {
      vty_out (vty, "Debug option unset ripng\r\n");
      vty_out (vty, "------------------------\r\n");
      vty_out (vty, "event  DUmp event of ripngd.\r\n");
      vty_out (vty, "packet Dump packet information of ripngd.\r\n");
      vty_out (vty, "------------------------\r\n");
      return CMD_SUCCESS;
     }
  if (strcmp (argv[0], "event") == 0)
    debug_unset (DEBUG_EVENT);
  if (strcmp (argv[0], "packet") == 0)
    debug_unset (DEBUG_PACKET);

  return CMD_SUCCESS;
}

/* Debug node. */
struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""				/* Debug node has no interface. */
};

int
config_write_debug (struct vty *vty)
{
  if (debug (DEBUG_EVENT))
    vty_out (vty, "debug ripng event%s", VTY_NEWLINE);
  if (debug (DEBUG_PACKET))
    vty_out (vty, "debug ripng packet%s", VTY_NEWLINE);

  return 0;
}

void
ripng_debug_init ()
{
  install_node (&debug_node, config_write_debug);

  install_element (VIEW_NODE, &show_debug_ripng_cmd);
  install_element (ENABLE_NODE, &show_debug_ripng_cmd);
  install_element (ENABLE_NODE, &debug_ripng_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_cmd);
  install_element (CONFIG_NODE, &debug_ripng_cmd);
  install_element (CONFIG_NODE, &no_debug_ripng_cmd);
}
