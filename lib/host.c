/* Host[Router] information
   Copyright (C) 1997 Kunihiro Ishiguro

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif /* HAVE_PTHREAD */

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "host.h"
#include "log.h"
#include "memory.h"

/* Hostname configuration */
DEFUN (config_hostname, 
       hostname_cmd,
       "hostname HOSTNAME",
       "Set router hostname string.")
{
  if (!isalpha(*argv[0]))
    {
      vty_out (vty, "Please specify string starting with alphabet\r\n");
      return CMD_WARNING;
    }

  if (host.name)
    XFREE (0, host.name);
    
  host.name = strdup (argv[0]);
  config_replace_string (self, "hostname %s", host.name);
  return CMD_SUCCESS;
}


/* VTY interface password set. */
DEFUN (config_password, password_cmd,
       "password PASSWORD",
       "Set router enable password string.")
{
  if (!isalnum (*argv[0]))
    {
      vty_out (vty, "Please specify string starting with alphanumeric\r\n");
      return CMD_WARNING;
    }

  if (host.password)
    XFREE (0, host.password);

  host.password = strdup (argv[0]);
  config_replace_string (self, "password %s", host.password);
  return CMD_SUCCESS;
}

/* VTY enable password set. */
DEFUN (config_enable_password, enable_password_cmd,
       "enable password PASSWORD",
       "Set router password string.")
{
  if (!isalnum (*argv[0]))
    {
      vty_out (vty, "Please specify string starting with alphanumeric\r\n");
      return CMD_WARNING;
    }

  if (host.enable)
    XFREE (0, host.enable);

  host.enable = strdup (argv[0]);
  config_replace_string (self, "enable password %s", host.enable);
  return CMD_SUCCESS;
}

DEFUN (config_logfile,
       config_logfile_cmd,
       "logfile PATH",
       "log filename specify command")
{
  char *str;

  str = log_open (argv[0]);
  if (str == NULL)
    {
      vty_out (vty, "can't open logfile %s\n", argv[0]);
      return CMD_WARNING;
    }
  if (host.logfile)
    XFREE (0, host.logfile);

  host.logfile = strdup (argv[0]);
  config_replace_string (self, "logfile %s", host.logfile);
  return CMD_SUCCESS;
}

struct host host;

void
host_config_set (char *filename)
{
  host.config = strdup (filename);
}

char *
host_config_file ()
{
  return host.config;
}

void
host_init ()
{
  /* Default value settings. */
  host.name = strdup ("Router");
  host.password = NULL;
  host.enable = NULL;
  host.logfile = NULL;
  host.config = NULL;

  install_element (CONFIG_NODE, &hostname_cmd);
  install_element (CONFIG_NODE, &password_cmd);
  install_element (CONFIG_NODE, &enable_password_cmd);
  install_element (CONFIG_NODE, &config_logfile_cmd);
}
