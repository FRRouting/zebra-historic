/* zebra daemon main routine.
   Copyright (C) 1997, 98 Kunihiro Ishiguro

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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include "zebra.h"
#include "version.h"
#include "getopt.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "thread.h"

/* command line options */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

char config_current[] = DEFAULT_CONFIG_FILE;
char config_default[] = SYSCONFDIR DEFAULT_CONFIG_FILE;

/* Master of threads. */
struct thread_master *master;

/* zebra program name */
char *progname;

/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages kernel routing table management and \
redistribution between different routing protocols.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to zebra@zebra.org\n", progname);
    }

  exit (status);
}

/* Main startup routine. */
main (int argc, char **argv)
{
  char *p;
  int vty_port = 0;
  int daemon_mode = 0;
  char *config_file = NULL;
  struct thread thread;

  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  while (1) 
    {
      int opt;
  
      opt = getopt_long (argc, argv, "dlf:hP:v", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'l':
	  log_mode = 1;
	case 'f':
	  config_file = optarg;
	  break;
	case 'P':
	  vty_port = atoi (optarg);
	  break;
	case 'v':
	  print_version ();
	  exit (0);
	  break;
	case 'h':
	  usage (0);
	  break;
	default:
	  usage (1);
	  break;
	}
    }

  log_init ();

  master = thread_make_master ();

  /* Vty related initialize. */
  cmd_init ();
  vty_init ();
  host_init ();
  access_list_init ();

  /* zebra related initialize. */
  radix_init ();
  zebra_init ();
  rib_init ();
  zebra_if_init ();

  /* Configuration file read*/
  vty_read_config (config_file, config_current, config_default);

  /* Make vty server socket. */
  vty_serv_sock (vty_port ? vty_port : ZEBRA_VTY_PORT);

  /* daemonize */
  if (daemon_mode)
    daemon_me ();

  /* output pid of zebra */
  pid_output (PATH_ZEBRA_PID);

  /* get kernel routing table and insert it into rib */
  hostinfo_get ();
  rt_read ();
  interface_list ();

  /* ripng_test (); */

  while (thread_fetch (master, &thread))
    thread_call (&thread);
}
