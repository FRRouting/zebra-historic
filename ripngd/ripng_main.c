/* RIPngd main routine.
   Copyright (C) 1998 Kunihiro Ishiguro

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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <sys/time.h>

#include "ripngd.h"
#include "version.h"
#include "getopt.h"
#include "vector.h"
#include "vty.h"
#include "thread.h"

/* Configuration filename and directory. */
char config_current[] = RIPNG_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR RIPNG_DEFAULT_CONFIG;

/* RIPngd options. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* RIPngd program name */
char *progname;

/* Master of threads. */
struct thread_master *master;

/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages RIPng.\n\n\
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

/* RIPngd main routine. */
int
main (int argc, char **argv)
{
  char *p;
  int vty_port = 0;
  int daemon_mode = 0;
  char *config_file = NULL;
  struct thread thread;

  /* get program name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "df:hP:v", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
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

  master = thread_make_master ();

  /* RIPngd inits. */
  log_init ();
  cmd_init ();
  vty_init ();
  host_init ();

  ripng_if_init ();
  ripng_init ();
  zebra_init ();

  /* Get configuration file. */
  vty_read_config (config_file, config_current, config_default);

  /* Create VTY socket */
  vty_serv_sock (vty_port ? vty_port : RIPNG_VTY_PORT);

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon_me ();

  /* Process id file create. */
  pid_output (PATH_RIPNGD_PID);

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);
}
