/*
 * zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#include "zebra/zebra.h"
#include "version.h"
#include "getopt.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "log.h"

/* Master of threads. */
struct thread_master *master;

/* zebra program name */
char *progname;

/* Route retain mode flag. */
int retain_mode = 0;

/* Command line options. */
struct option longopts[] = 
{
  { "batch",       no_argument,       NULL, 'b'},
  { "daemon",      no_argument,       NULL, 'd'},
  { "log_mode",    no_argument,       NULL, 'l'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "retain",      no_argument,       NULL, 'r'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* Default configuration file path. */
char config_current[] = DEFAULT_CONFIG_FILE;
char config_default[] = SYSCONFDIR DEFAULT_CONFIG_FILE;

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
-b, --batch        Runs in batch mode\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-l, --log_mode     Set verbose log mode flag\n\
-P, --vty_port     Set vty's port number\n\
-r, --retain       When program terminates, retain added route by zebra.\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGINT handler. */
void
sigint (int sig)
{
  /* Decrared in rib.c */
  void rib_close ();

  zlog (NULL, LOG_INFO, "Terminating on signal");

  if (!retain_mode)
    rib_close ();

  exit (0);
}

/* Signale wrapper. */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0) 
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* Initialization of signal handles. */
void
signal_init ()
{
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigint);
  signal_set (SIGPIPE, SIG_IGN);
}

/* Main startup routine. */
int
main (int argc, char **argv)
{
  char *p;
  int vty_port = 0;
  int batch_mode = 0;
  int daemon_mode = 0;
  char *config_file = NULL;
  struct thread thread;

  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_STDOUT, ZLOG_ZEBRA,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  while (1) 
    {
      int opt;
  
      opt = getopt_long (argc, argv, "bdlf:hP:rv", longopts, 0);

      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'b':
	  batch_mode = 1;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'l':
	  /* log_mode = 1; */
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'P':
	  vty_port = atoi (optarg);
	  break;
	case 'r':
	  retain_mode = 1;
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

  /* Make master thread emulator. */
  master = thread_make_master ();

  /* Vty related initialize. */
  signal_init ();
  cmd_init ();
  vty_init ();
  memory_init ();

  /* Zebra related initialize. */
  zebra_init ();
  rib_init ();
  zebra_if_init ();
  access_list_init ();

  /* Make kernel routing socket. */
  kernel_init ();
  interface_list ();
  route_read ();

  hostinfo_get ();
  sort_node ();

  /* Configuration file read*/
  vty_read_config (config_file, config_current, config_default);

  /* Clean up rib. */
  rib_weed_tables();

  /* Exit when zebra is working in batch mode. */
  if (batch_mode)
    exit (0);

  /* Daemonize. */
  if (daemon_mode)
    daemon (0, 0);

  /* Make vty server socket. */
  vty_serv_sock (vty_port ? vty_port : ZEBRA_VTY_PORT, AF_INET);

  /* Output pid of zebra. */
  pid_output (PATH_ZEBRA_PID);

  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached... */
  exit (0);
}
