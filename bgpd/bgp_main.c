/* Main routine of bgpd.
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <config.h>
#include <sys/time.h>

#include "bgpd.h"
#include "getopt.h"
#include "bgp_aspath.h"
#include "thread.h"

/* bgpd options, we use GNU getopt library. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "bgp_port",    required_argument, NULL, 'p'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};

/* Configuration file and directory. */
char config_current[] = BGP_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR BGP_DEFAULT_CONFIG;

/* bgpd program name. */
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
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages kernel routing table management and \
redistribution between different routing protocols.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-p, --bgp_port     Set bgp protocol's port number\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to zebra@zebra.org\n", progname);
    }

  exit (status);
}

/* Main routine of bgpd. Treatment of argument and start bgp finite
   state machine is handled at here. */
int
main (int argc, char **argv)
{
  char *p;
  int opt;
  int daemon_mode = 0;
  int bgp_port = 0;
  int vty_port = 0;

  char *config_file = NULL;
  struct thread thread;

  /* Preserve name of myself. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* Command line argument treatment. */
  while (1) 
    {
      opt = getopt_long (argc, argv, "df:hp:P:v", longopts, 0);
    
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
	case 'p':
	  bgp_port = atoi (optarg);
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

  /* Initializations. */
  master = thread_make_master ();

  signal_init ();
  cmd_init ();
  vty_init ();
  host_init ();

  bgp_init ();
  bgp_radix_init ();
  aspath_init ();
  community_init ();

  route_map_init ();
  route_map_init_vty ();
  bgp_route_map_init ();

  access_list_init ();
  view_init ();
  bgp_dump_init ();
  memory_init_vty ();

  /* parse config file */
  vty_read_config (config_file, config_current, config_default);

  if (daemon_mode)
    daemon_me ();

  /* pid file create */
  pid_output (PATH_BGPD_PID);

  /* Make bgp vty socket. */
  vty_serv_sock (vty_port ? vty_port : BGP_VTY_PORT);

  /* make BGP server fd */
  bgp_serv_sock (bgp_port ? bgp_port : BGP_PORT_DEFAULT, AF_INET);
#ifdef HYDRANGEA
  bgp_serv_sock (bgp_port ? bgp_port : BGP_PORT_DEFAULT, AF_INET6);
#endif /* HYDRANGEA */

  /* print bannar */
  bgp_start_msg ();

  /* start finite state machine, here we go! */
  while (thread_fetch (master, &thread))
    {
      thread_call (&thread);
#ifdef DEBUG
      thread_master_debug (master);
#endif /* DEBUG */
    }
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  log ("SIGHUP received\n");
  rotate_log ();
}

/* SIGINT handler. */
void
sigint (int sig)
{
  log ("SIGINT received\n");

  /* Close all bgp peer and free all of resources. */
  bgp_terminate ();

  /* Rest in peace. */
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
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, SIG_IGN);
  signal_set (SIGPIPE, SIG_IGN);
}
