/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospfd.h"

extern void start_msg (void);
extern void rotate_log (void);

/* ospfd options, we use GNU getopt library. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};

/* Configuration file and directory. */
char config_current[] = OSPF_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR OSPF_DEFAULT_CONFIG;

/* ospfd program name. */
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
Daemon which manages OSPF version 2 and 3.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to yasu@sfc.wide.ad.jp\n", progname);
    }

  exit (status);
}


void
terminate (int i)
{
  ospf_terminate();
  exit (i);
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

  /* Close all ospf peer and free all of resources. */
  terminate (0);
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
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, SIG_IGN);
  signal_set (SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
  signal_set (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
  signal_set (SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
  signal_set (SIGTTOU, SIG_IGN);
#endif
}


/* Main routine of ospfd. Treatment of argument and start ospf finite
   state machine is handled at here. */
int
main (int argc, char **argv)
{
  char *p;
  int opt;
  int daemon_mode = 0;
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
  zlog_default = openzlog (progname, ZLOG_STDOUT, ZLOG_OSPF,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  /* Initializations. */
  master = thread_make_master ();

  signal_init ();
  cmd_init ();
  vty_init ();

  /* Make ospf protocol socket. */
  ospf_serv_sock ();
  mcast_prepare ();

  ospf_init ();
  ospf_zebra_init ();

#ifdef OLD
  get_interface_all();
#else
  zebra_get_interface ();
#endif

  access_list_init ();

#if 0
  memory_init_vty ();
#else
  memory_init ();
  sort_node ();
#endif

  /* parse config file */
  vty_read_config (config_file, config_current, config_default);

  if (daemon_mode)
    daemon (0, 0);

  /* pid file create */
  pid_output (PATH_OSPFD_PID);

  /* Make ospf vty socket. */
  vty_serv_sock (vty_port ? vty_port : OSPF_VTY_PORT, AF_INET);

  /* print bannar */
  ospf_start_msg ();

  /* start finite state machine, here we go! */
  while (thread_fetch (master, &thread))
    {
      thread_call (&thread);
#ifdef DEBUG
      thread_master_debug (master);
#endif /* DEBUG */
    }
}

