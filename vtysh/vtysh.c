/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "command.h"

#include "vtysh/vtysh.h"

/* Struct VTY. */
struct vty *vty;

/* VTY shell client structure. */
struct vtysh_client
{
  int fd;
} vtysh_client[VTYSH_INDEX_MAX];

/* When '^Z' is received from vty, move down to the enable mode. */
int
vtysh_end ()
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      /* Nothing to do. */
      break;
    case CONFIG_NODE:
      /* vty_config_unlock (vty); */
      vty->node = ENABLE_NODE;
      break;
    case INTERFACE_NODE:
    case ZEBRA_NODE:
    case RIP_NODE:
    case RIPNG_NODE:
    case BGP_NODE:
    case BGP_VPNV4_NODE:
    case RMAP_NODE:
    case OSPF_NODE:
    case OSPF6_NODE:
    case MASC_NODE:
    case VTY_NODE:
      vty->node = ENABLE_NODE;
      break;
    default:
      /* Unknown node, we ignore it. */
      break;
    }
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_end_all,
	 vtysh_end_all_cmd,
	 "end",
	 "End current mode and down to previous mode\n")
{
  return vtysh_end (vty);
}

void
vclient_close (struct vtysh_client *vclient)
{
  if (vclient->fd > 0)
    close (vclient->fd);
  vclient->fd = -1;
}

int
vtysh_client_execute (struct vtysh_client *vclient, char *line)
{
  int ret;
  char buf[1001];
  int nbytes;
  int i;

  if (vclient->fd < 0)
    return CMD_SUCCESS;

  ret = write (vclient->fd, line, strlen (line) + 1);
  if (ret <= 0)
    {
      vclient_close (vclient);
      return CMD_SUCCESS;
    }
	
  while (1)
    {
      nbytes = read (vclient->fd, buf, 1000);

      if (nbytes <= 0)
	{
	  vclient_close (vclient);
	  return CMD_SUCCESS;
	}

      if (nbytes > 0)
	{
#if 0
	  printf ("nbytes %d\n", nbytes);
#endif /* 0 */

	  buf[nbytes] = '\0';
	  printf ("%s", buf);

	  if (nbytes >= 4)
	    {
	      i = nbytes - 4;
	      if (buf[i] == '\0' && buf[i + 1] == '\0' && buf[i + 2] == '\0')
		{
		  ret = buf[i + 3];
		  break;
		}
	    }
	}
    }
  return ret;
#if 0
  FD_ZERO (&readfd);
	
  timer_wait.tv_sec = 0;
  timer_wait.tv_usec = 10;

  while (1)
    {
      FD_SET (vclient->fd, &readfd);
      ret = select (FD_SETSIZE, &readfd, NULL, NULL, &timer_wait);
		
      if (FD_ISSET (vclient->fd, &readfd))
	{
	  nbytes = read (vclient->fd, buf, 100);
	  if (nbytes <= 0)
	    {
	      vclient_close (vclient);
	      return CMD_SUCCESS;
	    }

	  if (nbytes > 0)
	    {
	      printf ("nbytes %d\n", nbytes);

	      for (i = 0; i < nbytes; i++)
		printf ("debug i[%d]: %d\n", i, buf[i]);


	      buf[nbytes] = '\0';
	      printf ("%s", buf);

	      if (nbytes >= 4)
		{
		  index = nbytes - 4;
		  if (buf[index] == '\0' 
		      && buf[index + 1] == '\0' 
		      && buf[index + 2] == '\0')
		    {
		      printf ("ret %d\n", buf[index + 3]);
		    }
		}
	    }
	}
      else
	break;
    }
#endif /* 0 */
}

/* Command execution over the vty interface. */
void
vtysh_execute (char *line)
{
  int ret;
  vector vline;
  struct cmd_element *cmd;

  /* Split readline string up into the vector */
  vline = cmd_make_strvec (line);

  if (vline == NULL)
    return;

  ret = cmd_execute_command (vline, vty, &cmd);

  switch (ret)
    {
    case CMD_WARNING:
      if (vty->type == VTY_FILE)
	printf ("Warning...\n");
      break;
    case CMD_ERR_AMBIGUOUS:
      printf ("%% Ambiguous command.\n");
      break;
    case CMD_ERR_NO_MATCH:
      printf ("%% Unknown command.\n");
      break;
    case CMD_ERR_INCOMPLETE:
      printf ("%% Command incomplete.\n");
      break;
    case CMD_SUCCESS_DAEMON:
      {
	if (cmd->daemon & VTYSH_ZEBRA)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_ZEBRA], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->daemon & VTYSH_RIPD)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_RIP], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->daemon & VTYSH_RIPNGD)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_RIPNG], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->daemon & VTYSH_OSPFD)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_OSPF], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->daemon & VTYSH_OSPF6D)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_OSPF6], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->daemon & VTYSH_BGPD)
	  if (vtysh_client_execute (&vtysh_client[VTYSH_INDEX_BGP], line)
	      != CMD_SUCCESS)
	    goto end;
	if (cmd->func)
	  (*cmd->func) (cmd, vty, 0, NULL);
      }
      break;
    }
 end:
  cmd_free_strvec (vline);
}

void
vtysh_completion_display_matches_hook (char **matches, int num_matches,
				       int max_length)
{
  printf ("hogehoge\n");
}

/* We don't care about the point of the cursor when '?' is typed. */
int
vtysh_rl_describe ()
{
  int ret;
  int i;
  vector vline;
  vector describe;
  int width;
  struct desc *desc;

  vline = cmd_make_strvec (rl_line_buffer);

  /* In case of '> ?'. */
  if (vline == NULL)
    {
      vline = vector_init (1);
      vector_set (vline, '\0');
    }
  else 
    if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
      vector_set (vline, '\0');

  describe = cmd_describe_command (vline, vty, &ret);

  printf ("\n");

  /* Ambiguous and no match error. */
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      cmd_free_strvec (vline);
      printf ("%% Ambiguous command.\n");
      rl_on_new_line ();
      return 0;
      break;
    case CMD_ERR_NO_MATCH:
      cmd_free_strvec (vline);
      printf ("%% There is no matched command.\n");
      rl_on_new_line ();
      return 0;
      break;
    }  

  /* Get width of command string. */
  width = 0;
  for (i = 0; i < vector_max (describe); i++)
    if ((desc = vector_slot (describe, i)) != NULL)
      {
	int len;

	if (desc->cmd[0] == '\0')
	  continue;

	len = strlen (desc->cmd);
	if (desc->cmd[0] == '.')
	  len--;

	if (width < len)
	  width = len;
      }

  for (i = 0; i < vector_max (describe); i++)
    if ((desc = vector_slot (describe, i)) != NULL)
      {
	if (desc->cmd[0] == '\0')
	  continue;

	if (! desc->str)
	  printf ("  %-s\n",
		  desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd);
	else
	  printf ("  %-*s  %s\n",
		  width,
		  desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
		  desc->str);
      }

  cmd_free_strvec (vline);
  vector_free (describe);

  rl_on_new_line();

  return 0;
}

char *
command_generator (char *text, int state)
{
  int ret;
  vector vline;
  static char **matched = NULL;
  static int index = 0;

  /* First call. */
  if (! state)
    {
      index = 0;

  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    return NULL;

  vline = cmd_make_strvec (rl_line_buffer);
  if (vline == NULL)
    return NULL;

      if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
	vector_set (vline, '\0');

      matched = cmd_complete_command (vline, vty, &ret);
    }

  if (matched && matched[index])
    return matched[index++];

  return NULL;
}

char **
new_completion (char *text, int start, int end)
{
  char **matches;

  matches = completion_matches (text, command_generator);

  if (matches)
    rl_point = rl_end;

  return matches;
}

char **
vtysh_completion (char *text, int start, int end)
{
  int ret;
  vector vline;
  char **matched = NULL;

  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    return NULL;

  vline = cmd_make_strvec (rl_line_buffer);
  if (vline == NULL)
    return NULL;

  /* In case of 'help \t'. */
  if (rl_end && isspace ((int) rl_line_buffer[rl_end - 1]))
    vector_set (vline, '\0');

  matched = cmd_complete_command (vline, vty, &ret);

  cmd_free_strvec (vline);

  return (char **) matched;
}

/* BGP node structure. */
struct cmd_node bgp_node =
{
  BGP_NODE,
  "%s(config-router)# ",
};

/* BGP node structure. */
struct cmd_node rip_node =
{
  RIP_NODE,
  "%s(config-router)# ",
};

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

DEFUNSH (VTYSH_BGPD,
	 router_bgp,
	 router_bgp_cmd,
	 "router bgp <1-65535>",
	 ROUTER_STR
	 BGP_STR
	 AS_STR)
{
  vty->node = BGP_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_RIPD,
	 router_rip,
	 router_rip_cmd,
	 "router rip",
	 ROUTER_STR
	 "RIP")
{
  vty->node = RIP_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_RIPNGD,
	 router_ripng,
	 router_ripng_cmd,
	 "router ripng",
	 ROUTER_STR
	 "RIPng")
{
  vty->node = RIPNG_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_OSPFD,
	 router_ospf,
	 router_ospf_cmd,
	 "router ospf",
	 "Enable a routing process\n"
	 "Start OSPF configuration\n")
{
  vty->node = OSPF_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_OSPF6D,
	 router_ospf6,
	 router_ospf6_cmd,
	 "router ospf6",
	 OSPF6_ROUTER_STR
	 OSPF6_STR)
{
  vty->node = OSPF6_NODE;
  return CMD_SUCCESS;
}

/* Enable command */
DEFUNSH (VTYSH_ALL,
	 vtysh_enable, 
	 vtysh_enable_cmd,
	 "enable",
	 "Turn on privileged mode command\n")
{
  vty->node = ENABLE_NODE;
  return CMD_SUCCESS;
}

/* Disable command */
DEFUNSH (VTYSH_ALL,
	 vtysh_disable, 
	 vtysh_disable_cmd,
	 "disable",
	 "Turn off privileged mode command\n")
{
  if (vty->node == ENABLE_NODE)
    vty->node = VIEW_NODE;
  return CMD_SUCCESS;
}

/* Configration from terminal */
DEFUNSH (VTYSH_ALL,
	 vtysh_config_terminal,
	 vtysh_config_terminal_cmd,
	 "configure terminal",
	 "Configuration from vty interface\n"
	 "Configuration terminal\n")
{
  vty->node = CONFIG_NODE;
  return CMD_SUCCESS;
}

int
vtysh_exit (struct vty *vty)
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      exit (0);
      break;
    case CONFIG_NODE:
      vty->node = ENABLE_NODE;
      break;
    case INTERFACE_NODE:
    case ZEBRA_NODE:
    case BGP_NODE:
    case RIP_NODE:
    case RIPNG_NODE:
    case OSPF_NODE:
    case OSPF6_NODE:
    case MASC_NODE:
    case RMAP_NODE:
    case VTY_NODE:
      vty->node = CONFIG_NODE;
      break;
    case BGP_VPNV4_NODE:
      vty->node = BGP_NODE;
    default:
      break;
    }
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ALL,
	 vtysh_exit_all,
	 vtysh_exit_all_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUNSH (VTYSH_ZEBRA,
	 vtysh_exit_zebra,
	 vtysh_exit_zebra_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUNSH (VTYSH_RIPD,
	 vtysh_exit_ripd,
	 vtysh_exit_ripd_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUNSH (VTYSH_BGPD,
	 vtysh_exit_bgpd,
	 vtysh_exit_bgpd_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUNSH (VTYSH_OSPFD,
	 vtysh_exit_ospfd,
	 vtysh_exit_ospfd_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUNSH (VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_OSPFD,
	 vtysh_interface,
	 vtysh_interface_cmd,
	 "interface IFNAME",
	 "Select an interface to configure\n"
	 "Interface's name\n")
{
  vty->node = INTERFACE_NODE;
  return CMD_SUCCESS;
}

DEFUNSH (VTYSH_ZEBRA|VTYSH_RIPD|VTYSH_OSPFD,
	 vtysh_exit_interface,
	 vtysh_exit_interface_cmd,
	 "exit",
	 "Exit current mode and down to previous mode\n")
{
  return vtysh_exit (vty);
}

DEFUN (vtysh_write_terminal,
       vtysh_write_terminal_cmd,
       "write terminal",
       "Write running configuration to memory, network, or terminal\n"
       "Write to terminal\n")
{
  int ret;
  char line[] = "write terminal\n";

  vty_out (vty, "%sCurrrent Configuration:%s", VTY_NEWLINE,
	   VTY_NEWLINE);
  vty_out (vty, "!%s", VTY_NEWLINE);

  /* user_config_write (); */

  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_ZEBRA], line);
  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_RIP], line);
  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_RIPNG], line);
  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_OSPF], line);
  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_OSPF6], line);
  ret = vtysh_client_execute (&vtysh_client[VTYSH_INDEX_BGP], line);

  return CMD_SUCCESS;
}

ALIAS (vtysh_write_terminal,
       vtysh_show_running_config_cmd,
       "show running-config",
       SHOW_STR
       "running configuration\n")

/* Execute command in child process. */
int
execute_command (char *command, char *arg)
{
  int ret;
  pid_t pid;
  int status;

  /* Call fork(). */
  pid = fork ();

  if (pid < 0)
    {
      /* Failure of fork(). */
      fprintf (stderr, "Can't fork: %s\n", strerror (errno));
      exit (1);
    }
  else if (pid == 0)
    {
      /* This is child process. */
      ret = execlp (command, command, arg, NULL);

      /* When execlp suceed, this part is not executed. */
      fprintf (stderr, "Can't execute %s: %s\n", command, strerror (errno));
      exit (1);
    }
  else
    {
      /* This is parent. */
      execute_flag = 1;
      ret = wait4 (pid, &status, 0, NULL);
      execute_flag = 0;
    }
  return 0;
}

DEFUN (vtysh_ping,
       vtysh_ping_cmd,
       "ping HOST",
       "Ping\n"
       "Hostname\n")
{
  execute_command ("ping", argv[0]);
  return CMD_SUCCESS;
}

DEFUN (vtysh_traceroute,
       vtysh_traceroute_cmd,
       "traceroute HOST",
       "Traceroute\n"
       "Hostname\n")
{
  execute_command ("traceroute", argv[0]);
  return CMD_SUCCESS;
}

DEFUN (vtysh_telnet,
       vtysh_telnet_cmd,
       "telnet HOST",
       "Telnet\n"
       "Hostname\n")
{
  execute_command ("telnet", argv[0]);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_shell,
       vtysh_start_shell_cmd,
       "start-shell",
       "Start UNIX shell\n")
{
  execute_command ("sh", NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_bash,
       vtysh_start_bash_cmd,
       "start-shell bash",
       "Start UNIX shell\n"
       "Start bash\n")
{
  execute_command ("bash", NULL);
  return CMD_SUCCESS;
}

DEFUN (vtysh_start_zsh,
       vtysh_start_zsh_cmd,
       "start-shell zsh",
       "Start UNIX shell\n"
       "Start Z shell\n")
{
  execute_command ("zsh", NULL);
  return CMD_SUCCESS;
}

/* Route map node structure. */
struct cmd_node rmap_node =
{
  RMAP_NODE,
  "%s(config-route-map)# ",
};

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

struct cmd_node bgp_vpnv4_node =
{
  BGP_VPNV4_NODE,
  "%s(config-router-af)# ",
};

struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# ",
};

/* RIPng node structure. */
struct cmd_node ripng_node =
{
  RIPNG_NODE,
  "%s(config-router)# ",
};

/* OSPF6 node structure. */
struct cmd_node ospf6_node =
{
  OSPF6_NODE,
  "%s(config-ospf6)# ",
};

void
vtysh_install_default (enum node_type node)
{
  install_element (node, &config_list_cmd);
}

/* Making connection to protocol daemon. */
int
vtysh_connect (struct vtysh_client *vclient, char *path)
{
  int ret;
  int sock;
  struct sockaddr_un addr;

  memset (vclient, 0, sizeof (struct vtysh_client));
  vclient->fd = -1;

  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
#ifdef DEBUG
      perror ("sock");
#endif /* DEBUG */
      return -1;
    }

  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, path, strlen (path));

  ret = connect (sock, (struct sockaddr *) &addr, sizeof (struct sockaddr_un));
  if (ret < 0)
    {
#ifdef DEBUG
      perror ("connect");
#endif /* DEBUG */
      return -1;
    }
  vclient->fd = sock;

  return 0;
}

void
vtysh_connect_all()
{
  /* Clear each daemons client structure. */
  vtysh_connect (&vtysh_client[VTYSH_INDEX_ZEBRA], ZEBRA_PATH);
  vtysh_connect (&vtysh_client[VTYSH_INDEX_RIP], RIP_PATH);
  vtysh_connect (&vtysh_client[VTYSH_INDEX_RIPNG], RIPNG_PATH);
  vtysh_connect (&vtysh_client[VTYSH_INDEX_OSPF], OSPF_PATH);
  vtysh_connect (&vtysh_client[VTYSH_INDEX_OSPF6], OSPF6_PATH);
  vtysh_connect (&vtysh_client[VTYSH_INDEX_BGP], BGP_PATH);
}


/* To disable readline's filename completion */
int
vtysh_completion_entry_fucntion (int ignore, int invoking_key)
{
  return 0;
}

void
vtysh_readline_init ()
{
  /* readline related settings. */
  rl_bind_key ('?', vtysh_rl_describe);
  rl_completion_entry_function = vtysh_completion_entry_fucntion;
  rl_attempted_completion_function = (CPPFunction *)new_completion;
}

char *
vtysh_prompt ()
{
  static char buf[100];

  sprintf (buf, cmd_prompt (vty->node), "zebra");
  return buf;
}

void
vtysh_init_vty ()
{
  /* Make vty structure. */
  vty = vty_new ();
  vty->type = VTY_SHELL;
  vty->node = VIEW_NODE;

  /* Initialize commands. */
  cmd_init (0);

  /* Install nodes. */
  install_node (&bgp_node, NULL);
  install_node (&rip_node, NULL);
  install_node (&interface_node, NULL);
  install_node (&rmap_node, NULL);
  install_node (&zebra_node, NULL);
  install_node (&bgp_vpnv4_node, NULL);
  install_node (&ospf_node, NULL);
  install_node (&ripng_node, NULL);
  install_node (&ospf6_node, NULL);

  vtysh_install_default (VIEW_NODE);
  vtysh_install_default (ENABLE_NODE);
  vtysh_install_default (CONFIG_NODE);

  install_element (VIEW_NODE, &vtysh_enable_cmd);
  install_element (ENABLE_NODE, &vtysh_config_terminal_cmd);
  install_element (VIEW_NODE, &vtysh_exit_all_cmd);
  install_element (CONFIG_NODE, &vtysh_exit_all_cmd);
  install_element (ENABLE_NODE, &vtysh_exit_all_cmd);
  install_element (BGP_NODE, &vtysh_exit_bgpd_cmd);
  install_element (RIP_NODE, &vtysh_exit_ripd_cmd);
  install_element (OSPF_NODE, &vtysh_exit_ospfd_cmd);
  install_element (ENABLE_NODE, &vtysh_disable_cmd);
  install_element (CONFIG_NODE, &vtysh_end_all_cmd);
  install_element (ENABLE_NODE, &vtysh_end_all_cmd);
  install_element (RIP_NODE, &vtysh_end_all_cmd);
  install_element (RIPNG_NODE, &vtysh_end_all_cmd);
  install_element (OSPF_NODE, &vtysh_end_all_cmd);
  install_element (OSPF6_NODE, &vtysh_end_all_cmd);
  install_element (BGP_NODE, &vtysh_end_all_cmd);
  install_element (INTERFACE_NODE, &vtysh_end_all_cmd);
  install_element (INTERFACE_NODE, &vtysh_exit_interface_cmd);
  install_element (CONFIG_NODE, &router_rip_cmd);
  install_element (CONFIG_NODE, &router_ripng_cmd);
  install_element (CONFIG_NODE, &router_ospf_cmd);
  install_element (CONFIG_NODE, &router_ospf6_cmd);
  install_element (CONFIG_NODE, &router_bgp_cmd);
  install_element (CONFIG_NODE, &vtysh_interface_cmd);
  install_element (ENABLE_NODE, &vtysh_write_terminal_cmd);
  install_element (ENABLE_NODE, &vtysh_show_running_config_cmd);
  install_element (VIEW_NODE, &vtysh_ping_cmd);
  install_element (VIEW_NODE, &vtysh_traceroute_cmd);
  install_element (VIEW_NODE, &vtysh_telnet_cmd);
  install_element (ENABLE_NODE, &vtysh_ping_cmd);
  install_element (ENABLE_NODE, &vtysh_traceroute_cmd);
  install_element (ENABLE_NODE, &vtysh_telnet_cmd);
  install_element (ENABLE_NODE, &vtysh_start_shell_cmd);
  install_element (ENABLE_NODE, &vtysh_start_bash_cmd);
  install_element (ENABLE_NODE, &vtysh_start_zsh_cmd);
}
