/*
 * $Id: command.h,v 1.33 1999/02/19 17:01:47 developer Exp $
 *
 * Zebra configuration command interface routine
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_COMMAND_H
#define _ZEBRA_COMMAND_H

#include "vector.h"
#include "vty.h"

/* Host configuration variable */
struct host
{
  /* Host name of this router. */
  char *name;

  /* Password for vty interface. */
  char *password;

  /* Enable password */
  char *enable;

#ifdef HAVE_PTHREAD
  /*   pthread_mutex_t mutex_lock; */
#endif /* HAVE_PTHREAD */  

  /* Log filename. */
  char *logfile;

  /* New zlog output. */
  char *log;

  /* config file name of this host */
  char *config;
};

/* There are some command levels which called from command node. */
enum node_type 
{
  AUTH_NODE,			/* Authentication mode of vty interface. */
  VIEW_NODE,			/* View node. Default mode of vty interface. */
  AUTH_ENABLE_NODE,		/* Authentication mode for change enable. */
  ENABLE_NODE,			/* Enable node. */
  CONFIG_NODE,			/* Config node. Default mode of config file. */
  DEBUG_NODE,			/* Debug node. */
  INTERFACE_NODE,		/* Interface mode node. */
  ZEBRA_NODE,			/* zebra connection node. */
  RIP_NODE,			/* RIP protocol mode node. */ 
  RIPNG_NODE,			/* RIPng protocol mode node. */
  BGP_NODE,			/* BGP protocol mode which includes BGP4+ */
  OSPF_NODE,			/* OSPF protocol mode */
  OSPF6_NODE,			/* OSPF protocol for IPv6 mode */
  RDISC_NODE,			/* ICMP Router Discovery Protocol mode. */ 
  IP_NODE,			/* Static ip route node. */
  ACCESS_NODE,			/* Access list node. */
  AS_LIST_NODE,			/* AS list node. */
  DISTRIBUTE_NODE,		/* Distribute list node. */
  RMAP_NODE,			/* Route map node. */
  VTY_NODE			/* Vty node. */
};

/* Node which has some commands and prompt string and configuration
   function pointer . */
struct cmd_node 
{
  /* Node index. */
  enum node_type node;		

  /* Prompt character at vty interface. */
  char *prompt;			

  /* Node's configuration write function */
  int (*func) (struct vty *);

  /* Vector of this node's command list. */
  vector cmd_vector;	

  /* Description vector of this node. */
  vector desc_vector;
};

/* Structure of command element. */
struct cmd_element 
{
  char *string;			/* Command specification by string. */
  int (*func) (struct cmd_element *, struct vty *, int, char **);
  char *doc;			/* Documentation of this command */
  vector strvec;		/* Pointing out each command index */
  vector descvec;		/* Pointing out each command index */
  int cmdsize;			/* Command index count. */
  char *config;			/* Configuration string */
  vector subconfig;		/* Sub configuration string */
};

enum cmd_doc_type {DOC_STR, DOC_FUNC};

struct cmd_doc
{
  enum cmd_doc_type *type;
  void *data;
};

/* Structure of command element. */
struct cmd_element2
{
  char *string;			/* Command specification by string. */
  int (*func) (struct cmd_element *, struct vty *, int, char **);
  vector strvec;		/* Pointing out each command index */
  vector descvec;		/* Pointing out each command index */
  int cmdsize;			/* Command index count. */
  char *config;			/* Configuration string */
  vector subconfig;		/* Sub configuration string */
};

/* Command description structure. */
struct desc
{
  /* Command string. */
  char *cmd;

  /* Command's description. */
  char *str;
};

/* Return value of the commands. */
#define CMD_SUCCESS              0
#define CMD_WARNING              1
#define CMD_ERR_NO_MATCH         2
#define CMD_ERR_AMBIGUOUS        3
#define CMD_ERR_INCOMPLETE       4
#define CMD_ERR_EXEED_ARGC_MAX   5
#define CMD_ERR_NOTHING_TODO     6
#define CMD_COMPLETE_FULL_MATCH  7
#define CMD_COMPLETE_MATCH       8
#define CMD_VARARG_MATCH         9

/* Argc max counts. */
#define CMD_ARGC_MAX   25

/* DEFUN for vty command interafce. Little bit hacky ;-). */
#define DEFUN(funcname, cmdname, cmdstr, helpstr) \
  int funcname (struct cmd_element *, struct vty *, int, char **); \
  struct cmd_element cmdname = \
  { \
    cmdstr, \
    funcname, \
    helpstr \
  }; \
  int funcname \
  (struct cmd_element *self, struct vty *vty, int argc, char **argv)

/* New DEFUN for vty command interafce. */
#define DEFUN2(funcname, cmdname, cmdstr, helpstr) \
  int funcname (struct cmd_element *, struct vty *, int, char **); \
  struct cmd_doc hogehoge[] = \
  { \
    helpstr \
  }; \
  struct cmd_element cmdname = \
  { \
    cmdstr, \
    funcname, \
  }; \
  int funcname \
  (struct cmd_element *self, struct vty *vty, int argc, char **argv)

/* ALIAS macro for define alias of existing command. */
#define ALIAS(funcname, cmdname, cmdstr, helpstr) \
  struct cmd_element cmdname = \
  { \
    cmdstr, \
    funcname, \
    helpstr \
  };

/* Some macroes */
#define CMD_OPT(X)  ((X) == '[')
#define CMD_EXT(X)  ((X) >= 'A' && (X) <= 'Z')

/* Description. */
#define SHOW_STR "Show running system information\n"
#define IP_STR "IP information\n"
#define NO_STR "Negate a command or set its defaults\n"
#define BGP_STR "BGP information\n"
#define NEIGHBOR_STR "Specify neighbor router\n"
#define DEBUG_STR "Debugging functions\n"

/* Prototypes. */
void install_node (struct cmd_node *, int (*) (struct vty *));
void install_element (enum node_type, struct cmd_element *);
void sort_node ();
void desc_vector_free (vector descvec);

vector cmd_make_strvec (char *);
void cmd_free_strvec (vector);
vector cmd_describe_command ();
char **cmd_complete_command ();
char *cmd_prompt (enum node_type);
int config_from_file (struct vty *, FILE *);
int cmd_execute_command (vector, struct vty *);
void config_replace_string (struct cmd_element *, char *, ...);
void cmd_init ();

/* Export typical functions. */
extern struct cmd_element config_end_cmd;
extern struct cmd_element config_exit_cmd;
extern struct cmd_element config_help_cmd;
int config_exit (struct cmd_element *, struct vty *, int, char **);
int config_help (struct cmd_element *, struct vty *, int, char **);
char *host_config_file ();
void host_config_set (char *);

#endif /* _ZEBRA_COMMAND_H */
