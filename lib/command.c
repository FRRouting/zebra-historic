/*
 * Command interpreter routine for virtual terminal [aka TeletYpe]
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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

#include <zebra.h>

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "log.h"
#include "version.h"

/* Command vector which includes some level of command lists. Normally
   each daemon maintains each own cmdvec. */
vector cmdvec;

/* Host information structure. */
struct host host;

/* Default motd string. */
char *default_motd = 
"\r\n\
Hello, this is zebra (version " ZEBRA_VERSION ")\r\n\
Copyright 1996-1999 Kunihiro Ishiguro\r\n\
\r\n";

/* Standard command node structures. */
struct cmd_node auth_node =
{
  AUTH_NODE,
  "Password: ",
};

struct cmd_node view_node =
{
  VIEW_NODE,
  "%s> ",
};

struct cmd_node auth_enable_node =
{
  AUTH_ENABLE_NODE,
  "Password: ",
};

struct cmd_node enable_node =
{
  ENABLE_NODE,
  "%s# ",
};

struct cmd_node config_node =
{
  CONFIG_NODE,
  "%s(config)# ",
};

/* Install top node of command vector. */
void
install_node (struct cmd_node *node, 
	      int (*func) (struct vty *))
{
  vector_set_index (cmdvec, node->node, node);
  node->func = func;
  node->cmd_vector = vector_init (VECTOR_MIN_SIZE);
}

/* Compare two command's string.  Used in sort_node (). */
int
cmp_node (const void *p, const void *q)
{
  struct cmd_element *a = *(struct cmd_element **)p;
  struct cmd_element *b = *(struct cmd_element **)q;

  return strcmp (a->string, b->string);
}

/* Sort each node's command element according to command string. */
void
sort_node ()
{
  int i;
  struct cmd_node *cnode;
  
  for (i = 0; i < vector_max (cmdvec); i++) 
    if ((cnode = vector_slot (cmdvec, i)) != NULL)
      {	
	vector cmd_vector = cnode->cmd_vector;
	qsort (cmd_vector->index, cmd_vector->max, sizeof (void *), cmp_node);
      }
}

/* Breaking up string into each command piece. I assume given
   character is separated by a space character. Return value is a
   vector which includes char ** data element. */
vector
cmd_make_strvec (char *string)
{
  char *cp, *start, *token;
  int strlen;
  vector strvec;
  
  if (string == NULL)
    return NULL;
  
  cp = string;

  /* Skip white spaces. */
  while (isspace (*cp) && *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  if (*cp == '!' || *cp == '#')
    return NULL;

  /* Prepare return vector. */
  strvec = vector_init (VECTOR_MIN_SIZE);

  /* Copy each command piece and set into vector. */
  while (1) 
    {
      start = cp;
      while (!(isspace (*cp) || *cp == '\r' || *cp == '\n') && *cp != '\0')
	cp++;
      strlen = cp - start;
      token = XMALLOC (MTYPE_STRVEC, strlen + 1);
      bcopy (start, token, strlen);
      *(token + strlen) = '\0';
      vector_set (strvec, token);

      while ((isspace (*cp) || *cp == '\n' || *cp == '\r') && *cp != '\0')
	cp++;

      if (*cp == '\0' || *cp == '!' || *cp == '#') 
	return strvec;
    }
}

/* Free allocated string vector. */
void
cmd_free_strvec (vector v)
{
  int i;
  char *cp;

  if (!v)
    return;

  for (i = 0; i < vector_max (v); i++)
    if ((cp = vector_slot (v, i)) != NULL)
      XFREE (MTYPE_STRVEC, cp);

  vector_free (v);
}

/* Fetch next description.  Used in cmd_make_descvec(). */
char *
cmd_desc_str (char **string)
{
  char *cp, *start, *token;
  int strlen;
  
  cp = *string;

  if (cp == NULL)
    return NULL;

  /* Skip white spaces. */
  while (isspace (*cp) && *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  start = cp;

  while (!(*cp == '\r' || *cp == '\n') && *cp != '\0')
    cp++;

  strlen = cp - start;
  token = XMALLOC (MTYPE_STRVEC, strlen + 1);
  bcopy (start, token, strlen);
  *(token + strlen) = '\0';

  *string = cp;

  return token;
}

/* New string vector. */
vector
cmd_make_descvec (char *string, char *descstr)
{
  int multiple = 0;
  char *sp;
  char *token;
  int len;
  char *cp;
  char *dp;
  vector allvec;
  vector strvec = NULL;
  struct desc *desc;

  cp = string;
  dp = descstr;

  if (cp == NULL)
    return NULL;

  allvec = vector_init (VECTOR_MIN_SIZE);

  while (1)
    {
      while (isspace (*cp) && *cp != '\0')
	cp++;

      if (*cp == '(')
	{
	  multiple = 1;
	  cp++;
	}
      if (*cp == ')')
	{
	  multiple = 0;
	  cp++;
	}
      if (*cp == '|')
	{
	  if (!multiple)
	    {
	      fprintf (stderr, "Command parse error!: %s\n", string);
	      exit (1);
	    }
	  cp++;
	}
      
      while (isspace (*cp) && *cp != '\0')
	cp++;

      if (*cp == '(')
	{
	  multiple = 1;
	  cp++;
	}

      if (*cp == '\0') 
	return allvec;

      sp = cp;

      while (! (isspace (*cp) || *cp == '\r' || *cp == '\n' || *cp == ')' || *cp == '|') && *cp != '\0')
	cp++;

      len = cp - sp;

      token = XMALLOC (MTYPE_STRVEC, len + 1);
      memcpy (token, sp, len);
      *(token + len) = '\0';

      desc = XMALLOC (MTYPE_DESC, sizeof (struct desc));
      desc->cmd = token;
      desc->str = cmd_desc_str (&dp);

      if (multiple)
	{
	  if (multiple == 1)
	    {
	      strvec = vector_init (VECTOR_MIN_SIZE);
	      vector_set (allvec, strvec);
	    }
	  multiple++;
	}
      else
	{
	  strvec = vector_init (VECTOR_MIN_SIZE);
	  vector_set (allvec, strvec);
	}
      vector_set (strvec, desc);
    }
}

/* Count mandantory string vector size.  This is to determine inputed
   command has enough command length. */
int
cmd_cmdsize (vector strvec)
{
  int i;
  char *str;
  int size = 0;
  vector descvec;

  for (i = 0; i < vector_max (strvec); i++)
    {
      descvec = vector_slot (strvec, i);

      if (vector_max (descvec) == 1)
	{
	  struct desc *desc = vector_slot (descvec, 0);

	  str = desc->cmd;
	  
	  if (str == NULL || str[0] == '[')
	    return size;
	  else
	    size++;
	}
      else
	size++;
    }
  return size;
}

/* Return prompt character of specified node. */
char *
cmd_prompt (enum node_type node)
{
  struct cmd_node *cnode;

  cnode = vector_slot (cmdvec, node);
  return cnode->prompt;
}

/* Install a command into a node. */
void
install_element (enum node_type ntype, struct cmd_element *cmd)
{
  struct cmd_node *cnode;

  cnode = vector_slot (cmdvec, ntype);

  if (cnode == NULL) 
    {
      fprintf (stderr, "Command node doesn't exist, please check it\n");
      exit (1);
    }

  vector_set (cnode->cmd_vector, cmd);

  cmd->strvec = cmd_make_descvec (cmd->string, cmd->doc);
  cmd->cmdsize = cmd_cmdsize (cmd->strvec);
}

static unsigned char itoa64[] =	
"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void
to64(char *s, long v, int n)
{
  while (--n >= 0) 
    {
      *s++ = itoa64[v&0x3f];
      v >>= 6;
    }
}

char *zencrypt (char *passwd)
{
  char salt[6];
  struct timeval tv;
  char *crypt (const char *, const char *);

  gettimeofday(&tv,0);
  
  to64(&salt[0], random(), 3);
  to64(&salt[3], tv.tv_usec, 3);
  salt[5] = '\0';

  return crypt (passwd, salt);
}

/* This function write configuration of this host. */
int
config_write_host (struct vty *vty)
{
  if (host.name)
    vty_out (vty, "hostname %s%s", host.name, VTY_NEWLINE);

  /* For security reason, only output password configuration to
     file. */
  if (vty->type == VTY_FILE)
    {
      if (host.encrypt)
	{
	  if (host.password_encrypt)
	    vty_out (vty, "password 8 %s%s", 
		     host.password_encrypt, VTY_NEWLINE);
	  if (host.enable_encrypt)
	    vty_out (vty, "enable password 8 %s%s", 
		     host.enable_encrypt, VTY_NEWLINE);
	}
      else
	{
	  if (host.password)
	    vty_out (vty, "password %s%s", host.password, VTY_NEWLINE);
	  if (host.enable)
	    vty_out (vty, "enable password %s%s", host.enable, VTY_NEWLINE);
	}
    }      

  if (host.lines >= 0)
    vty_out (vty, "lines %d%s", host.lines, VTY_NEWLINE);

  if (host.logfile)
    vty_out (vty, "log file %s%s", host.logfile, VTY_NEWLINE);

  if (host.log_stdout)
    vty_out (vty, "log stdout%s", VTY_NEWLINE);

  if (host.log_syslog)
    vty_out (vty, "log syslog%s", VTY_NEWLINE);

  if (host.advanced)
    vty_out (vty, "service advanced-vty%s", VTY_NEWLINE);

  if (host.encrypt)
    vty_out (vty, "service password-encryption%s", VTY_NEWLINE);

  if (! host.motd)
    vty_out (vty, "no banner motd%s", VTY_NEWLINE);

  return 1;
}

/* Utility function for getting command vector. */
vector
cmd_node_vector (vector v, enum node_type ntype)
{
  struct cmd_node *cnode = vector_slot (v, ntype);
  return cnode->cmd_vector;
}

/* Filter command vector by symbol */
int
cmd_filter_by_symbol (char *command, char *symbol)
{
  int i, lim;

  if (strcmp (symbol, "IPV4_ADDRESS") == 0)
    {
      i = 0;
      lim = strlen (command);
      while (i < lim)
	{
	  if (! (isdigit (command[i]) || command[i] == '.' || command[i] == '/'))
	    return 1;
	  i++;
	}
      return 0;
    }
  if (strcmp (symbol, "STRING") == 0)
    {
      i = 0;
      lim = strlen (command);
      while (i < lim)
	{
	  if (! (isalpha (command[i]) || command[i] == '_' || command[i] == '-'))
	    return 1;
	  i++;
	}
      return 0;
    }
  if (strcmp (symbol, "IFNAME") == 0)
    {
      i = 0;
      lim = strlen (command);
      while (i < lim)
	{
	  if (! isalnum (command[i]))
	    return 1;
	  i++;
	}
      return 0;
    }
  return 0;
}

/* Completion match types. */
enum match_type 
{
  no_match,
  extend_match,
  vararg_match,
  partly_match,
  exact_match 
};

/* Make completion match and return match type flag. */
enum match_type
cmd_filter_by_completion (char *command, vector v, int index)
{
  int i;
  char *str;
  struct cmd_element *cmd_element;
  enum match_type match_type;
  vector descvec;
  struct desc *desc;
  
  match_type = no_match;

  /* If command and cmd_element string does not match set NULL to vector */
  for (i = 0; i < vector_max (v); i++) 
    if ((cmd_element = vector_slot (v, i)) != NULL)
      {

	if (index < vector_max (cmd_element->strvec))
	  {
	    int j;
	    int matched = 0;

	    descvec = vector_slot (cmd_element->strvec, index);
	    
	    for (j = 0; j < vector_max (descvec); j++)
	      {
		desc = vector_slot (descvec, j);
		str = desc->cmd;

		if (CMD_VARARG (str))
		  return vararg_match;

		/* Check is this point's argument optional ? */
		if (CMD_OPT (str[0]) || CMD_EXT (str[0]))
		  {
		    if (match_type < extend_match)
		      match_type = extend_match;
		    matched++;
		  }
		else if (strncmp (command, str, strlen (command)) == 0)
		  {
		    if (strcmp (command, str) == 0) 
		      match_type = exact_match;
		    else
		      {
			if (match_type < partly_match)
			  match_type = partly_match;
		      }
		    matched++;
		  }
	      }
	    if (! matched)
	      vector_slot (v, i) = NULL;
	  }
	else 
	  {
	    vector_slot (v, i) = NULL;
	  }
      }
  return match_type;
}

/* Check ambiguous match */
int
is_cmd_ambiguous (char *command, vector v, int index, enum match_type type)
{
  int i;
  int j;
  char *str = NULL;
  struct cmd_element *cmd_element;
  char *matched = NULL;
  vector descvec;
  struct desc *desc;
  
  for (i = 0; i < vector_max (v); i++) 
    if ((cmd_element = vector_slot (v, i)) != NULL)
      {
	int match = 0;

	descvec = vector_slot (cmd_element->strvec, index);

	for (j = 0; j < vector_max (descvec); j++)
	  {
	    desc = vector_slot (descvec, j);
	    str = desc->cmd;

	    switch (type)
	      {
	      case exact_match:
		if (! (CMD_OPT (str[0]) || CMD_EXT (str[0]))
		    && strcmp (command, str) == 0)
		  match++;
		break;
	      case partly_match:
		if (! (CMD_OPT (str[0]) || CMD_EXT (str[0]))
		    && strncmp (command, str, strlen (command)) == 0)
		  {
		    if (matched && strcmp (matched, str) != 0)
		      return 1;	/* There is ambiguous match. */
		    else
		      matched = str;
		    match++;
		  }
		break;
	      case extend_match:
		if (CMD_OPT(str[0]) || CMD_EXT (str[0]))
		  match++;
		break;
	      case no_match:
	      default:
		break;
	      }
	  }
	if (! match)
	  vector_slot (v, i) = NULL;
      }
  return 0;
}

/* If src matches dst return dst string, otherwise return NULL */
char *
cmd_entry_function (char *src, char *dst)
{
  /* In case of 'command \t', given src is NULL string. */
  if (src == NULL)
    {
      if (CMD_OPT (dst[0]) || CMD_EXT (dst[0]) || CMD_VARARG (dst))
	return NULL;
      else
	return dst;
    }

  if (strncmp (src, dst, strlen (src)) == 0)
    return dst;
  else
    return NULL;
}

/* If src matches dst return dst string, otherwise return NULL */
/* This versio will return the dst string always if it is
   CMD_EXT for '?' key processing */
char *
cmd_entry_function_desc (char *src, char *dst)
{
  /* Optional or variable commands always match on '?' */
  if (CMD_OPT (dst[0]) || CMD_EXT (dst[0]))
    return dst;

  /* In case of 'command \t', given src is NULL string. */
  if (src == NULL)
    return dst;

  if (strncmp (src, dst, strlen (src)) == 0)
    return dst;
  else
    return NULL;
}

/* Check same string element existence.  If it isn't there return
    1. */
int
cmd_unique_string (vector v, char *str)
{
  int i;
  char *match;

  for (i = 0; i < vector_max (v); i++)
    if ((match = vector_slot (v, i)) != NULL)
      if (strcmp (match, str) == 0)
	return 0;
  return 1;
}

/* Compare string to description vector.  If there is same string
   return 1 else return 0. */
int
desc_unique_string (vector v, char *str)
{
  int i;
  struct desc *desc;

  for (i = 0; i < vector_max (v); i++)
    if ((desc = vector_slot (v, i)) != NULL)
      if (strcmp (desc->cmd, str) == 0)
	return 1;
  return 0;
}

/* '?' describe command support. */
vector
cmd_describe_command (vector vline, struct vty *vty, int *status)
{
  int i;
  vector cmd_vector;
#define INIT_MATCHVEC_SIZE 10
  vector matchvec;
  struct cmd_element *cmd_element;
  int index;
  static struct desc desc_cr = { "<cr>", "" };

  /* Set index. */
  index = vector_max (vline) - 1;

  /* Make copy vector of current node's command vector. */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  /* Filter commands. */
  for (i = 0; i < index; i++)
    {
      enum match_type match;
      char *command;

      command = vector_slot (vline, i);

      match = cmd_filter_by_completion (command, cmd_vector, i);

      if (is_cmd_ambiguous (command, cmd_vector, i, match))
	{
	  vector_free (cmd_vector);
	  *status = CMD_ERR_AMBIGUOUS;
	  return NULL;
	}
    }

  /* Prepare match vector */
  matchvec = vector_init (INIT_MATCHVEC_SIZE);

  /* Make description vector. */
  for (i = 0; i < vector_max (cmd_vector); i++)
    if ((cmd_element = vector_slot (cmd_vector, i)) != NULL)
      {
	char *string = NULL;
	vector strvec = cmd_element->strvec;

	if (index > vector_max (strvec))
	  vector_slot (cmd_vector, i) = NULL;
	else
	  {
	    /* Check is command is completed. */
	    if (index == vector_max (strvec))
	      {
		string = "<cr>";
		if (! desc_unique_string (matchvec, string))
		  vector_set (matchvec, &desc_cr);
	      }
	    else
	      {
		int j;
		vector descvec = vector_slot (strvec, index);
		struct desc *desc;

		for (j = 0; j < vector_max (descvec); j++)
		  {
		    desc = vector_slot (descvec, j);
		    string = cmd_entry_function_desc (vector_slot (vline, index), desc->cmd);
		    if (string)
		      {
			/* Uniqueness check */
			if (! desc_unique_string (matchvec, string))
			  vector_set (matchvec, desc);
		      }
		  }
	      }
	  }
      }
  vector_free (cmd_vector);

#if 0
  if (vector_slot (matchvec, 0) == NULL)
    {
      desc_vector_free (matchvec);
      *status= CMD_ERR_NO_MATCH;
    }
#endif /* 0 */

  return matchvec;
}

/* Command line completion support. */
char **
cmd_complete_command (vector vline, struct vty *vty, int *status)
{
  int i;
  vector cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));
#define INIT_MATCHVEC_SIZE 10
  vector matchvec;
  struct cmd_element *cmd_element;
  int index = vector_max (vline) - 1;
  char **match_str;
  struct desc *desc;
  vector descvec;

  /* First, filter by preceeding command string */
  for (i = 0; i < index; i++)
    {
      enum match_type match;
      char *command = vector_slot (vline, i);

      /* First try completion match, if there is exactly match return 1 */
      match = cmd_filter_by_completion (command, cmd_vector, i);

      /* If there is exact match then filter ambiguous match else chech
	 ambiguousness. */
      if (is_cmd_ambiguous (command, cmd_vector, i, match))
	{
	  vector_free (cmd_vector);
	  *status = CMD_ERR_AMBIGUOUS;
	  return NULL;
	}
    }

  /* Prepare match vector. */
  matchvec = vector_init (INIT_MATCHVEC_SIZE);

  /* Now we got into completion */
  for (i = 0; i < vector_max (cmd_vector); i++)
    if ((cmd_element = vector_slot (cmd_vector, i)) != NULL)
      {
	char *string;
	vector strvec = cmd_element->strvec;
	
	/* Check field length */
	if (index >= vector_max (strvec))
	  vector_slot (cmd_vector, i) = NULL;
	else 
	  {
	    int j;

	    descvec = vector_slot (strvec, index);
	    for (j = 0; j < vector_max (descvec); j++)
	      {
		desc = vector_slot (descvec, j);

		if ((string = cmd_entry_function (vector_slot (vline, index),
						  desc->cmd)))
		  if (cmd_unique_string (matchvec, string))
		    vector_set (matchvec, string);
	      }
	  }
      }

  /* We don't need cmd_vector any more. */
  vector_free (cmd_vector);

  /* No matched command */
  if (vector_slot (matchvec, 0) == NULL)
    {
      vector_free (matchvec);

      /* In case of 'command \t' pattern.  Do you need '?' command at
         the end of the line. */
      if (vector_slot (vline, index) == '\0')
	*status = CMD_ERR_NOTHING_TODO;
      else
	*status = CMD_ERR_NO_MATCH;
      return NULL;
    }

  /* Only one matched */
  if (vector_slot (matchvec, 1) == NULL)
    {
      match_str = (char **) matchvec->index;

      vector_only_wrapper_free (matchvec);
      *status = CMD_COMPLETE_FULL_MATCH;
      return match_str;
    }

  /* Check complete match or partly match and make lcd of these
     matches.  Sorry for complication. */
  {
    int i;
    int j;
    int index;

    index = 0;
    for (i = 0; i < vector_max (matchvec) - 1; i++)
      {
	char c1, c2;
	char *s1 = vector_slot (matchvec, i);
	char *s2 = vector_slot (matchvec, i + 1);
	for (j = 0; (c1 = s1[j]) && (c2 = s2[j]); j++)
	  if (c1 != c2)
	    break;
	if (index > j)
	  index = j;
      }
  }

  match_str = (char **) matchvec->index;
  vector_only_wrapper_free (matchvec);
  *status = CMD_COMPLETE_MATCH;
  return match_str;
}

/* Command line parser. */
void
cmd_parse ()
{
  ;
}

/* Execute command by argument vline vector. */
int
cmd_execute_command (vector vline, struct vty *vty)
{
  int i;
  int index;
  vector cmd_vector;
  struct cmd_element *cmd_element;
  struct cmd_element *matched_element;
  unsigned int matched_count, incomplete_count;
  int argc;
  char *argv[CMD_ARGC_MAX];
  enum match_type match = 0;
  int varflag;

  /* Make copy of command elements. */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  for (index = 0; index < vector_max (vline); index++) 
    {
      char *command = vector_slot (vline, index);

      match = cmd_filter_by_completion (command, cmd_vector, index);

      if (match == vararg_match)
	break;

      if (is_cmd_ambiguous (command, cmd_vector, index, match))
	{
	  vector_free (cmd_vector);
	  return CMD_ERR_AMBIGUOUS;
	}
    }

  /* Check matched count. */
  matched_element = NULL;
  matched_count = 0;
  incomplete_count = 0;

  for (i = 0; i < vector_max (cmd_vector); i++) 
    if (vector_slot (cmd_vector,i) != NULL)
      {
	cmd_element = vector_slot (cmd_vector,i);

	if (match == vararg_match || index >= cmd_element->cmdsize)
	  {
	    matched_element = cmd_element;
	    matched_count++;
	  }
	else
	  {
	    incomplete_count++;
	  }
      }
  
  /* Finish of using cmd_vector. */
  vector_free (cmd_vector);

  /* To execute command, matched_count must be 1.*/
  if (matched_count == 0) 
    {
      if (incomplete_count)
	return CMD_ERR_INCOMPLETE;
      else
	return CMD_ERR_NO_MATCH;
    }

  if (matched_count > 1) 
    return CMD_ERR_AMBIGUOUS;

  /* Argument treatment */
  varflag = 0;
  argc = 0;

  for (i = 0; i < vector_max (vline); i++)
    {
      if (varflag)
	argv[argc++] = vector_slot (vline, i);
      else
	{	  
	  vector descvec = vector_slot (matched_element->strvec, i);

	  if (vector_max (descvec) == 1)
	    {
	      struct desc *desc = vector_slot (descvec, 0);
	      char *str = desc->cmd;

	      if (CMD_VARARG (str))
		varflag = 1;

	      if (varflag || CMD_VARIABLE (str) || CMD_OPTION (str))
		argv[argc++] = vector_slot (vline, i);
	    }
	  else
	    argv[argc++] = vector_slot (vline, i);
	}

      if (argc >= CMD_ARGC_MAX)
	return CMD_ERR_EXEED_ARGC_MAX;
    }

  /* Execute matched command. */
  return (*matched_element->func) (matched_element, vty, argc, argv);
}

/* Filter vector by command character with index. */
int
cmd_filter_by_string (char *command, vector v, int index)
{
  int i;
  char *str;
  struct cmd_element *cmd_element;
  
  /* If command and cmd_element string does not match set NULL to vector */
  for (i = 0; i < vector_max (v); i++) 
    if ((cmd_element = vector_slot (v, i)) != NULL)
      {
	/* If given index is bigger than max string vector of command,
           set NULL*/
	if (index >= vector_max (cmd_element->strvec))
	  vector_slot (v, i) = NULL;
	else 
	  {
	    int j;
	    int match;
	    vector descvec;
	    struct desc *desc;

	    descvec = vector_slot (cmd_element->strvec, index);
	    match = 0;

	    for (j = 0; j < vector_max (descvec); j++)
	      {
		desc = vector_slot (descvec, j);

		str = desc->cmd;

		/* Check is this point's argument is optional */
		if (CMD_OPT (str[0]))
		  match++;
		else if (CMD_EXT (str[0]))
		  {
		    /*
		    if (cmd_filter_by_symbol (command, str))
		      vector_slot (v, i) = NULL;
		    */
		    match++;
		  }
		else if (CMD_VARARG (str))
		  return CMD_VARARG_MATCH;
		else
		  {		  
		    if (strcmp (command, str) == 0)
		      match++;
		  }
	      }
	    if (! match)
	      vector_slot (v, i) = NULL;
	  }
      }
  return CMD_SUCCESS;
}

/* Execute command by argument readline. */
int
cmd_execute_command_strict (vector v, vector vline, struct vty *vty)
{
  int i;
  int index;
  vector cmd_vector;
  struct cmd_element *cmd_element;
  struct cmd_element *matched_element;
  unsigned int matched_count, incomplete_count;
  int argc;
  char *argv[CMD_ARGC_MAX];
  int varflag;
  int ret = 0;

  /* Make copy of command element */
  cmd_vector = vector_copy (cmd_node_vector (v, vty->node));

  for (index = 0; index < vector_max (vline); index++) 
    {
      ret = cmd_filter_by_string (vector_slot (vline, index), 
				  cmd_vector, index);

      /* If command meets '...' then finish matching. */
      if (ret == CMD_VARARG_MATCH)
	break;
    }

  /* Check matched count. */
  matched_element = NULL;
  matched_count = 0;
  incomplete_count = 0;
  for (i = 0; i < vector_max (cmd_vector); i++) 
    if (vector_slot (cmd_vector,i) != NULL)
      {
	cmd_element = vector_slot (cmd_vector,i);

	if (ret == CMD_VARARG_MATCH || index >= cmd_element->cmdsize)
	  {
	    matched_element = cmd_element;
	    matched_count++;
	  }
	else
	  incomplete_count++;
      }
  
  /* Finish of using cmd_vector. */
  vector_free (cmd_vector);

  /* To execute command, matched_count must be 1.*/
  if (matched_count == 0) 
    {
      if (incomplete_count)
	return CMD_ERR_INCOMPLETE;
      else
	return CMD_ERR_NO_MATCH;
    }

  if (matched_count > 1) 
    return CMD_ERR_AMBIGUOUS;

  /* Argument treatment */
  varflag = 0;
  argc = 0;

  for (i = 0; i < vector_max (vline); i++)
    {
      if (varflag)
	argv[argc++] = vector_slot (vline, i);
      else
	{	  
	  vector descvec = vector_slot (matched_element->strvec, i);

	  if (vector_max (descvec) == 1)
	    {
	      struct desc *desc = vector_slot (descvec, 0);
	      char *str = desc->cmd;

	      if (CMD_VARARG (str))
		varflag = 1;
	  
	      if (varflag || CMD_VARIABLE (str) || CMD_OPTION (str))
		argv[argc++] = vector_slot (vline, i);
	    }
	  else
	    argv[argc++] = vector_slot (vline, i);
	}

      if (argc >= CMD_ARGC_MAX)
	return CMD_ERR_EXEED_ARGC_MAX;
    }

  /* Now execute matched command */
  return (*matched_element->func) (matched_element, vty, argc, argv);
}

/* Configration make from file. */
int
config_from_file (struct vty *vty, FILE *fp)
{
  int ret;
  vector vline;

  while (fgets (vty->buf, VTY_BUFSIZ, fp))
    {
      vline = cmd_make_strvec (vty->buf);

      /* In case of comment line */
      if (vline == NULL)
	continue;
      /* Execute configuration command : this is strict match */
      ret = cmd_execute_command_strict (cmdvec, vline, vty);

      /* Try again with setting node to CONFIG_NODE */
      if (ret != CMD_SUCCESS && ret != CMD_WARNING)
	{
	  vty->node = CONFIG_NODE;
	  ret = cmd_execute_command_strict (cmdvec, vline, vty);
	}	  

      cmd_free_strvec (vline);

      if (ret != CMD_SUCCESS && ret != CMD_WARNING)
	return ret;
    }
  return CMD_SUCCESS;
}

/* Configration from terminal */
DEFUN (config_terminal,
       config_terminal_cmd,
       "configure terminal",
       "Configuration from vty interface\n"
       "Configuration terminal\n")
{
  vty->node = CONFIG_NODE;
  return CMD_SUCCESS;
}

/* Enable command */
DEFUN (enable, 
       config_enable_cmd,
       "enable",
       "Turn on privileged commands\n")
{
  /* If enable password is NULL, change to ENABLE_NODE */
  if (host.enable == NULL && host.enable_encrypt == NULL)
    vty->node = ENABLE_NODE;
  else
    vty->node = AUTH_ENABLE_NODE;

  return CMD_SUCCESS;
}

/* Down vty node level. */
DEFUN (config_exit,
       config_exit_cmd,
       "exit",
       "Exit current mode and down to previous mode\n")
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      vty->status = VTY_CLOSE;
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
    case RMAP_NODE:
    case VTY_NODE:
      vty->node = CONFIG_NODE;
      break;
    default:
      break;
    }
  return CMD_SUCCESS;
}

/* quit is alias of exit. */
ALIAS (config_exit,
       config_quit_cmd,
       "quit",
       "Exit current mode and down to previous mode\n")
       
/* End of configuration. */
DEFUN (config_end,
       config_end_cmd,
       "end",
       "End current mode and change to enable mode.")
{
  switch (vty->node)
    {
    case VIEW_NODE:
    case ENABLE_NODE:
      /* Nothing to do. */
      break;
    case CONFIG_NODE:
    case INTERFACE_NODE:
    case ZEBRA_NODE:
    case RIP_NODE:
    case RIPNG_NODE:
    case BGP_NODE:
    case RMAP_NODE:
    case OSPF_NODE:
    case OSPF6_NODE:
    case VTY_NODE:
      vty->node = ENABLE_NODE;
      break;
    default:
      break;
    }
  return CMD_SUCCESS;
}

/* Show version. */
DEFUN (show_version,
       show_version_cmd,
       "show version",
       SHOW_STR
       "Displays zebra version\n")
{
  vty_out (vty, "Zebra %s (%s).\r\n", ZEBRA_VERSION, host_name);
  vty_out (vty, "Copyright 1996-1999, Kunihiro Ishiguro.\r\n");

  return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN (config_help,
       config_help_cmd,
       "help",
       "Description of the interactive help system\n")
{
  vty_out (vty, 
	   "Zebra VTY provides advanced help feature.  When you need help,\r\n\
anytime at the command line please press '?'.\r\n\
\r\n\
If nothing matches, the help list will be empty and you must backup\r\n\
 until entering a '?' shows the available options.\r\n\
Two styles of help are provided:\r\n\
1. Full help is available when you are ready to enter a\r\n\
command argument (e.g. 'show ?') and describes each possible\r\n\
argument.\r\n\
2. Partial help is provided when an abbreviated argument is entered\r\n\
   and you want to know what arguments match the input\r\n\
   (e.g. 'show me?'.)\r\n\r\n");
  return CMD_SUCCESS;
}

/* Help display function for all node. */
DEFUN (config_list,
       config_list_cmd,
       "list",
       "Print command list\n")
{
  int i;
  struct cmd_node *cnode = vector_slot (cmdvec, vty->node);
  struct cmd_element *cmd;

  for (i = 0; i < vector_max (cnode->cmd_vector); i++)
    if ((cmd = vector_slot (cnode->cmd_vector, i)) != NULL)
      vty_out (vty, "  %s\r\n", cmd->string);
  return CMD_SUCCESS;
}

/* Write current configuration into file. */
DEFUN (config_write_file, 
       config_write_file_cmd,
       "write file",  
       "Write running configuration to memory, network, or terminal\n"
       "Write to configuration file\n")
{
  int i;
  int fd;
  struct cmd_node *node;
  char *config_file;
  struct vty *file_vty;

  /* Get filename. */
  config_file = host.config;

  /* Open file to configuration write. */
  fd = open (config_file, O_CREAT | O_WRONLY | O_TRUNC);
  if (fd < 0)
    {
      vty_out (vty, "Can't open configuration file %s.\r\n", config_file);
      return CMD_WARNING;
    }

  /* Make vty for configuration file. */
  file_vty = vty_new ();
  file_vty->fd = fd;
  file_vty->type = VTY_FILE;

  /* Config file header print. */
  vty_out (file_vty, "!\n! Zebra configuration saved from vty\n!   ");
  vty_time_print (file_vty);
  vty_out (file_vty, "!\n");

  for (i = 0; i < vector_max (cmdvec); i++)
    if ((node = vector_slot (cmdvec, i)) && node->func)
      {
	if ((*node->func) (file_vty))
	  vty_out (file_vty, "!\n");
      }
  vty_out (vty, "Configuration saved to %s\r\n", config_file);

  vty_close (file_vty);
  return CMD_SUCCESS;
}

ALIAS (config_write_file, 
       config_write_memory_cmd,
       "write memory",  
       "Write running configuration to memory, network, or terminal\n"
       "Write configuration to the file (same as write file)\n")

ALIAS (config_write_file, 
       copy_runningconfig_startupconfig_cmd,
       "copy running-config startup-config",  
       "Copy configuration\n"
       "Copy running config to... \n"
       "Copy running config to startup config (same as write file)\n")

/* Write current configuration into the terminal. */
DEFUN (config_write_terminal,
       config_write_terminal_cmd,
       "write terminal",
       "Write running configuration to memory, network, or terminal\n"
       "Write to terminal\n")
{
  int i;
  struct cmd_node *node;

  vty_out (vty, "\r\nCurrrent Configuration:\r\n");
  vty_out (vty, "!\r\n");

  for (i = 0; i < vector_max (cmdvec); i++)
    if ((node = vector_slot (cmdvec, i)) && node->func)
      {
	if ((*node->func) (vty))
	  vty_out (vty, "!\r\n");
      }
  return CMD_SUCCESS;
}

/* Write current configuration into the terminal. */
ALIAS (config_write_terminal,
       show_running_config_cmd,
       "show running-config",
       SHOW_STR
       "running configuration\n")

/* Hostname configuration */
DEFUN (config_hostname, 
       hostname_cmd,
       "hostname WORD",
       "Set system's network name\n"
       "This system's network name\n")
{
  if (!isalpha(*argv[0]))
    {
      vty_out (vty, "Please specify string starting with alphabet\r\n");
      return CMD_WARNING;
    }

  if (host.name)
    XFREE (0, host.name);
    
  host.name = strdup (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (config_no_hostname, 
       no_hostname_cmd,
       "no hostname [HOSTNAME]",
       NO_STR
       "Reset system's network name\n"
       "Host name of this router\n")
{
  if (host.name)
    XFREE (0, host.name);
  host.name = NULL;
  return CMD_SUCCESS;
}

/* VTY interface password set. */
DEFUN (config_password, password_cmd,
       "password [CRYPT] PASSWORD",
       "Assign the terminal connection password\n"
       "Crypt: 8 for crypt, password string for cleartext\n"
       "Password string\n")
{
  /* Argument check. */
  if (argc == 0)
    {
      vty_out (vty, "Please specify password.\r\n");
      return CMD_WARNING;
    }

  if (argc == 2)
    {
      if (*argv[0] == '8')
	{
	  if (host.password)
	    XFREE (0, host.password);
	  if (host.password_encrypt)
	    XFREE (0, host.password_encrypt);
	  host.password_encrypt = XSTRDUP (0, strdup (argv[1]));
	  return CMD_SUCCESS;
	}
      else
	{
	  vty_out (vty, "Unknown encryption type.\r\n");
	  return CMD_WARNING;
	}
    }

  if (!isalnum (*argv[0]))
    {
      vty_out (vty, 
	       "Please specify string starting with alphanumeric\r\n");
      return CMD_WARNING;
    }

  if (host.password)
    XFREE (0, host.password);
  host.password = NULL;

  if (host.encrypt)
    {
      if (host.password_encrypt)
	XFREE (0, host.password_encrypt);
      host.password_encrypt = XSTRDUP (0, zencrypt (argv[0]));
    }
  else
    host.password = XSTRDUP (0, argv[0]);

  return CMD_SUCCESS;
}

/* VTY enable password set. */
DEFUN (config_enable_password, enable_password_cmd,
       "enable password [CRYPT] PASSWORD",
       "Modify enable password parameters\n"
       "Assign the privileged level password\n"
       "Crypt: 8 for crypt, password string for cleartext\n"
       "Password string\n")
{
  /* Argument check. */
  if (argc == 0)
    {
      vty_out (vty, "Please specify password.\r\n");
      return CMD_WARNING;
    }

  /* Crypt type is specified. */
  if (argc == 2)
    {
      if (*argv[0] == '8')
	{
	  if (host.enable)
	    XFREE (0, host.enable);
	  host.enable = NULL;

	  if (host.enable_encrypt)
	    XFREE (0, host.enable_encrypt);
	  host.enable_encrypt = XSTRDUP (0, argv[1]);

	  return CMD_SUCCESS;
	}
      else
	{
	  vty_out (vty, "Unknown encryption type.\r\n");
	  return CMD_WARNING;
	}
    }

  if (!isalnum (*argv[0]))
    {
      vty_out (vty, 
	       "Please specify string starting with alphanumeric\r\n");
      return CMD_WARNING;
    }

  if (host.enable)
    XFREE (0, host.enable);
  host.enable = NULL;

  /* Plain password input. */
  if (host.encrypt)
    {
      if (host.enable_encrypt)
	XFREE (0, host.enable_encrypt);
      host.enable_encrypt = XSTRDUP (0, zencrypt (argv[0]));
    }
  else
    host.enable = XSTRDUP (0, argv[0]);

  return CMD_SUCCESS;
}

DEFUN (service_password_encrypt,
       service_password_encrypt_cmd,
       "service password-encryption",
       "Set up miscellaneous service\n"
       "Enable encrypted passwords\n")
{
  if (host.encrypt)
    return CMD_SUCCESS;

  host.encrypt = 1;

  if (host.password)
    {
      if (host.password_encrypt)
	XFREE (0, host.password_encrypt);
      host.password_encrypt = XSTRDUP (0, zencrypt (host.password));
    }
  if (host.enable)
    {
      if (host.enable_encrypt)
	XFREE (0, host.enable_encrypt);
      host.enable_encrypt = XSTRDUP (0, zencrypt (host.enable));
    }

  return CMD_SUCCESS;
}

DEFUN (no_service_password_encrypt,
       no_service_password_encrypt_cmd,
       "no service password-encryption",
       NO_STR
       "Set up miscellaneous service\n"
       "Enable encrypted passwords\n")
{
  if (! host.encrypt)
    return CMD_SUCCESS;

  host.encrypt = 0;

  if (host.password_encrypt)
    XFREE (0, host.password_encrypt);
  host.password_encrypt = NULL;

  if (host.enable_encrypt)
    XFREE (0, host.enable_encrypt);
  host.enable_encrypt = NULL;

  return CMD_SUCCESS;
}

DEFUN (config_terminal_length, config_terminal_length_cmd,
       "terminal length <0-512>",
       "Terminal configuration setup\n"
       "Terminal length setup\n"
       "Number of lines of VTY (0 means no line control)\n")
{
  int lines;
  char *endptr = NULL;

  lines = strtol (argv[0], &endptr, 10);
  if (lines > 512 || *endptr != '\0')
    {
      vty_out (vty, "length is malformed\r\n");
      return CMD_WARNING;
    }
  host.lines = lines;
  vty->height = lines;

  return CMD_SUCCESS;
}

/* VTY interface override no. of terminal lines. */
DEFUN (config_lines, config_lines_cmd,
       "lines LINES",
       "Override no. of terminal lines\n"
       "lines integer\n")
{
  host.lines = strtol(argv[0], (char**)0, 10);
  return CMD_SUCCESS;
}

DEFUN (config_log_stdout,
       config_log_stdout_cmd,
       "log stdout",
       "Logging control\n"
       "Logging goes to stdout\n")
{
  zlog_set_flag (NULL, ZLOG_STDOUT);
  host.log_stdout = 1;
  return CMD_SUCCESS;
}

DEFUN (no_config_log_stdout,
       no_config_log_stdout_cmd,
       "no log stdout",
       NO_STR
       "Logging control\n"
       "Cancel logging to stdout\n")
{
  zlog_reset_flag (NULL, ZLOG_STDOUT);
  host.log_stdout = 0;
  return CMD_SUCCESS;
}

DEFUN (config_log_file,
       config_log_file_cmd,
       "log file FILENAME",
       "Logging control\n"
       "Logging to file\n"
       "Logging filename\n")
{
  int ret;

  ret = zlog_set_file (NULL, ZLOG_FILE, argv[0]);

  if (!ret)
    {
      vty_out (vty, "can't open logfile %s\n", argv[0]);
      return CMD_WARNING;
    }

  if (host.logfile)
    XFREE (MTYPE_TMP, host.logfile);

  host.logfile = strdup (argv[0]);

  return CMD_SUCCESS;
}

DEFUN (no_config_log_file,
       no_config_log_file_cmd,
       "no log file [FILENAME]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file\n"
       "Logging file name\n")
{
  zlog_reset_file (NULL);

  if (host.logfile)
    XFREE (MTYPE_TMP, host.logfile);

  host.logfile = NULL;

  return CMD_SUCCESS;
}

DEFUN (config_log_syslog,
       config_log_syslog_cmd,
       "log syslog",
       "Logging control\n"
       "Logging goes to syslog\n")
{
  zlog_set_flag (NULL, ZLOG_SYSLOG);
  host.log_syslog = 1;
  return CMD_SUCCESS;
}

DEFUN (no_config_log_syslog,
       no_config_log_syslog_cmd,
       "no log syslog",
       NO_STR
       "Logging control\n"
       "Cancel logging to syslog\n")
{
  zlog_reset_flag (NULL, ZLOG_SYSLOG);
  host.log_syslog = 0;
  return CMD_SUCCESS;
}

DEFUN (banner_motd_default,
       banner_motd_default_cmd,
       "banner motd default",
       "Set banner string\n"
       "Strings for motd\n"
       "Default string\n")
{
  host.motd = default_motd;
  return CMD_SUCCESS;
}

DEFUN (no_banner_motd,
       no_banner_motd_cmd,
       "no banner motd",
       NO_STR
       "Set banner string\n"
       "Strings for motd\n")
{
  host.motd = NULL;
  return CMD_SUCCESS;
}

/* Set config filename.  Called from vty.c */
void
host_config_set (char *filename)
{
  host.config = strdup (filename);
}

void
install_default (enum node_type node)
{
  install_element (node, &config_exit_cmd);
  install_element (node, &config_quit_cmd);
  install_element (node, &config_end_cmd);
  install_element (node, &config_help_cmd);
  install_element (node, &config_list_cmd);
}

/* Initialize command interface. Install basic nodes and commands. */
void
cmd_init ()
{
  /* Allocate initial top vector of commands. */
  cmdvec = vector_init (VECTOR_MIN_SIZE);

  /* Default host value settings. */
  host.name = NULL;
  host.password = NULL;
  host.enable = NULL;
  host.lines = -1;
  host.logfile = NULL;
  host.config = NULL;
  host.motd = default_motd;

  /* Install top nodes. */
  install_node (&view_node, NULL);
  install_node (&enable_node, NULL);
  install_node (&auth_node, NULL);
  install_node (&auth_enable_node, NULL);
  install_node (&config_node, config_write_host);

  /* Each node's basic commands. */
  install_element (VIEW_NODE, &config_exit_cmd);
  install_element (VIEW_NODE, &config_quit_cmd);
  install_element (VIEW_NODE, &config_help_cmd);
  install_element (VIEW_NODE, &config_list_cmd);
  install_element (VIEW_NODE, &config_enable_cmd);
  install_element (VIEW_NODE, &show_version_cmd);
  install_element (VIEW_NODE, &config_terminal_length_cmd);

  install_default (ENABLE_NODE);
  install_element (ENABLE_NODE, &config_terminal_cmd);
  install_element (ENABLE_NODE, &config_write_terminal_cmd);
  install_element (ENABLE_NODE, &show_running_config_cmd);
  install_element (ENABLE_NODE, &config_write_file_cmd);
  install_element (ENABLE_NODE, &config_write_memory_cmd);
  install_element (ENABLE_NODE, &copy_runningconfig_startupconfig_cmd);
  install_element (ENABLE_NODE, &show_version_cmd);
  install_element (ENABLE_NODE, &config_terminal_length_cmd);

  install_default (CONFIG_NODE);
  install_element (CONFIG_NODE, &hostname_cmd);
  install_element (CONFIG_NODE, &no_hostname_cmd);
  install_element (CONFIG_NODE, &password_cmd);
  install_element (CONFIG_NODE, &enable_password_cmd);
  install_element (CONFIG_NODE, &config_lines_cmd);
  install_element (CONFIG_NODE, &config_log_stdout_cmd);
  install_element (CONFIG_NODE, &no_config_log_stdout_cmd);
  install_element (CONFIG_NODE, &config_log_file_cmd);
  install_element (CONFIG_NODE, &no_config_log_file_cmd);
  install_element (CONFIG_NODE, &config_log_syslog_cmd);
  install_element (CONFIG_NODE, &no_config_log_syslog_cmd);
  install_element (CONFIG_NODE, &service_password_encrypt_cmd);
  install_element (CONFIG_NODE, &no_service_password_encrypt_cmd);
  install_element (CONFIG_NODE, &banner_motd_default_cmd);
  install_element (CONFIG_NODE, &no_banner_motd_cmd);

  srand(time(NULL));
}
