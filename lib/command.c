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

/* Command vector which includes some level of command lists. Normally
   each daemon maintains each own cmdvec. */
vector cmdvec;

/* Host information structure. */
struct host host;

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

/* Configuration node structure. */
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
  node->desc_vector = vector_init (VECTOR_MIN_SIZE);
}

/* Compare two command's string. Sort sort_node (). */
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
  
  for (i = 0; i < vector_max (cmdvec); i++) 
    {
      struct cmd_node *cnode;

      cnode = vector_slot (cmdvec, i);

      if (cnode)
	{	
	  vector cmd_vector;

	  cmd_vector = cnode->cmd_vector;
	  qsort (cmd_vector->index, cmd_vector->max, 
		 sizeof (void *), cmp_node);
	}
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

/* Breaking up string into each description */
vector
cmd_make_descvec (char *string)
{
  char *cp, *start, *token;
  int strlen;
  vector descvec;
  
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
  descvec = vector_init (VECTOR_MIN_SIZE);

  /* Copy each command piece and set into vector. */
  while (1) 
    {
      start = cp;
      while (!(*cp == '\r' || *cp == '\n') && *cp != '\0')
	cp++;
      strlen = cp - start;
      token = XMALLOC (MTYPE_STRVEC, strlen + 1);
      bcopy (start, token, strlen);
      *(token + strlen) = '\0';
      vector_set (descvec, token);

      if ((*cp == '\n' || *cp == '\r') && *cp != '\0')
	cp++;

      if (*cp == '\0' || *cp == '!' || *cp == '#') 
	return descvec;
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

/* Count mandantory string vector size.  This is to determine inputed
   command has enough command length. */
int
cmd_cmdsize (vector v)
{
  int i;
  char *str;
  int size = 0;

  for (i = 0; i < vector_max (v); i++)
    {
      str = vector_slot (v, i);
      if (str == NULL || str[0] == '[')
	return size;
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

/* Lookup description structure. */
struct desc *
desc_make (struct cmd_element *cmd, char *str, int index)
{
  struct desc *desc;

  desc = XMALLOC (MTYPE_DESC, sizeof (struct desc));

  desc->cmd = str;

  if (index >= vector_max (cmd->descvec)) 
    desc->str = NULL;
  else
    desc->str = vector_slot (cmd->descvec, index);

  return desc;
}

/* Free description vector. */
void
desc_vector_free (vector descvec)
{
  int i;
  struct desc *desc;

  for (i = 0; i < vector_max (descvec); i++)
    if ((desc = vector_slot (descvec, i)) != NULL)
      XFREE (MTYPE_DESC, desc);

  vector_free (descvec);
}

/* Return next string pointer. */
char *
desc_next (char *str, char *pnt)
{
  int i;
  int len; 
  int term;

  len = strlen (str);
  term = 0;
  
  for (i = (pnt - str); i < len; i++)
    {
      if (term)
	return str + i;
      if (str[i] == '\0')
	term = 1;
    }
  return pnt;
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
  cmd->strvec = cmd_make_strvec (cmd->string);
  cmd->cmdsize = cmd_cmdsize (cmd->strvec);
  cmd->descvec = cmd_make_descvec (cmd->doc);

  /* Make check. */
  if (vector_max (cmd->descvec) < vector_max (cmd->strvec))
    {
      zlog (NULL, LOG_INFO, "Warning : No description exists. %s", cmd->string);
      zlog (NULL, LOG_INFO, "%d %d", vector_max (cmd->descvec),vector_max (cmd->strvec));
    }
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
      if (host.password)
	vty_out (vty, "password %s%s", host.password, VTY_NEWLINE);
      if (host.enable)
	vty_out (vty, "enable password %s%s", host.enable, VTY_NEWLINE);
    }      

  if (host.logfile)
    vty_out (vty, "log file %s%s", host.logfile, VTY_NEWLINE);

  if (host.log)
    vty_out (vty, "log %s%s", host.log, VTY_NEWLINE);

  return 0;
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
  enum match_type match;
  
  match = no_match;
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
	    str = vector_slot (cmd_element->strvec, index);

	    /* Check is this point's argument optional ? */
	    if (CMD_OPT (str[0]) || CMD_EXT (str[0]))
	      {
		if (match < extend_match)
		  match = extend_match;
		continue;
	      }

	    /* There is vararg. */
	    if (strcmp (str, "...") == 0)
	      return vararg_match;

	    /* If completion match fail set it NULL. */
	    if (strncmp (command, str, strlen (command)) != 0)
	      {
		vector_slot (v, i) = NULL;
		continue;
	      }

	    /* OK, there is a match, set match type flag. */
	    if (strcmp (command, str) == 0) 
	      match = exact_match;
	    else
	      {
		if (match < partly_match)
		  match = partly_match;
	      }
	  }
      }
  return match;
}

/* Check ambiguous match */
int
cmd_filter_ambiguous (char *command, vector v, int index, enum match_type type)
{
  int i;
  char *str;
  struct cmd_element *cmd_element;
  char *matched = NULL;
  
  for (i = 0; i < vector_max (v); i++) 
    if ((cmd_element = vector_slot (v, i)) != NULL)
      {
	str = vector_slot (cmd_element->strvec, index);

	/* If there is exact mach filter not exact match. */
	if (type == exact_match)
	  {
	    if (CMD_OPT (str[0]) || CMD_EXT (str[0])
		|| strcmp (command, str) != 0)
	      vector_slot (v, i) = NULL;
	  }

	/* If there is patly matched string filter option and extend match. */
	if (type == partly_match)
	  {
	    if (CMD_OPT (str[0]) || CMD_EXT (str[0]))
	      {
		vector_slot (v, i) = NULL;
		continue;
	      }

	    if (strncmp (command, str, strlen (command)) == 0)
	      {
		if (matched && strcmp (matched, str) != 0)
		  return 1;	/* There is ambiguous match. */
		else
		  matched = str;
	      }
	  }

	/* If there is only extend match. */
	if (type == extend_match)
	  {
	    if (CMD_OPT(str[0]) || CMD_EXT (str[0]))
	      ;
	    else
	      vector_slot (v, i) = NULL;
	  }
      }
  return 0;
}

/* Yet another filter function for describe command. */
void
cmd_filter_describe (char *command, vector v, int index)
{
  int i;
  struct cmd_element *cmd;
  char *str;

  if (command == NULL)
    return;

  for (i = 0; i < vector_max (v); i++)
    if ((cmd = vector_slot (v, i)) != NULL)
      {
	if (index >= vector_max (cmd->strvec))
	  vector_slot (v, i) = NULL;
	else
	  {
	    str = vector_slot (cmd->strvec, index);

	    if (strncmp (command, str, strlen (command)) != 0)
	      vector_slot (v, i) = NULL;
	  }
      }
}

/* If src matches dst return dst string, otherwise return NULL */
char *
cmd_entry_function (char *src, char *dst)
{
  /* In case of 'command \t', given src is NULL string. */
  if (src == NULL)
    {
      if (CMD_OPT (dst[0]) || CMD_EXT (dst[0]))
	return NULL;
      else
	return dst;
    }

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

  /* Set index. */
  index = vector_max (vline) - 1;

  /* Make copy vector of current node's command vector. */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  /* Filter commands. */
  for (i = 0; i < index; i++)
    {
      enum match_type match;
      int ambiguous;
      char *command;

      command = vector_slot (vline, i);

      match = cmd_filter_by_completion (command, cmd_vector, i);

      ambiguous = cmd_filter_ambiguous (command, cmd_vector, i, match);
      if (ambiguous) 
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
	char *string;
	vector strvec = cmd_element->strvec;

	if (index > vector_max (strvec))
	  vector_slot (cmd_vector, i) = NULL;
	else
	  {
	    /* Check is command is completed. */
	    if (index == vector_max (strvec))
	      string = "<cr>";
	    else
	      string = cmd_entry_function (vector_slot (vline, index),
					   vector_slot (strvec, index));

	    if (string)
	      {
		/* Uniqueness check */
		if (! desc_unique_string (matchvec, string))
		  {
		    struct desc *desc;

		    desc = desc_make (cmd_element, string, index);
		    vector_set (matchvec, desc);
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

  /* First, filter by preceeding command string */
  for (i = 0; i < index; i++)
    {
      enum match_type match;
      int ambiguous;
      char *command = vector_slot (vline, i);

      /* First try completion match, if there is exactly match return 1 */
      match = cmd_filter_by_completion (command, cmd_vector, i);

      /* If there is exact match then filter ambiguous match else chech
	 ambiguousness. */
      ambiguous = cmd_filter_ambiguous (command, cmd_vector, i, match);
      if (ambiguous) 
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
	    if ((string = cmd_entry_function (vector_slot (vline, index),
					      vector_slot (strvec, index))))
	      /* Uniqueness check */
	      if (cmd_unique_string (matchvec, string))
		vector_set (matchvec, string);
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

  /* Make copy of command element */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  for (index = 0; index < vector_max (vline); index++) 
    {
      int ambiguous;
      char *command = vector_slot (vline, index);

      if (command == NULL)
	break;

      /* First try completion match, if there is exactly match return 1 */
      match = cmd_filter_by_completion (command, cmd_vector, index);

      /* If there is vararg match there shoud be only one match at
         this point. */
      if (match == vararg_match)
	break;

      /* If there is exact match then filter ambiguous match else check
         ambiguousness. */
      ambiguous = cmd_filter_ambiguous (command, cmd_vector, index, match);
      if (ambiguous) 
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
      char *str = vector_slot (matched_element->strvec, i);

      if (!varflag && strcmp (str, "...") == 0)
	varflag = 1;

      if (varflag || (str[0] >= 'A' && str[0] <= 'Z') || (str[0] == '['))
	argv[argc++] = vector_slot (vline, i);

      if (argc >= CMD_ARGC_MAX)
	return CMD_ERR_EXEED_ARGC_MAX;
    }

  /* Now execute matched command */
  return (*matched_element->func)(matched_element, vty, argc, argv);
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
	    str = vector_slot (cmd_element->strvec, index);
	    /* Check is this point's argument is optional */
	    if (str[0] == '[')
	      continue; /* return; */
	    if (str[0] >= 'A' && str[0] <= 'Z')
	      {
		if (cmd_filter_by_symbol (command, str))
		  vector_slot (v, i) = NULL;
		continue; /* return ; */
	      }

	    if (strcmp (str, "...") == 0)
	      return CMD_VARARG_MATCH;

	    if (strcmp (command, str) != 0)
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
  vector cmd_vector;
  struct cmd_element *cmd_element;
  unsigned int matched_count;
  int argc;
  char *argv[CMD_ARGC_MAX];
  int varflag;

  /* Make copy of command element */
  cmd_vector = vector_copy (cmd_node_vector (v, vty->node));

  for (i = 0; i < vector_max (vline); i++) 
    {
      int ret;
      
      ret = cmd_filter_by_string (vector_slot (vline, i), cmd_vector, i);

      /* If command meets '...' then finish matching. */
      if (ret == CMD_VARARG_MATCH)
	break;
    }

  /* Check matched count. */
  cmd_element = NULL;
  matched_count = 0;
  for (i = 0; i < vector_max (cmd_vector); i++) 
    if (vector_slot (cmd_vector,i) != NULL)
      {
	cmd_element = vector_slot (cmd_vector,i);
	matched_count++;
      }
  
  /* Finish of using cmd_vector. */
  vector_free (cmd_vector);

  /* To execute command, matched_count must be 1.*/
  if (matched_count == 0) 
    return CMD_ERR_NO_MATCH;
  if (matched_count > 1) 
    return CMD_ERR_AMBIGUOUS;

  /* Argument treatment */
  varflag = 0;
  argc = 0;
  for (i = 0; i < vector_max (vline); i++)
    {
      char *str = vector_slot (cmd_element->strvec, i);

      if (!varflag && strcmp (str, "...") == 0)
	varflag = 1;
	  
      if (varflag || (str[0] >= 'A' && str[0] <= 'Z') || (str[0] == '['))
	argv[argc++] = vector_slot (vline, i);

      if (argc >= CMD_ARGC_MAX)
	return CMD_ERR_EXEED_ARGC_MAX;
    }

  /* Now execute matched command */
  return (*cmd_element->func)(cmd_element, vty, argc, argv);
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
       "config terminal",
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
  if (host.enable == NULL)
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
      vty->status = VTY_CLOSE;
      break;
    case ENABLE_NODE:
      vty->node = VIEW_NODE;
      break;
    case CONFIG_NODE:
      vty->node = ENABLE_NODE;
      break;
    case INTERFACE_NODE:
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

/* Help display function for all node. */
DEFUN (config_help,
       config_help_cmd,
       "help",
       "Description of the interactive help system\n")
{
  vty_out (vty, 
	   "Help may be requested at any point in a command by entering\r\n"
	   "a question mark '?'.  If nothing matches, the help list will\r\n"
	   "be empty and you must backup until entering a '?' shows the\r\n"
	   "available options.\r\n"
	   "Two styles of help are provided:\r\n"
	   "1. Full help is available when you are ready to enter a\r\n"
	   "command argument (e.g. 'show ?') and describes each possible\r\n"
	   "argument.\r\n"
	   "2. Partial help is provided when an abbreviated argument is entered\r\n"
	   "   and you want to know what arguments match the input\r\n"
	   "   (e.g. 'show me?'.)\r\n\r\n");
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

  for (i = 0; i < vector_max (cmdvec); i++)
    if ((node = vector_slot (cmdvec, i)) && node->func)
      {
	vty_out (file_vty, "!\n");
	(*node->func) (file_vty);
      }
  vty_out (vty, "Configuration saved to %s\r\n", config_file);

  vty_close (file_vty);
  return CMD_SUCCESS;
}

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

  for (i = 0; i < vector_max (cmdvec); i++)
    if ((node = vector_slot (cmdvec, i)) && node->func)
      {
	vty_out (vty, "!\r\n");
	(*node->func) (vty);
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

/* VTY interface password set. */
DEFUN (config_password, password_cmd,
       "password PASSWORD",
       "Assign the terminal connection password\n"
       "Password string\n")
{
  if (host.password)
    XFREE (0, host.password);

  host.password = strdup (argv[0]);
  return CMD_SUCCESS;
}

/* VTY enable password set. */
DEFUN (config_enable_password, enable_password_cmd,
       "enable password PASSWORD",
       "Modify enable password parameters\n"
       "Assign the privileged level password\n"
       "Password string\n")
{
  if (!isalnum (*argv[0]))
    {
      vty_out (vty, "Please specify string starting with alphanumeric\r\n");
      return CMD_WARNING;
    }

  if (host.enable)
    XFREE (0, host.enable);

  host.enable = strdup (argv[0]);
  return CMD_SUCCESS;
}

DEFUN (config_log,
       config_log_cmd,
       "log stdout",
       "Logging control\n"
       "Logging goes to stdout\n")
{
  zlog_set_flag (NULL, ZLOG_STDOUT);
  host.log = "stdout";
  return CMD_SUCCESS;
}

DEFUN (config_log_file,
       config_log_file_cmd,
       "log file FILENAME",
       "Logging control\n"
       "Logging to file\n"
       "Loggin filename\n")
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

#if 0
void func_name ()
{
  ;
}

DEFUN2 (test,
	test_cmd,
	"test command",
        ({DOC_STR, "Log filename specify command\n"},
	{DOC_FUNC, func_name}))
{
  return 0;
}
#endif /* 0 */

/* Set config filename.  Called from vty.c */
void
host_config_set (char *filename)
{
  host.config = strdup (filename);
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
  host.logfile = NULL;
  host.config = NULL;

  /* Install top nodes. */
  install_node (&view_node, NULL);
  install_node (&enable_node, NULL);
  install_node (&auth_node, NULL);
  install_node (&auth_enable_node, NULL);
  install_node (&config_node, config_write_host);

  /* Each node's basic commands. */
  install_element (VIEW_NODE, &config_enable_cmd);
  install_element (VIEW_NODE, &config_exit_cmd);
  install_element (VIEW_NODE, &config_help_cmd);
  install_element (VIEW_NODE, &config_list_cmd);
  install_element (ENABLE_NODE, &config_terminal_cmd);
  install_element (ENABLE_NODE, &config_exit_cmd);
  install_element (ENABLE_NODE, &config_help_cmd);
  install_element (ENABLE_NODE, &config_list_cmd);
  install_element (ENABLE_NODE, &config_write_terminal_cmd);
  install_element (ENABLE_NODE, &show_running_config_cmd);
  install_element (ENABLE_NODE, &config_write_file_cmd);
  install_element (CONFIG_NODE, &config_end_cmd);
  install_element (CONFIG_NODE, &config_exit_cmd);
  install_element (CONFIG_NODE, &config_help_cmd);
  install_element (CONFIG_NODE, &config_list_cmd);
  install_element (CONFIG_NODE, &hostname_cmd);
  install_element (CONFIG_NODE, &password_cmd);
  install_element (CONFIG_NODE, &enable_password_cmd);
  install_element (CONFIG_NODE, &config_log_cmd);
  install_element (CONFIG_NODE, &config_log_file_cmd);
}
