/*
 * Virtual terminal [aka TeletYpe] interface routine.
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

#include "linklist.h"
#include "buffer.h"
#include "version.h"
#include "command.h"
#include "sockunion.h"
#include "thread.h"
#include "memory.h"
#include "str.h"
#include "log.h"
#include "prefix.h"
#include "filter.h"

/* Extern host structure from command.c */
extern struct host host;

/* Vector which store each vty structure. */
static vector vtyvec;

/* Vty timeout value. */
static unsigned long vty_timeout_val = VTY_TIMEOUT_DEFAULT;

/* Vty access-class command */
static char *vty_accesslist_name = NULL;

/* Vty events */
enum event {VTY_SERV, VTY_READ, VTY_WRITE};

static void vty_event (enum event, int, struct vty *);

/* VTY standard output function. */
int
vty_out (struct vty *vty, char *format, ...)
{
  va_list args;
  int len;
  /* XXX need overflow check */
  char buf[1024];

  /* vararg print */
  va_start (args, format);

  len = vsnprintf (buf, sizeof buf, format, args);

  if (len < 0)
    {    
      zlog (NULL, LOG_INFO, "Vty closed due to vty output buffer shortage.");
      return -1;
    }

  buffer_write (vty->obuf, (u_char *)buf, len);

  va_end (args);
  return len;
}

/* Output current time to the vty. */
void
vty_time_print (struct vty *vty)
{
  time_t clock;
  struct tm *tm;
#define TIME_BUF 25
  char buf [TIME_BUF];
  int ret;
  
  time (&clock);
  tm = localtime (&clock);

  ret = strftime (buf, TIME_BUF, "%Y/%m/%d %H:%M:%S", tm);
  if (ret == 0)
    {
      zlog (NULL, LOG_INFO, "strftime error");
      return;
    }
  vty_out (vty, "%s\n", buf);

  return;
}

/* Say hello to vty interface. */
static void
vty_hello (struct vty *vty)
{
  if (host.motd)
    vty_out (vty, host.motd);
}

/* Put out prompt and wait input from user. */
static void
vty_prompt (struct vty *vty)
{
  struct utsname names;
  const char*hostname;
  hostname = host.name;
  if (!hostname)
  {
    uname (&names);
    hostname = names.nodename;
  }
  vty_out (vty, cmd_prompt (vty->node), hostname);
}

/* Send WILL TELOPT_ECHO to remote server. */
void
vty_will_echo (struct vty *vty)
{
  char cmd[] = { IAC, WILL, TELOPT_ECHO, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Make suppress Go-Ahead telnet option. */
static void
vty_will_suppress_go_ahead (struct vty *vty)
{
  char cmd[] = { IAC, WILL, TELOPT_SGA, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Make don't use linemode over telnet. */
static void
vty_dont_linemode (struct vty *vty)
{
  char cmd[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
  vty_out (vty, "%s", cmd);
}

/* Use window size. */
static void
vty_do_window_size (struct vty *vty)
{
  char cmd[] = { IAC, DO, TELOPT_NAWS, '\0' };
  vty_out (vty, "%s", cmd);
}

#if 0 /* Currently not used. */
/* Make don't use lflow vty interface. */
static void
vty_dont_lflow_ahead (struct vty *vty)
{
  char cmd[] = { IAC, DONT, TELOPT_LFLOW, '\0' };
  vty_out (vty, "%s", cmd);
}
#endif /* 0 */

/* Allocate new vty struct. */
struct vty *
vty_new ()
{
  struct vty *new = XMALLOC (MTYPE_VTY, sizeof (struct vty));
  bzero (new, sizeof (struct vty));

  new->obuf = (struct buffer *) buffer_new (BUFFER_VTY, 100);
  new->buf = XMALLOC (MTYPE_VTY, VTY_BUFSIZ);
  new->max = VTY_BUFSIZ;

  return new;
}

/* Authentication of vty */
static void
vty_auth (struct vty *vty, char *buf)
{
  char *passwd = NULL;
  enum node_type next_node = 0;
  int fail;
  char *crypt (const char *, const char *);

  switch (vty->node)
    {
    case AUTH_NODE:
      if (host.encrypt)
	passwd = host.password_encrypt;
      else
	passwd = host.password;
      if (host.advanced)
	next_node = host.enable ? VIEW_NODE : ENABLE_NODE;
      else
	next_node = VIEW_NODE;
      break;
    case AUTH_ENABLE_NODE:
      if (host.encrypt)
	passwd = host.enable_encrypt;
      else
	passwd = host.enable;
      next_node = ENABLE_NODE;
      break;
    }

  if (passwd)
    {
      if (host.encrypt)
	fail = strcmp (crypt(buf, passwd), passwd);
      else
	fail = strcmp (buf, passwd);
    }
  else
    fail = 1;

  if (! fail)
    {
      vty->fail = 0;
      vty->node = next_node;	/* Success ! */
    }
  else
    {
      vty->fail++;
      if (vty->fail >= 3)
	{
	  if (vty->node == AUTH_NODE)
	    {
	      vty_out (vty, "%% Bad passwords, too many failures!\r\n");
	      vty->status = VTY_CLOSE;
	    }
	  else			
	    {
	      /* AUTH_ENABLE_NODE */
	      vty->fail = 0;
	      vty_out (vty, "%% Bad enable passwords, too many failures!\r\n");
	      vty->node = VIEW_NODE;
	    }
	}
    }
}

/* Command execution over the vty interface. */
static void
vty_command (struct vty *vty, char *buf)
{
  int ret;
  vector vline;

  /* Split readline string up into the vector */
  vline = cmd_make_strvec (buf);

  if (vline == NULL)
    return;

  ret = cmd_execute_command (vline, vty);

  if (ret != CMD_SUCCESS)
    switch (ret)
      {
      case CMD_WARNING:
	if (vty->type == VTY_FILE)
	  vty_out (vty, "Warning...\r\n");
	break;
      case CMD_ERR_AMBIGUOUS:
	vty_out (vty, "%% Ambiguous command.\r\n");
	break;
      case CMD_ERR_NO_MATCH:
	vty_out (vty, "%% Unknown command.\r\n");
	break;
      case CMD_ERR_INCOMPLETE:
	vty_out (vty, "%% Command incomplete.\r\n");
	break;
      }

  cmd_free_strvec (vline);
}

char telnet_backward_char = 0x08;
char telnet_space_char = ' ';

/* Basic function to write buffer to vty. */
static void
vty_write (struct vty *vty, char *buf, size_t nbytes)
{
  if ((vty->node == AUTH_NODE) || (vty->node == AUTH_ENABLE_NODE))
    return;

  /* Should we do buffering here ?  And make vty_flush (vty) ? */
  buffer_write (vty->obuf, (u_char *)buf, nbytes);
}

/* Ensure length of input buffer.  Is buffer is short, double it. */
static void
vty_ensure (struct vty *vty, int length)
{
  if (vty->max <= length)
    {
      vty->max *= 2;
      vty->buf = XREALLOC (MTYPE_VTY, vty->buf, vty->max);
    }
}

/* Basic function to insert character into vty. */
static void
vty_self_insert (struct vty *vty, char c)
{
  int i;
  int length;

  vty_ensure (vty, vty->length + 1);
  length = vty->length - vty->cp;
  memmove (&vty->buf[vty->cp + 1], &vty->buf[vty->cp], length);
  vty->buf[vty->cp] = c;

  vty_write (vty, &vty->buf[vty->cp], length + 1);
  for (i = 0; i < length; i++)
    vty_write (vty, &telnet_backward_char, 1);

  vty->cp++;
  vty->length++;
}

/* Self insert character 'c' in overwrite mode. */
static void
vty_self_insert_overwrite (struct vty *vty, char c)
{
  vty_ensure (vty, vty->length + 1);
  vty->buf[vty->cp++] = c;

  if (vty->cp > vty->length)
    vty->length++;

  if ((vty->node == AUTH_NODE) || (vty->node == AUTH_ENABLE_NODE))
    return;

  vty_write (vty, &c, 1);
}

/* Insert a word into vty interface with overwrite mode. */
static void
vty_insert_word_overwrite (struct vty *vty, char *str)
{
  int len = strlen (str);
  vty_write (vty, str, len);
  strcpy (&vty->buf[vty->cp], str);
  vty->cp += len;
  vty->length = vty->cp;
}

/* Forward character. */
static void
vty_forward_char (struct vty *vty)
{
  if (vty->cp < vty->length)
    {
      vty_write (vty, &vty->buf[vty->cp], 1);
      vty->cp++;
    }
}

/* Backward character. */
static void
vty_backward_char (struct vty *vty)
{
  if (vty->cp > 0)
    {
      vty->cp--;
      vty_write (vty, &telnet_backward_char, 1);
    }
}

/* Move to the beginning of the line. */
static void
vty_beginning_of_line (struct vty *vty)
{
  while (vty->cp)
    vty_backward_char (vty);
}

/* Move to the end of the line. */
static void
vty_end_of_line (struct vty *vty)
{
  while (vty->cp < vty->length)
    vty_forward_char (vty);
}

static void vty_kill_line_from_beginning (struct vty *);
static void vty_redraw_line (struct vty *);

/* Print command line history.  This function is called from
   vty_next_line and vty_previous_line. */
static void
vty_history_print (struct vty *vty)
{
  int length;

  vty_kill_line_from_beginning (vty);

  /* Get previous line from history buffer */
  length = strlen (vty->hist[vty->hp]);
  bcopy (vty->hist[vty->hp], vty->buf, length);
  vty->cp = vty->length = length;

  /* Redraw current line */
  vty_redraw_line (vty);
}

/* Show next command line history. */
void
vty_next_line (struct vty *vty)
{
  int try_index;

  if (vty->hp == vty->hindex)
    return;

  /* Try is there history exist or not. */
  try_index = vty->hp;
  if (try_index == (VTY_MAXHIST - 1))
    try_index = 0;
  else
    try_index++;

  /* If there is not history return. */
  if (vty->hist[try_index] == NULL)
    return;
  else
    vty->hp = try_index;

  vty_history_print (vty);
}

/* Show previous command line history. */
void
vty_previous_line (struct vty *vty)
{
  int try_index;

  try_index = vty->hp;
  if (try_index == 0)
    try_index = VTY_MAXHIST - 1;
  else
    try_index--;

  if (vty->hist[try_index] == NULL)
    return;
  else
    vty->hp = try_index;

  vty_history_print (vty);
}

/* This function redraw all of the command line character. */
static void
vty_redraw_line (struct vty *vty)
{
  vty_write (vty, vty->buf, vty->length);
  vty->cp = vty->length;
}

/* Forward word. */
static void
vty_forward_word (struct vty *vty)
{
  while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
    vty_forward_char (vty);
  
  while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
    vty_forward_char (vty);
}

/* Backward word without skipping training space. */
static void
vty_backward_pure_word (struct vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_backward_char (vty);
}

/* Backward word. */
static void
vty_backward_word (struct vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
    vty_backward_char (vty);

  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_backward_char (vty);
}

/* When '^D' is typed at the beginning of the line we move to the down
   level. */
static void
vty_down_level (struct vty *vty)
{
  vty_out (vty, "\r\n");
  config_exit (NULL, vty, 0, NULL);
  vty_prompt (vty);
  vty->cp = 0;
}

/* When '^Z' is received from vty, move down to the enable mode. */
static void
vty_end_config (struct vty *vty)
{
  vty_out (vty, "\r\n");

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
      /* Unknown node, we have to ignore it. */
      break;
    }

  vty_prompt (vty);
  vty->cp = 0;
}

/* Delete a charcter at the current point. */
static void
vty_delete_char (struct vty *vty)
{
  int i;
  int size;

  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    return;

  if (vty->length == 0)
    {
      vty_down_level (vty);
      return;
    }

  if (vty->cp == vty->length)
    return;			/* completion need here? */

  size = vty->length - vty->cp;

  vty->length--;
  memmove (&vty->buf[vty->cp], &vty->buf[vty->cp + 1], size - 1);
  vty->buf[vty->length] = '\0';

  vty_write (vty, &vty->buf[vty->cp], size - 1);
  vty_write (vty, &telnet_space_char, 1);

  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_backward_char, 1);
}

/* Delete a character before the point. */
static void
vty_delete_backward_char (struct vty *vty)
{
  if (vty->cp == 0)
    return;

  vty_backward_char (vty);
  vty_delete_char (vty);
}

/* Kill rest of line from current point. */
static void
vty_kill_line (struct vty *vty)
{
  int i;
  int size;

  size = vty->length - vty->cp;
  
  if (size == 0)
    return;

  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_space_char, 1);
  for (i = 0; i < size; i++)
    vty_write (vty, &telnet_backward_char, 1);

  bzero (&vty->buf[vty->cp], size);
  vty->length = vty->cp;
}

/* Kill line from the beginning. */
static void
vty_kill_line_from_beginning (struct vty *vty)
{
  vty_beginning_of_line (vty);
  vty_kill_line (vty);
}

/* Delete a word before the point. */
static void
vty_forward_kill_word (struct vty *vty)
{
  while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
    vty_delete_char (vty);
  while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
    vty_delete_char (vty);
}

/* Delete a word before the point. */
static void
vty_backward_kill_word (struct vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
    vty_delete_backward_char (vty);
  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_delete_backward_char (vty);
}

/* Transpose chars before or at the point. */
static void
vty_transpose_chars (struct vty *vty)
{
  char c1, c2;

  /* If length is short or point is near by the beginning of line then
     return. */
  if (vty->length < 2 || vty->cp < 1)
    return;

  /* In case of point is located at the end of the line. */
  if (vty->cp == vty->length)
    {
      c1 = vty->buf[vty->cp - 1];
      c2 = vty->buf[vty->cp - 2];

      vty_backward_char (vty);
      vty_backward_char (vty);
      vty_self_insert_overwrite (vty, c1);
      vty_self_insert_overwrite (vty, c2);
    }
  else
    {
      c1 = vty->buf[vty->cp];
      c2 = vty->buf[vty->cp - 1];

      vty_backward_char (vty);
      vty_self_insert_overwrite (vty, c1);
      vty_self_insert_overwrite (vty, c2);
    }
}

/* Do completion at vty interface. */
static void
vty_complete_command (struct vty *vty)
{
  int i;
  int ret;
  char **matched = NULL;
  vector vline;

  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
    return;

  vline = cmd_make_strvec (vty->buf);
  if (vline == NULL)
    return;

  /* In case of 'help \t'. */
  if (isspace (vty->buf[vty->length - 1]))
    vector_set (vline, '\0');

  matched = cmd_complete_command (vline, vty, &ret);
  
  cmd_free_strvec (vline);

  vty_out (vty, "\r\n");
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      vty_out (vty, "%% Ambiguous command.\r\n");
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_ERR_NO_MATCH:
      /* vty_out (vty, "%% There is no matched command.\r\n"); */
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_COMPLETE_FULL_MATCH:
      vty_prompt (vty);
      vty_redraw_line (vty);
      vty_backward_pure_word (vty);
      vty_insert_word_overwrite (vty, matched[0]);
      vty_self_insert (vty, ' ');
      break;
    case CMD_COMPLETE_MATCH:
      for (i = 0; matched[i] != NULL; i++)
	{
	  if (i != 0 && ((i % 6) == 0))
	    vty_out (vty, "\r\n");
	  vty_out (vty, "%-10s ", matched[i]);
	}
      vty_out (vty, "\r\n");

      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_ERR_NOTHING_TODO:
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    default:
      break;
    }
  if (matched)
    vector_only_index_free (matched);
}

/* Describe matched command function. */
static void
vty_describe_command (struct vty *vty)
{
  int ret;
  vector vline;
  vector describe;
  int i;
  struct desc *desc;

  vline = cmd_make_strvec (vty->buf);

  /* In case of '> ?'. */
  if (vline == NULL)
    {
      vline = vector_init (1);
      vector_set (vline, '\0');
    }
  else 
    if (isspace (vty->buf[vty->length - 1]))
      vector_set (vline, '\0');

  describe = cmd_describe_command (vline, vty, &ret);

  vty_out (vty, "\r\n");

  /* Ambiguous error. */
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      cmd_free_strvec (vline);
      vty_out (vty, "%% Ambiguous command.\r\n");
      vty_prompt (vty);
      vty_redraw_line (vty);
      return;
      break;
    case CMD_ERR_NO_MATCH:
      cmd_free_strvec (vline);
      vty_out (vty, "%% There is no matched command.\r\n");
      vty_prompt (vty);
      vty_redraw_line (vty);
      return;
      break;
    }  

  /* Print out description. */
  for (i = 0; i < vector_max (describe); i++)
    if ((desc = vector_slot (describe, i)) != NULL)
      {
	if (desc->cmd[0] == '\0')
	  continue;
	
	vty_out (vty, "  %-17s %s\r\n", 
		 desc->cmd[0] == '.' ? desc->cmd + 1 : desc->cmd,
		 desc->str ? desc->str : "");
      }

  cmd_free_strvec (vline);
  vector_free (describe);

  vty_prompt (vty);
  vty_redraw_line (vty);
}

void
vty_clear_buf (struct vty *vty)
{
  bzero (vty->buf, vty->max);
}

/* ^C stop current input and do not add command line to the history. */
static void
vty_stop_input (struct vty *vty)
{
  vty->cp = vty->length = 0;
  vty_clear_buf (vty);
  vty_out (vty, "\r\n");

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
      /* Unknown node, we have to ignore it. */
      break;
    }
  vty_prompt (vty);
}

/* Add current command line to the history buffer. */
static void
vty_hist_add (struct vty *vty)
{
  if (vty->length == 0)
    return;

  /* Insert history entry. */
  if (vty->hist[vty->hindex])
    XFREE (MTYPE_VTY_HIST, vty->hist[vty->hindex]);
  vty->hist[vty->hindex] = XSTRDUP (MTYPE_VTY_HIST, vty->buf);

  /* History index rotation. */
  vty->hindex++;
  if (vty->hindex == VTY_MAXHIST)
    vty->hindex = 0;

  vty->hp = vty->hindex;
}

/* #define TELNET_OPTION_DEBUG */

/* Get telnet window size. */
static int
vty_telnet_option (struct vty *vty, unsigned char *buf, int nbytes)
{
#ifdef TELNET_OPTION_DEBUG
  int i;

  for (i = 0; i < nbytes; i++)
    {
      switch (buf[i])
	{
	case IAC:
	  vty_out (vty, "IAC ");
	  break;
	case WILL:
	  vty_out (vty, "WILL ");
	  break;
	case WONT:
	  vty_out (vty, "WONT ");
	  break;
	case DO:
	  vty_out (vty, "DO ");
	  break;
	case DONT:
	  vty_out (vty, "DONT ");
	  break;
	case SB:
	  vty_out (vty, "SB ");
	  break;
	case SE:
	  vty_out (vty, "SE ");
	  break;
	case TELOPT_ECHO:
	  vty_out (vty, "TELOPT_ECHO \r\n");
	  break;
	case TELOPT_SGA:
	  vty_out (vty, "TELOPT_SGA \r\n");
	  break;
	case TELOPT_NAWS:
	  vty_out (vty, "TELOPT_NAWS \r\n");
	  break;
	default:
	  vty_out (vty, "%x ", buf[i]);
	  break;
	}
    }
  vty_out (vty, "\r\n");

#endif /* TELNET_OPTION_DEBUG */

  switch (buf[1])
    {
    case SB:
      if (buf[2] == TELOPT_NAWS)
	{
	  vty->width = buf[4];
	  vty->height = vty->lines >= 0 ? vty->lines : buf[6];
	  return 8;
	}
      break;
    default:
      break;
    }
  return 2;
}

/* Execute current command line. */
static void
vty_execute (struct vty *vty)
{
  switch (vty->node)
    {
    case AUTH_NODE:
    case AUTH_ENABLE_NODE:
      vty_auth (vty, vty->buf);
      break;
    default:
      vty_command (vty, vty->buf);
      vty_hist_add (vty);
      break;
    }

  /* Clear command line buffer. */
  vty->cp = vty->length = 0;
  vty_clear_buf (vty);

  if (vty->status != VTY_CLOSE)
    vty_prompt (vty);
}

#define CONTROL(X)  ((X) - '@')
#define VTY_NORMAL     0
#define VTY_PRE_ESCAPE 1
#define VTY_ESCAPE     2

/* Escape character command map. */
static void
vty_escape_map (unsigned char c, struct vty *vty)
{
  switch (c)
    {
    case ('A'):
      vty_previous_line (vty);
      break;
    case ('B'):
      vty_next_line (vty);
      break;
    case ('C'):
      vty_forward_char (vty);
      break;
    case ('D'):
      vty_backward_char (vty);
      break;
    default:
      break;
    }

  /* Go back to normal mode. */
  vty->escape = VTY_NORMAL;
}

/* Quit print out to the buffer. */
static void
vty_buffer_reset (struct vty *vty)
{
  buffer_reset (vty->obuf);
  vty_prompt (vty);
}

/* Read data via vty socket. */
static int
vty_read (struct thread *thread)
{
  int i;
  int ret;
  int nbytes;
  unsigned char buf[VTY_READ_BUFSIZ];

  int vty_sock = THREAD_FD (thread);
  struct vty *vty = THREAD_ARG (thread);
  vty->t_read = NULL;

  /* Read raw data from socket */
  nbytes = read (vty->fd, buf, VTY_READ_BUFSIZ);
  if (nbytes <= 0)
    vty->status = VTY_CLOSE;

  for (i = 0; i < nbytes; i++) 
    {
      if (vty->status == VTY_MORE)
	{
	  switch (buf[i])
	    {
	    case 'q':
	    case 'Q':
	      vty_buffer_reset (vty);
	      break;
	    default:
	      break;
	    }
	  continue;
	}

      /* Escape character. */
      if (vty->escape == VTY_ESCAPE)
	{
	  vty_escape_map (buf[i], vty);
	  continue;
	}

      /* Pre-escape status. */
      if (vty->escape == VTY_PRE_ESCAPE)
	{
	  switch (buf[i])
	    {
	    case '[':
	      vty->escape = VTY_ESCAPE;
	      break;
	    case 'b':
	      vty_backward_word (vty);
	      vty->escape = VTY_NORMAL;
	      break;
	    case 'f':
	      vty_forward_word (vty);
	      vty->escape = VTY_NORMAL;
	      break;
	    case 'd':
	      vty_forward_kill_word (vty);
	      vty->escape = VTY_NORMAL;
	      break;
	    case CONTROL('H'):
	      vty_backward_kill_word (vty);
	      vty->escape = VTY_NORMAL;
	      break;
	    default:
	      vty->escape = VTY_NORMAL;
	      break;
	    }
	  continue;
	}

      switch (buf[i])
	{
	case 0xff:
	  /* In case of telnet command */
	  ret = vty_telnet_option (vty, buf + i, nbytes - i);
	  i += ret;
	  break;
	case CONTROL('A'):
	  vty_beginning_of_line (vty);
	  break;
	case CONTROL('B'):
	  vty_backward_char (vty);
	  break;
	case CONTROL('C'):
	  vty_stop_input (vty);
	  break;
	case CONTROL('D'):
	  vty_delete_char (vty);
	  break;
	case CONTROL('E'):
	  vty_end_of_line (vty);
	  break;
	case CONTROL('F'):
	  vty_forward_char (vty);
	  break;
	case CONTROL('H'):
	case 0x7f:
	  vty_delete_backward_char (vty);
	  break;
	case CONTROL('K'):
	  vty_kill_line (vty);
	  break;
	case CONTROL('N'):
	  vty_next_line (vty);
	  break;
	case CONTROL('P'):
	  vty_previous_line (vty);
	  break;
	case CONTROL('T'):
	  vty_transpose_chars (vty);
	  break;
	case CONTROL('U'):
	  vty_kill_line_from_beginning (vty);
	  break;
	case CONTROL('W'):
	  vty_backward_kill_word (vty);
	  break;
	case CONTROL('Z'):
	  vty_end_config (vty);
	  break;
	case '\n':
	case '\r':
	  vty_out (vty, "\r\n");
	  vty_execute (vty);
	  break;
	case '\t':
	  vty_complete_command (vty);
	  break;
	case '?':
	  if (vty->node == AUTH_NODE || vty->node == AUTH_ENABLE_NODE)
	    vty_self_insert (vty, buf[i]);
	  else
	    vty_describe_command (vty);
	  break;
	case '\033':
	  if (i + 1 < nbytes && buf[i + 1] == '[')
	    {
	      vty->escape = VTY_ESCAPE;
	      i++;
	    }
	  else
	    vty->escape = VTY_PRE_ESCAPE;
	  break;
	default:
	  if (buf[i] > 31 && buf[i] < 127)
	    vty_self_insert (vty, buf[i]);
	  break;
	}
    }

  /* Check status. */
  if (vty->status == VTY_CLOSE)
    vty_close (vty);
  else
    {
      vty_event (VTY_WRITE, vty_sock, vty);
      vty_event (VTY_READ, vty_sock, vty);
    }
  return 0;
}

/* Flush buffer to the vty. */
static int
vty_flush (struct thread *thread)
{
  int erase;
  struct vty *vty = THREAD_ARG (thread);
  vty->t_write = NULL;

  if (vty->status == VTY_MORE)
    erase = 1;
  else
    erase = 0;

  if (vty->lines == 0)
    buffer_flush_all (vty->obuf, vty->fd);
  else
    buffer_flush_window (vty->obuf, vty->fd, vty->width, 
			 vty->lines >= 0 ? vty->lines : vty->height, erase);
  

  if (buffer_empty (vty->obuf))
    {
      if (vty->status == VTY_CLOSE)
	vty_close (vty);
      else
	vty->status = VTY_NORMAL;
    }
  else
    vty->status = VTY_MORE;

  return 0;
}

/* Create new vty structure. */
struct vty *
vty_create (int vty_sock, union sockunion *su)
{
  struct vty *vty;

  /* Allocate new vty structure and set up default values. */
  vty = vty_new ();
  vty->fd = vty_sock;
  vty->type = VTY_TERM;
  vty->address = sockunion_su2str (su);
  vty->node = AUTH_NODE;
  vty->fail = 0;
  vty->cp = 0;
  vty_clear_buf (vty);
  vty->length = 0;
  bzero (vty->hist, sizeof (vty->hist));
  vty->hp = 0;
  vty->hindex = 0;
  vector_set_index (vtyvec, vty_sock, vty);
  vty->status = VTY_NORMAL;
  vty->v_timeout = vty_timeout_val;
  if (host.lines >= 0)
    vty->lines = host.lines;
  else
    vty->lines = -1;

  /* Vty is not available if password isn't set. */
  if (host.password == NULL && host.password_encrypt == NULL)
    {
      vty_out (vty, "Vty password is not set.\r\n");
      vty->status = VTY_CLOSE;
      vty_close (vty);
      return NULL;
    }

  /* Say hello to the world. */
  vty_hello (vty);
  vty_out (vty, "\r\nUser Access Verification\r\n\r\n");

  /* Setting up terminal. */
  vty_will_echo (vty);
  vty_will_suppress_go_ahead (vty);

  vty_dont_linemode (vty);
  vty_do_window_size (vty);
  /* vty_dont_lflow_ahead (vty); */

  vty_prompt (vty);

  /* Add read/write thread. */
  vty_event (VTY_WRITE, vty_sock, vty);
  vty_event (VTY_READ, vty_sock, vty);

  return vty;
}

/* Accept connection from the network. */
static int
vty_accept (struct thread *thread)
{
  int vty_sock;
  struct vty *vty;
  union sockunion su;
  int ret;
  unsigned int on;
  int accept_sock;

  accept_sock = THREAD_FD (thread);
  memset (&su, 0, sizeof (union sockunion));

  /* We can handle IPv4 or IPv6 socket. */
  vty_sock = sockunion_accept (accept_sock, &su);
  if (vty_sock < 0)
    {
      zlog (NULL, LOG_INFO, "can't accept vty socket : %s", strerror (errno));
      exit (1);
    }

  /* Convert IPv4 compatible IPv6 address to IPv4 address. */
#ifdef HAVE_IPV6
  if (su.sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_V4MAPPED (&su.sin6.sin6_addr))
	{
	  struct sockaddr_in sin;

	  memset (&sin, 0, sizeof (struct sockaddr_in));
	  sin.sin_family = AF_INET;
	  memcpy (&sin.sin_addr, ((char *)&su.sin6.sin6_addr) + 12, 4);
	  memcpy (&su, &sin, sizeof (struct sockaddr_in));
	}
    }
#endif /* HAVE_IPV6 */

  /* VTY's accesslist apply. */
  if (vty_accesslist_name)
    {
      struct prefix *p = NULL;
      struct access_list *acl = NULL;
      
      p = sockunion2hostprefix (&su);

      if (! (acl = access_list_lookup (vty_accesslist_name)) ||
	  (access_list_apply (acl, p) != FILTER_PERMIT))
	{
	  char *buf;
	  zlog (NULL, LOG_INFO, "Vty connection refused from %s",
		(buf = sockunion_su2str (&su)));
	  free (buf);
	  close (vty_sock);
	  
	  /* continue accepting connections */
	  vty_event (VTY_SERV, accept_sock, NULL);
	  
	  prefix_free (p);

	  return 0;
	}
      prefix_free (p);
    }

  on = 1;
  ret = setsockopt (vty_sock, IPPROTO_TCP, TCP_NODELAY, 
		    (char *) &on, sizeof (on));
  if (ret < 0)
    zlog (NULL, LOG_INFO, "can't set sockopt to vty_sock : %s", 
	  strerror (errno));

  vty = vty_create (vty_sock, &su);

  /* We continue hearing vty socket. */
  vty_event (VTY_SERV, accept_sock, NULL);

  return 0;
}

#ifdef HAVE_IPV6
void
vty_serv_sock_addrinfo (unsigned short port)
{
  int ret;
  struct addrinfo req;
  struct addrinfo *ainfo;
  struct addrinfo *ainfo_save;
  int sock;
  char port_str[BUFSIZ];

  memset (&req, 0, sizeof (struct addrinfo));
  req.ai_flags = AI_PASSIVE;
  req.ai_family = AF_UNSPEC;
  req.ai_socktype = SOCK_STREAM;
  sprintf (port_str, "%d", port);

  ret = getaddrinfo (NULL, port_str, &req, &ainfo);

  if (ret != 0)
    {
      fprintf (stderr, "getaddrinfo failed: %s\n", strerror (errno));
      exit (1);
    }

  ainfo_save = ainfo;

  do
    {
      sock = socket (ainfo->ai_family, ainfo->ai_socktype, ainfo->ai_protocol);
      if (sock < 0)
	continue;

      sockopt_reuseaddr (sock);
      sockopt_reuseport (sock);

      ret = bind (sock, ainfo->ai_addr, ainfo->ai_addrlen);
      if (ret < 0)
	continue;

      ret = listen (sock, 3);
      if (ret < 0) 
	continue;

      vty_event (VTY_SERV, sock, NULL);
    }
  while ((ainfo = ainfo->ai_next) != NULL);

  freeaddrinfo (ainfo_save);
}
#endif /* HAVE_IPV6 */

/* Make vty server socket. */
void
vty_serv_sock_family (unsigned short port, int family)
{
  int ret;
  union sockunion su;
  int accept_sock;

  memset (&su, 0, sizeof (union sockunion));
  su.sa.sa_family = family;

  /* Make new socket. */
  accept_sock = sockunion_stream_socket (&su);

  /* This is server, so reuse address. */
  sockopt_reuseaddr (accept_sock);
  sockopt_reuseport (accept_sock);

  /* Bind socket to universal address and given port. */
  sockunion_bind (accept_sock, &su, port, NULL);

  /* Listen socket under queue 3. */
  ret = listen (accept_sock, 3);
  if (ret < 0) 
    {
      zlog (NULL, LOG_WARNING, "can't listen socket");
      return;
    }

  /* Add vty server event. */
  vty_event (VTY_SERV, accept_sock, NULL);
}

/* Determine address family to bind. */
void
vty_serv_sock (unsigned short port)
{
#ifdef HAVE_IPV6
  vty_serv_sock_addrinfo (port);
#else
  vty_serv_sock_family (port, AF_INET);
#endif /* HAVE_IPV6 */
}

/* Close vty interface. */
void
vty_close (struct vty *vty)
{
  int i;

  /* Cancel threads.*/
  if (vty->t_read)
    thread_cancel (vty->t_read);
  if (vty->t_write)
    thread_cancel (vty->t_write);
  if (vty->t_timeout)
    thread_cancel (vty->t_timeout);

  /* Flush buffer. */
  if (! buffer_empty (vty->obuf))
    buffer_flush_all (vty->obuf, vty->fd);

  /* Free input buffer. */
  buffer_free (vty->obuf);

  /* Free command history. */
  for (i = 0; i < VTY_MAXHIST; i++)
    if (vty->hist[i])
      XFREE (MTYPE_VTY_HIST, vty->hist[i]);

  /* Unset vector. */
  vector_unset (vtyvec, vty->fd);

  /* Close socket. */
  close (vty->fd);

  if (vty->address)
    XFREE (0, vty->address);
  if (vty->buf)
    XFREE (MTYPE_VTY, vty->buf);

  /* OK free vty. */
  XFREE (MTYPE_VTY, vty);
}

/* When time out occur output message then close connection. */
static int
vty_timeout (struct thread *thread)
{
  struct vty *vty;

  vty = THREAD_ARG (thread);
  vty->t_timeout = NULL;
  vty->v_timeout = 0;

  /* Clear buffer*/
  buffer_reset (vty->obuf);
  vty_out (vty, "\r\nVty connection is timed out.\r\n");

  /* Close connection. */
  vty->status = VTY_CLOSE;
  vty_close (vty);

  return 0;
}

/* Read up configuration file from file_name. */
static void
vty_read_file (FILE *confp)
{
  int ret;
  struct vty *vty;

  vty = vty_new ();
  vty->fd = 0;			/* stdout */
  vty->type = VTY_TERM;
  vty->node = CONFIG_NODE;
  
  /* Execute configuration file */
  ret = config_from_file (vty, confp);

  vty_close (vty);

  if (ret != CMD_SUCCESS) 
    {
      switch (ret)
	{
	case CMD_ERR_AMBIGUOUS:
	  fprintf (stderr, "Ambiguous command.\n");
	  break;
	case CMD_ERR_NO_MATCH:
	  fprintf (stderr, "There is no such command.\n");
	  break;
	}
      fprintf (stderr, "Error occured during reading below line.\n%s\n", 
	       vty->buf);
      exit (1);
    }
}

#ifndef DIRECTORY_SEP
#define DIRECTORY_SEP '/'
#endif /* DIRECTORY_SEP */

#ifndef IS_DIRECTORY_SEP
#define IS_DIRECTORY_SEP(c) ((c) == DIRECTORY_SEP)
#endif

/* Read up configuration file from file_name. */
void
vty_read_config (char *config_file, 
		 char *config_current_dir, 
		 char *config_default_dir)
{
  char *cwd;
  FILE *confp;
  char *fullpath;

  /* If -f flag specified. */
  if (config_file != NULL)
    {
      if (! IS_DIRECTORY_SEP (config_file[0]))
	{
	  cwd = getcwd (NULL, MAXPATHLEN);
	  fullpath = XMALLOC (MTYPE_TMP, 
				     strlen (cwd) + strlen (config_file) + 2);
	  sprintf (fullpath, "%s/%s", cwd, config_file);
	}
      else
	fullpath = config_file;

      confp = fopen (fullpath, "r");

      if (confp == NULL)
	{
	  fprintf (stderr, "can't open configuration file [%s]\n", 
		   config_file);
	  exit(1);
	}
    }
  else
    {
      /* Relative path configuration file open. */
      confp = fopen (config_current_dir, "r");

      /* If there is no relative path exists, open system default file. */
      if (confp == NULL)
	{
	  confp = fopen (config_default_dir, "r");
	  if (confp == NULL)
	    {
	      fprintf (stderr, "can't open configuration file [%s]\n",
		       config_default_dir);
	      exit (1);
	    }      
	  else
	    fullpath = config_default_dir;
	}
      else
	{
	  /* Rleative path configuration file. */
	  cwd = getcwd (NULL, MAXPATHLEN);
	  fullpath = XMALLOC (MTYPE_TMP, 
			      strlen (cwd) + strlen (config_current_dir) + 2);
	  sprintf (fullpath, "%s/%s", cwd, config_current_dir);
	}  
    }  
  vty_read_file (confp);

  fclose (confp);

  host_config_set (fullpath);
}

/* Master of the threads. */
/* extern struct thread_master *master; */
struct thread_master *master;

static void
vty_event (enum event event, int sock, struct vty *vty)
{
  switch (event)
    {
    case VTY_SERV:
      thread_add_read (master, vty_accept, vty, sock);
      break;
    case VTY_READ:
      vty->t_read = thread_add_read (master, vty_read, vty, sock);

      /* Time out treatment. */
      if (vty->v_timeout)
	{
	  if (vty->t_timeout)
	    thread_cancel (vty->t_timeout);
	  vty->t_timeout = 
	    thread_add_timer (master, vty_timeout, vty, vty->v_timeout);
	}
      break;
    case VTY_WRITE:
      vty->t_write = thread_add_write (master, vty_flush, vty, sock);
      break;
    }
}

/* Who is on vty ? This is only vty function exist in vty.c ;-) */
DEFUN (config_who,
       config_who_cmd,
       "who",
       "Display who is on vty\n")
{
  int i;
  struct vty *v;

  for (i = 0; i < vector_max (vtyvec); i++)
    if ((v = vector_slot (vtyvec, i)) != NULL)
      vty_out (vty, "vty[%d] connected from %s.\r\n", i, v->address);
  return CMD_SUCCESS;
}

/* Move to vty configuration mode. */
DEFUN (line_vty,
       line_vty_cmd,
       "line vty",
       "Configure vty\n"
       "Configure vty\n")
{
  vty->node = VTY_NODE;
  return CMD_SUCCESS;
}

/* Set time out value. */
DEFUN (exec_timeout,
       exec_timeout_cmd,
       "exec-timeout VAL",
       "Set timeout value\n"
       "Timeout value\n")
{
  if (all_digit (argv[0]))
    vty_timeout_val = strtol (argv[0], NULL, 10);
  else
    {
      vty_out (vty, "Invalid timeout value\r\n");
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/* Set vty access class. */
DEFUN (vty_access_class,
       vty_access_class_cmd,
       "access-class ACCESS-LIST",
       "Apply access list to vty\n"
       "Access list name\n")
{
  if (vty_accesslist_name)
    XFREE(MTYPE_VTY, vty_accesslist_name);

  vty_accesslist_name = XSTRDUP(MTYPE_VTY, argv[0]);

  return CMD_SUCCESS;
}

/* Clear vty access class. */
DEFUN (no_vty_access_class,
       no_vty_access_class_cmd,
       "no access-class [ACCESS-LIST]",
       NO_STR
       "Access list to remove from vty\n"
       "Access list name\n")
{
  if (!vty_accesslist_name || (argc && strcmp(vty_accesslist_name, argv[0])))
    {
      vty_out (vty, "Access-class not currently applied to vty%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  XFREE(MTYPE_VTY, vty_accesslist_name);

  vty_accesslist_name = NULL;

  return CMD_SUCCESS;
}

DEFUN (service_advanced_vty,
       service_advanced_vty_cmd,
       "service advanced-vty",
       "Set up miscellaneous service\n"
       "Enable advanced mode vty interface\n")
{
  host.advanced = 1;
  return CMD_SUCCESS;
}

DEFUN (no_service_advanced_vty,
       no_service_advanced_vty_cmd,
       "no service advanced-vty",
       NO_STR
       "Set up miscellaneous service\n"
       "Enable advanced mode vty interface\n")
{
  host.advanced = 0;
  return CMD_SUCCESS;
}

/* Display current configuration. */
int
vty_config_write (struct vty *vty)
{
  int write = 0;

  if ((vty_timeout_val != VTY_TIMEOUT_DEFAULT) || vty_accesslist_name)
    {
      vty_out (vty, "line vty%s", VTY_NEWLINE);

      if (vty_timeout_val != VTY_TIMEOUT_DEFAULT)
	vty_out (vty, " exec-timeout %d%s", vty_timeout_val, VTY_NEWLINE);
      if (vty_accesslist_name)
	vty_out (vty, " access-class %s%s", vty_accesslist_name, VTY_NEWLINE);

      write++;
    }
  return write;
}

struct cmd_node vty_node =
{
  VTY_NODE,
  "%s(config-vty)# ",
};

/* Install vty's own commands like `who' command. */
void
vty_init ()
{
  vtyvec = vector_init (VECTOR_MIN_SIZE);

  /* Install bgp top node. */
  install_node (&vty_node, vty_config_write);

  install_element (VIEW_NODE, &config_who_cmd);
  install_element (ENABLE_NODE, &config_who_cmd);
  install_element (CONFIG_NODE, &line_vty_cmd);
  install_element (CONFIG_NODE, &service_advanced_vty_cmd);
  install_element (CONFIG_NODE, &no_service_advanced_vty_cmd);

  install_default (VTY_NODE);
  install_element (VTY_NODE, &exec_timeout_cmd);
  install_element (VTY_NODE, &vty_access_class_cmd);
  install_element (VTY_NODE, &no_vty_access_class_cmd);
}
