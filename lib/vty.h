/*
 * $Id: vty.h,v 1.16 1999/02/19 17:01:50 developer Exp $
 *
 * Virtual terminal [aka TeletYpe] interface routine
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_VTY_H
#define _ZEBRA_VTY_H

#define VTY_BUFSIZ 512
#define VTY_MAXHIST 20

/* VTY struct. */
struct vty 
{
  /* File descripter of this vty. */
  int fd;

  /* Is this vty connect to file or not */
  enum {VTY_TERM, VTY_FILE} type;

  /* Node status of this vty */
  int node;

  /* What address is this vty comming from. */
  char *address;

  /* Privilege level of this vty. */
  int privilege;

  /* Fail count */
  int fail;

  /* Output buffer. */
  struct buffer *obuf;

  /* Command input buffer */
  char buf[VTY_BUFSIZ];

  /* Command cursor point */
  int cp;

  /* Command length */
  int length;

  /* Histry of command */
  char *hist[VTY_MAXHIST];

  /* History lookup current point */
  int hp;

  /* History insert end point */
  int hindex;

  /* For current referencing point of interface, route-map,
     access-list etc... */
  void *index;

  /* For escape character. */
  unsigned char escape;

  /* Current vty status. */
  enum { VTY_NORMAL, VTY_CLOSE, VTY_ERROR, VTY_MORE } status;

  /* Window width/height. */
  int width;
  int height;

  /* Current executing function pointer. */
  int (*func) (struct vty *, void *arg);

  /* Read and write thread. */
  struct thread *t_read;
  struct thread *t_write;

  /* Timeout seconds and thread. */
  unsigned long v_timeout;
  struct thread *t_timeout;
};

/* Small macro to determine newline is newline only or linefeed needed. */
#define VTY_NEWLINE  vty->type == VTY_FILE ? "\n" : "\r\n"

/* Default time out value */
/* #define VTY_TIMEOUT_DEFAULT 10 */
#define VTY_TIMEOUT_DEFAULT 300

/* Prototypes. */
struct vty *vty_new ();
int vty_out (struct vty *, char *, ...);
void vty_read_config (char *, char *, char *);
void vty_time_print (struct vty *);
void vty_serv_sock (unsigned short, int);
void vty_close (struct vty *);
void vty_init ();

#endif /* _ZEBRA_VTY_H */
