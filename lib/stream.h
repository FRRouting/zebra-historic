/*
 * $Id: stream.h,v 1.7 1999/02/19 17:01:49 developer Exp $
 *
 * Packet interface
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_STREAM_H
#define _ZEBRA_STREAM_H

/* Stream buffer. */
struct stream
{
  struct stream *next;

  unsigned char *data;
  
  /* Current pointer. */
  unsigned long cp;

  /* Store pointer. */
  unsigned long sp;

  /* End of pointer. */
  unsigned long ep;

  unsigned long size;
};

/* First in first out queue structure. */
struct stream_fifo
{
  unsigned long count;

  struct stream *head;
  struct stream *tail;
};

/* Utility macros. */
#define STREAM_PNT(S)   ((S)->data + (S)->sp)
#define STREAM_SIZE(S)  ((S)->size)

/* Stream prototypes. */
struct stream *stream_new (size_t);
void stream_free (struct stream *);

int stream_putc (struct stream *, u_char);
int stream_putw (struct stream *, u_int16_t);
int stream_putl (struct stream *, u_int32_t);
int stream_put_ipv4 (struct stream *, u_int32_t);
void stream_memcpy (struct stream *, void *, size_t);
void stream_strncpy (void *, struct stream *, size_t);

int stream_putc_at (struct stream *s, unsigned long cp, u_char c);
int stream_putw_at (struct stream *s, unsigned long cp, u_int16_t w);

u_char stream_getc (struct stream *);
u_int16_t stream_getw (struct stream *);
u_int32_t stream_getl (struct stream *);
u_int32_t stream_get_ipv4 (struct stream *);

void stream_forward (struct stream *, int);
void stream_set_sp (struct stream *, unsigned long);

int stream_read (struct stream *, int, size_t);
int stream_write (struct stream *, u_char *, size_t);

u_char *stream_pnt (struct stream *);
void stream_set_cursor (struct stream *, unsigned long);
void stream_reset (struct stream *);
int stream_flush (struct stream *, int);
int stream_empty (struct stream *);

u_char *stream_get_data (struct stream *);
unsigned long stream_get_size (struct stream *);
unsigned long stream_get_cp (struct stream *);

/* Stream fifo. */
struct stream_fifo *stream_fifo_new ();
void stream_fifo_push (struct stream_fifo *fifo, struct stream *s);
struct stream *stream_fifo_pop (struct stream_fifo *fifo);
struct stream *stream_fifo_head (struct stream_fifo *fifo);
void stream_fifo_free (struct stream_fifo *fifo);

#endif /* _ZEBRA_STREAM_H */
