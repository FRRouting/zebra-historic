/*
 * $Id: stream.c,v 1.10 1999/02/20 16:05:34 developer Exp $
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

#include <zebra.h>

#include "stream.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"

/* Stream is fixed length buffer for network output/input. */

/* Make stream buffer. */
struct stream *
stream_new (size_t size)
{
  struct stream *s;

  s = XMALLOC (MTYPE_STREAM, sizeof (struct stream));
  bzero (s, sizeof (struct stream));

  s->data = XMALLOC (MTYPE_STREAM_DATA, size);
  s->size = size;
  return s;
}

/* Free it now. */
void
stream_free (struct stream *s)
{
  XFREE (MTYPE_STREAM_DATA, s->data);
  XFREE (MTYPE_STREAM, s);
}

/* Stream structre' stream pointer related functions.  */
void
stream_set_sp (struct stream *s, unsigned long pos)
{
  s->sp = pos;
}

/* Get next character from the stream. */
u_char
stream_getc (struct stream *s)
{
  u_char c;

  c = s->data[s->sp];
  s->sp++;
  return c;
}

/* Get next word from the stream. */
u_int16_t
stream_getw (struct stream *s)
{
  u_int16_t w;

  w = s->data[s->sp++] << 8;
  w |= s->data[s->sp++];
  return w;
}

/* Get next long word from the stream. */
u_int32_t
stream_getl (struct stream *s)
{
  u_int32_t l;

  l  = s->data[s->sp++] << 24;
  l |= s->data[s->sp++] << 16;
  l |= s->data[s->sp++] << 8;
  l |= s->data[s->sp++];
  return l;
}

/* Get next long word from the stream. */
u_int32_t
stream_get_ipv4 (struct stream *s)
{
  u_int32_t l;

  memcpy (&l, s->data + s->sp, 4);
  s->sp += 4;

  return l;
}

/* Forward pointer. */
void
stream_forward (struct stream *s, int size)
{
  s->sp += size;
}

unsigned long
stream_get_cp (struct stream *s)
{
  return s->cp;
}

void
stream_set_cursor (struct stream *s, unsigned long pos)
{
  s->cp = pos;
}

/* Put character to the stream. */
int
stream_putc (struct stream *s, u_char c)
{
  s->data[s->cp] = c;
  s->cp++;
  if (s->cp > s->ep)
    s->ep = s->cp;
  return 1;
}

/* Put word to the stream. */
int
stream_putw (struct stream *s, u_int16_t w)
{
  s->data[s->cp++] = (u_char)(w >>  8);
  s->data[s->cp++] = (u_char) w;

  if (s->cp > s->ep)
    s->ep = s->cp;
  return 2;
}

/* Put long word to the stream. */
int
stream_putl (struct stream *s, u_int32_t l)
{
  s->data[s->cp++] = (u_char)(l >> 24);
  s->data[s->cp++] = (u_char)(l >> 16);
  s->data[s->cp++] = (u_char)(l >>  8);
  s->data[s->cp++] = (u_char)l;

  if (s->cp > s->ep)
    s->ep = s->cp;
  return 4;
}

int
stream_putc_at (struct stream *s, unsigned long cp, u_char c)
{
  s->data[cp] = c;
  return 1;
}

int
stream_putw_at (struct stream *s, unsigned long cp, u_int16_t w)
{
  s->data[cp] = (u_char)(w >>  8);
  s->data[cp + 1] = (u_char) w;

  return 2;
}

void
stream_memcpy (struct stream *s, void *src, size_t size)
{
  memcpy (s->data + s->cp, src, size);
  s->cp += size;
  if (s->cp > s->ep)
    s->ep = s->cp;
}

void
stream_strncpy (void *dst, struct stream *s, size_t size)
{
  strncpy (dst, s->data + s->sp, size);

  s->sp += size;
  if (s->cp > s->ep)
    s->ep = s->cp;
}

/* Put long word to the stream. */
int
stream_put_ipv4 (struct stream *s, u_int32_t l)
{
  memcpy (s->data + s->cp, &l, 4);
  s->cp += 4;

  if (s->cp > s->ep)
    s->ep = s->cp;
  return 4;
}

/* Put prefix by nlri type format. */
int
stream_put_prefix (struct stream *s, struct prefix *p)
{
  u_char psize;

  psize = PSIZE (p->prefixlen);

  stream_putc (s, p->prefixlen);
  memcpy (s->data + s->cp, &p->u.prefix, psize);
  s->cp += psize;
  
  if (s->cp > s->ep)
    s->ep = s->cp;

  return psize;
}

/* Read size from fd. */
int
stream_read (struct stream *s, int fd, size_t size)
{
  int nbytes;

  nbytes = readn (fd, s->data + s->cp, size);

  if (nbytes > 0)
    {
      s->cp += nbytes;
      s->ep += nbytes;
    }
  return nbytes;
}

/* Write data to buffer. */
int
stream_write (struct stream *s, u_char *ptr, size_t size)
{
  memcpy (s->data + s->cp, ptr, size);
  s->cp += size;
  if (s->cp > s->ep)
    s->ep = s->cp;
  return size;
}

/* Return current read pointer. */
u_char *
stream_pnt (struct stream *s)
{
  return s->data + s->sp;
}

/* Check does this stream empty? */
int
stream_empty (struct stream *s)
{
  if (s->cp == 0 && s->ep == 0 && s->sp == 0)
    return 1;
  else
    return 0;
}

/* Reset stream. */
void
stream_reset (struct stream *s)
{
  s->cp = 0;
  s->ep = 0;
  s->sp = 0;
}

u_char *
stream_get_data (struct stream *s)
{
  return s->data;
}

unsigned long
stream_get_size (struct stream *s)
{
  return s->size;
}

/* Write stream contens to the file discriptor. */
int
stream_flush (struct stream *s, int fd)
{
  int nbytes;

  nbytes = write (fd, s->data + s->sp, s->ep - s->sp);

  return nbytes;
}

/* Stream first in first out queue. */

struct stream_fifo *
stream_fifo_new ()
{
  struct stream_fifo *new;
 
  new = XMALLOC (MTYPE_STREAM_FIFO, sizeof (struct stream_fifo));
  bzero (new, sizeof (struct stream_fifo)); 
  return new;
}

/* Add new stream to fifo. */
void
stream_fifo_push (struct stream_fifo *fifo, struct stream *s)
{
  if (fifo->tail)
    fifo->tail->next = s;
  else
    fifo->head = s;
     
  fifo->tail = s;

  fifo->count++;
}

/* Delete first stream from fifo. */
struct stream *
stream_fifo_pop (struct stream_fifo *fifo)
{
  struct stream *s;
  
  s = fifo->head; 

  if (s)
    { 
      fifo->head = s->next;

      if (fifo->head == NULL)
	fifo->tail = NULL;
    }

  fifo->count--;

  return s; 
}

/* Return first fifo entry. */
struct stream *
stream_fifo_head (struct stream_fifo *fifo)
{
  return fifo->head;
}

void
stream_fifo_free (struct stream_fifo *fifo)
{
  struct stream *s;
  struct stream *next;

  for (s = fifo->head; s; s = next)
    {
      next = s->next;
      stream_free (s);
    }
}
