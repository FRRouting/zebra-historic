/*
 * $Id: buffer.c,v 1.45 1999/02/19 17:01:47 developer Exp $
 *
 * Buffering of output and input. 
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include "memory.h"
#include "buffer.h"
#include "roken.h"

/* Make buffer data. */
struct buffer_data *
buffer_data_new (size_t size)
{
  struct buffer_data *d;

  d = XMALLOC (MTYPE_BUFFER_DATA, sizeof (struct buffer_data));
  bzero (d, sizeof (struct buffer_data));

  d->cp = 0;
  d->sp = 0;
  d->ep = 0;
  d->data = XMALLOC (MTYPE_BUFFER_DATA, size);

  return d;
}

void
buffer_data_free (struct buffer_data *d)
{
  if (d->data)
    XFREE (MTYPE_BUFFER_DATA, d->data);
  XFREE (MTYPE_BUFFER_DATA, d);
}

/* Make new buffer. */
struct buffer *
buffer_new (int type, size_t size)
{
  struct buffer *b;

  b = XMALLOC (MTYPE_BUFFER, sizeof (struct buffer));
  bzero (b, sizeof (struct buffer));

  b->type = type;
  b->size = size;

  /* In case of BUFFER_STREAM, allocate buffer at first time. */
  if (type == BUFFER_STREAM)
    b->head = b->tail = buffer_data_new (size);
  else
    b->head = b->tail = NULL;

  return b;
}

/* Free buffer. */
void
buffer_free (struct buffer *b)
{
  struct buffer_data *d;
  struct buffer_data *next;

  d = b->head;
  while (d)
    {
      next = d->next;
      buffer_data_free (d);
      d = next;
    }
  XFREE (MTYPE_BUFFER, b);
}

/* Make string clone. */
char *
buffer_getstr (struct buffer *b)
{
  return strdup ((char *)b->head->data);
}

/* Return 1 if buffer is empty. */
int
buffer_empty (struct buffer *b)
{
  if (b->rhead == NULL || (b->rhead == b->head && b->rhead->cp == 0))
    return 1;
  else
    return 0;
}

void
buffer_reset (struct buffer *b)
{
  struct buffer_data *d;
  
  for (d = b->head; d; d = d->next)
    d->sp = d->cp = d->ep = 0;

  b->rhead = b->whead = b->head;
}

/* Add buffer_data to the end of buffer. */
void
buffer_add (struct buffer *b)
{
  struct buffer_data *d;

  d = buffer_data_new (b->size);

  if (b->tail == NULL)
    {
      d->prev = NULL;
      d->next = NULL;
      b->head = d;
      b->tail = d;
      b->rhead = d;
      b->whead = d;
    }
  else
    {
      d->prev = b->tail;
      d->next = NULL;

      b->tail->next = d;
      b->tail = d;
    }

  b->alloc++;
}

/* Write data to buffer. */
int
buffer_write (struct buffer *b, u_char *ptr, size_t size)
{
  struct buffer_data *d;

  d = b->whead;

  /* If there is no data buffer add it. */
  if (d == NULL)
    {
      buffer_add (b);
      d = b->whead;
    }

  /* We use even last one byte of data buffer. */
  while (size)    
    {
      /* Last data. */
      if (size < (b->size - d->ep))
	{
	  memcpy ((d->data + d->cp), ptr, size);
	  d->cp += size;
	  if (d->cp > d->ep)
	    d->ep = d->cp;
	  size = 0;
	}
      else
	{
	  /* If current data buffer can't contain all of data. Make
             link list of data buffer and store data to there. */
	  memcpy ((d->data + d->cp), ptr, (b->size - d->ep));

	  size -= (b->size - d->ep);
	  ptr += (b->size - d->ep);

	  d->cp += (b->size - d->ep);
	  if (d->cp > d->ep)
	    d->ep = d->cp;

	  if (d->next)
	    {
	      d = d->next;
	      b->whead = d;
	    }
	  else
	    buffer_add (b);
	  d = b->whead;
	}
    }
  return 1;
}

/* Insert character into the buffer. */
int
buffer_putc (struct buffer *b, u_char c)
{
  struct buffer_data *d = b->tail;

  d->data[d->cp] = c;
  d->cp++;
  d->ep++;
  return 1;
}

/* Insert word (2 octets) into ther buffer. */
int
buffer_putw (struct buffer *b, u_short c)
{
  struct buffer_data *d = b->tail;

  memcpy (d->data, &c, 2);

  d->cp += 2;
  d->ep += 2;
  return 1;
}

/* Put string to the buffer. */
int
buffer_putstr (struct buffer *b, u_char *c)
{
  size_t size;

  size = strlen ((char *)c);
  buffer_write (b, c, size);
  return 1;
}

#define DATA_SIZE(D)  ((D)->ep - (D)->sp)
#define DATA_PNT(D)   ((D)->data + (D)->sp)

/* Flush specified size to the fd. */
void
buffer_flush (struct buffer *b, int fd, size_t size)
{
  struct buffer_data *d;
  int iov_index;
  struct iovec *iovec;

  iovec = malloc (sizeof (struct iovec) * b->alloc);
  iov_index = 0;

  for (d = b->head; d; d = d->next)
    {
      iovec[iov_index].iov_base = (char *)DATA_PNT(d);
      if (size <= DATA_SIZE (d))
	{
	  iovec[iov_index].iov_len = size;
	  d->sp += size;
	  iov_index++;
	  break;
	}
      else
	{
	  iovec[iov_index].iov_len = DATA_SIZE (d);
	  size -= DATA_SIZE (d);
	}
      iov_index++;
    }
  writev (fd, iovec, iov_index);

  free (iovec);
}

/* Flush all buffer to the fd. */
int
buffer_flush_all (struct buffer *b, int fd)
{
  int ret;
  struct buffer_data *d;
  int iov_index;
  struct iovec *iovec;

  if (buffer_empty (b))
    return 0;

  iovec = malloc (sizeof (struct iovec) * b->alloc);
  iov_index = 0;

  for (d = b->head; d; d = d->next)
    {
      iovec[iov_index].iov_base = (char *)d->data + d->sp;
      iovec[iov_index].iov_len = d->ep - d->sp;
      iov_index++;
    }
  ret = writev (fd, iovec, iov_index);

  free (iovec);
  buffer_reset (b);

  return ret;
}

/* Flush buffer to the file descriptor.  Mainly used from vty
   interface. */
int
buffer_flush_vty (struct buffer *b, int fd, int length, int erase_flag)
{
  int nbytes;
  int iov_index;
  struct iovec *iov;
  struct iovec small_iov[3];
  char more[] = " --More-- ";
  char erase[] = { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
		   ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		   0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08};
  struct buffer_data *d;

  /* For erase and more data add two to b's buffer_data count.*/
  if (b->alloc == 1)
    iov = small_iov;
  else
    iov = XMALLOC (MTYPE_TMP, sizeof (struct iovec) * (b->alloc + 2));

  d = b->rhead;
  iov_index = 0;

  /* Previously print out is performed. */
  if (erase_flag)
    {
      iov[iov_index].iov_base = erase;
      iov[iov_index].iov_len = sizeof erase;
      iov_index++;
    }

  /* Real data. */
  while (length && d)
    {
      if (length <= DATA_SIZE (d))
	{
	  iov[iov_index].iov_base = (char *) DATA_PNT (d);
	  iov[iov_index].iov_len = length;
	  iov_index++;

	  d->sp += length;
	  break;
	}
      else
	{
	  iov[iov_index].iov_base = (char *) DATA_PNT (d);
	  iov[iov_index].iov_len = DATA_SIZE(d);
	  iov_index++;

	  length -= DATA_SIZE (d);
	  d->sp += DATA_SIZE (d);
	}
      
      if (d->sp == d->ep)
	{
	  d->cp = 0;
	  d->sp = 0;
	  d->ep = 0;
	  d = d->next;
	  b->rhead = d;
	}
    }

  /* In case of `more' display need. */
  if (buffer_empty (b))
    {
      b->rhead = b->head;
      b->whead = b->head;
    }
  else
    {
      iov[iov_index].iov_base = more;
      iov[iov_index].iov_len = sizeof more;
      iov_index++;
    }

  /* We use write or writev*/
  nbytes = writev (fd, iov, iov_index);

  /* Error treatment. */
  if (nbytes < 0)
    {
      if (errno == EINTR)
	;
      if (errno == EWOULDBLOCK)
	;
    }
  if (b->alloc != 1)
    XFREE (MTYPE_TMP, iov);

  return nbytes;
}

/* Calculate size of outputs then flush buffer to the file
   descriptor. */
int
buffer_flush_window (struct buffer *b, int fd, int width, int height, 
		     int erase)
{
  unsigned long cp;
  unsigned long length;
  int lp;
  int lineno;
  int ret;
  struct buffer_data *d = b->rhead;

  if (height >= 2)
    height--;

  /* We have to calculate how many bytes should be written. */
  lp = 0;
  lineno = 0;
  length = 0;
  
  while (d && d->ep)
    {
      cp = d->sp;

      while (cp <= d->ep)
	{
	  if (d->data[cp] == '\n')
	    {
	      lineno++;
	      if (lineno == height)
		{
		  cp++;
		  length++;
		  goto flush;
		}
	      lp = 0;
	    }
	  else if (lp == width)
	    {
	      lineno++;
	      if (lineno == height)
		{
		  cp++;
		  length++;
		  goto flush;
		}
	      lp = 0;
	    }
	  lp++;
	  length++;
	  cp++;
	}
#ifdef DEBUG
      printf ("(cp:%ld ep:%ld lp:%d length:%ld lineno:%d)\n", 
	      cp, d->ep, lp, length, lineno);
#endif /* DEBUG */

      if (d->ep == b->size)
	{
	  length--;
	  lp--;
	}
      d = d->next;
    }

  /* Write data to the file descriptor. */
 flush:
#ifdef DEBUG
  printf ("cp:%ld lp:%d length:%ld ineno:%d\n",
	  cp, lp, length, lineno);
#endif /* DEBUG */

  ret = buffer_flush_vty (b, fd, length, erase);

  return ret;
}

void
buffer_debug (struct buffer *b)
{
  printf ("alloc %ld\n", b->alloc);
}

#ifdef TEST
main ()
{
  struct buffer *b;
  char kuni[] = "kunihi\n";

  b = buffer_new (BUFFER_VTY, 10);
  buffer_write (b, kuni, sizeof kuni);
  buffer_write (b, kuni, sizeof kuni);
  buffer_write (b, kuni, sizeof kuni);

  buffer_debug (b);

  buffer_flush (b, 0, 11);
  printf ("\n");
  buffer_flush_all (b, 0);
}
#endif /* TEST */
