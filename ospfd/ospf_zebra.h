/*
 * Zebra connect library for OSPFd
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_ZEBRA_H
#define _ZEBRA_OSPF_ZEBRA_H

/* Zebra configuration structure. */
struct zebra
{
  int enable;
  int sock;
  int r_ospf;

  struct thread *t_read;
  struct thread *t_write;

  struct stream *ibuf;
} zebra;

/* Prototypes */
void ospf_zebra_get_interface (struct stream *, u_int16_t);
int zebra_read (struct thread *thread);
void zebra_init ();

#endif /* _ZEBRA_OSPF_ZEBRA_H */
