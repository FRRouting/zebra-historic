/*
 * Additional zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

/* Structure for the zebra client. */
struct zebra
{
  /* Flag of communication to zebra is enabled or not.  Default is on. */
  int enable;

  /* Socket to zebra daemon. */
  int sock;

  /* Read and write thread. */
  struct thread *t_read;
  struct thread *t_write;

  /* Input buffer for zebra message. */
  struct stream *ibuf;

  /* Redistribute information. */
  u_char redist_default;
  u_char redist[ZEBRA_ROUTE_MAX];

  /* Pointer to the functions. */
  int (*ipv4_route_add) (int, struct zebra *, zebra_size_t);
  int (*ipv4_route_delete) (int, struct zebra *, zebra_size_t);
  int (*ipv6_route_add) (int, struct zebra *, zebra_size_t);
  int (*ipv6_route_delete) (int, struct zebra *, zebra_size_t);
  int (*get_all_interface) (int, struct zebra *, zebra_size_t);
};

struct zebra *zebra_new ();
int zebra_create (struct zebra *);

#endif /* _ZEBRA_ZCLIENT_H */
