/*
 * Copyright (C) 1999 Yasuhiro Ohara
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

#ifndef OSPF_NETWORK_H
#define OSPF_NETWORK_H

struct afswitch
{
  char *af_name;
  short af_af;
  int   ospf_sock;
  size_t salen;
  struct sockaddr *allspf;
  struct sockaddr *alldr;
};

struct ospf_prefix
{
  u_int8_t prefix_length;
  u_int8_t prefix_options;
  u_int16_t prefix_reserved;
  /* followed by address_prefix */
};

/* size_t PREFIX_SPACE (int prefixlength); */
#define PREFIX_SPACE(x) ((((x) + 31) / 32) * 4)
/* size_t PREFIX_SIZE (struct prefix *); meaning real (sizeof (struct prefix)) */
#define PREFIX_SIZE(x)  ((PREFIX_SPACE ((x)->prefix_length)) + sizeof (struct prefix))
/* struct prefix *NEXT_PREFIX (struct prefix *); */
#define NEXT_PREFIX(x)   ((struct prefix *)((char *)(x) + PREFIX_SIZE (x)))

int iov_clear (struct iovec *iov, size_t iovlen);
int iov_count (struct iovec *iov);
int iov_index (struct iovec *iov, void *base);
int iov_totallen (struct iovec *iov);
void *iov_prepend (int mtype, struct iovec *iov, size_t len);
void *iov_append (int mtype, struct iovec *iov, size_t len);
void *iov_realloc (int mtype, struct iovec *iov, u_int index, size_t len);
void *iov_attach_last (struct iovec *iov, void *base, size_t len);
void *iov_attach_first (struct iovec *iov, void *base, size_t len);
int iov_free (int mtype, struct iovec *iov, u_int begin, u_int end);

int send_database_description (struct thread *);
int send_linkstate_request (struct thread *);
int send_linkstate_update (struct thread *);
int send_linkstate_ack (struct thread *);

int ospf_send (u_int8_t, struct iovec *, struct sockaddr *, struct interface *);
void ospf_terminate ();
int ospf_serv_sock ();

int mcast_prepare ();
int mcast_join (int, struct sockaddr *, size_t, char *, u_int);
int mcast_leave (int, struct sockaddr *, size_t, char *, u_int);

#endif /* OSPF_NETWORK_H */
