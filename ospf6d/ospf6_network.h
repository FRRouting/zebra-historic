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

#ifndef OSPF6_NETWORK_H
#define OSPF6_NETWORK_H

struct ospf6_prefix
{
  unsigned char  o6p_prefix_len;
  unsigned char  o6p_prefix_opt;
  unsigned short o6p_prefix_reserved;
  /* followed by one address_prefix */
};

/* size_t OSPF6_PREFIX_SPACE (int prefixlength); */
#define OSPF6_PREFIX_SPACE(x) ((((x) + 31) / 32) * 4)

/* size_t OSPF6_PREFIX_SIZE (struct ospf6_prefix *); */
#define OSPF6_PREFIX_SIZE(x) \
   (OSPF6_PREFIX_SPACE ((x)->o6p_prefix_len) + sizeof (struct ospf6_prefix))

/* struct ospf6_prefix *OSPF6_NEXT_PREFIX (struct ospf6_prefix *); */
#define OSPF6_NEXT_PREFIX(x) \
   ((struct ospf6_prefix *)((char *)(x) + OSPF6_PREFIX_SIZE (x)))



/* Function Prototypes */
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

int sockunion_ospf_socket (union sockunion *);
int sockfd_to_family (int);
int ospf6_recv (struct thread *);
int ospf6_serv_sock ();
int mcast_join (int, struct sockaddr *, char *, u_int);
int mcast_leave (int, struct sockaddr *, char *, u_int);
int ospf6_send (u_char, struct iovec *, struct sockaddr *, struct ospf6_if *);
int send_hello (struct thread *);
int send_database_description (struct thread *);
int send_linkstate_request (struct thread *);
int send_linkstate_update (struct thread *);
int send_linkstate_ack (struct thread *);

#endif /* OSPF6_NETWORK_H */

