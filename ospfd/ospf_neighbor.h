/*
 * OSPF Neighbor functions.
 * Copyright (C) 1999 Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_NEIGHBOR_H
#define _ZEBRA_OSPF_NEIGHBOR_H

/* Neighbor Data Structure */
struct ospf_neighbor
{
  /* This neighbor's parent ospf interface. */
  struct ospf_interface *oi;

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream *obuf;

  /* Neighbor related socket fd. */
  int fd;

  /* OSPF neighbor Information */
  char *host;				/* Printable address of the neighbor.*/
  u_char status;
  u_char master_slave;
  u_int32_t dd_sequence_number;
  u_int32_t last_received_db_desc;

  /* Neighbor Information from Hello. */
  struct in_addr router_id;
  u_char priority;
  struct prefix address;
  u_char options;
  struct in_addr d_router;
  struct in_addr bd_router;

  /* LSA data. */
  struct _list *link_state_retransmission;
  struct _list *database_summary;
  struct _list *link_state_request;

  /* Timer values. */
  u_int32_t v_inactivity;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_inactivity;

  /* Statistics Field */
};

/* Prototypes. */
struct ospf_neighbor *ospf_nbr_new ();

#endif /* _ZEBRA_OSPF_NEIGHBOR_H */
