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
  u_char status;			/* NSM status. */
  u_char ms_flag;			/* Master/Slave bit flag. */
  u_int32_t dd_seqnum;			/* DD Sequence Number. */

  /* Neighbor Information from Hello. */
  struct prefix address;		/* Neighbor Interface Address. */

  struct in_addr router_id;		/* Router ID. */
  u_char options;			/* Options. */
  int priority;				/* Router Priority. */
  struct in_addr d_router;		/* Designated Router. */
  struct in_addr bd_router;		/* Backup Designated Router. */

  /* Last Received Databse Description packet. */
  u_char last_flags;
  u_char last_options;
  u_int32_t last_dd_seqnum;

  /* LSA data. */
  list ls_retransmission;
  list db_summary;
  list ls_request;

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
void ospf_nbr_free (struct ospf_neighbor *);
int ospf_nbr_bidirectional (struct in_addr *, struct in_addr *, int);
void ospf_nbr_add_myself (struct ospf_interface *);
int ospf_nbr_count (struct route_table *);
struct ospf_neighbor *ospf_nbr_lookup_by_router_id (struct route_table *, struct in_addr *);
int ospf_adjacent_count (struct route_table *);
int ospf_fully_adjacent_count (struct route_table *);

#endif /* _ZEBRA_OSPF_NEIGHBOR_H */
