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

#ifndef OSPF6_NEIGHBOR_H
#define OSPF6_NEIGHBOR_H

struct ospf6_neighbor
{
  /* OSPFv3 Interface this neighbor belongs to */
  struct ospf6_interface *ospf6_interface;

  /* Neighbor state */
  u_char state;

  /* including MASTER bit */
  u_char dd_bits;

  /* DD sequence number */
  u_int32_t seqnum;

  /* Neighbor Router ID String */
  char str[16];

  /* Neighbor Router ID */
  u_int32_t rtr_id;

  /* Router Priority of this neighbor */
  u_char rtr_pri;

  u_int32_t ifid;
  u_int32_t dr;
  u_int32_t bdr;
  u_int32_t prevdr;
  u_int32_t prevbdr;

  /* Link-LSA's options field */
  char options[3];

  /* IPaddr of I/F on our side link */
  struct in6_addr hisaddr;

  /* last received DD , including OSPF capability of this neighbor */
  struct ospf6_dbdesc last_dd;

  /* LSAs to retransmit to this neighbor */
  list dbdesc_lsa;

  /* LSA lists for this neighbor */
  list summarylist;
  list requestlist;
  list retranslist;

  /* placeholder for DbDesc */
  struct iovec dbdesc_last_send[1024];

  struct thread          *inactivity_timer;
  /* new member for dbdesc */
  /* retransmission thread */

  /* Retransmit LSUpdate */
  struct thread *send_update;

  /* Retransmit DbDesc */
  struct thread *thread_dbdesc;

  /* Retransmit LsReq */
  struct thread *thread_rxmt_lsreq;

  /* statistics */
  u_int ospf6_stat_state_changed;
  u_int ospf6_stat_seqnum_mismatch;
  u_int ospf6_stat_bad_lsreq;
  u_int ospf6_stat_oneway_received;
  u_int ospf6_stat_inactivity_timer;
  u_int ospf6_stat_dr_election;
  u_int ospf6_stat_retrans_dbdesc;
  u_int ospf6_stat_retrans_lsreq;
  u_int ospf6_stat_retrans_lsupdate;
  u_int ospf6_stat_received_lsa;
  u_int ospf6_stat_received_lsupdate;

  struct timeval tv_last_hello_received;
};


/* Function Prototypes */
int
ospf6_neighbor_last_dbdesc_release (struct thread *);

struct ospf6_lsa *
ospf6_neighbor_dbdesc_lsa_lookup (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_dbdesc_lsa_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_dbdesc_lsa_remove (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_dbdesc_lsa_remove_all (struct ospf6_neighbor *);

struct ospf6_lsa *
ospf6_neighbor_summary_lookup (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_summary_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_summary_remove (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_summary_remove_all (struct ospf6_neighbor *);

struct ospf6_lsa *
ospf6_neighbor_request_lookup (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_request_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_request_remove (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_request_remove_all (struct ospf6_neighbor *);

struct ospf6_lsa *
ospf6_neighbor_retrans_lookup (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_retrans_add (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_retrans_remove (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_neighbor_retrans_remove_all (struct ospf6_neighbor *);

void
ospf6_neighbor_thread_cancel_all (struct ospf6_neighbor *);
void
ospf6_neighbor_list_remove_all (struct ospf6_neighbor *);

struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t);

void
ospf6_neighbor_delete (struct ospf6_neighbor *);

struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t, struct ospf6_interface *);

void ospf6_neighbor_show_summary (struct vty *, struct ospf6_neighbor *);
void ospf6_neighbor_show (struct vty *, struct ospf6_neighbor *);
void ospf6_neighbor_show_detail (struct vty *, struct ospf6_neighbor *);

#endif /* OSPF6_NEIGHBOR_H */

