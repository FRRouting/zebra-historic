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

struct neighbor
{
  struct ospf6_interface     *ospf6_interface;
  unsigned char        state;
  struct thread       *inactivity_timer;
  struct thread       *send_lsreq;       /* Retransmit LSReq */
  struct thread       *send_update;      /* Retransmit LSUpdate */
  unsigned char        dd_bits;          /* including MASTER bit */
  unsigned long        seqnum;        /* DD sequence number */
  char                 str[16];          /* Router ID String */
  unsigned long        rtr_id;           /* Router ID of this neighbor */
  unsigned char        rtr_pri;          /* Router Priority of this neighbor */
  unsigned long        ifid;
  unsigned long        prevdr;
  unsigned long        dr;
  unsigned long        prevbdr;
  unsigned long        bdr;
  char                 options[3];     /* Link-LSA's options field */
  struct sockaddr_in6  hisaddr;        /* IPaddr of I/F on our side link   */
                                       /* , should be LinkLocal address    */
  struct ospf6_dbdesc last_dd;         /* last received DD , including     */
                                       /* OSPF capability of this neighbor */

  /* LSAs to retransmit to this neighbor */
  list dbdesc_lsa;

  /* LSA lists for this neighbor */
  list summarylist;
  list requestlist;
  list retranslist;

  /* new member for dbdesc */
  /* retransmission thread */
  struct thread *thread_dbdesc_retrans;        /* Retransmit DbDesc */
  struct iovec dbdesc_last_send[1024];   /* placeholder for DbDesc */
  struct thread *thread_lsreq_retrans;         /* Retransmit LsReq */

  /* statistics */
  unsigned int ospf6_stat_state_changed;
  unsigned int ospf6_stat_seqnum_mismatch;
  unsigned int ospf6_stat_bad_lsreq;
  unsigned int ospf6_stat_oneway_received;
  unsigned int ospf6_stat_inactivity_timer;
  unsigned int ospf6_stat_dr_election;
  unsigned int ospf6_stat_retrans_dbdesc;
  unsigned int ospf6_stat_retrans_lsreq;
  unsigned int ospf6_stat_retrans_lsupdate;
  unsigned int ospf6_stat_received_lsa;
  unsigned int ospf6_stat_received_lsupdate;
};
struct ospf6_neighbor
{
  struct ospf6_interface *ospf6_interface;
  u_char                  state;
  u_char        dd_bits;          /* including MASTER bit */
  u_int32_t     seqnum;        /* DD sequence number */
  char                 str[16];          /* Router ID String */
  u_int32_t        rtr_id;           /* Router ID of this neighbor */
  u_char        rtr_pri;          /* Router Priority of this neighbor */
  u_int32_t        ifid;
  u_int32_t        prevdr;
  u_int32_t        dr;
  u_int32_t        prevbdr;
  u_int32_t        bdr;
  char                 options[3];     /* Link-LSA's options field */
  struct sockaddr_in6  hisaddr;        /* IPaddr of I/F on our side link */
                                       /* Probably LinkLocal address     */
  struct ospf6_dbdesc last_dd; /* last received DD , including     */
                                       /* OSPF capability of this neighbor */

  /* LSAs to retransmit to this neighbor */
  list dbdesc_lsa;

  /* LSA lists for this neighbor */
  list summarylist;
  list requestlist;
  list retranslist;

  struct iovec dbdesc_last_send[1024];   /* placeholder for DbDesc */

  struct thread          *inactivity_timer;
  /* new member for dbdesc */
  /* retransmission thread */
  struct thread          *send_update;      /* Retransmit LSUpdate */
  struct thread *thread_dbdesc_retrans;        /* Retransmit DbDesc */
  struct thread *thread_lsreq_retrans;         /* Retransmit LsReq */

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

void ospf6_neighbor_vty_summary (struct vty *, struct ospf6_neighbor *);
void ospf6_neighbor_vty (struct vty *, struct ospf6_neighbor *);
void ospf6_neighbor_vty_detail (struct vty *, struct ospf6_neighbor *);

#endif /* OSPF6_NEIGHBOR_H */

