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
  struct ospf6_if     *ospf6_if;
  unsigned char        state;
  struct thread       *inactivity_timer;
  struct thread       *send_dd;          /* Retransmit DD */
  struct thread       *send_lsreq;       /* Retransmit LSReq */
  struct thread       *send_update;      /* Retransmit LSUpdate */
  unsigned char        dd_bits;          /* including MASTER bit */
  unsigned long        dd_seqnum;        /* DD sequence number */
  char                 str[16];          /* Router ID String */
  unsigned long        rtr_id;           /* Router ID of this neighbor */
  unsigned char        rtr_pri;          /* Router Priority of this neighbor */
  unsigned long        ifid;
  unsigned long        prevdr;
  unsigned long        dr;
  unsigned long        prevbdr;
  unsigned long        bdr;
  struct sockaddr_in6  hisaddr;        /* IPaddr of I/F on our side link */
                                       /* Probably LinkLocal address     */
  struct database_description last_dd; /* last received DD , including     */
                                       /* OSPF capability of this neighbor */

  /* LSAs to retransmit to this neighbor */
  list dd_retrans;
  list direct_ack;  /* we will retrans in the case of direct ack. */

  /* LSA lists for this neighbor */
  list summarylist;
  list retranslist;
  list requestlist;

  /* new member for dbdesc */
  struct thread *thread_dbdesc_retrans;
  struct iovec dbdesc_last_send[MAXIOVLIST];
};

/* Neighbor state */
#define NBS_DOWN     1
#define NBS_ATTEMPT  2
#define NBS_INIT     3
#define NBS_TWOWAY   4
#define NBS_EXSTART  5
#define NBS_EXCHANGE 6
#define NBS_LOADING  7
#define NBS_FULL     8



/* Function Prototypes */

int nbs_change (state_t, char *, struct neighbor *);
int nbs_full_change (struct ospf6_if *);
int neighbor_thread_cancel (struct neighbor *);
int list_cleared_of_lsa (struct neighbor *);
int free_last_dd (struct thread *);
int need_adjacency (struct neighbor *);

void delete_ospf6_nbr (struct neighbor *);

/* Neighbor event */
int hello_received (struct thread *);
int twoway_received (struct thread *);
int negotiation_done (struct thread *);
int exchange_done (struct thread *);
int loading_done (struct thread *);
int adj_ok (struct thread *);
int seqnumber_mismatch (struct thread *);
int bad_lsreq (struct thread *);
int oneway_received (struct thread *);
int inactivity_timer (struct thread *);

int dr_election (struct ospf6_if *);

unsigned int count_nbr_in_state (state_t, struct area *);

void
ospf6_ipv4_nexthop_from_linklocal (struct in6_addr *,
                                        struct in_addr *,
                                        u_int);

#endif /* OSPF6_NEIGHBOR_H */

