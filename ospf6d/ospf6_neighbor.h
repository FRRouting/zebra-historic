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

/* Identifier of last received DD packet */
struct dd_ident
{
  u_char options[3];
  ddbits_t bits;
  ddseqnum_t sequence_number;
};

struct neighbor
{
  struct ospf6_if *ospf6_if;
  state_t          state;
  struct thread   *inactivity_timer;
  struct thread   *send_dd;          /* Retransmit DD */
  struct thread   *send_lsreq;       /* Retransmit LSReq */
  struct thread   *send_update;      /* Retransmit LSUpdate */
  ddbits_t         dd_bits;          /* including MASTER bit */
  ddseqnum_t       dd_seqnum;        /* DD sequence number */
  struct dd_ident  last_dd;          /* last received DD */
  rtr_id_t         rtr_id;           /* Router ID of this neighbor */
  rtr_pri_t        rtr_pri;          /* Router Priority of this neighbor */
  u_char           nboptions[3];     /* OSPF capability of this neighbor */
  ifid_t           ifid;
  ifid_t           prevdr;
  ifid_t           dr;
  ifid_t           prevbdr;
  ifid_t           bdr;
  list             addrs;            /* IPaddrs of IF on our side link */
    /* note that the data of "addrs" member is struct prefix */

  /* LSAs to retransmit to this neighbor */
  list dd_retrans;
  list direct_ack;  /* we will retrans in the case of direct ack. */

  /* LSA lists for this neighbor */
  list summarylist;
  list retranslist;
  list requestlist;
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

#endif /* OSPF6_NEIGHBOR_H */

