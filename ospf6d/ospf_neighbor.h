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

#ifndef OSPF_NEIGHBOR_H
#define OSPF_NEIGHBOR_H

#define MAXIOVLIST 1024

struct last_received
{
  u_char options[3];
  ddbits bits;
  u_int32_t sequence_number;
};

struct neighbor
{
  struct ospf_if *interface;
  u_int8_t	state;
  struct thread	*inactivity_timer;
  struct thread *send_dd;                       /* Retransmit DD */
  struct thread *send_lsreq;                    /* Retransmit LSReq */
  struct thread *send_update;                   /* Retransmit LSUpdate */
  ddbits	dd_bits;			/* including MASTER bit */
  u_int32_t	dd_sequence_number;
  struct last_received last_dd;
  rtr_id_t	rtr_id;
  rtr_pri_t	rtr_pri;
  u_char	nboptions[3];
  ifid_t	ifid;
  struct in6_addr ipaddr;
  ifid_t	prevdr;
  ifid_t	dr;
  ifid_t	prevbdr;
  ifid_t	bdr;

  list dd_retrans;   /* (struct lsa_internal *) as Data */
  struct lsa_internal *direct_ack[MAXLSDBSIZE];

  list summarylist;  /* (struct lsa_internal *) as Data */
  list retranslist;  /* (struct lsa_internal *) as Data */
  list requestlist;  /* (struct lsa_internal *) as Data */
};

/* Neighbor state */
#define NBS_DOWN		1
#define NBS_ATTEMPT		2
#define NBS_INIT		3
#define NBS_TWOWAY		4
#define NBS_EXSTART		5
#define NBS_EXCHANGE		6
#define NBS_LOADING		7
#define NBS_FULL		8

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

int dr_election (struct ospf_if *);
int list_cleared_of_lsa (struct neighbor *);

#endif /* OSPF_NEIGHBOR_H */
