/*
 * OSPF Interface functions.
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

#ifndef _ZEBRA_OSPF_INTERFACE_H
#define _ZEBRA_OSPF_INTERFACE_H

/* OSPF interface type definition. */
#define OSPF_IFTYPE_POINTOPOINT		1
#define OSPF_IFTYPE_BROADCAST		2
#define OSPF_IFTYPE_NBMA		3
#define OSPF_IFTYPE_POINTOMULTIPOINT	4
#define OSPF_IFTYPE_VIRTUALLINK		5

#define OSPF_AUTH_SIZE			8

/* OSPF interface flag. */
#define OSPF_IF_DISABLE                 0
#define OSPF_IF_ENABLE                  1

/* OSPF interface structure */
struct ospf_interface
{
  /* This interface's parent ospf. */
  struct ospf *ospf;

  /* Packet receive and send buffer. */
  struct stream *ibuf;			/* Input buffer */

  /*  struct stream *obuf; */
  struct ospf_fifo *obuf;		/* Output queue */

  /* Interface data from zebra. */
  struct interface *ifp;

  /* Interface related socket fd. */
  int fd;				/* Input socket fd */

  /* OSPF Specific interface data. */
  u_char flag;			        /* OSPF is enabled on this */
  u_char type;				/* OSPF Network Type */
  int status;				/* OSPF Interface State */

  struct prefix *address;		/* Interface prefix */

  /*  u_char options;	*/		/* Options */
  /*  u_char priority;	*/		/* Router Priority */
  /* struct in_addr d_router;	*/	/* Designated Router */
  /* struct in_addr bd_router;	*/	/* Backup Designated Router */

  struct ospf_area *area;		/* OSPF Area */

  u_char auth_data[OSPF_AUTH_SIZE + 1]; /* Authentication Key */

  u_int32_t transmit_delay;		/* Interface Transmisson Delay */
  u_int32_t output_cost;		/* Interface Output Cost */
  u_int32_t retransmit_interval;	/* Retransmission Interval */

  struct route_table *nbrs;             /* OSPF Neighbor List */
  struct ospf_neighbor *nbr_self;	/* Neighbor Self */

  struct ospf_lsa *network_lsa_self;	/* self-originated network-LSA */
  struct ospf_lsa *summary_lsa_self;	/* self-originated summary-LSA */

  list ls_ack;				/* Link State Acknowledgment list. */

  /* Timer values. */
  u_int32_t v_hello;			/* Hello Interval */
  u_int32_t v_wait;			/* Router Dead Interval */
  u_int32_t v_ls_ack;			/* Delayed Link State Acknowledgment */

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_hello;
  struct thread *t_wait;
  struct thread *t_ls_ack;

  /* Statistics fields. */
  u_int32_t hello_in;	        /* Hello message input count. */
  u_int32_t hello_out;	        /* Hello message output count. */
  u_int32_t db_desc_in;         /* database desc. message input count. */
  u_int32_t db_desc_out;        /* database desc. message output count. */
  u_int32_t ls_req_in;          /* LS request message input count. */
  u_int32_t ls_req_out;         /* LS request message output count. */
  u_int32_t ls_upd_in;          /* LS update message input count. */
  u_int32_t ls_upd_out;         /* LS update message output count. */
  u_int32_t ls_ack_in;          /* LS Ack message input count. */
  u_int32_t ls_ack_out;         /* LS Ack message output count. */
  u_int32_t discarded;		/* discarded input count by error. */
};

#define DR(I)			((I)->nbr_self->d_router)
#define BDR(I)			((I)->nbr_self->bd_router)
#define OPTIONS(I)		((I)->nbr_self->options)
#define PRIORITY(I)		((I)->nbr_self->priority)

/* Prototypes. */
void ospf_if_reset_variables (struct ospf_interface *oi);
struct ospf_interface *ospf_if_new ();
struct ospf_interface *ospf_if_lookup_by_addr ();
int ospf_if_new_hook (struct interface *);
void ospf_if_init ();
void ospf_if_stream_set (int, struct ospf_interface *);
void ospf_if_stream_unset (struct ospf_interface *);
int ospf_if_is_enable (struct interface *);

#endif /* _ZEBRA_OSPF_INTERFACE_H */
