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

/* OSPF interface structure */
struct ospf_interface
{
  /* This interface's parent ospf. */
  struct ospf *ospf;

  /* Packet receive and send buffer. */
  struct stream *ibuf;
  struct stream *obuf;

  /* Interface data from zebra. */
  struct interface *ifp;

  /* Interface related socket fd. */
  int fd;

  /* OSPF Specific interface data. */
  u_char type;				/* OSPF Network Type */
  int status;				/* OSPF Interface State */

  struct in_addr router_id;		/* Router ID */
  struct in_addr area_id;		/* Area ID */
  u_int16_t auth_type;			/* Authentication Type */
  u_char auth_data [OSPF_AUTH_SIZE];    /* Authentication Key */

  struct in_addr d_router;		/* Designated Router */
  struct in_addr bd_router;		/* Backup Designated Router */

  u_int16_t hello_interval;		/* Hello Interval */
  u_char router_priority;		/* Router Priority */
  u_int32_t dead_interval;		/* Router Dead Interval */
  u_int32_t transmit_delay;		/* Interface Transmisson Delay */
  u_int32_t output_cost;		/* Interface Output Cost */
  u_int32_t retransmit_interval;	/* Retransmission Interval */

  struct _list *neighbors;		/* OSPF Neighbor List */

  /* Timer values. */
  u_int32_t v_hello;			/* Hello Timer */
  u_int32_t v_wait;			/* Wait Timer */

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_hello;
  struct thread *t_wait;

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
  u_int32_t discarded;		/* discarded input count by checksum error. */
};


/* Prototypes. */
struct ospf_interface *ospf_if_new ();
int ospf_if_new_hook (struct interface *);
void ospf_if_init ();
void ospf_if_stream_set (int, struct ospf_interface *);

#endif /* _ZEBRA_OSPF_INTERFACE_H */
