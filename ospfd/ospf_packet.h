/* OSPF Sending and Receiving OSPF Packets
   Copyright (C) 1999 Toshiaki Takada

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _ZEBRA_OSPF_PACKET_H
#define _ZEBRA_OSPF_PACKET_H

#define OSPF_HEADER_SIZE         24
#define OSPF_AUTH_SIZE	          8
#define OSPF_MAX_PACKET_SIZE  65535   /* includes IP Header size. */
#define OSPF_HELLO_MIN_SIZE	 20
#define OSPF_DB_DESC_MIN_SIZE     8
#define OSPF_LS_REQ_MIN_SIZE      8
#define OSPF_LS_UPD_MIN_SIZE      0
#define OSPF_LS_ACK_MIN_SIZE      0

#define OSPF_MSG_HELLO	       1  /* OSPF Hello Message. */
#define OSPF_MSG_DB_DESC       2  /* OSPF Database Descriptoin Message. */
#define OSPF_MSG_LS_REQ	       3  /* OSPF Link State Request Message. */
#define OSPF_MSG_LS_UPD	       4  /* OSPF Link State Update Message. */
#define OSPF_MSG_LS_ACK	       5  /* OSPF Link State Acknoledgement Message. */

/* OSPF packet header structure. */
struct ospf_header
{
  u_char version;			/* OSPF Version. */
  u_char type;				/* Packet Type. */
  u_int16_t length;			/* Packet Length. */
  struct in_addr router_id;		/* Router ID. */
  struct in_addr area_id;		/* Area ID. */
  u_int16_t checksum;			/* Check Sum. */
  u_int16_t auth_type;			/* Authentication Type. */
  u_char auth_data [OSPF_AUTH_SIZE];	/* Authentication Data. */
};

/* OSPF Hello body format. */
struct ospf_hello
{
  struct in_addr network_mask;
  u_int16_t hello_interval;
  u_char options;
  u_char priority;
  u_int32_t dead_interval;
  struct in_addr d_router;
  struct in_addr bd_router;
  struct in_addr neighbors[1];
};

/* OSPF Database Description body format. */
struct ospf_db_desc
{
  u_int16_t mtu;
  u_char options;
  u_char flags;
  u_int32_t dd_seqnum;
};


/* Macros. */
#define OSPF_OUTPUT_PNT(S)	((S)->data + (S)->putp)
#define OSPF_OUTPUT_LENGTH(S)	((S)->putp)

#define IS_SET_DD_MS(X)		((X) & OSPF_DD_FLAG_MS)
#define IS_SET_DD_M(X)		((X) & OSPF_DD_FLAG_M)
#define IS_SET_DD_I(X)		((X) & OSPF_DD_FLAG_I)

/* Prototypes. */
int ospf_read (struct thread *);
int ospf_hello_send (struct thread *);
int ospf_db_desc_send (struct thread *);
int ospf_ls_req_send (struct thread *);
int ospf_ls_upd_send (struct thread *);
int ospf_ls_ack_send (struct thread *);

#endif /* _ZEBRA_OSPF_PACKET_H */
