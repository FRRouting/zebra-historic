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

#ifndef OSPF_MESG_H
#define OSPF_MESG_H

/* Message Definition */

/* Type */
#define	MSGT_HELLO			1  /* Discover/maintain neighbors */
#define	MSGT_DATABASE_DESCRIPTION	2  /* Summarize database contents */
#define MSGT_LINKSTATE_REQUEST		3  /* Database download */
#define MSGT_LINKSTATE_UPDATE		4  /* Database update */
#define	MSGT_LINKSTATE_ACK		5  /* Flooding acknowledgment */

/* OSPF packet header */
struct ospf_msghdr
{
  vers_t version;
  u_int8_t type;
  u_int16_t len;
  rtr_id_t router_id;
  area_id_t area_id;
  u_int16_t cksum;
  union {
    struct v2hdr {
      u_int16_t	autype;
      char auth_data[8];
    } v2hdr;
    struct v3hdr {
      u_int8_t instance_id;
      u_int8_t reserved;
    } v3hdr;
  } changed;
};
#define v2autype changed.v2hdr.autype
#define v2auth_data changed.v2hdr.auth_data
#define v3instance_id changed.v3hdr.instance_id

#define OSPFV2HDRLEN (sizeof (struct ospf_msghdr))
#define OSPFV3HDRLEN (sizeof (struct ospf_msghdr) - 8 * sizeof (char))

/* HELLO */
#define MAXLISTEDNB	64
struct hello2
{
	struct in_addr	netmask;
	hello_int_t	hello_interval;
	u_char 		opt[8];
	rtr_pri_t	rtr_pri;
	rtr_dead_int_t	router_dead_interval;
	ifid_t		dr;
	ifid_t		bdr;
};
#define V2HELLO_IS_EBITSET(x) (x[7] & OPT_E)
#define V2HELLO_EBITSET(x) (x[7] |= OPT_E)

#define OSPFV2HELLOLEN (sizeof (struct hello2))

struct hello3
{
  u_int32_t interface_id;
  u_int8_t rtr_pri;
  u_char options[3];
  u_int16_t hello_interval;
  u_int16_t router_dead_interval;
  rtr_id_t dr;
  rtr_id_t bdr;
};

#define OSPFV3HELLOLEN (sizeof (struct hello3))

/* Databese Description */
struct database_description
{
  u_int8_t zero1;
  u_char options[3];
  u_int16_t interface_mtu;
#define DEFAULT_INTERFACE_MTU 1500
  u_int8_t zero2;
  ddbits bits;
  u_int32_t sequence_number;
  /* Followed by LSAs */
};
#define DD_IS_MSBIT_SET(x) ((x) & (1 << 0))
#define DD_MSBIT_SET(x) ((x) |= (1 << 0))
#define DD_MSBIT_CLEAR(x) ((x) &= ~(1 << 0))
#define DD_IS_MBIT_SET(x) ((x) & (1 << 1))
#define DD_MBIT_SET(x) ((x) |= (1 << 1))
#define DD_MBIT_CLEAR(x) ((x) &= ~(1 << 1))
#define DD_IS_IBIT_SET(x) ((x) & (1 << 2))
#define DD_IBIT_SET(x) ((x) |= (1 << 2))
#define DD_IBIT_CLEAR(x) ((x) &= ~(1 << 2))

#define OSPFV3DDLEN (sizeof (struct database_description))

/* Link State Request */
struct linkstate_request
{
  u_int16_t lsreq_age_zero;     /* MBZ */
  u_int16_t lsreq_type;         /* LS type */
  u_int32_t lsreq_id;           /* Link State ID */
  u_int32_t lsreq_advrtr;       /* Advertising Router */
};

/* Link State Update */
struct linkstate_update
{
  u_int32_t lsupdate_num;
  /* Followed by LSAs */
};

/* Link State Acknowledgement will include only LSA header.*/

#endif /* OSPF_MESG_H */
