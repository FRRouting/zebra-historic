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

#ifndef OSPF6_MESG_H
#define OSPF6_MESG_H

/* Message Definition */

/* Type */
#define MSGT_NONE                 0  /* Unknown message */
#define MSGT_HELLO                1  /* Discover/maintain neighbors */
#define MSGT_DATABASE_DESCRIPTION 2  /* Summarize database contents */
#define MSGT_LINKSTATE_REQUEST    3  /* Database download */
#define MSGT_LINKSTATE_UPDATE     4  /* Database update */
#define MSGT_LINKSTATE_ACK        5  /* Flooding acknowledgment */

/* OSPF packet header */
struct ospf6_hdr
{
  vers_t         version;
  u_char         type;
  unsigned short len;
  rtr_id_t       router_id;
  area_id_t      area_id;
  unsigned short cksum;
  u_char         instance_id;
  u_char         reserved;
};

/* HELLO */
#define MAXLISTEDNBR     64
struct hello
{
  ifid_t         interface_id;
  rtr_pri_t      rtr_pri;
  u_char         options[3];
  hello_int_t    hello_interval;
  rtr_dead_int_t router_dead_interval;
  rtr_id_t       dr;
  rtr_id_t       bdr;
  /* Followed by Router-IDs */
};

/* Databese Description */
struct database_description
{
  u_char         mbz1;
  u_char         options[3];
  unsigned short interface_mtu;
  u_char         mbz2;
  ddbits_t       bits;
  ddseqnum_t     sequence_number;
  /* Followed by LSAs */
};
#define DEFAULT_INTERFACE_MTU 1500

#define DD_IS_MSBIT_SET(x) ((x) & (1 << 0))
#define DD_MSBIT_SET(x) ((x) |= (1 << 0))
#define DD_MSBIT_CLEAR(x) ((x) &= ~(1 << 0))
#define DD_IS_MBIT_SET(x) ((x) & (1 << 1))
#define DD_MBIT_SET(x) ((x) |= (1 << 1))
#define DD_MBIT_CLEAR(x) ((x) &= ~(1 << 1))
#define DD_IS_IBIT_SET(x) ((x) & (1 << 2))
#define DD_IBIT_SET(x) ((x) |= (1 << 2))
#define DD_IBIT_CLEAR(x) ((x) &= ~(1 << 2))

/* Link State Request */
struct linkstate_request
{
  unsigned short lsreq_age_zero;     /* MBZ */
  unsigned short lsreq_type;         /* LS type */
  unsigned long  lsreq_id;           /* Link State ID */
  unsigned long  lsreq_advrtr;       /* Advertising Router */
};

/* Link State Update */
struct linkstate_update
{
  unsigned long  lsupdate_num;
  /* Followed by LSAs */
};

/* Link State Acknowledgement will include only LSA header.*/

/* Function Prototypes */
int proc_hello (struct sockaddr_in6 *, struct iovec *, struct ospf6_if *);
int proc_database_description (struct sockaddr_in6 *, struct iovec *,
                               struct ospf6_if *);
int proc_linkstate_request (struct sockaddr_in6 *, struct iovec *,
                            struct ospf6_if *);
int proc_linkstate_update (struct sockaddr_in6 *, struct iovec *,
                           struct ospf6_if *);
int proc_linkstate_ack (struct sockaddr_in6 *, struct iovec *,
                        struct ospf6_if *);
int proc_ospf6_hdr (struct iovec *, struct ospf6_if *);
int make_ospf6_hdr (msgtype_t, struct iovec *, struct ospf6_if *);
int make_hello (struct iovec *, struct sockaddr_in6 *, struct ospf6_if *);
int make_database_description (struct iovec *, struct sockaddr_in6 *,
                               struct neighbor *);
int make_linkstate_request (struct iovec *, struct sockaddr_in6 *,
                            struct neighbor *);
int make_linkstate_update (struct iovec *, struct sockaddr_in6 *,
                           struct neighbor *);

int ospf6_receive (struct thread *);

#endif /* OSPF6_MESG_H */

