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
#define MSGT_NONE                 0x0  /* Unknown message */
#define MSGT_HELLO                0x1  /* Discover/maintain neighbors */
#define MSGT_DATABASE_DESCRIPTION 0x2  /* Summarize database contents */
#define MSGT_DBDESC               0x2  /* Summarize database contents */
#define MSGT_LINKSTATE_REQUEST    0x3  /* Database download */
#define MSGT_LSREQ                0x3  /* Database download */
#define MSGT_LINKSTATE_UPDATE     0x4  /* Database update */
#define MSGT_LSUPDATE             0x4  /* Database update */
#define MSGT_LINKSTATE_ACK        0x5  /* Flooding acknowledgment */
#define MSGT_LSACK                0x5  /* Flooding acknowledgment */
#define MSGT_MAX                  0x6

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
struct ospf6_header
{
  unsigned char  version;
  unsigned char  type;
  unsigned short len;
  unsigned long  router_id;
  unsigned long  area_id;
  unsigned short cksum;
  unsigned char  instance_id;
  unsigned char  reserved;
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
struct ospf6_hello
{
  unsigned long  interface_id;
  unsigned char  rtr_pri;
  u_char         options[3];
  unsigned short hello_interval;
  unsigned short router_dead_interval;
  unsigned long  dr;
  unsigned long  bdr;
};

#if 0
/* Databese Description */
struct database_description
{
  u_char         mbz1;
  u_char         options[3];
  unsigned short interface_mtu;
  u_char         mbz2;
  unsigned char  bits;
  unsigned long  sequence_number;
  /* Followed by LSAs */
};
#endif /* 0 */

/* new Database Description (name changed) */
struct ospf6_dbdesc
{
  unsigned char  mbz1;
  unsigned char  options[3];
  unsigned short ifmtu;
  unsigned char  mbz2;
  unsigned char  bits;
  unsigned long  seqnum;
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
#if 0
int make_ospf6_hdr (msgtype_t, struct iovec *, struct ospf6_if *);
int make_hello (struct iovec *, struct sockaddr_in6 *, struct ospf6_if *);
int make_database_description (struct iovec *, struct sockaddr_in6 *,
                               struct neighbor *);
int make_linkstate_request (struct iovec *, struct sockaddr_in6 *,
                            struct neighbor *);
int make_linkstate_update (struct iovec *, struct sockaddr_in6 *,
                           struct neighbor *);
#endif

struct ospf6_lsa_hdr *
ospf6_message_get_lsa_hdr (struct iovec *);

int ospf6_receive (struct thread *);

int ospf6_send_hello (struct thread *);
int ospf6_send_dbdesc_retrans (struct thread *);
int ospf6_send_dbdesc (struct thread *);

void ospf6_message_send (unsigned char, struct iovec *, struct in6_addr *,
			 u_int);

#endif /* OSPF6_MESG_H */

