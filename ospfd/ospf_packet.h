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

#define OSPF_HEADER_SIZE         20
#define OSPF_AUTH_SIZE	          8
#define OSPF_MAX_PACKET_SIZE  65535   /* includes IP Header size. */

#define OSPF_MSG_HELLO	       1
#define OSPF_MSG_DB_DESC       2
#define OSPF_MSG_LS_REQ	       3
#define OSPF_MSG_LS_UPD	       4
#define OSPF_MSG_LS_ACK	       5

/* OSPF packet header structure. */
struct ospf_header
{
  u_char version;
  u_char type;
  u_int16_t length;
  struct in_addr router_id;
  struct in_addr area_id;
  u_int16_t checksum;
  u_int16_t auth_type;
  u_char auth_data [OSPF_AUTH_SIZE];
};

/* OSPF Hello body format. */
/* struct ospf_hello_body */
struct _ospf_hello
{
  struct in_addr network_mask;
  u_int16_t hello_interval;
  u_char options;
  u_char priority;
  u_int32_t dead_interval;
  struct in_addr d_router;
  struct in_addr bd_router;
  struct in_addr neighbor[1];
};

/* OSPF LSA header structure. */
struct ospf_lsa_header
{
  u_int16_t ls_age;
  u_char options;
  u_char ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;
  u_int32_t ls_seq_number;
  u_int16_t ls_checksum;
  u_int16_t length;
};

/* OSPF Router-LSAs structure. */
struct _ospf_router_lsa
{
  u_char flags;
  u_char zero;
  u_int16_t number_links;
  struct _lsa_link
  {
    struct in_addr link_id;
    struct in_addr link_data;
    u_char type;
    u_char number_tos;
    u_int16_t metric;
    struct /* _tos_metric */
    {
      u_char tos;
      u_char zero;
      u_int16_t metric;
    } *tos_metric;
  } lsa_link[1];
};

/* OSPF Network-LSAs structure. */
typedef struct _ospf_network_lsa
{
  struct in_addr network_mask;
  struct in_addr attached_router[1];
} ospf_network_lsa;

/* OSPF Summary-LSAs structure. */
struct _ospf_summary_lsa
{
  struct in_addr network_mask;
  struct /* _tos_metric */
  {
    u_char tos;                 /* 0 is normal */
    u_char metric[3];
  } tos_metric[1];
};
/* OSPF AS-external-LSAs structure. */
struct _ospf_as_external_lsa
{
  struct in_addr network_mask;
  struct lsa_metric
  {
    u_char tos;
    u_char metric[3];
    struct in_addr fwd_address;
    struct in_addr ext_route_tag;
  } lsa_metric[1];
};


/* OSPF LSA */
struct ospf_lsa
{
  struct ospf_lsa_header header;
  union
  {
    struct _ospf_router_lsa router_lsa;
    struct _ospf_network_lsa network_lsa;
    struct _ospf_summary_lsa summary_lsa;
    struct _ospf_as_external_lsa as_external_lsa;
  } u;
};

#define ospf_router_lsa         u.router_lsa
#define ospf_network_lsa        u.network_lsa
#define ospf_summary_lsa        u.summary_lsa
#define ospf_as_external_lsa    u.as_external_lsa

/* OSPF Database Description body format. */
struct _ospf_db_desc
{
  u_int16_t interface_mtu;
  u_char options;
  u_char flags;
  u_int32_t seq_number;
  struct ospf_lsa lsa[1];
};

/* OSPF Link State Request body format. */
struct _ospf_ls_req
{
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;
};

/* OSPF Link State Update body format. */
struct _ospf_ls_upd
{
  u_int32_t number_lsa;
  struct ospf_lsa lsa[1];
};

/* OSPF Link State Ack body format. */
struct _ospf_ls_ack
{
  struct ospf_lsa_header lsa_header[1];
};

/* OSPF packet structure format. */
struct ospf_packet
{
  struct ospf_header header;
  union
  {
    /* OSPF Hello body */
    struct _ospf_hello hello;

    /* OSPF Database Description body */
    struct _ospf_db_desc db_desc;

    /* OSPF Link State Request body */
    struct _ospf_ls_req ls_req[1];

    /* OSPF Link State Update body */
    struct _ospf_ls_upd ls_upd;

    /* OSPF Link State Ack body */
    struct _ospf_ls_ack ls_ack;
  } u;
};

/* Prototypes. */
int ospf_read (struct thread *);

#endif /* _ZEBRA_OSPF_PACKET_H */
