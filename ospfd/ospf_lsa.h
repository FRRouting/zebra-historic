/* OSPF LSA structure definition header.
   Copyright (C) 1998 Toshiaki Takada

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

/* OSPF LSA Type definition. */
#define OSPF_ROUTER_LSA		1
#define OSPF_NETWROK_LSA	2
#define OSPF_SUMMARY_LSA	3
#define OSPF_SUMMARY_LSA_ASBR	4
#define OSPF_AS_EXTERNAL_LSA	5
#define OSPF_HOGE_LSA		6
#define OSPF_HOGA_LSA		7

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

/* OSPF Router Link Type for Router-LSAs. */
#define OSPF_LINK_TYPE_POINT_TO_POINT		1
#define OSPF_LINK_TYPE_TRANSIT_NETWORK		2
#define OSPF_LINK_TYPE_STUB_NETWORK		3
#define OSPF_LINK_TYPE_VIRTUAL_LINK		4

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
    struct _lsa_tos_metric
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
  struct _tos_metric
  {
    u_char tos;			/* 0 is normal */
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
  } un_lsa;
};

#define ospf_router_lsa		un_lsa.router_lsa
#define ospf_network_lsa	un_lsa.network_lsa
#define ospf_summary_lsa	un_lsa.summary_lsa
#define ospf_as_external_lsa	un_lsa.as_external_lsa
