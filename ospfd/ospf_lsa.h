/* OSPF Link State Advertisement
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

#ifndef _ZEBRA_OSPF_LSA_H
#define _ZEBRA_OSPF_LSA_H

/* OSPF LSA Type definition. */
#define OSPF_ROUTER_LSA         1
#define OSPF_NETWORK_LSA        2
#define OSPF_SUMMARY_LSA        3
#define OSPF_SUMMARY_LSA_ASBR   4
#define OSPF_AS_EXTERNAL_LSA    5

#define OSPF_LSA_HEADER_SIZE	20

/* OSPF LSA header structure. */
struct lsa_header
{
  u_int16_t ls_age;
  u_char options;
  u_char type;
  struct in_addr id;
  struct in_addr adv_router;
  u_int32_t seq_number;
  u_int16_t checksum;
  u_int16_t length;
};

#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_VIRTUALLINK      4

/* OSPF Router-LSAs structure. */
struct router_lsa
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
struct network_lsa
{
  struct in_addr network_mask;
  struct in_addr attached_router[1];
};

/* OSPF Summary-LSAs structure. */
struct summary_lsa
{
  struct in_addr network_mask;
  struct /* _tos_metric */
  {
    u_char tos;                 /* 0 is normal */
    u_char metric[3];
  } tos_metric[1];
};

/* OSPF AS-external-LSAs structure. */
struct as_external_lsa
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


#endif /* _ZEBRA_OSPF_LSA_H */
