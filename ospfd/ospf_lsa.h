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
#define OSPF_MIN_LSA		1
#define OSPF_ROUTER_LSA         1
#define OSPF_NETWORK_LSA        2
#define OSPF_SUMMARY_LSA        3
#define OSPF_SUMMARY_LSA_ASBR   4
#define OSPF_AS_EXTERNAL_LSA    5
#define OSPF_MAX_LSA		5

#define OSPF_LSA_HEADER_SIZE	20

/* OSPF LSA structure. */
struct ospf_lsa
{
  u_int16_t ls_age;
  u_char options;
  u_char type;
  struct in_addr id;
  struct in_addr adv_router;
  int ls_seqnum;
  u_int16_t checksum;
  u_int16_t length;
};

/* OSPF LSA Link Type. */
#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_VIRTUALLINK      4

/* OSPF Router LSA Flag. */
#define ROUTER_LSA_VIRTUAL	       0x04
#define ROUTER_LSA_EXTERNAL	       0x02
#define ROUTER_LSA_BORDER	       0x01

/* OSPF Router-LSAs structure. */
struct router_lsa
{
  struct ospf_lsa header;
  u_char flags;
  u_char zero;
  u_int16_t links;
  struct in_addr link_id;
  struct in_addr link_data;
  u_char type;
  u_char tos;
  u_int16_t metric;
};

/* OSPF Network-LSAs structure. */
struct network_lsa
{
  struct ospf_lsa header;
  struct in_addr mask;
  struct in_addr routers[1];
};

/* OSPF Summary-LSAs structure. */
struct summary_lsa
{
  struct ospf_lsa header;
  struct in_addr mask;
  u_char tos;
  u_char metric[3];
};

/* OSPF AS-external-LSAs structure. */
struct as_external_lsa
{
  struct ospf_lsa header;
  struct in_addr mask;
  struct {
    u_char tos;
    u_char metric[3];
    struct in_addr fwd_addr;
    struct in_addr route_tag;
  } e[1];
};

#define GET_METRIC(x)           ((x[0] << 16) | (x[1] << 8) | x[2])
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)

/* Prototypes. */
struct ospf_lsa *ospf_router_lsa (struct ospf_interface *);
struct ospf_lsa *ospf_network_lsa (struct ospf_interface *);
u_int16_t ospf_lsa_checksum (struct ospf_lsa *);
void ospf_add_router_lsa (struct ospf_area *, struct ospf_lsa *);
void ospf_add_network_lsa (struct ospf_area *, struct ospf_lsa *);
void ospf_add_summary_lsa (struct ospf_area *, struct ospf_lsa *);
struct ospf_lsa *ospf_lsa_lookup (struct ospf_area *, u_int32_t,
				  struct in_addr, struct in_addr);
struct ospf_lsa *ospf_lsa_lookup_by_header (struct ospf_area *,
					    struct ospf_lsa *);
listnode ospf_lsa_lookup_from_list (list, u_char, struct in_addr,
				    struct in_addr);
int ospf_lsa_more_recent (struct ospf_lsa *, struct ospf_lsa *);
int ospf_lsa_count (struct ospf_area *);
void ospf_lsa_init ();

#endif /* _ZEBRA_OSPF_LSA_H */
