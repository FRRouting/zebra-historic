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

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#define MAXLISTEDLSA 512
#define MAXLSASIZE   1024

#define AREALSTYPESIZE              0x0009

#define HASHVAL   64
#define hash(x)  ((x) % HASHVAL)

#define MY_ROUTER_LSA_ID    0

struct ospf6_lsdb
{
  u_int stat_router;
  u_int stat_network;
  u_int stat_inter_router;
  u_int stat_inter_prefix;
  u_int stat_intra_prefix;
  u_int stat_as_external;
  u_int stat_link;

  list lsdb;
};

/* Function Prototypes */
struct ospf6_lsa_hdr *
attach_lsa_hdr_to_iov (struct ospf6_lsa *, struct iovec *);
struct ospf6_lsa_hdr *
attach_lsa_to_iov (struct ospf6_lsa *lsa, struct iovec *iov);

void
ospf6_add_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);
void
ospf6_remove_delayed_ack (struct ospf6_lsa *, struct ospf6_interface *);

void
ospf6_lsdb_collect_type_advrtr (list, unsigned short,
                                unsigned long, void *);

struct ospf6_lsa *
ospf6_lsdb_lookup_from_lsdb (u_int16_t type, u_int32_t ls_id,
                             u_int32_t advrtr, list lsdb);

struct ospf6_lsa*
ospf6_lsdb_lookup (u_int16_t, u_int32_t, u_int32_t, struct ospf6 *);

void ospf6_lsdb_install (struct ospf6_lsa *);
void ospf6_lsdb_remove_all (list);

void ospf6_lsdb_check_maxage_linklocal (struct ospf6_interface *);
void ospf6_lsdb_check_maxage_area (struct ospf6_area *);
void ospf6_lsdb_check_maxage_as (struct ospf6 *);

void ospf6_lsdb_init ();

#endif /* OSPF6_LSDB_H */

