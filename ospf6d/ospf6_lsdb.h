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
#define typeindex(x)     (((ntohs (x)) & 0x000f) - 1)

#define HASHVAL   64
#define hash(x)  ((x) % HASHVAL)

/* for LSA list in Neighbor Data Structure */
#define lsdb_size(x)     (sizeof (x) / sizeof (struct lsa_internal *))

#define MY_ROUTER_LSA_ID    0

/* Function Prototypes */
int lsa_delete_from_list (struct lsa_internal *, list l);
int lsa_delete_all_list (list);
int lsa_delete (struct lsa_internal *);
int lsa_change (struct lsa_internal *);
int lsa_install (struct lsa_internal *);
list lsa_lookup_by_advrtr (unsigned short, unsigned long, struct area *);
struct lsa_internal *lsa_lookup (unsigned short, unsigned long,
                                 unsigned long, struct area *,
                                 struct ospf6_if *);
struct lsa_hdr *attach_lsa_to_iov (struct lsa_internal *, struct iovec *);
struct lsa_hdr *attach_lsa_hdr_to_iov (struct lsa_internal *, struct iovec *);
struct lsa_internal *get_linklocal_lsa (rtr_id_t, struct ospf6_if *);
void attach_lsa_to_retranslist (struct lsa_internal *, struct neighbor *);
void detach_lsa_from_retranslist (struct lsa_internal *, struct neighbor *);
struct lsa_internal *lslist_lookup (struct lsa_internal *, list);

#endif /* OSPF6_LSDB_H */

