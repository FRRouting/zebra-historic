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

#ifndef OSPF6_DBEX_H
#define OSPF6_DBEX_H

/* for ack_type() */
#define NO_ACK       0
#define DELAYED_ACK  1
#define DIRECT_ACK   2

#define NONE       0
#define FLOODBACK  1
#define IMPLIEDACK 2
#define DUPLICATE  4

/* Function Prototypes */
int prepare_neighbor_lsdb (struct neighbor *);
int check_neighbor_lsdb (struct iovec *, struct neighbor *);
int proceed_summarylist (struct neighbor *);
void direct_acknowledge (struct lsa_internal *);
void delayed_acknowledge (struct lsa_internal *);
int lsa_receive (struct lsa_hdr *, struct neighbor *);
int ack_type (struct lsa_internal *, int, int);
int lsa_flood (struct lsa_internal *);

#endif /* OSPF6_DBEX_H */

