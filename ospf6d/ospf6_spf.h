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


#ifndef OSPF_SPF_H
#define OSPF_SPF_H

#define MAX_ENTRY          ( 256 )
#define ROUTING_TABLE_SIZE (sizeof (struct routing_table_entry) * MAX_ENTRY)

typedef u_int32_t *vertex_id;

struct vertex                /* Transit Vertex */
{
  u_int32_t            vtx_id[2];    /* [0:Router-ID][1:Interface-ID (which can be 0)] */
  struct lsa_internal *vtx_lsa;      /* Associated LSA */
  list                 vtx_nexthops; /* For ECMP */
  u_int32_t            vtx_distance; /* Distance from Root (Cost) */
  list                 vtx_path;     /* List of Path described by (struct vertex *) */
  struct vertex       *vtx_parent;   /* for vertex on candidate list */
  u_int8_t             vtx_depth;    /* for vertex on spf tree */
};

#define MAXDEPTH 256

struct spftree
{
  struct vertex *root;
  list searchlist[HASHVAL][HASHVAL];   /* having (struct vertex *) as data */
  list depthlist[MAXDEPTH];            /* having (struct vertex *) as data */
};

struct routing_table_entry
{
  u_int32_t dst[2];
  u_int32_t ifindex;
  u_int32_t nexthop[2];
  u_int32_t cost;

  struct in6_addr destination;
  u_int32_t prefixlength;
  struct in6_addr next_hop;
};

struct nexthop_info
{
  u_int32_t ifindex;
  u_int32_t nexthop[2];

  struct in6_addr nexthop_addr;
};

#define IS_DST_ROUTER_TYPE(x) (!(x)->vtx_id[1])
#define IS_DST_NETWORK_TYPE(x) ((x)->vtx_id[1])

int spf_calculation (struct thread *);
int routing_table_calculation (struct thread *);

#endif /* OSPF_SPF_H */
