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

#ifndef OSPF6_PROTO_H
#define OSPF6_PROTO_H

/* OSPF protocol version */
#define OSPF_V2                 2
#define OSPF_V3                 3

/* OSPF protocol number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif

/* TOS field normaly null */
#define TOS_VALUE               0x0

/* Architectural Constants */
#define LS_REFRESH_TIME         1800       /* 30 min */
#define MIN_LS_INTERVAL         5
#define MIN_LS_ARRIVAL          1
#define MAXAGE                  3600       /* 1 hour */
#define CHECK_AGE               300        /* 5 min */
#define MAX_AGE_DIFF            900        /* 15 min */
#define LS_INFINITY             0xffffff   /* 24-bit binary value */
#define INITIAL_SEQUENCE_NUMBER 0x80000001 /* signed 32-bit integer */
#define MAX_SEQUENCE_NUMBER     0x7fffffff /* signed 32-bit integer */

#define MAXOSPFMESSAGELEN         4096

/* Configurable Constants */

#define DEFAULT_HELLO_INTERVAL    10
#define DEFAULT_ROUTER_DEAD_TIMER 40


/* TopLevel Structure */
struct ospf6
{
  instance_id_t instance_id;
  vers_t        version;
  rtr_id_t      router_id;
  list          area_list;
  struct ospf6_rtable rtable;
};

/* OSPF options */
/* present in HELLO, DD, LSA */
#define V3OPT_SET(x,opt)       ((x)[2] |=  (opt))
#define V3OPT_ISSET(x,opt)     ((x)[2] &   (opt))
#define V3OPT_CLEAR(x,opt)     ((x)[2] &= ~(opt))

#define V3OPT_V6     (1 << 0)   /* IPv6 forwarding Capability */
#define V3OPT_E      (1 << 1)   /* AS External Capability */
#define V3OPT_MC     (1 << 2)   /* Multicasting Capability */
#define V3OPT_N      (1 << 3)   /* Handling Type-7 LSA Capability */
#define V3OPT_R      (1 << 4)   /* Forwarding Capability (Any Protocol) */
#define V3OPT_DC     (1 << 5)   /* Demand Circuit handling Capability */

#endif /* OSPF6_PROTO_H */

