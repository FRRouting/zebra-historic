/* OSPFd main header.
   Copyright (C) 1998, 99 Kunihiro Ishiguro, Toshiaki Takada

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

#ifndef _ZEBRA_OSPFD_H
#define _ZEBRA_OSPFD_H

#define OSPF_VERSION		2

/* Default protocol, port number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP		89
#endif /* IPPROTO_OSPFIGP */

/* VTY port number. */
#define OSPF_VTY_PORT	       2604

/* IP TTL for OSPF protocol. */
#define OSPF_IP_TTL		1

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"

enum
{
  /* Debug option. */
  DEBUG_OSPF_ISM = 0x01,
  DEBUG_OSPF_NSM = 0x02,
};

/* Architectual Constants */
#define OSPF_LS_REFRESH_TIME		      1800
#define OSPF_MIN_LS_INTERVAL		         5
#define OSPF_MIN_LS_ARRIVAL		         1
#define OSPF_LSA_MAX_AGE		      3600
#define OSPF_CHECK_AGE			       300
#define OSPF_LSA_MAX_AGE_DIFF		       900
#define OSPF_LS_INFINITY		  0xffffff
#define OSPF_DEFAULT_DESTINATION	0x00000000	/* 0.0.0.0 */
#define OSPF_INITIAL_SEQUENCE_NUMBER	0x80000001
#define OSPF_MAX_SEQUENCE_NUMBER	0x7fffffff

#define OSPF_ALLSPFROUTERS		0xe0000005	/* 224.0.0.5 */
#define OSPF_ALLDROUTERS		0xe0000006	/* 224.0.0.6 */

#define OSPF_AREA_BACKBONE		0x00000000	/* 0.0.0.0 */

/* OSPF Authentication Type. */
#define OSPF_AUTH_NULL			    0
#define OSPF_AUTH_SIMPLE		    1
#define OSPF_AUTH_CRYPTOGRAPHIC		    2

/* OSPF interface default values. */
#define OSPF_OUTPUT_COST_DEFAULT           10
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40
#define OSPF_HELLO_INTERVAL_DEFAULT	   10
#define OSPF_ROUTER_PRIORITY_DEFAULT	    1
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT    5
#define OSPF_TRANSMIT_DELAY_DEFAULT         1

/* Area ID Format type. */
#define OSPF_AREA_ID_FORMAT_ADDRESS         1
#define OSPF_AREA_ID_FORMAT_DECIMAL         2

/* Area External Routing Capability. */
#define OSPF_AREA_DEFAULT		    0
#define OSPF_AREA_STUB			    1
#define OSPF_AREA_NSSA			    2

/* OSPF options. */
#define OSPF_OPTION_T			 0x01  /* TOS. */
#define OSPF_OPTION_E			 0x02
#define OSPF_OPTION_MC			 0x04
#define OSPF_OPTION_NP			 0x08
#define OSPF_OPTION_EA			 0x10
#define OSPF_OPTION_DC			 0x20

/* OSPF Database Description flags. */
#define OSPF_DD_FLAG_MS			 0x01
#define OSPF_DD_FLAG_M			 0x02
#define OSPF_DD_FLAG_I			 0x04
#define OSPF_DD_FLAG_ALL		 0x07

/* OSPF Transit Capability. */
#define OSPF_TRANSIT_FALSE		 0
#define OSPF_TRANSIT_TRUE		 1

/* OSPF instance structure. */
struct ospf
{
  struct in_addr router_id;		/* OSPF Router ID. */
  struct in_addr router_id_static;	/* OSPF static Router ID. */

  list iflist;				/* Zebra interface list. */

  list areas;				/* OSPF areas. */
  struct route_table *networks;		/* OSPF config networks. */

  struct route_table *external_lsa;	/* AS-External-LSAs. */

  struct route_table *old_table;        /* Old routing table. */
  struct route_table *new_table;        /* Current routing table. */

  int spf_calc;		                /* SPF calculation flag. */
  struct thread *t_spf_calc;	        /* SPF calculation timer. */
};

/* OSPF area structure. */
struct ospf_area
{
  int count;				/* Reference count by ospf_network. */

  struct in_addr area_id;		/* Area ID. */
  char format;				/* Area ID format. */
  list address_range;

  /* Configuration variables. */
  int external_routing;			/* ExternalRoutingCapability. */
  int default_cost;			/* StubDefaultCost. */
  int auth_type;			/* Authentication type. */

  /* Area related LSAs. */
  struct route_table *lsa[4];

  /* self originated LSAs. */
  struct ospf_lsa *router_lsa_self;
  struct ospf_lsa *summary_lsa_self;
  struct ospf_lsa *summary_lsa_asbr_self;

  /* Shortest Path Tree. */
  struct vertex *spf;

  /* TransitCapability. */
  u_char transit;
};

#define ROUTER_LSA(a)                   (a)->lsa[0]
#define NETWORK_LSA(a)			(a)->lsa[1]
#define SUMMARY_LSA(a)			(a)->lsa[2]
#define SUMMARY_LSA_ASBR(a)		(a)->lsa[3]

/* OSPF config network structure. */
struct ospf_network
{
  struct in_addr area_id;			/* Area ID. */

  /* interface associated with network. */
  struct interface *ifp;
};

/* To convert index into message structure. */
typedef struct message
{
  int key;
  char *str;
} message;

/* Messages */
extern message ospf_ism_status_msg[];
extern message ospf_nsm_status_msg[];
extern message ospf_lsa_type_msg[];
extern int ospf_ism_status_msg_max;
extern int ospf_nsm_status_msg_max;
extern int ospf_lsa_type_msg_max;

extern char *progname;

/* Prototypes. */
void ospf_init (void);
void ospf_if_update (void);
void ospf_terminate (void);
void ospf_route_init (void);

extern struct thread_master *master;
extern struct ospf *ospf_top;

#endif /* _ZEBRA_OSPFD_H */
