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

#define OSPF_VTY_PORT	       2604

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"

enum
{
  /* Debug option. */
  DEBUG_OSPF_ISM = 0x01,
  DEBUG_OSPF_NSM = 0x02,
};

/* Architectual Constants */
#define OSPF_LS_REFRESH_TIME		   1800
#define OSPF_MIN_LS_INTERVAL		      5
#define OSPF_MIN_LS_ARRIVAL		      1
#define OSPF_MAX_AGE			   3600
#define OSPF_CHECK_AGE			    300
#define OSPF_MAX_AGE_DIFF		    900
#define OSPF_LS_INFINITY		  0xffffff
#define OSPF_DEFAULT_DESTINATION	 "0.0.0.0"
#define OSPF_INITIAL_SEQUENCE_NUMBER	0x80000001
#define OSPF_MAX_SEQUENCE_NUMBER	0x7fffffff

#define OSPF_ALLSPFROUTERS		"224.0.0.5"
#define OSPF_ALLDROUTERS		"224.0.0.6"

/* OSPF Authentication Type. */
#define OSPF_AUTH_NULL			0
#define OSPF_AUTH_SIMPLE		1
#define OSPF_AUTH_CRYPTOGRAPHIC		2

/* OSPF interface default values. */
#define OSPF_HELLO_INTERVAL_DEFAULT	   10
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40

#define OSPF_ROUTER_PRIORITY_DEFAULT	    1
#define OSPF_TRANSMIT_DELAY_DEFAULT        30
#define OSPF_OUTPUT_COST_DEFAULT          100
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT   30

#define OSPF_AREA_ID_FORMAT_ADDRESS         1
#define OSPF_AREA_ID_FORMAT_DECIMAL         2

/* OSPF instance structure. */
struct ospf
{
  u_int32_t process_id;			/* OSPF Process ID. */

  struct _list *if_list;		/* Zebra interface list. */
  struct _list *neighbor;		/* OSPF neighbor list. */

  /* configuration data. */
  struct route_table *network_area;	/* OSPF config network_area. */
};

/* OSPF config area structure. */
struct area
{
  int area_id_format;
  struct in_addr area_id;
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
extern int ospf_ism_status_msg_max;
extern int ospf_nsm_status_msg_max;

extern char *progname;

/* Prototypes. */
void ospf_init (void);
void ospf_if_update (void);

extern struct thread_master *master;

#endif /* _ZEBRA_OSPFD_H */
