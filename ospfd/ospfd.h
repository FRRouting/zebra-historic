/* OSPFd main routine.
   Copyright (C) 1998 Kunihiro Ishiguro

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

/* Default protocol, port number. */
#define OSPF_PROTO_DEFAULT   89
#define OSPF_VTY_PORT	   2604

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG "ospfd.conf"

/* OSPF message header. */
#define OSPF_AUTH_SIZE	8

/* OSPF packet header structure. */
struct ospf_header
{
  u_char version;
  u_char type;
  u_int16_t length;
  struct in_addr router_id;
  struct in_addr area_id;
  u_int16_t checksum;
  u_int16_t auth_type;
  u_char auth_data[OSPF_AUTH_SIZE];
};

/* OSPF Hello body format. */
/* struct ospf_hello_body */
struct _ospf_hello
{
  struct in_addr network_mask;
  u_int16_t hello_interval;
  u_char options;
  u_char priority;
  u_int32_t dead_interval;
  struct in_addr d_router;
  struct in_addr bd_router;
  struct in_addr neighbor[1];
};

/* OSPF Database Description body format. */
struct _ospf_db_desc
{
  u_int16_t interface_mtu;
  u_char options;
  u_char flags;
  u_int32_t seq_number;
  struct ospf_lsa lsa[1];
};

/* OSPF Link State Request body format. */
struct _ospf_ls_req
{
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;
};

/* OSPF Link State Update body format. */
struct _ospf_ls_upd
{
  u_int32_t number_lsa;
  struct ospf_lsa lsa[1];
};

/* OSPF Link State Ack body format. */
struct _ospf_ls_ack
{
  struct ospf_lsa_header lsa_header[1];
};

/* Neighbor Data Structure */
struct ospf_neighbor {
  /* Neighbor Information */
  u_char state;
  u_int32_t inactivity_timer;
  u_char master_slave;
  u_int32_t dd_sequence_number;
  u_int32_t last_received_db_desc;
  struct in_addr nbr_id;
  u_int16_t nbr_priority;
  struct in_addr nbr_ip_addr;
  u_char nbr_options;
  struct in_addr neighbors_drouter;
  struct in_addr neighbors_bdrouter;
  struct hoge * link_state_retransmission;
  struct hoge * database_summary;
  struct hoge * link_state_request;

  /* Timer values. */
  /* Threads. */
  /* Statistics Field */
};

/* OSPF packet structure format. */
struct ospf_packet
{
  struct ospf_header header;
  union
  {
    /* OSPF Hello body */
    struct _ospf_hello hello;

    /* OSPF Database Description body */
    struct _ospf_db_desc db_desc;

    /* OSPF Link State Request body */
    struct _ospf_ls_req ls_req[1];

    /* OSPF Link State Update body */
    struct _ospf_ls_upd ls_upd;

    /* OSPF Link State Ack body */
    struct _ospf_ls_ack ls_ack;
  } un_ospf;
};

#define ospf_hello	un_ospf.hello
#define ospf_db_desc	un_ospf.db_desc
#define ospf_ls_req	un_ospf.ls_req
#define ospf_ls_upd	un_ospf.ls_upd
#define ospf_ls_ack	un_ospf.ls_ack

/* Interface Data Structure */
struct ospf_interface {
  u_char type;
  u_char state;
  struct in_addr ip_intf_addr;
  struct in_addr ip_intf_mask;
  struct in_addr area_id;
  u_int16_t hello_interval;
  u_int32_t rtr_dead_interval;
  u_int32_t intf_trans_delay;
  u_char router_priority;
  u_int32_t hello_timer;
  u_int32_t wait_timer;
  struct ospf_neighbor neighbors;
  struct in_addr drouter;
  struct in_addr bdrouter;
  u_int32_t intf_output_cost;
  u_int32_t rxmt_interval;
  u_int16_t auth_type;
  u_char auth_key[8];
};


/* Architectual Constants */
#define OSPF_LS_REFRESH_TIME		1800
#define OSPF_MIN_LS_INTERVAL		   5
#define OSPF_MIN_LS_ARRIVAL		   1
#define OSPF_MAX_AGE			3600
#define OSPF_CHECK_AGE			 300
#define OSPF_MAX_AGE_DIFF		 900
#define OSPF_LS_INFINITY		0xffffff
#define OSPF_DEFAULT_DESTINATION	0.0.0.0
#define OSPF_INITIAL_SEQUENCE_NUMBER	0x80000001
#define OSPF_MAX_SEQUENCE_NUMBER	0x7fffffff

/* Prototypes. */
void ospf_terminate ();
