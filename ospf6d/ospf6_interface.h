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

#ifndef OSPF6_INTERFACE_H
#define OSPF6_INTERFACE_H

/* This file defines interface data structure. */

struct ospf6_if
{
  struct interface *interface;       /* IF info from zebra */
  struct area      *area;            /* back pointer to area */
  list              nbr_list;        /* list of neighbor found in this IF */

  struct in6_addr  *myaddr;
  list prefix_connected;

  unsigned long     ifid;
  unsigned char     instance_id;
  unsigned long     inf_trans_delay; /* I/F transmission delay, default 1sec */
  rtr_pri_t         rtr_pri;
  hello_int_t       hello_interval;
  rtr_dead_int_t    rtr_dead_interval; /* 4 times by hello_interval */
  cost_t            cost;            /* output cost */
  rxmt_int_t        rxmt_interval;   /* default 5 sec */
  unsigned long     ifmtu;

  state_t           state;
  rtr_id_t          dr;
  rtr_id_t          bdr;
  rtr_id_t          prevdr;
  rtr_id_t          prevbdr;

  struct thread    *send_hello;
  struct thread    *send_ack;        /* Timer for delayed Ack */

  list              delayed_ack;
  list              linklocal_lsa;   /* include Link-LSA */


  signed long     link_lsa_seqnum;      /* Signed 32bit integer */
  signed long     network_lsa_seqnum;   /* Signed 32bit integer */
  signed long     intra_prefix_seqnum;  /* Signed 32bit integer */

  /* statistics */
  unsigned int ospf6_stat_dr_election;
  unsigned int ospf6_stat_delayed_lsack;
};

struct ospf6_interface
{
  struct interface *interface;       /* IF info from zebra */
  struct area      *area;            /* back pointer to area */
  list              neighbor_list;   /* list of struct neighbor */

  struct in6_addr  *lladdr;          /* linklocal address of this I/F */
  list              prefix_list;     /* list of struct in6_addr */

  u_int32_t     if_id;
  u_char     instance_id;
  u_int32_t     transdelay;      /* I/F transmission delay */
  u_char     priority;
  u_int16_t    hello_interval;
  u_int16_t    dead_interval;
  u_int32_t     cost;
  u_int32_t     rxmt_interval;
  u_int32_t     ifmtu;

  unsigned char     state;
  u_int32_t     dr;
  u_int32_t     bdr;
  u_int32_t     prevdr;
  u_int32_t     prevbdr;

  struct thread    *thread_send_hello;
  struct thread    *thread_send_lsack_delayed; /* Timer for delayed Ack */

  list              lsa_delayed_ack;
  list              lsdb;                      /* includes Link-LSA */

  /* Sequence number place holder */
  int32_t       lsa_seqnum_link;
  int32_t       lsa_seqnum_network;
  int32_t       lsa_seqnum_intra_prefix;

  /* statistics */
  unsigned int ospf6_stat_dr_election;
  unsigned int ospf6_stat_delayed_lsack;
};



/* Function Prototypes */
void ospf6_if_init ();
struct in6_addr *ospf6_if_linklocal_addr (struct interface *);
struct ospf6_if *make_ospf6_if (struct interface *);
void delete_ospf6_if (struct ospf6_if *);
struct ospf6_if *ospf6_if_lookup (char *);
struct ospf6_if *ospf6_if_lookup_by_index (int);
int ospf6_if_count_full_nbr (struct ospf6_if *);
int ospf6_if_get_linklocal (struct in6_addr *, struct ospf6_if *);
int ospf6_if_is_enabled (struct ospf6_if *);
int show_if (struct vty *, struct interface *);
int ospf6_if_config_write (struct vty *);
void ospf6_if_init ();

#endif /* OSPF6_INTERFACE_H */

