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

#ifndef OSPF_INTERFACE_H
#define OSPF_INTERFACE_H

/* This file defines interface data structure. */

struct ospf_if
{
  struct interface *interface;       /* IF info from zebra */
  char *ifname;
  ifid_t ifid;

  struct area *area;                /* back pointer */
  state_t state;
  u_int32_t inf_trans_delay;        /* default 1 sec */
  rtr_pri_t rtr_pri;                /* 8-bit */
  hello_int_t hello_interval;
  rtr_dead_int_t rtr_dead_interval; /* 4 times by hello_interval */
  cost_t cost;                      /* output cost */
  rxmt_int_t rxmt_interval;         /* default 5 sec */
  autype_t autype;                  /* authentication type */
  char auth_data[8];                /* authentication key */
  list nb_list;                     /* list of (struct neighbor *) */
  rtr_id_t dr;                      /* in OSPFv2 this is interface id. */
  rtr_id_t prevdr;
  rtr_id_t bdr;                     /* in OSPFv2 this is interface id. */
  rtr_id_t prevbdr;

#ifdef NBMA                         /* for Non Broadcast Multiaccess Network */
  u_int32_t poll_interval;          /* Not yet */
#endif /* NBMA */

  struct thread *send_hello;
  struct thread *send_ack;          /* for delayed Ack */
  struct lsa_internal *delayed_ack[256];

  list linklocal_lsa;               /* include Link-LSA */
};

/* Authentication */
#define AUTYPE_NULL		0
#define AUTYPE_SIMPLE_PASSWD	1
#define AUTYPE_CRYPTOGRAPHIC	2
#define AUTYPE_OTHER		3

/* interface state */
#define IFS_NONE		0
#define	IFS_DOWN		1
#define	IFS_LOOPBACK		2
#define IFS_WAITING		3
#define IFS_PTOP		4
#define IFS_DROTHER		5
#define IFS_BDR			6
#define IFS_DR			7

/* interface event */
int interface_up (struct thread *);
int interface_down (struct thread *);
int wait_timer (struct thread *);
int backup_seen (struct thread *);
int neighbor_change (struct thread *);

void get_interface_all ();
void show_address (struct vty *, struct ospf_if *);
prefixlen_t mask2prefix (const char *, const int);
struct network *get_address (struct rt_addrinfo *);
void address_prepare (struct ospf_if *);

int send_hello (struct thread *);
int send_database_description (struct thread *);

int dr_change (struct ospf_if *);

#endif /* OSPF_INTERFACE_H */

