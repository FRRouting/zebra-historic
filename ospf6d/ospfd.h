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

#ifndef OSPFD_H
#define OSPFD_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet6/ip6.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>

/* include other stuffs */
#include "version.h"
#include "log.h"
#include "getopt.h"
#include "vty.h"
#include "linklist.h"
#include "thread.h"
#include "vector.h"
#include "command.h"
#include "memory.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "client.h"
#include "stream.h"
#include "zebra/zebra.h"

#if 0
#define HASHVAL     256
#define MAXLSDBSIZE 128
#define MAXBRANCH   128
#else
#define HASHVAL     64
#define MAXLSDBSIZE 64
#define MAXBRANCH   64
#endif
#define hash(x)        ((x) % HASHVAL)


/* OSPF stuffs */
#include "ospf_types.h"
#include "ospf_mesg.h"
#include "ospf_interface.h"
#include "ospf_lsa.h"
#include "ospf_spf.h"
#include "ospf_area.h"
#include "ospf_neighbor.h"
#include "ospf_network.h"
#include "ospf_proto.h"

#ifndef DEBUG_OSPF
#define DEBUG_OSPF
#endif

#ifdef DEBUG_OSPF

/*
#ifndef DEBUG_HELLO
#define DEBUG_HELLO
#endif
*/

#ifndef DEBUG_DATABASE_DESCRITPION
#define DEBUG_DATABASE_DESCRIPTION
#endif

#ifndef DEBUG_LINKSTATE_REQUEST
#define DEBUG_LINKSTATE_REQUEST
#endif

#ifndef DEBUG_LINKSTATE_UPDATE
#define DEBUG_LINKSTATE_UPDATE
#endif

#ifndef DEBUG_LINKSTATE_ACK
#define DEBUG_LINKSTATE_ACK
#endif

#ifndef DEBUG_LSA_PTR
#define DEBUG_LSA_PTR
#endif

#ifndef DEBUG_SPFCALC
#define DEBUG_SPFCALC
#endif

#endif /* DEBUG_OSPF */

extern struct thread_master *master;
extern struct ospfstat ospfstat;
extern struct afswitch inet;
extern struct afswitch inet6;
extern list ospf_list;
extern list ospf_iflist;
extern char *ifs_name[];
extern char *nbs_name[];
extern char *mesg_name[];

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG		"ospfd.conf"

/* Default port values. */
#define OSPF_VTY_PORT			2604

#define DEFAULT_HELLO_INTERVAL		10
#define DEFAULT_ROUTER_DEAD_TIMER	40

#define MAXOSPFMESSAGELEN		4096

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef HYDRANGEA
#define IPV6_ADD_MEMBERSHIP		IPV6_JOIN_GROUP
#endif
#ifdef KAME
#ifdef IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP		IPV6_JOIN_GROUP
#endif
#ifdef IPV6_JOIN_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP		IPV6_JOIN_MEMBERSHIP
#endif
#endif
#endif

#ifndef IPV6_DROP_MEMBERSHIP
#ifdef IPV6_LEAVE_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif
#endif

/* Command Description */
#define OSPF_STR "OSPF information\n"
#define OSPF_INTERFACE_STR "OSPF Interface infomation\n"
#define OSPF_NEIGHBOR_STR "OSPF Neighbor information\n"
#define V4NOTATION_STR "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define OSPF_ROUTER_STR "OSPF Router infomation\n"
#define OSPF_IFNAME_STR "Interface name(e.g. ep0)\n"
#define OSPF_NUMBER_STR "Specify by number\n"

extern int ospf_sock;
extern struct
{
  char *name;
  unsigned long alloc;
} mstat[MTYPE_MAX];


struct ospfstat
{
  u_long ospfs_total;		/* total packets received */
  u_long ospfs_drop;		/* packets dropped */
  u_long ospfs_recvinet;	/* inet packets received */
  u_long ospfs_recvinet6;	/* inet6 packets received */
  u_long ospfs_pktloopback;	/* receive locally originated one */
  u_long ospfs_norecvif;	/* receive i/f not fount */
  u_long ospfs_recvver2;	/* version 2 packet received */
  u_long ospfs_recvver3;	/* version 3 packet received */
  u_long ospfs_verunknown;	/* version unknown */
  u_long ospfs_vermismatch;	/* version mismatch */
  u_long ospfs_areamismatch;	/* receive i/f area mismatch */
  u_long ospfs_badsum;		/* checksum bad */
  u_long ospfs_authfail;	/* authentication fail */
  u_long ospfs_unknowntype;	/* message type unknown */
};

/* Function Prototype */
struct neighbor *nb_lookup_by_nb_id (rtr_id_t, list);
struct neighbor *make_neighbor (rtr_id_t, struct ospf_if *);
struct ospf_if *if_lookup_by_addr (struct prefix *, list);
struct ospf_if *if_lookup_by_addr_in_net (struct prefix *, list);
struct ospf_if *if_lookup_by_ifname (char *, list);
struct ospf_if *make_interface (char *);
void ospf_init ();
void detach_interface (struct ospf_if *, struct area *);
int show_area (struct vty *, struct area *);
int show_area_if_all (struct vty *, list);
int show_all_neighbor (struct vty *);
int show_ospf_top_all (struct vty *);
int show_ospf_top (struct vty *, struct ospf *);
int show_int (struct vty *, struct ospf_if *);
int ospf_config_write (struct vty *);


void list_free (list);

#endif /* OSPFD_H */
