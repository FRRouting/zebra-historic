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

#ifndef OSPF6D_H
#define OSPF6D_H

#include <zebra.h>

/* Include other stuffs */
#include "zebra/zebra.h"

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
#include "stream.h"
#include "thread.h"
#include "filter.h"
#include "client.h"
#include "zclient.h"

#define HASHVAL 64

/* OSPF stuffs */
#include "ospf6_types.h"
#include "ospf6_interface.h"
#include "ospf6_lsa.h"
#include "ospf6_dump.h"
#include "ospf6_spf.h"
#include "ospf6_area.h"
#include "ospf6_mesg.h"
#include "ospf6_neighbor.h"
#include "ospf6_network.h"
#include "ospf6_proto.h"
#include "ospf6_zebra.h"

#ifndef DEBUG_OSPF6
#define DEBUG_OSPF6
#endif

#ifdef DEBUG_OSPF6

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

#endif /* DEBUG_OSPF6 */

extern int     errno;
extern list    iflist;
extern struct  thread_master *master;
extern list    ospf6_list;
extern int     ospf6_sock;
extern int     daemon_mode;
extern struct  sockaddr_in6 allspfrouters6;
extern struct  sockaddr_in6 alldrouters6;
extern char   *progname;

/* Default configuration file name for ospfd. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

#define DEFAULT_HELLO_INTERVAL    10
#define DEFAULT_ROUTER_DEAD_TIMER 40

#define MAXOSPFMESSAGELEN         4096
#define MAXIOVLIST 1024

#ifdef INRIA_IPV6
#ifndef IPV6_PKTINFO
#define IPV6_PKTINFO IPV6_RECVPKTINFO
#endif /* IPV6_PKTINFO */
#endif /* INRIA_IPV6 */

/* historycal for KAME */
#ifndef IPV6_ADD_MEMBERSHIP
#ifdef HYDRANGEA
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#ifdef KAME
#ifdef IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#ifdef IPV6_JOIN_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_MEMBERSHIP
#endif
#endif
#endif

#ifndef IPV6_DROP_MEMBERSHIP
#ifdef  IPV6_LEAVE_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif
#endif

#define INSTALL   1
#define NOINSTALL 0

/* Command Description */
#define V4NOTATION_STR     "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define OSPF6_NUMBER_STR    "Specify by number\n"

#define INTERFACE_STR       "Interface infomation\n"
#define IFNAME_STR          "Interface name(e.g. ep0)\n"
#define IP6_STR             "IP6 Information\n"
#define OSPF6_STR           "Open Shortest Path First (OSPF) for IPv6\n"
#define OSPF6_ROUTER_STR    "Enable a routing process\n"
#define OSPF6_INSTANCE_STR  "<1-65535> Instance ID\n"
#define SECONDS_STR         "<1-65535> Seconds\n"
#define ROUTE_STR           "Routing Table\n"

#define HASHVAL   64
#define hash(x)  ((x) % HASHVAL)

/* Function Prototypes */
struct ospf6 *make_ospf6 (rtr_id_t);
struct ospf6 *ospf6_lookup (instance_id_t);
struct area  *make_area (area_id_t, struct ospf6 *);
struct area *area_lookup (area_id_t, struct ospf6 *);
struct ospf6_if *make_ospf6_if (char *);
struct ospf6_if *ospf6_if_lookup (char *);
struct ospf6_if *ospf6_if_lookup_by_addr (struct prefix *);
struct ospf6_if *ospf6_if_lookup_by_addr_in_net (struct prefix *);
struct neighbor *make_neighbor (rtr_id_t, struct ospf6_if *);
struct neighbor *nbr_lookup (rtr_id_t, struct ospf6 *);
void ospf6_terminate ();
int show_ospf6_top (struct vty *, struct ospf6 *);
int show_area (struct vty *, struct area *);
int show_if (struct vty *, struct interface *);
int show_nbr (struct vty *, struct neighbor *);
void ospf6_init ();

#endif /* OSPF6D_H */

