/*
 * OSPFd main header.
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_OSPFD_H
#define _ZEBRA_OSPFD_H

#include "filter.h"

#define OSPF_VERSION            2

/* Default protocol, port number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif /* IPPROTO_OSPFIGP */

/* VTY port number. */
#define OSPF_VTY_PORT          2604

/* IP TTL for OSPF protocol. */
#define OSPF_IP_TTL             1
#define OSPF_VL_IP_TTL          100

/* Default configuration file name for ospfd. */
#define OSPF_DEFAULT_CONFIG   "ospfd.conf"

enum
{
  /* Debug option. */
  DEBUG_OSPF_ISM = 0x01,
  DEBUG_OSPF_NSM = 0x02,
};

/* Architectual Constants */
#define OSPF_LS_REFRESH_TIME                  1800
#define OSPF_MIN_LS_INTERVAL                     5
#define OSPF_MIN_LS_ARRIVAL                      1
#define OSPF_LSA_MAX_AGE                      3600
#define OSPF_CHECK_AGE                         300
#define OSPF_LSA_MAX_AGE_DIFF                  900
#define OSPF_LS_INFINITY                  0xffffff
#define OSPF_DEFAULT_DESTINATION        0x00000000      /* 0.0.0.0 */
#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001
#define OSPF_MAX_SEQUENCE_NUMBER        0x7fffffff

#define OSPF_LSA_MAX_AGE_CHECK_INTERVAL         30

#define OSPF_ALLSPFROUTERS              0xe0000005      /* 224.0.0.5 */
#define OSPF_ALLDROUTERS                0xe0000006      /* 224.0.0.6 */

#define OSPF_AREA_BACKBONE              0x00000000      /* 0.0.0.0 */

/* OSPF Authentication Type. */
#define OSPF_AUTH_NULL                      0
#define OSPF_AUTH_SIMPLE                    1
#define OSPF_AUTH_CRYPTOGRAPHIC             2

/* OSPF interface default values. */
#define OSPF_OUTPUT_COST_DEFAULT           10
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40
#define OSPF_HELLO_INTERVAL_DEFAULT        10
#define OSPF_ROUTER_PRIORITY_DEFAULT        1
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT    5
#define OSPF_TRANSMIT_DELAY_DEFAULT         1

/* Area ID Format type. */
#define OSPF_AREA_ID_FORMAT_ADDRESS         1
#define OSPF_AREA_ID_FORMAT_DECIMAL         2

/* Area External Routing Capability. */
#define OSPF_AREA_DEFAULT                   0
#define OSPF_AREA_STUB                      1
#define OSPF_AREA_NSSA                      2

/* OSPF options. */
#define OSPF_OPTION_T                    0x01  /* TOS. */
#define OSPF_OPTION_E                    0x02
#define OSPF_OPTION_MC                   0x04
#define OSPF_OPTION_NP                   0x08
#define OSPF_OPTION_EA                   0x10
#define OSPF_OPTION_DC                   0x20

/* OSPF Database Description flags. */
#define OSPF_DD_FLAG_MS                  0x01
#define OSPF_DD_FLAG_M                   0x02
#define OSPF_DD_FLAG_I                   0x04
#define OSPF_DD_FLAG_ALL                 0x07

/* OSPF Transit Capability. */
#define OSPF_TRANSIT_FALSE               0
#define OSPF_TRANSIT_TRUE                1


/* OSPF ABR/ASBR internal flags */

#define OSPF_FLAG_ABR           0x0001  /* The router is an ABR  */
#define OSPF_FLAG_ASBR          0x0002  /* The router is an ASBR */

#define OSPF_IS_ABR		(ospf_top->flags & OSPF_FLAG_ABR)
#define OSPF_IS_ASBR		(ospf_top->flags & OSPF_FLAG_ASBR)

#define OSPF_IS_AREA_BACKBONE(A) \
	((A)->area_id.s_addr == OSPF_AREA_BACKBONE)

/* OSPF ABR types */
#define OSPF_ABR_UNKNOWN        0
#define OSPF_ABR_STAND          1
#define OSPF_ABR_IBM            2
#define OSPF_ABR_CISCO          3
#define OSPF_ABR_SHORTCUT       4

/* Timer value. */
#define OSPF_ROUTER_ID_UPDATE_DELAY             1


/* OSPF instance structure. */
struct ospf
{
  /* OSPF Router ID. */
  struct in_addr router_id;

  /* OSPF Router ID configured manually. */
  struct in_addr router_id_static;

  u_char flags;                         /* ABR/ASBR internal flags. */
  u_char abr_type;                      /* ABR type. */
  u_char RFC1583Compat;                 /* RFC1583Compatibility flag. */

  list iflist;                          /* Zebra interface list. */
  list vlinks;                          /* List of configured VLs. */

  list areas;                           /* OSPF areas. */
  struct ospf_area *backbone;           /* Pointer to the Backbone. */
  struct route_table *networks;         /* OSPF config networks. */

  struct ospf_lsdb *external_lsa;	/* LSDB of AS-external-LSAs. */
  struct route_table *external_self;    /* Self-originated ASE-LSAs. */
  struct route_table *external_route;   /* External Route. */
  struct route_table *rtrs_external;	/* Table for Looking up AS-external-LSA
					   related to an ASBR route. */
  list external_lsa_queue;		/* Initial queue of ASE-LSAs. */

  struct route_table *old_table;        /* Old routing table. */
  struct route_table *new_table;        /* Current routing table. */

  struct route_table *old_rtrs;         /* Old ABR/ASBR RT. */
  struct route_table *new_rtrs;         /* New ABR/ASBR RT. */

  /* Threads. */
  struct thread *t_router_id_update;	/* Router ID update thread. */

  int spf_calc;		                /* SPF calculation flag. */
  struct thread *t_spf_calc;	        /* SPF calculation timer. */
  time_t ts_spf;			/* SPF calculation time stamp. */

  int ase_calc;				/* ASE calculation flag. */
  struct thread *t_ase_calc;		/* ASE calculation timer. */

  list maxage_lsa;                      /* List of MaxAge LSA for deletion. */
  struct thread *t_maxage;              /* The thread to delete MaxAge LSAs. */
  struct thread *t_maxage_walker;       /* The thread of checking MaxAge 
                                           LSAs. */

  struct thread *t_rlsa_update;         /* The thread to update Router-LSAs. */
  struct thread *t_abr_task;            /* Thread to run ABR functions. */
  struct thread *t_asbr_check;          /* Thread to check ASE-LSAs. */

  int redistribute;                     /* Number of redistributed protocols. */

  /* Distribute lists out of other route sources. */
  struct 
  {
    char *name;
    struct access_list *list;
  } dist_lists_proto [ZEBRA_ROUTE_MAX];

#define LIST_NAME(T) ospf_top->dist_lists_proto[T].name
#define LIST_PTR(T)  ospf_top->dist_lists_proto[T].list

  struct 
  {
    u_char  metric_type;                /* Ext. metric type (E1 or E2).  */
    u_char  metric_method;              /* How ext. metric is specified. */

#define OSPF_EXT_METRIC_AUTO    0
#define OSPF_EXT_METRIC_STATIC  1

    u_int32_t metric_value;             /* Value for static metric (24-bit). */
  } dist_info [ZEBRA_ROUTE_MAX];

  list            refresh_queue;          /* LSA Refreshment Queue. */
  struct thread * t_lsa_refresher;        /* Refreshment Queue Server. */
  int             refresh_queue_interval; /* How often the is served. */
  int             refresh_queue_limit;    /* How many LSAs per interval. */
  int             refresh_queue_count;    /* How many updated. */

#define OSPF_REFRESH_QUEUE_INTERVAL 1
#define OSPF_REFRESH_QUEUE_RATE     70
#define OSPF_REFRESH_PER_SLICE      5

#define OSPF_LS_REFRESH_SHIFT       (60 * 15)
#define OSPF_LS_REFRESH_JITTER      10

  list            refresh_group;        /* LSA Refresh Group. */
  struct thread * t_refresh_group;      /* Refresh Group Checker. */
  u_int16_t       group_age;            /* Min AGE in the LSA Group. */

#define OSPF_REFRESH_GROUP_TIME    1
#define OSPF_REFRESH_GROUP_AGE_DIF 3    /* We don't care if age is +-1 sec. */
#define OSPF_REFRESH_GROUP_LIMIT   10   

};


#define OSPF_SCHEDULE_MAXAGE(T, F) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), 0, 2)

#define OSPF_SCHEDULE_RLSA_UPDATE(T, F) \
      if (!(T)) \
        (T) = thread_add_timer (master, (F), 0, 2)


/* Constants for ShortcutConfigured */

#define OSPF_SHORTCUT_DEFAULT 0
#define OSPF_SHORTCUT_ENABLE  1
#define OSPF_SHORTCUT_DISABLE 2

/* OSPF area structure. */
struct ospf_area
{
  struct ospf * top;

  int count;                            /* Reference count by ospf_network. */

  list iflist;                          /* list of Zebra if's belonging to
                                           the area.  */
  struct in_addr area_id;               /* Area ID. */
  char format;                          /* Area ID format. */
  list address_range;

  /* Configuration variables. */
  int external_routing;                 /* ExternalRoutingCapability. */
  int no_summary;                       /* Don't inject summaries into stub area. */
  int shortcut_configured;              /* Area configured as shortcut. */
  int shortcut_capability;              /* Other ABRs agree on S-bit */
  u_int32_t default_cost;               /* StubDefaultCost. */
  int auth_type;                        /* Authentication type. */

  /* Area related LSAs. */
  struct ospf_lsdb *lsa[4];

  /* self originated LSAs. */
  struct ospf_lsa *router_lsa_self;
  /* struct route_table *summary_lsa_self; */
  /* struct route_table *summary_lsa_asbr_self; */

  struct 
  {
    char *name;
    struct access_list *list;
  } export_list;                        /* area announce list. */

#define EXP_LIST_NAME(A) (A)->export_list.name
#define EXP_LIST_PTR(A)  (A)->export_list.list

  struct 
  {
    char *name;
    struct access_list *list;
  } import_list;                        /* area acceptance list. */

#define IMP_LIST_NAME(A) (A)->import_list.name
#define IMP_LIST_PTR(A)  (A)->import_list.list


  /* Self originated LSAs reflesh thread test. */
  struct thread *t_router_lsa_self;

  /* Shortest Path Tree. */
  struct vertex *spf;

  /* Statistics field. */
  u_int32_t spf_calculation;		/* SPF Calculation Count. */

  /* TransitCapability. */
  u_char transit;

  struct route_table *ranges;           /* Configured Area Ranges. */

  u_int  act_ints;                      /* Number of active interfaces. */
  u_int  full_nbrs;                     /* Number of fully adjacent
                                           nbrs in this area. */
  u_int  full_vls;                      /* Number of fully adjacent
                                           virtual nbrs. */
};

#define ROUTER_LSA(a)                   (a)->lsa[0]
#define NETWORK_LSA(a)                  (a)->lsa[1]
#define SUMMARY_LSA(a)                  (a)->lsa[2]
#define SUMMARY_LSA_ASBR(a)             (a)->lsa[3]

/* OSPF config network structure. */
struct ospf_network
{
  struct in_addr area_id;                       /* Area ID. */

  /* interface associated with network. */
  struct interface *ifp;
};

/* Macro. */
#define OSPF_AREA_SAME(X,Y)   (memcmp ((X->area_id), (Y->area_id), IPV4_MAX_BYTELEN) == 0)

#define CHECK_FLAG(V,F)\
        (V & F)

#define SET_FLAG(V,F)\
        V = V | (F)

#define UNSET_FLAG(V,F)\
        V = V & ~(F)


#define LIST_ITERATOR(L, N) \
      for ((N) = listhead ((L)); (N); nextnode(N))

#define RT_ITERATOR(R, N) \
      for ((N) = route_top ((R)); (N); (N) = route_next ((N)))


#define OSPF_TIMER_OFF(X) \
      do { \
       if (X) \
         { \
           thread_cancel (X); \
           (X) = NULL; \
         } \
      } while (0)

/* Messages */
extern struct message ospf_ism_status_msg[];
extern struct message ospf_nsm_status_msg[];
extern struct message ospf_lsa_type_msg[];
extern struct message ospf_link_state_id_type_msg[];
extern int ospf_ism_status_msg_max;
extern int ospf_nsm_status_msg_max;
extern int ospf_lsa_type_msg_max;
extern int ospf_link_state_id_type_msg_max;

extern char *progname;

/* Prototypes. */
void ospf_init (void);
void ospf_if_update (void);
void ospf_terminate (void);
void ospf_route_init (void);
void ospf_init_end (void);

extern struct thread_master *master;
extern struct ospf *ospf_top;

struct ospf_area *ospf_area_new (struct in_addr);
struct ospf_area *ospf_area_lookup_by_area_id (struct in_addr);
void ospf_interface_down (struct ospf *, struct prefix *, struct ospf_area *);

extern int ospf_zlog;

#endif /* _ZEBRA_OSPFD_H */
