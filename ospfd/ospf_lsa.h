/*
 * OSPF Link State Advertisement
 * Copyright (C) 1999, 2000 Toshiaki Takada
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

#ifndef _ZEBRA_OSPF_LSA_H
#define _ZEBRA_OSPF_LSA_H

/* OSPF LSA Type definition. */
#define OSPF_UNKNOWN_LSA	0
#define OSPF_MIN_LSA		1
#define OSPF_ROUTER_LSA         1
#define OSPF_NETWORK_LSA        2
#define OSPF_SUMMARY_LSA        3
#define OSPF_SUMMARY_LSA_ASBR   4
#define OSPF_AS_EXTERNAL_LSA    5
#define OSPF_MAX_LSA		6

#define OSPF_LSA_HEADER_SIZE	20
#define OSPF_MAX_LSA_SIZE	1500

/* OSPF LSA origination flag. */
#define OSPF_LSA_SELF		  0x01
#define OSPF_LSA_SELF_CHECKED	  0x02
#define OSPF_LSA_RECEIVED	  0x04
#define OSPF_LSA_APPROVED	  0x08

/* OSPF LSA header. */
struct lsa_header
{
  u_int16_t ls_age;
  u_char options;
  u_char type;
  struct in_addr id;
  struct in_addr adv_router;
  int ls_seqnum;
  u_int16_t checksum;
  u_int16_t length;
};

/* OSPF LSA. */
struct ospf_lsa
{
  /* LSA origin flag. */
  u_char flags;

  /* LSA redistribute type. */
  u_char redistribute;

  /* LSA data. */
  struct lsa_header *data;

  /* Received time stamp. */
  time_t ts;

  /* Timer value. */
  u_int32_t v_age;
  
  /* Thread. */
  struct thread *t_age;

  /* References to this LSA in neighbor retrans. lists*/
  u_int ref;

  /* Parent LSDB. */
  struct ospf_lsdb *lsdb;

  /* Related Route. */
  void *route;

  /* Last time it was originated */
  time_t originated; 

  /* Refreshement List or Queue */
  list refresh_list;
};

/* OSPF LSA Link Type. */
#define LSA_LINK_TYPE_POINTOPOINT      1
#define LSA_LINK_TYPE_TRANSIT          2
#define LSA_LINK_TYPE_STUB             3
#define LSA_LINK_TYPE_VIRTUALLINK      4

/* OSPF Router LSA Flag. */
#define ROUTER_LSA_BORDER	       0x01 /* The router is an ABR */
#define ROUTER_LSA_EXTERNAL	       0x02 /* The router is an ASBR */
#define ROUTER_LSA_VIRTUAL	       0x04 /* The router has a VL in this area */
#define ROUTER_LSA_NT		       0x10 /* NSSA-specific flag */
#define ROUTER_LSA_SHORTCUT	       0x20 /* Shortcut-ABR specific flag */

#define IS_ROUTER_LSA_VIRTUAL(x)       ((x)->flags & ROUTER_LSA_VIRTUAL)
#define IS_ROUTER_LSA_EXTERNAL(x)      ((x)->flags & ROUTER_LSA_EXTERNAL)
#define IS_ROUTER_LSA_BORDER(x)	       ((x)->flags & ROUTER_LSA_BORDER)
#define IS_ROUTER_LSA_SHORTCUT(x)      ((x)->flags & ROUTER_LSA_SHORTCUT)

/* OSPF Router-LSA Link information. */
struct router_lsa_link
{
  struct in_addr link_id;
  struct in_addr link_data;
  struct {
    u_char type;
    u_char tos_count;
    u_int16_t metric;
  } m[1];
};

/* OSPF Router-LSAs structure. */
struct router_lsa
{
  struct lsa_header header;
  u_char flags;
  u_char zero;
  u_int16_t links;
  struct {
    struct in_addr link_id;
    struct in_addr link_data;
    u_char type;
    u_char tos;
    u_int16_t metric;
  } link[1];
};

/* OSPF Network-LSAs structure. */
struct network_lsa
{
  struct lsa_header header;
  struct in_addr mask;
  struct in_addr routers[1];
};

/* OSPF Summary-LSAs structure. */
struct summary_lsa
{
  struct lsa_header header;
  struct in_addr mask;
  u_char tos;
  u_char metric[3];
};

/* OSPF AS-external-LSAs structure. */
struct as_external_lsa
{
  struct lsa_header header;
  struct in_addr mask;
  struct {
    u_char tos;
    u_char metric[3];
    struct in_addr fwd_addr;
    u_int32_t route_tag;
    /*    struct in_addr route_tag; */
  } e[1];
};

/* Redistributed external information. */
struct external_info
{
  u_char flags;				/* Origination flag. */
  struct prefix_ipv4 p;			/* Prefix. */
  unsigned int ifindex;			/* Interface Index. */
  struct in_addr nexthop;		/* Nexhoop address. */
  u_int32_t tag;			/* Additional Route tag. */
  /* struct ospf_lsa *lsa; */		/* Originated-LSA. */
};

#define EXTERNAL_INITIAL		0x00
#define EXTERNAL_ORIGINATED		0x01
#define EXTERNAL_FILTERED		0x02


#define EXTERNAL_METRIC_TYPE_1      0
#define EXTERNAL_METRIC_TYPE_2      1

/* Macros. */
#define GET_METRIC(x) get_metric(x)
#define IS_EXTERNAL_METRIC(x)   ((x) & 0x80)

#define GET_AGE(x)      (ntohs ((x)->data->ls_age) + time (NULL) - (x)->ts)
#define LS_AGE(x)       (OSPF_LSA_MAX_AGE < GET_AGE(x) ? \
                                            OSPF_LSA_MAX_AGE : GET_AGE(x))

#define OSPF_SUMMARY_LSA_SELF_FIND_BY_PREFIX(A,P) \
        ospf_lsdb_iterator (SUMMARY_LSA ((A)), \
                            (struct prefix_ipv4 *) (P), 0, find_summary)

#define OSPF_SUMMARY_ASBR_LSA_SELF_FIND_BY_PREFIX(A,P) \
        ospf_lsdb_iterator (SUMMARY_LSA_ASBR ((A)), \
                            (struct prefix_ipv4 *) (P), 0, find_asbr_summary)

#define OSPF_EXTERNAL_LSA_SELF_FIND_BY_PREFIX(P) \
	ospf_lsdb_iterator (ospf_top->external_lsa, \
                            ((struct prefix_ipv4 *) (P)), 0, find_external)

struct ospf_route;
struct new_lsdb;

/* Prototypes. */
struct ospf_lsa *ospf_router_lsa (struct ospf_area *);
struct ospf_lsa *ospf_network_lsa (struct ospf_interface *);
struct ospf_lsa *ospf_summary_lsa (struct prefix_ipv4 *, u_int32_t,
				   struct ospf_area *, struct ospf_lsa*);
struct ospf_lsa *ospf_summary_asbr_lsa (struct prefix_ipv4 *, u_int32_t, 
		                        struct ospf_area *, struct ospf_lsa *);
struct ospf_lsa *ospf_external_lsa (struct prefix_ipv4 *, u_char ,
				    u_int32_t, u_int32_t, struct in_addr,
                                    struct ospf_lsa *);
u_int16_t ospf_lsa_checksum (struct lsa_header *);
struct ospf_lsa *ospf_lsa_new ();
struct ospf_lsa *ospf_lsa_dup ();
void ospf_lsa_free (struct ospf_lsa *lsa);
struct lsa_header *ospf_lsa_data_new (size_t);
struct lsa_header *ospf_lsa_data_dup (struct lsa_header *);
void ospf_lsa_data_free (struct lsa_header *);
struct ospf_lsa *ospf_lsa_install (struct ospf_neighbor *, struct ospf_lsa *);

struct ospf_lsa *ospf_router_lsa_install (struct ospf_area *, struct ospf_lsa *);
struct ospf_lsa *ospf_network_lsa_install (struct ospf_interface *, struct ospf_lsa *);
struct ospf_lsa *ospf_summary_lsa_install (struct ospf_area *, struct ospf_lsa *);
struct ospf_lsa *ospf_summary_asbr_lsa_install (struct ospf_area *, struct ospf_lsa *);
struct ospf_lsa *ospf_external_lsa_install (struct ospf_lsa *);

void ospf_external_lsa_flush (u_char, struct prefix_ipv4 *,
			      unsigned int, struct in_addr);

struct ospf_lsa *ospf_external_lsa_originate (u_char, struct external_info *);
int ospf_external_lsa_originate_timer (struct thread *);
struct external_info *ospf_external_info_add (u_char, struct prefix_ipv4,
					      unsigned int, struct in_addr);
void ospf_external_info_delete (u_char, struct prefix_ipv4);

struct ospf_lsa *ospf_lsa_lookup (struct ospf_area *, u_int32_t,
				  struct in_addr, struct in_addr);
struct ospf_lsa *ospf_lsa_lookup_by_id (struct ospf_area *,u_int32_t, struct in_addr);
struct ospf_lsa *ospf_lsa_lookup_by_header (struct ospf_area *,
					    struct lsa_header *);
int ospf_lsa_more_recent (struct ospf_lsa *, struct ospf_lsa *);
int ospf_lsa_different (struct ospf_lsa *, struct ospf_lsa *);
void ospf_lsa_flush_self_originated (struct ospf_neighbor *,
				     struct ospf_lsa *, struct ospf_lsa *);
int ospf_lsa_count (struct ospf_area *);
int ospf_lsa_count_table (struct ospf_lsdb *);
void ospf_lsa_init ();

int ospf_lsa_is_self_originated (struct ospf_lsa *);

int find_summary (struct ospf_lsa *, void *, int);
int find_asbr_summary (struct ospf_lsa *, void *, int);
int find_external (struct ospf_lsa *, void *, int);

void ospf_lsa_maxage (struct ospf_lsa *);
u_int32_t get_metric (u_char *);
void ospf_update_router_lsas ();

int ospf_lsa_maxage_walker (struct thread *);
void ospf_schedule_update_router_lsas ();

int ospf_network_lsa_refresh (struct thread *);
struct ospf_lsa *ospf_external_lsa_refresh (struct ospf_lsa *);

struct in_addr ospf_get_free_id_for_prefix (struct ospf_lsdb *,
					    struct prefix_ipv4 *,
					    struct in_addr);
struct in_addr ospf_lsa_unique_id (struct new_lsdb *, u_char,
				   struct prefix_ipv4 *);
void ospf_schedule_lsa_flood_area (struct ospf_area *, struct ospf_lsa *);
void ospf_schedule_lsa_flush_area (struct ospf_area *, struct ospf_lsa *);
void ospf_schedule_router_lsa_originate (struct ospf_area *);
void ospf_schedule_network_lsa_originate (struct ospf_interface *);

void ospf_refresher_register_lsa (struct ospf *, struct ospf_lsa *);
void ospf_refresher_unregister_lsa (struct ospf_lsa *);

int ospf_forward_address_get (struct in_addr, struct in_addr *);

#endif /* _ZEBRA_OSPF_LSA_H */
