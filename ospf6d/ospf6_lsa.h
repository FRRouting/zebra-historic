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

#ifndef OSPF_LSA_H
#define OSPF_LSA_H

#define MAXLISTEDLSA 512
#define MAXLSASIZE   1024

#define THIS_IS_REFRESH  ((struct thread *)0xffffffff)

/* LSA definition */

/* Type */
#define	LST_V2ROUTER_LSA               1
#define	LST_V2NETWORK_LSA              2
#define LST_V2TYPE3_SUMMARY_LSA        3	/* routes to network */
#define LST_V2TYPE4_SUMMARY_LSA        4	/* routes to ASBR */
#define LST_V2AS_EXTERNAL_LSA          5

#define LST_ROUTER_LSA              0x2001
#define LST_NETWORK_LSA             0x2002
#define LST_INTER_AREA_PREFIX_LSA   0x2003
#define LST_INTER_AREA_ROUTER_LSA   0x2004
#define LST_AS_EXTERNAL_LSA         0x4005
#define LST_GROUP_MEMBERSHIP_LSA    0x2006
#define LST_TYPE_7_LSA              0x2007
#define LST_LINK_LSA                0x0008
#define LST_INTRA_AREA_PREFIX_LSA   0x2009

#define AREALSTYPESIZE              0x0009
#define typeindex(x)     (((ntohs (x)) & 0x000f) - 1)

#define GET_LSASCOPE(x)  ((ntohs (x)) & 0x6000)
#define SCOPE_LINKLOCAL  0x0000
#define SCOPE_AREA       0x2000
#define SCOPE_AS         0x4000
#define SCOPE_RESERVED   0x6000

/* NOTE that all lsa is left NETWORK BYTE ORDER */
struct lsa_hdr
{
  u_int16_t lsh_age;      /* LS age */
  u_int16_t lsh_type;     /* LS type */
  u_int32_t lsh_id;       /* Link State ID */
  u_int32_t lsh_advrtr;   /* Advertising Router */
  u_int32_t lsh_seqnum;   /* LS sequence number */
  u_int16_t lsh_cksum;    /* LS checksum */
  u_int16_t lsh_len;      /* length */
};

#define LSA_NEXT(x) ((struct lsa_hdr *)((char *)(x) + ntohs ((x)->lsh_len)))
#define lsa_issame(x,y) ((x)->lsh_type == (y)->lsh_type && \
                         (x)->lsh_id == (y)->lsh_id && \
                         (x)->lsh_advrtr == (y)->lsh_advrtr)

struct lsa_internal
{
  struct lsa_hdr   *lsh;
  u_int32_t         birth;     /* tv_sec when LS age 0 */
  u_int32_t         installed; /* tv_sec when installed */
  struct thread    *expire;
  struct thread    *refresh;   /* For self-originated LSA */
  struct neighbor  *from;
  struct area      *area;
  struct ospf_if   *iface;
};

/* for LSA list in Neighbor Data Structure */
#define lsdb_size(x)     (sizeof (x) / sizeof (struct lsa_internal *))

#define MY_ROUTER_LSA_ID    0

struct router_lsa
{
  u_int8_t rlsa_bits;
  u_char   rlsa_options[3];
  /* followed by router_lsd(s) */
};
#define ROUTER_LSA_BIT_B     (1 << 0)
#define ROUTER_LSA_BIT_E     (1 << 1)
#define ROUTER_LSA_BIT_V     (1 << 2)
#define ROUTER_LSA_BIT_W     (1 << 3)

#define ROUTER_LSA_SET(x,y)    ((x)->rlsa_bits |=  (y))
#define ROUTER_LSA_ISSET(x,y)  ((x)->rlsa_bits &   (y))
#define ROUTER_LSA_CLEAR(x,y)  ((x)->rlsa_bits &= ~(y))

struct router_lsd
{
  u_int8_t  rlsd_type;
  u_int8_t  rlsd_reserved;
  u_int16_t rlsd_metric;                /* output cost */
  u_int32_t rlsd_interface_id;
  u_int32_t rlsd_neighbor_interface_id;
  u_int32_t rlsd_neighbor_router_id;
};

#define LSDT_POINTTOPOINT       1
#define LSDT_TRANSIT_NETWORK    2
#define LSDT_STUB_NETWORK       3
#define LSDT_VIRTUAL_LINK       4

struct network_lsa
{
  u_int8_t nlsa_reserved;
  u_char   nlsa_options[3];
  /* followed by router_id(s) */
};

/* for ack_type() */
#define NO_ACK       0
#define DELAYED_ACK  1
#define DIRECT_ACK   2

#define NONE       0
#define FLOODBACK  1
#define IMPLIEDACK 2
#define DUPLICATE  4

struct link_lsa
{
  u_int8_t llsa_rtr_pri;
  u_char   llsa_options[3];
  struct in6_addr llsa_linklocal;
  u_int32_t llsa_prefix_num;
  /* followed by prefix(es) */
};

struct intra_area_prefix_lsa
{
  u_int16_t intra_prefix_num;
  u_int16_t intra_prefix_refer_lstype;
  u_int32_t intra_prefix_refer_lsid;
  u_int32_t intra_prefix_refer_advrtr;
};

int prepare_neighbor_lsdb (struct neighbor *);
int which_is_more_recent (struct lsa_internal *, struct lsa_internal *);
struct lsa_hdr *search_lsa_instance (struct lsa_hdr *, struct area *);
int check_neighbor_lsdb (struct iovec *, struct neighbor *);
int proceed_retrans_lsdb (struct neighbor *);
int vty_lsdb (struct vty *vty, struct area *area);
u_short calc_lsa_age_external (struct lsa_internal *);
struct lsa_internal *lsa_lookup (u_int16_t, u_int32_t, u_int32_t,
				 struct area *, struct ospf_if *);
struct lsa_hdr *attach_lsa_to_iov (struct lsa_internal *, struct iovec *);
struct lsa_hdr *attach_lsa_hdr_to_iov (struct lsa_internal *, struct iovec *);
int lsa_receive (struct lsa_hdr *, struct neighbor *);
int lsa_refresh (struct thread *);
struct lsa_internal *make_lsa_hdr_internal (struct lsa_hdr *,
					    struct neighbor *);
char *print_lsahdr (struct lsa_hdr *lsh);

int construct_router_lsa (struct area *);
int construct_network_lsa (struct ospf6_if *);
int construct_intra_prefix_lsa (struct ospf6_if *);
int construct_link_lsa (struct ospf6_if *);

/* Function Prototypes */
int list_clear_all (list);
int lsa_list_clear_all (list);

#endif /* OSPF_LSA_H */
