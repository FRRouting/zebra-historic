/* BGP attributes. 
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

/* Attribute flags */
#define ATTR_FLAG_OPTIONAL   0x80	/* Attribute is optional. */
#define ATTR_FLAG_TRANS      0x40	/* Attribute is transitive. */
#define ATTR_FLAG_PARTIAL    0x20	/* Attribute is partial. */
#define ATTR_FLAG_EXTLEN     0x10	/* Extended length flag. */

/* Default attribute value. */
#define DEFAULT_LOCAL_PREF    100

/* BGP-4+ */
#define SAFI_UNICAST            1
#define SAFI_MULTICAST          2
#define SAFI_UNI_MULTICAST      3

struct attr
{
  /* Reference count of this attribute. */
  int refcnt;			

  /* Flag of attribute is set or not. */
  u_int32_t attr_flag;

  /* Origin attribute. */
  u_char origin;

  struct in_addr next_hop;

  u_char next_hop_flag;

  u_int32_t med;
  u_char med_flag;

  u_int32_t local_pref;
  u_char local_pref_flag;

  u_char atomic_aggregate;
  u_char atomic_aggregate_flag;

  u_char aggregator;
  u_char aggregator_flag;

  u_int32_t dpa;
  u_char dpa_flag;

  u_int32_t weight;

  unsigned char mp_nexthop_len;
  unsigned char mp_nexthop[32];

  /* AS Path structure */
  struct aspath *aspath;	

  /* Community structure */
  struct community *community;	
};

/* bgp_attr is linked from radix route. */
struct bgp_attr
{
  struct attr *attr;
  struct peer *peer;
};

/* Prototypes. */
void attr_init ();
struct attr *bgp_attr_new();
struct attr *bgp_attr_parse (u_char *pnt, u_int16_t size, struct peer *peer);
struct attr *bgp_attr_check ();
void bgp_attr_free (struct attr *);
