/*
 * BGP attributes management routines.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
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

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "roken.h"
#include "vector.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "hash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_packet.h"

#include "zebra/zebra.h"

/* Attribute strings for logging. */
message attr_str [] = 
{
  { BGP_ATTR_ORIGIN,           "ORIGIN" }, 
  { BGP_ATTR_AS_PATH,          "AS_PATH" }, 
  { BGP_ATTR_NEXT_HOP,         "NEXT_HOP" }, 
  { BGP_ATTR_MULTI_EXIT_DISC,  "MULTI_EXIT_DISC" }, 
  { BGP_ATTR_LOCAL_PREF,       "LOCAL_PREF" }, 
  { BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" }, 
  { BGP_ATTR_AGGREGATOR,       "AGGREGATOR" }, 
  { BGP_ATTR_COMMUNITIES,      "COMMUNITY" }, 
  { BGP_ATTR_ORIGINATOR,       "ORIGINATOR" }, 
  { BGP_ATTR_CLUSTERLIST,      "CLUSTERLIST" }, 
  { BGP_ATTR_DPA,              "DPA" },
  { BGP_ATTR_ADVERTISER,       "ADVERTISER"} ,
  { BGP_ATTR_RCID_PATH,        "RCID_PATH" },
  { BGP_ATTR_MP_REACH_NLRI,    "MP_REACH_NLRI" },
  { BGP_ATTR_MP_UNREACH_NLRI,  "MP_UNREACH_NLRI" },
  { 0, NULL }
};

/* Attribute hash routines. */

struct Hash *attrhash;

unsigned int
attrhash_key_make (struct attr *attr)
{
  unsigned int key = 0;

  key += attr->origin;
  key += attr->nexthop.s_addr;
  key += attr->med;
  key += attr->local_pref;
  key += attr->aggregator_as;
  key += attr->aggregator_addr.s_addr;
  key += attr->dpa;
  key += attr->weight;

#ifdef HAVE_IPV6
  {
    int i;

    key += attr->mp_nexthop_len;
    for (i = 0; i < 16; i++)
      key += attr->mp_nexthop_global.s6_addr[i];
    for (i = 0; i < 16; i++)
      key += attr->mp_nexthop_local.s6_addr[i];
  }
#endif /* HAVE_IPV6 */

  if (attr->aspath)
    key += aspath_key_make (attr->aspath);
  if (attr->community)
    key += community_hash_make (attr->community);

  return key %= HASHTABSIZE;
}

int
attrhash_cmp (struct attr *attr1, struct attr *attr2)
{
  if (attr1->flag == attr2->flag &&
      attr1->origin == attr2->origin &&
      attr1->nexthop.s_addr == attr2->nexthop.s_addr &&
      attr1->med == attr2->med &&
      attr1->local_pref == attr2->local_pref &&
      attr1->aggregator_as == attr2->aggregator_as &&
      attr1->aggregator_addr.s_addr == attr2->aggregator_addr.s_addr &&
      attr1->dpa == attr2->dpa &&
      attr1->weight == attr2->weight &&
#ifdef HAVE_IPV6
      attr1->mp_nexthop_len == attr2->mp_nexthop_len &&
#endif /* HAVE_IPV6 */
      attr1->aspath == attr2->aspath &&
      attr1->community == attr2->community)
    return 1;
  else
    return 0;
}

void
attrhash_init ()
{
  attrhash = hash_new (HASHTABSIZE);
  attrhash->hash_key = attrhash_key_make;
  attrhash->hash_cmp = attrhash_cmp;
}

/* Internet argument attribute. */
struct attr *
bgp_attr_intern (struct attr *attr)
{
  struct attr *find;
  struct attr *new;

  find = (struct attr *) hash_search (attrhash, attr);

  if (find)
    {
      find->refcnt++;
      if (find->aspath)
	find->aspath->refcnt++;
      if (find->community)
	find->community->refcnt++;
      return find;
    }

  new = XMALLOC (MTYPE_ATTR, sizeof (struct attr));

  *new = *attr;
  new->refcnt = 1;
  if (new->aspath)
    new->aspath->refcnt++;
  if (new->community)
    new->community->refcnt++;

  hash_push (attrhash, new);

  return new;
}

/* Called from bgp_view.c. Make network statement's attribute. */
struct attr *
bgp_attr_make_default ()
{
  struct attr attr;

  bzero (&attr, sizeof attr);
  attr.origin = BGP_ORIGIN_IGP;
  attr.local_pref = 100;
  attr.aspath = aspath_empty_aspath ();
#ifdef HAVE_IPV6
  attr.mp_nexthop_len = 16;
#endif

  return bgp_attr_intern (&attr);
}

/* Free bgp attribute and aspath. */
void
bgp_attr_free (struct attr *attr)
{
  struct attr *ret;
  struct aspath *aspath;
  struct community *community;

  /* Decrement attribute reference. */
  attr->refcnt--;
  aspath = attr->aspath;
  community = attr->community;

  /* If reference becomes zero then free attribute object. */
  if (attr->refcnt == 0)
    {    
      ret = hash_pull (attrhash, attr);
      assert (ret != NULL);

      XFREE (MTYPE_ATTR, attr);
    }

  /* aspath refcount shoud be decrement. */
  if (aspath)
    aspath_free (aspath);

  if (community)
    community_free (community);
}

/* Get origin attribute of the update message. */
int
bgp_attr_origin (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag)
{
  /* Origin attribute length must be one. */
  if (length != 1)
    {
      zlog (peer->log, LOG_ERR, "Origin attribute length is not one [%d]",
	    length);
      bgp_notify_send (peer, BGP_NOTIFY_UPDATE_ERR,
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
		       NULL);
      return -1;
    }

  /* Origin attribute must be transitive. */
  if (flag != ATTR_FLAG_TRANS)
    {
      zlog (peer->log, LOG_ERR, 
	    "Origin attribute flag isn't transitive [%d]", flag);
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR, 
		       NULL);
      return -1;
    }

  /* Fetch origin attribute. */
  attr->origin = stream_getc (BGP_INPUT (peer));

  /* If origin attribute is unknown return error. */
  if ((attr->origin != BGP_ORIGIN_IGP) &&
      (attr->origin != BGP_ORIGIN_EGP) &&
      (attr->origin != BGP_ORIGIN_INCOMPLETE))
    {
      zlog (peer->log, LOG_ERR, "Origin attribute value is invalid [%d]",
	      attr->origin);
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_INVAL_ORIGIN,
		       NULL);
      return -1;
    }

  /* Set oring attribute flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);

  return 0;
}

/* Parse AS path information.  This function is wrapper of
   aspath_parse. */
int
bgp_attr_aspath (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag)
{
  /* Attribute already has as path then send notify to the peer. */
  if (attr->aspath)
    {
      zlog (peer->log, LOG_WARNING, "Duplicate aspath in same update message");
      return -1;
    }

  /* In case of IBGP, length will be zero. */
  attr->aspath = aspath_parse (stream_pnt (peer->ibuf), length);
  if (!attr->aspath)
    {
      zlog (peer->log, LOG_ERR, "Malformed AS path is coming", length);
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_MAL_AS_PATH,
		       NULL);
      return -1;
    }
  stream_forward (peer->ibuf, length);

  /* Set aspath attribute flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);

  return 0;
}

/* Nexthop attribute. */
int
bgp_attr_nexthop (struct peer *peer, bgp_size_t length, 
		  struct attr *attr, u_char flag)
{
  /* Check nexthop attribute length. */
  if (length != 4)
    {
      zlog (peer->log, LOG_ERR, "Nexthop attribute length isn't four [%d]",
	      length);

      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, 
		       NULL);
      return -1;
    }

  attr->nexthop.s_addr = stream_get_ipv4 (peer->ibuf);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);

  return 0;
}

/* MED atrribute. */
int
bgp_attr_med (struct peer *peer, bgp_size_t length, 
	      struct attr *attr, u_char flag)
{
  if (length != 4)
    {
      zlog (peer->log, LOG_ERR, 
	    "MED attribute length isn't four [%d]", length);
      
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, 
		       NULL);
      return -1;
    }

  attr->med = stream_getl (peer->ibuf);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  return 0;
}

/* Local preference attribute. */
int
bgp_attr_local_pref (struct peer *peer, bgp_size_t length, 
		     struct attr *attr, u_char flag)
{
  if (length == 4) 
    attr->local_pref = stream_getl (peer->ibuf);
  else 
    attr->local_pref = 0;

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);

  return 0;
}

/* Atomic aggregate. */
int
bgp_attr_atomic (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag)
{
  if (length != 0)
    {
      zlog (peer->log, LOG_ERR, "Bad atomic aggregate length %d", length);

      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, 
		       NULL);
      return -1;
    }

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  return 0;
}

/* Aggregator attribute */
int
bgp_attr_aggregator (struct peer *peer, bgp_size_t length,
		     struct attr *attr, u_char flag)
{
  if (length != 6)
    {
      zlog (peer->log, LOG_ERR, "Aggregator length is not 6 [%d]", length);

      bgp_notify_send (peer,
		       BGP_NOTIFY_UPDATE_ERR,
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
		       NULL);
      return -1;
    }
  attr->aggregator_as = stream_getw (peer->ibuf);
  attr->aggregator_addr.s_addr = stream_get_ipv4 (peer->ibuf);

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);

  return 0;
}

/* Community attribute. */
int
bgp_attr_community (struct peer *peer, bgp_size_t length, 
		    struct attr *attr, u_char flag)
{
  if (length == 0)
    attr->community = NULL;
  else
    {
      attr->community = community_parse (stream_pnt (peer->ibuf), length);
      stream_forward (peer->ibuf, length);
    }

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);

  return 0;
}

#ifdef HAVE_IPV6
/* Multiprotocol reachability information parse. */
int
bgp_mp_reach_parse (struct peer *peer, bgp_size_t length, struct attr *attr)
{
  u_int16_t afi;
  u_char safi;
  u_char snpa_num;
  u_char snpa_len;
  u_char *lim;
  bgp_size_t nlri_len;
  
  /* Set end of packet. */
  lim = stream_pnt (peer->ibuf) + length;

  /* Load AFI, SAFI. */
  afi = stream_getw (peer->ibuf);
  safi = stream_getc (peer->ibuf);

  /* Get nexthop length. */
  attr->mp_nexthop_len = stream_getc (peer->ibuf);

  /* Nexthop length check. */
  if (attr->mp_nexthop_len == 16)
    {
      memcpy (&attr->mp_nexthop_global, stream_pnt (peer->ibuf), 16);
      stream_forward (peer->ibuf, 16);
    }
  else if (attr->mp_nexthop_len == 32) 
    {
      memcpy (&attr->mp_nexthop_global, stream_pnt (peer->ibuf), 16);
      stream_forward (peer->ibuf, 16);
      memcpy (&attr->mp_nexthop_local, stream_pnt (peer->ibuf), 16);
      stream_forward (peer->ibuf, 16);
    }
  else
    {
      zlog (peer->log, LOG_INFO, "Next Hop Length is not 16 or 32");
      return -1;
    }

  snpa_num = stream_getc (peer->ibuf);

  while (snpa_num--)
    {
      snpa_len = stream_getc (peer->ibuf);
      stream_forward (peer->ibuf, (snpa_len + 1) >> 1);
    }
  
  /* If peer is based on old draft-00. I read NLRI length from the
     packet. */
  if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
    {
      bgp_size_t nlri_total_len;
      nlri_total_len = stream_getw (peer->ibuf);
    }

  nlri_len = lim - stream_pnt (peer->ibuf);
  nlri_parse (peer, attr, stream_pnt (peer->ibuf), nlri_len, AF_INET6);
  stream_forward (peer->ibuf, nlri_len);

  return 0;
}

/* Multiprotocol unreachable parse */
int
bgp_mp_unreach_parse (struct peer *peer, int length)
{
  u_int16_t afi;
  u_char safi;
  u_char *lim;

  lim = stream_pnt (peer->ibuf) + length;

  afi = stream_getw (peer->ibuf);
  safi = stream_getc (peer->ibuf);

  if (afi == AF_INET6 && safi == SAFI_UNICAST)
    {
      while (stream_pnt (peer->ibuf) < lim)
	{
	  u_char nlri_len;

	  nlri_len = stream_getc (peer->ibuf);
	  stream_forward (peer->ibuf, PSIZE (nlri_len));
	}
    }
  else
    stream_forward (peer->ibuf, length - 3);

  return 0;
}
#endif /* HAVE_IPV6 */

/* Read attribute of update packet.  This function is called from
   bgp_update () in bgpd.c */
int
bgp_attr_parse (struct peer *peer, struct attr *attr, bgp_size_t size)
{
  u_char *endp;
  bgp_size_t length;

  /* End pointer of BGP attribute. */
  endp = BGP_INPUT_PNT (peer) + size;

  /* Get attributes to the end of attribute length. */
  while (BGP_INPUT_PNT (peer) < endp)
    {
      int ret;
      u_char flag;
      u_char type;
      u_char *attr_endp;

      /* Check remaining length check.*/
      if (endp - BGP_INPUT_PNT (peer) < BGP_ATTR_MIN_LEN)
	{
	  zlog (peer->log, LOG_WARNING, 
		"neighbor %s: BGP attribute error remaingin length is %d",
		peer->host, endp - STREAM_PNT (BGP_INPUT (peer)));
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, NULL);
	}

      /* Fetch attribute flag and type. */
      flag = stream_getc (BGP_INPUT (peer));
      type = stream_getc (BGP_INPUT (peer));

      /* Check extended attribue length bit. */
      if (flag & ATTR_FLAG_EXTLEN)
	length = stream_getw (BGP_INPUT (peer));
      else
	length = stream_getc (BGP_INPUT (peer));
      
      /* Overflow check. */
      attr_endp =  BGP_INPUT_PNT (peer) + length;

      if (attr_endp > endp)
	{
	  zlog (peer->log, LOG_WARNING, 
		"neighbor %s: BGP attribute length is too large %d",
		peer->host, length);
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, NULL);
	}

      /* OK check attribute and store it's value. */
      switch (type)
	{
	case BGP_ATTR_ORIGIN:
	  ret = bgp_attr_origin (peer, length, attr, flag);
	  break;
	case BGP_ATTR_AS_PATH:
	  ret = bgp_attr_aspath (peer, length, attr, flag);
	  break;
	case BGP_ATTR_NEXT_HOP:	
	  ret = bgp_attr_nexthop (peer, length, attr, flag);
	  break;
	case BGP_ATTR_MULTI_EXIT_DISC:
	  ret = bgp_attr_med (peer, length, attr, flag);
	  break;
	case BGP_ATTR_LOCAL_PREF:
	  ret = bgp_attr_local_pref (peer, length, attr, flag);
	  break;
	case BGP_ATTR_ATOMIC_AGGREGATE:
	  ret = bgp_attr_atomic (peer, length, attr, flag);
	  break;
	case BGP_ATTR_AGGREGATOR:
	  ret = bgp_attr_aggregator (peer, length, attr, flag);
	  break;
	case BGP_ATTR_COMMUNITIES:
	  ret = bgp_attr_community (peer, length, attr, flag);
	  break;
	case BGP_ATTR_ORIGINATOR:
	case BGP_ATTR_CLUSTERLIST:
	case BGP_ATTR_DPA:
	  ret = 0;
	  stream_forward (peer->ibuf, length);
	  break;
#ifdef HAVE_IPV6
	case BGP_ATTR_MP_REACH_NLRI:
	  ret = bgp_mp_reach_parse (peer, length, attr);
	  break;
	case BGP_ATTR_MP_UNREACH_NLRI:
	  ret = bgp_mp_unreach_parse (peer, length);
	  break;
#endif /* HAVE_IPV6 */
	default:
	  /* Unknown attribute treatment. */
	  ret = 0;
	  zlog (peer->log, LOG_INFO, 
		"Unknown attribute type %d length %d received", type, length);
	  stream_forward (peer->ibuf, length);
	  break;
	}

      /* Check the fetched length. */
      if (BGP_INPUT_PNT (peer) != attr_endp)
	{
	  zlog (peer->log, LOG_WARNING, 
		"neighbor %s: BGP attribute fetch error %d.", peer->host);
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, NULL);
	}

      /* If error occured we should free allocated attribute. */
      if (ret < 0)
	  return ret;
    }

  if (BGP_INPUT_PNT (peer) != endp)
    {
      zlog (peer->log, LOG_WARNING, 
	    "neighbor %s: BGP attribute length mismatch.", peer->host);
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR, NULL);
    }
  return 0;
}

/* Check all attribute exist here? */
int
bgp_attr_check (struct peer *peer, struct attr *attr)
{
#define IBGP_ATTR_BIT (ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)   | \
                       ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)  | \
                       ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP) | \
                       ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))

#define EBGP_ATTR_BIT (ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)   | \
                       ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)  | \
		       ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP))

  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    {
      if ((attr->flag & IBGP_ATTR_BIT) != IBGP_ATTR_BIT)
	{
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)))
	    zlog (NULL, LOG_ERR, "Origin attribute is missing");
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)))
	    zlog (NULL, LOG_ERR, "AS path attribute is missing");
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP)))
	    zlog (NULL, LOG_ERR, "Nexthop attribute is missing");
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)))
	    zlog (NULL, LOG_ERR, "Local preference attribute is missing");
#ifdef DEBUG
	  printf ("IBGP_ATTR_BIT %d\n", IBGP_ATTR_BIT);
	  printf ("appried attr flag %d\n", attr->flag & IBGP_ATTR_BIT);
#endif /* DEBUG */	  

	  /* Missing well known attribute. */
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_MISS_ATTR, NULL);
	  return 1;
	}
    }
  else
    {
      if ((attr->flag & EBGP_ATTR_BIT) != EBGP_ATTR_BIT)
	{
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)))
	    zlog (NULL, LOG_ERR, "Origin attribute is missing");
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)))
	    zlog (NULL, LOG_ERR, "AS path attribute is missing");
	  if (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP)))
	    zlog (NULL, LOG_ERR, "Nexthop attribute is missing");

	  /* Missing well known attribute. */
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_MISS_ATTR, NULL);
	  return 1;
	}
    }
  return 0;
}

int stream_put_prefix (struct stream *, struct prefix *);

/* Make attribute packet. */
bgp_size_t
bgp_packet_attribute (struct peer *peer, struct stream *s, struct attr *attr,
		      struct prefix *p)
{
  unsigned long cp;
  struct aspath *aspath;

  /* Remember current pointer. */
  cp = stream_get_putp (s);

  /* Origin attribute. */
  stream_putc (s, ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);

  /* AS path attribute. */
  stream_putc (s, ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_AS_PATH);

  /* If remote-peer is EBGP */
  if (bgp_peer_sort (peer) == BGP_PEER_EBGP)
    {    
      aspath = aspath_dup (attr->aspath);
      aspath_add_left (aspath, peer->bgp->as);

      stream_putc (s, aspath->length);
      stream_memcpy (s, aspath->data, aspath->length);

      aspath_undup (aspath);
    }
  else
    {
      aspath = attr->aspath;
      stream_putc (s, aspath->length);
      stream_memcpy (s, aspath->data, aspath->length);
    }

  /* Nexthop attribute. */
  stream_putc (s, ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_NEXT_HOP);
  stream_putc (s, 4);
  stream_put_ipv4 (s, attr->nexthop.s_addr);

  /* MED attribute. */
  if (bgp_peer_sort (peer) == BGP_PEER_EBGP)
    {
      ;
    }

  /* Local preference. */
  if (bgp_peer_sort (peer) == BGP_PEER_IBGP)
    {
      stream_putc (s, ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

#ifdef HAVE_IPV6
  /* If p is IPv6 address put it into attribute. */
  if (p->family == AF_INET6)
    {
      unsigned long sizep;
      unsigned long draftp = 0;

      stream_putc (s, ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MP_REACH_NLRI);
      sizep = stream_get_putp (s);
      stream_putc (s, 0);	/* Length of this attribute. */
      stream_putw (s, AFI_IPV6);	/* AFI */
      stream_putc (s, SAFI_UNICAST);	/* SAFI */

      stream_putc (s, attr->mp_nexthop_len);

      if (attr->mp_nexthop_len == 16)
	stream_memcpy (s, &attr->mp_nexthop_global, 16);
      else if (attr->mp_nexthop_len == 32)
	{
	  stream_memcpy (s, &attr->mp_nexthop_global, 16);
	  stream_memcpy (s, &attr->mp_nexthop_local, 16);
	}
      
      /* SNPA */
      stream_putc (s, 0);

      /* In case of old draft BGP-4+. */
      if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
	{
	  draftp = stream_get_putp (s);
	  stream_putw (s, 0);
	}
      
      /* Prefix write. */
      stream_put_prefix (s, p);

      /* Set MP attribute length. */
      stream_putc_at (s, sizep, (stream_get_putp (s) - sizep) - 1);

      /* In case of old draft BGP-4+. */
      if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
	stream_putw_at (s, draftp, (stream_get_putp (s) - draftp) - 2);
    }
#endif /* HAVE_IPV6 */

  /* Return total size of attribute. */
  return stream_get_putp (s) - cp;
}

bgp_size_t
bgp_packet_withdraw (struct peer *peer, struct stream *s, struct prefix *p)
{
  unsigned long cp;
  unsigned long attrlen_pnt;
  bgp_size_t size;

  cp = stream_get_putp (s);

  stream_putc (s, ATTR_FLAG_OPTIONAL);
  stream_putc (s, BGP_ATTR_MP_UNREACH_NLRI);

  attrlen_pnt = stream_get_putp (s);
  stream_putc (s, 0);		/* Length of this attribute. */
  stream_putw (s, AFI_IPV6);	/* AFI */
  stream_putc (s, SAFI_UNICAST); /* SAFI */
  
  /* Prefix write. */
  stream_put_prefix (s, p);

  /* Set MP attribute length. */
  size = stream_get_putp (s) - attrlen_pnt - 1;
  stream_putc_at (s, attrlen_pnt, size);

  return stream_get_putp (s) - cp;
}

/* Initialization of attribute. */
void
bgp_attr_init ()
{
  void attrhash_init ();

  aspath_init ();
  attrhash_init ();
  community_init ();
}
