/* BGP attributes management routines.
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "linklist.h"
#include "log.h"
#include "zebra.h"
#include "prefix.h"
#include "memory.h"
#include "buffer.h"
#include "roken.h"
#include "vector.h"
#include "vty.h"

#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_route.h"
#include "bgp_aspath.h"
#include "bgp_community.h"
#include "bgp_peer.h"
#include "bgp_dump.h"

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

/* Allocate new bgp attribute object. */
struct attr *
bgp_attr_new ()
{
  struct attr *new;

  new = XMALLOC (MTYPE_ATTR, sizeof (struct attr));
  bzero (new, sizeof (struct attr));
  return new;
}

/* Free bgp attribute and aspath. */
void
bgp_attr_free (struct attr *attr)
{
  /* Decrement attribute reference. */
  attr->refcnt--;

  /* If reference becomes zero then free attribute object. */
  if (attr->refcnt == 0)
    {    
      if (attr->aspath)
	aspath_free (attr->aspath);
      if (attr->community)
	community_free (attr->community);
      XFREE (MTYPE_ATTR, attr);
    }
}

/* Get origin attribute of the update message. */
int
bgp_attr_origin (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  /* Origin attribute must be transitive. */
  if (flag != ATTR_FLAG_TRANS)
    {
      log_warn ("Origin attribute flag isn't transitive [%d]\n", flag);

      /* BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR */
      return -1;
    }

  /* Origin attribute length must be one. */
  if (length != 1)
    {
      log_warn ("Origin attribute which length isn't one [%d]\n", length);
      /* BGP_NOTIFY_UPDATE_ATTR_LENG_ERR */
      return -1;
    }

  /* Fetch origin attribute. */
  attr->origin = *pnt;

  /* If origin attribute is unknown return error. */
  if ((attr->origin != BGP_ORIGIN_IGP) &&
      (attr->origin != BGP_ORIGIN_EGP) &&
      (attr->origin != BGP_ORIGIN_INCOMPLETE))
    {
      log_warn ("Origin attribute value is invalid [%d]\n", *pnt);
      /* BGP_NOTIFY_UPDATE_INVAL_ORIGIN */
      return -1;
    }

  /* Success. */
  return 0;
}

/* Parse AS path information.  This function is wrapper of
   aspath_parse. */
int
bgp_attr_aspath (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  /* Attribute already has as path then send notify to the peer. */
  if (attr->aspath)
    {
      log_warn ("Duplicate aspath in same update message\n");
      return -1;
    }

  /* In case of IBGP, length will be zero. */
  attr->aspath = aspath_parse (pnt, length);

  return 0;
}

/**/
int
bgp_attr_nexthop (struct attr *attr, u_char flag, u_char *pnt, 
		  u_int16_t length)
{
  /* Check nexthop attribute length. */
  if (length != 4)
    {
      log_warn ("Nexthop attribute length isn't four [%d]\n", length);
      /* BGP_NOTIFY_UPDATE_ATTR_LENG_ERR */
      return -1;
    }

  memcpy (&attr->next_hop, pnt, 4);

  return 0;
}

/**/
int
bgp_attr_med (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (length != 4)
    {
      log_warn ("MED attribute length isn't four [%d]\n", length);
      return -1;
    }
  GETL (attr->med, pnt);
  return 0;
}

/**/
int
bgp_attr_local_pref (struct attr *attr, u_char flag, u_char *pnt, 
		     u_int16_t length)
{
  if (length == 4) 
    GETW (attr->local_pref, pnt);
  else 
    attr->local_pref = 0;
  return 0;
}

/**/
int
bgp_attr_atomic (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (length != 0)
    {
      log ("bad atomic_aggregate length %d\n", length);
      return -1;
    }

    attr->atomic_aggregate = 1;
    return 0;
}

int
bgp_attr_community (struct attr *attr, u_char flag, u_char *pnt, 
		    u_int16_t length)
{
  if (length == 0)
    attr->community = NULL;
  else 
    attr->community = community_parse (pnt, length);
  return 0;
}

#ifdef HAVE_IPV6
struct mp 
{
  u_int16_t family;
  u_char safi;
};

message address_family_str [] = 
{
  { 0, "Reserved"},
  { 1, "IP (IP Version 4)"},
  { 2, "IPv6 (IP Version 6)"},
  { 0, NULL },
};

void
route_parse_v6 (struct peer *peer, struct attr *attr,
		u_char *pnt, int masklen)
{
  struct prefix_ipv6 *p;
  struct bgp_route *binfo;

  /* Fetch prefix. */
  p = prefix_ipv6_new ();
  p->family = AF_INET6;
  p->prefixlen = masklen;
  memcpy (&p->prefix, pnt, PSIZE (masklen));

  /* Setup bgp information. */
  binfo = bgp_route_new();
  binfo->type = ZEBRA_ROUTE_BGP;
  binfo->peer = peer;
  binfo->attr = attr;

  /* bgp_in6_add_radix (pin6);*/
  
  /* zebra_route_ip6 (ZEBRA_ROUTE_IPV6_ADD, dest, mask, nexthop); */
}

/* Multiprotocol reachable parse */
void
bgp_mp_reach_parse (struct peer *peer, struct attr *attr, u_char *pnt, int length)
{
  u_int16_t afi;
  u_char safi;
  u_char nexthop_len;
  u_char snpa_num;
  u_char *lim;
  u_char nlri_len;
  u_int16_t nlri_total_len;
  
  /* Set end of packet. */
  lim = pnt + length;

  /* Load AFI, SAFI, Nexthop. */
  GETW (afi, pnt);
  GETC (safi, pnt);
  GETC (nexthop_len, pnt);
  if (nexthop_len != 16 && nexthop_len != 32) 
    log ("Next Hop Length is not 16 or 32\n");
#ifdef DUMP
  {
    int i;
    for (i = 0; i < nexthop_len; i++)
      printf ("%d\n", pnt[i]);
  }
#endif /* DUMP */
  memcpy (attr->mp_nexthop, pnt, nexthop_len);
#ifdef DUMP
  {
    char buf[INET6_ADDRSTRLEN];
    struct in6_addr tmp;
    memcpy (&tmp, attr->mp_nexthop, 16);
    printf ("debug : %s\n", inet_ntop (AF_INET6, &tmp, buf, INET6_ADDRSTRLEN));
  }
#endif /* DUMP */
  pnt += nexthop_len;
  attr->mp_nexthop_len = nexthop_len;

  GETC (snpa_num, pnt);
  pnt += snpa_num;
  
  /* If peer is based on old draft-00. I read NLRI length from the
     packet. */
  if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
    GETW (nlri_total_len, pnt);

#ifdef DUMP
  printf ("AFI %d\n", afi);
  printf ("SAFI %d\n", safi);
  printf ("nexthop_len %d\n", nexthop_len);
#endif 

  while (pnt < lim) 
    {
      GETC (nlri_len, pnt);
      route_parse_v6 (peer, attr, pnt, nlri_len);
      pnt += PSIZE (nlri_len);
    }
}

struct in6_addr
masklen2in6_addr (int mask)
{
  struct in6_addr maskaddr;
  char *pnt = (char *) &maskaddr;
  char mindex [] = { 0, 128, 192, 224, 240, 248, 252, 254 };

  bzero (&maskaddr, sizeof (struct in6_addr));

  while (mask > 8) {
    *pnt++ = 0xff;
    mask -= 8;
  }
  if (mask) {
    *pnt = mindex[mask];
  }
  return maskaddr;
}

/* Withdraw IPv6 route. */
void
mp_ipv6_withdraw (u_char *pnt, int length)
{
  return;
}

/* Multiprotocol unreachable parse */
void
bgp_mp_unreach_parse (struct peer *peer, u_char *pnt, int length)
{
  u_int16_t family;
  u_char safi;
  u_int16_t unfeasible_len;

  GETW (family, pnt);
  GETC (safi, pnt);
  GETW (unfeasible_len, pnt);

  switch (family) {
  case AF_INET:
    /* multicast ? need check of SAFI... */
    break;
  case AF_INET6:
    /* IPv6 withdraw */
    if (safi == SAFI_UNICAST)
      mp_ipv6_withdraw (pnt, unfeasible_len);
    break;
  default:
    break;
  }
}
#endif /* HAVE_IPV6 */

/* Read attribute of update packet.  This function is called from
   bgp_update () in bgpd.c */
struct attr *
bgp_attr_parse (u_char *pnt, u_int16_t size, struct peer *peer)
{
  int ret;
  u_char *lim;
  u_char flag;
  u_char type;
  u_int16_t length;
  struct attr *attr;

  /* Init return value. */
  ret = 0;

  /* Allocate new attribute. */
  attr= bgp_attr_new ();

  /* Get attributes until to the end of attribute length. */
  lim = pnt + size;
  while (pnt < lim)
    {
      /* Fetch attribute flag and type. */
      flag = *pnt++;
      type = *pnt++;

      /* If extended length is on. */
      if (flag & ATTR_FLAG_EXTLEN)
	GETW (length, pnt);
      else
	GETC (length, pnt);

      /* OK check attribute and store it's value. */
      switch (type)
	{
	case BGP_ATTR_ORIGIN:
	  ret = bgp_attr_origin (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_AS_PATH:
	  ret = bgp_attr_aspath (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_NEXT_HOP:	
	  ret = bgp_attr_nexthop (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_MULTI_EXIT_DISC:
	  ret = bgp_attr_med (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_LOCAL_PREF:
	  ret = bgp_attr_local_pref (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_ATOMIC_AGGREGATE:
	  ret = bgp_attr_atomic (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_COMMUNITIES:
	  ret = bgp_attr_community (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_ORIGINATOR:
	case BGP_ATTR_CLUSTERLIST:
	case BGP_ATTR_DPA:
	  break;
#ifdef HAVE_IPV6
	case BGP_ATTR_MP_REACH_NLRI:
	  bgp_mp_reach_parse (peer, attr, pnt, length);
	  break;
	case BGP_ATTR_MP_UNREACH_NLRI:
	  bgp_mp_unreach_parse (peer, pnt, length);
	  break;
#endif /* HAVE_IPV6 */
	default:
	  /* Unknown attribute treatment. */
	  break;
	}

      /* If error occured we should free allocated attribute. */
      if (ret < 0)
	{
	  bgp_attr_free (attr);
	  return NULL;
	}

      pnt += length;
    }

  return attr;
}

/* Check all attribute exist here? */
struct attr *
bgp_attr_check (struct attr *attr)
{
  return attr;
}

#if 0
attr_dump (FILE *fp, struct attr *attr)
{
  
}

struct attr *
attr_str2attr ()
{
  struct attr *attr;
  attr = bgp_attr_new ();
}

attr_test ()
{
  /* origin attribute: value ... attirbute: value ... */
  char buf [] = "i med: 0 lpref: 0 nethop: 202.216.226.1 aspath: 1 2 3 4 comm: no_export 3561:70";
  struct attr *attr;

  attr = attr_str2attr(buf);
  attr_dump (stdout, attr);
}
#endif /* 0 */

int
attr_make (u_char *buf, struct attr *attr)
{
  u_char *pnt = buf;

  /* origin */
  PUTC (ATTR_FLAG_TRANS,pnt);
  PUTC (BGP_ATTR_ORIGIN, pnt);
  PUTC (sizeof(attr->origin), pnt);
  PUTC (attr->origin, pnt);

  /* aspath */
  PUTC (ATTR_FLAG_TRANS, pnt);
  PUTC (BGP_ATTR_AS_PATH, pnt);
  PUTC (attr->aspath->length, pnt);
  memcpy (pnt, attr->aspath->data, attr->aspath->length);
  pnt += attr->aspath->length;

  /* next_hop */
  PUTC(ATTR_FLAG_TRANS, pnt);
  PUTC(BGP_ATTR_NEXT_HOP,pnt);
  PUTC(sizeof(attr->next_hop), pnt);
  memcpy (pnt, &attr->next_hop, sizeof(attr->next_hop));
  pnt += sizeof(attr->next_hop);

  /* med */
  if (attr->med)
    {
      PUTC(ATTR_FLAG_OPTIONAL, pnt);
      PUTC(BGP_ATTR_MULTI_EXIT_DISC, pnt);
      PUTC(sizeof(attr->med), pnt);
      PUTL(attr->med, pnt);
    }
  
  /* local_pref  */
  if (attr->local_pref) 
    {
      PUTC(0x40,pnt);
      PUTC(BGP_ATTR_LOCAL_PREF, pnt);
      PUTC(sizeof(attr->local_pref), pnt);
      PUTL(attr->local_pref,pnt);
    }  
  /* MP */
#ifdef HAVE_IPV6
  if (attr->mp_nexthop_len) 
    {
      int mp_size;
      u_char *mp_len;
      u_char *nlri_len;

      PUTC(ATTR_FLAG_OPTIONAL, pnt);
      PUTC(BGP_ATTR_MP_REACH_NLRI, pnt);

      /* size of MP Attribute */
      mp_len = pnt;
      PUTC (0, pnt);

      PUTC (0, pnt);		/* SAFI */
      PUTC (16, pnt);		/* nexthop_len */
      bcopy (attr->mp_nexthop, pnt, 16); /* nexthop */
      pnt += 16;
      PUTC (0, pnt);		/* SNPA_num */
  
      nlri_len = pnt;
      PUTW (0, pnt);		/* NLRI total len */

#if 0
      /* set nlri */
      PUTC (attr->v6masklen, pnt);
      bcopy (attr->v6addr, pnt, PSIZE (attr->v6masklen));
      pnt += PSIZE(attr->v6masklen);

      /* set nlri total len */
      PUTW (PSIZE(attr->v6masklen) + 1, nlri_len);
#endif
      mp_size = pnt - mp_len - 1;
      PUTC (mp_size, mp_len);

      printf ("mp attr size %d\n", mp_size);
    }
#endif /* HAVE_IPV6 */

  return pnt - buf;
}

void
attr_init ()
{
  aspath_init ();
  community_init ();
}
