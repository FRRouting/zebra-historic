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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
/* For bzero*/
#include <string.h>

#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_route.h"
#include "bgp_aspath.h"
#include "bgp_community.h"
#include "bgp_peer.h"
#include "bgp_dump.h"

#include "log.h"
#include "zebra.h"
#include "route.h"
#include "memory.h"

/* Attribute string for logging. */
message attr_str [] = {
  { BGP_ATTR_ORIGIN, "ORIGIN" }, 
  { BGP_ATTR_AS_PATH, "AS_PATH" }, 
  { BGP_ATTR_NEXT_HOP, "NEXT_HOP" }, 
  { BGP_ATTR_MULTI_EXIT_DISC, "MULTI_EXIT_DISC" }, 
  { BGP_ATTR_LOCAL_PREF, "LOCAL_PREF" }, 
  { BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" }, 
  { BGP_ATTR_AGGREGATOR, "AGGREGATOR" }, 
  { BGP_ATTR_COMMUNITIES, "COMMUNITY" }, 
  { BGP_ATTR_ORIGINATOR, "ORIGINATOR" }, 
  { BGP_ATTR_CLUSTERLIST, "CLUSTERLIST" }, 
  { BGP_ATTR_DPA, "DPA" },
  { BGP_ATTR_ADVERTISER, "ADVERTISER"} ,
  { BGP_ATTR_RCID_PATH, "RCID_PATH" },
  { BGP_ATTR_MP_REACH_NLRI, "MP_REACH_NLRI" },
  { BGP_ATTR_MP_UNREACH_NLRI, "MP_UNREACH_NLRI" },
  { 0, NULL }
};

/* Allocate new attribute object. */
struct attr *
attr_new ()
{
  struct attr *new;

  new = XMALLOC (MTYPE_ATTR, sizeof (struct attr));
  bzero (new, sizeof (struct attr));
  return new;
}

/* Free attribute and aspath. */
void
attr_free (struct attr *attr)
{
  attr->refcnt--;

  /* If reference becomes zero free attribute object. */
  if (attr->refcnt == 0)
    {    
      if (attr->aspath)
	aspath_free (attr->aspath);

      if (attr->community)
	community_free (attr->community);

      XFREE (MTYPE_ATTR, attr);
    }
}

/* Get ORIGIN attribute of the update message. */
int
attr_origin (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  /* Attribute flag check */
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

/**/
int
attr_aspath (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (attr->aspath)
    {
      log_warn ("Duplicate aspath in same update message\n");
      return;
    }

  /* In case of IBGP, length will be zero. */
  attr->aspath = aspath_parse (pnt, length);
}

/**/
int
attr_nexthop (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
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
attr_med (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (length != 4)
    {
      log_warn ("MED attribute length isn't four [%d]\n", length);
      return -1;
    }
  ld_4byte (attr->med, pnt);
  return 0;
}

/**/
int
attr_local_pref (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (length == 4) 
    {
      ld_4byte(attr->local_pref, pnt);
    }
  else 
    attr->local_pref = 0;
  return 0;
}

/**/
int
attr_atomic (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
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
attr_community (struct attr *attr, u_char flag, u_char *pnt, u_int16_t length)
{
  if (length == 0)
    attr->community = NULL;
  else 
    attr->community = community_parse (pnt, length);
  return 0;
}

/* Read attribute of update packet. */
struct attr *
attr_get (u_char *pnt, u_int16_t size, struct peer *peer)
{
  int ret;
  u_char *lim;
  u_char flag;
  u_char type;
  u_int16_t length;
  struct attr *attr;

  /* Allocate new attribute. */
  attr= attr_new ();

  /* Get attributes until to the end of attribute length. */
  lim = pnt + size;
  while (pnt < lim)
    {
      /* Fetch attribute flag and type. */
      flag = *pnt++;
      type = *pnt++;

      /* If extended length is on. */
      if (flag & ATTR_FLAG_EXTLEN)
	ld_2byte (length, pnt);
      else
	ld_1byte (length, pnt);

      /* OK check attribute and store it's value. */
      switch (type)
	{
	case BGP_ATTR_ORIGIN:
	  ret = attr_origin (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_AS_PATH:
	  ret = attr_aspath (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_NEXT_HOP:	
	  ret = attr_nexthop (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_MULTI_EXIT_DISC:
	  ret = attr_med (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_LOCAL_PREF:
	  ret = attr_local_pref (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_ATOMIC_AGGREGATE:
	  ret = attr_atomic (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_COMMUNITIES:
	  ret = attr_community (attr, flag, pnt, length);
	  break;
	case BGP_ATTR_ORIGINATOR:
	case BGP_ATTR_CLUSTERLIST:
	case BGP_ATTR_DPA:
	  break;
#ifdef HAVE_IPV6
	case BGP_ATTR_MP_REACH_NLRI:
	  ret = mp_reach_parse (peer, attr, pnt, length);
	  break;
	case BGP_ATTR_MP_UNREACH_NLRI:
	  ret = mp_unreach_parse (peer, pnt, length);
	  break;
#endif /* HAVE_IPV6 */
	default:
	  /* Unknown attribute treatment. */
	  break;
	}

      /* If error occured we should free allocated attribute. */
      if (ret < 0)
	{
	  attr_free (attr);
	  return NULL;
	}

      pnt += length;
    }

  return attr;
}

/* Check all attribute exist here? */
attr_check (struct attr *attr)
{
  ;
}

#if 0
attr_dump (FILE *fp, struct attr *attr)
{
  
}

struct attr *
attr_str2attr ()
{
  struct attr *attr;
  attr = attr_new ();
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

attr_make (u_char *buf, struct attr *attr)
{
  u_char *pnt = buf;

  /* origin */
  st_1byte (ATTR_FLAG_TRANS,pnt);
  st_1byte (BGP_ATTR_ORIGIN, pnt);
  st_1byte (sizeof(attr->origin), pnt);
  st_1byte (attr->origin, pnt);

  /* aspath */
  st_1byte (ATTR_FLAG_TRANS, pnt);
  st_1byte (BGP_ATTR_AS_PATH, pnt);
  st_1byte (attr->aspath->length, pnt);
  memcpy (pnt, attr->aspath->data, attr->aspath->length);
  pnt += attr->aspath->length;

  /* next_hop */
  st_1byte(ATTR_FLAG_TRANS, pnt);
  st_1byte(BGP_ATTR_NEXT_HOP,pnt);
  st_1byte(sizeof(attr->next_hop), pnt);
  st_4octet(attr->next_hop, pnt);

  /* med */
  if (attr->med)
    {
      st_1byte(ATTR_FLAG_OPTIONAL, pnt);
      st_1byte(BGP_ATTR_MULTI_EXIT_DISC, pnt);
      st_1byte(sizeof(attr->med), pnt);
      st_4byte(attr->med, pnt);
    }
  
  /* local_pref  */
  if (attr->local_pref) 
    {
      st_1byte(0x40,pnt);
      st_1byte(BGP_ATTR_LOCAL_PREF, pnt);
      st_1byte(sizeof(attr->local_pref), pnt);
      st_4byte(attr->local_pref,pnt);
    }  
  /* MP */
#ifdef HAVE_IPV6
  if (attr->mp_nexthop_len) 
    {
      int mp_size;
      u_char *mp_len;
      u_char *nlri_len;

      st_1byte(ATTR_FLAG_OPTIONAL, pnt);
      st_1byte(BGP_ATTR_MP_REACH_NLRI, pnt);

      /* size of MP Attribute */
      mp_len = pnt;
      st_1byte (0, pnt);

      st_1byte (0, pnt);		/* SAFI */
      st_1byte (16, pnt);		/* nexthop_len */
      bcopy (attr->mp_nexthop, pnt, 16); /* nexthop */
      pnt += 16;
      st_1byte (0, pnt);		/* SNPA_num */
  
      nlri_len = pnt;
      st_2byte (0, pnt);		/* NLRI total len */

#if 0
      /* set nlri */
      st_1byte (attr->v6masklen, pnt);
      bcopy (attr->v6addr, pnt, PSIZE (attr->v6masklen));
      pnt += PSIZE(attr->v6masklen);

      /* set nlri total len */
      st_2byte (PSIZE(attr->v6masklen) + 1, nlri_len);
#endif
      mp_size = pnt - mp_len - 1;
      st_1byte (mp_size, mp_len);

      printf ("mp attr size %d\n", mp_size);
    }
#endif /* HAVE_IPV6 */

  return pnt - buf;
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

/* Multiprotocol reachable parse */
mp_reach_parse (struct peer *peer,
		struct attr *attr,
		u_char *pnt,
		int length)
{
  u_int16_t afi;
  u_char safi;
  u_char nexthop_len;
  u_char snpa_num;
  u_char *start = pnt;
  u_char *lim;
  u_char nlri_len;
  u_int16_t nlri_total_len;
  
  /* Set end of packet. */
  lim = pnt + length;

  /* Load AFI, SAFI, Nexthop. */
  ld_2byte (afi, pnt);
  ld_1byte (safi, pnt);
  ld_1byte (nexthop_len, pnt);
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

  ld_1byte (snpa_num, pnt);
  pnt += snpa_num;
  
  /* If peer is based on old draft-00. I read NLRI length from the
     packet. */
  if (peer->version == BGP_VERSION_MP_4_DRAFT_00)
    ld_2byte (nlri_total_len, pnt);

#ifdef DUMP
  printf ("AFI %d\n", afi);
  printf ("SAFI %d\n", safi);
  printf ("nexthop_len %d\n", nexthop_len);
#endif 

  while (pnt < lim) 
    {
      ld_1byte (nlri_len, pnt);
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

route_parse_v6 (struct peer *peer,
		struct attr *attr,
		u_char *pnt,
		int masklen)
{
  struct prefix_in6 *pin6;
  struct in6_addr dest;
  struct bgp_info *binfo;
  char buf[64];

  pin6 = (struct prefix_in6 *) prefix_in6_new ();
  pin6->type = ZEBRA_ROUTE_BGP;
  pin6->mask = masklen;
  memcpy (&pin6->prefix, pnt, PSIZE (masklen));
  binfo = (struct bgp_info *) bgp_info_new();
  pin6->gate.info = binfo;
  binfo->peer = peer;
  binfo->attr = attr;

  bgp_in6_add_radix (pin6);
  
  /* zebra_route_ip6 (ZEBRA_ROUTE_IPV6_ADD, dest, mask, nexthop); */
}

/* Multiprotocol unreachable parse */
mp_unreach_parse (pnt, length)
     u_char *pnt;
     int length;
{
  u_int16_t family;
  u_char safi;
  u_int16_t unfeasible_len;

  ld_2byte (family, pnt);
  ld_1byte (safi, pnt);
  ld_2byte (unfeasible_len, pnt);

  switch (family) {
  case AF_INET:
    /* multicast ? need check of SAFI... */
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    /* IPv6 withdraw */
    if (safi == SAFI_UNICAST)
      mp_ipv6_withdraw (pnt, unfeasible_len);
    break;
#endif /* HAVE_IPV6 */
  default:
    break;
  }
}

mp_ipv6_withdraw (pnt, length)
     u_char *pnt;
     u_int16_t length;
{
  /**/
}

bgp_show_ipv6 (fp)
     FILE *fp;
{
  fprintf (fp, "this is ipv6 list\r\n");
}
#endif /* HAVE_IPV6 */
