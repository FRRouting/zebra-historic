/* BGP4 SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifdef HAVE_SNMP
#include <asn1.h>
#include <snmp.h>
#include <snmp_impl.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "smux.h"

#include "bgpd/bgpd.h"

#define BGP4MIB 1,3,6,1,2,1,15

/* BGP4-MIB. */
oid bgp_oid [] = { BGP4MIB };

/* Hook functions. */
int bgpVersion ();
int bgpLocalAs ();
int bgpPeerTable ();
int bgpRcvdPathAttrTable ();
int bgpIdentifier ();
int bgp4PathAttrTable ();
int bgpTraps ();

/* bgpPeerTable */
#define BGPPEERIDENTIFIER                     1
#define BGPPEERSTATE                          2
#define BGPPEERADMINSTATUS                    3
#define BGPPEERNEGOTIATEDVERSION              4
#define BGPPEERLOCALADDR                      5
#define BGPPEERLOCALPORT                      6
#define BGPPEERREMOTEADDR                     7
#define BGPPEERREMOTEPORT                     8
#define BGPPEERREMOTEAS                       9
#define BGPPEERINUPDATES                     10
#define BGPPEEROUTUPDATES                    11
#define BGPPEERINTOTALMESSAGES               12
#define BGPPEEROUTTOTALMESSAGES              13
#define BGPPEERLASTERROR                     14
#define BGPPEERFSMESTABLISHEDTRANSITIONS     15
#define BGPPEERFSMESTABLISHEDTIME            16
#define BGPPEERCONNECTRETRYINTERVAL          17
#define BGPPEERHOLDTIME                      18
#define BGPPEERKEEPALIVE                     19
#define BGPPEERHOLDTIMECONFIGURED            20
#define BGPPEERKEEPALIVECONFIGURED           21
#define BGPPEERMINASORIGINATIONINTERVAL      22
#define BGPPEERMINROUTEADVERTISEMENTINTERVAL 23
#define BGPPEERINUPDATEELAPSEDTIME           24

/* bgpRcvdPathAttrTable */
#define BGPPATHATTRPEER                       1
#define BGPPATHATTRDESTNETWORK                2
#define BGPPATHATTRORIGIN                     3
#define BGPPATHATTRASPATH                     4
#define BGPPATHATTRNEXTHOP                    5
#define BGPPATHATTRINTERASMETRIC              6

#define BGP4PATHATTRPEER                      1
#define BGP4PATHATTRIPADDRPREFIXLEN           2
#define BGP4PATHATTRIPADDRPREFIX              3
#define BGP4PATHATTRORIGIN                    4
#define BGP4PATHATTRASPATHSEGMENT             5
#define BGP4PATHATTRNEXTHOP                   6
#define BGP4PATHATTRMULTIEXITDISC             7
#define BGP4PATHATTRLOCALPREF                 8
#define BGP4PATHATTRATOMICAGGREGATE           9
#define BGP4PATHATTRAGGREGATORAS             10
#define BGP4PATHATTRAGGREGATORADDR           11
#define BGP4PATHATTRCALCLOCALPREF            12
#define BGP4PATHATTRBEST                     13
#define BGP4PATHATTRUNKNOWN                  14

#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_INTEGER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

struct variable bgpVersion_variables[] = 
{
  {0, OCTET_STRING, RONLY, bgpVersion, {0}, 0}
};

struct variable bgpLocalAs_variables[] = 
{
  {0, INTEGER, RONLY, bgpLocalAs, {0}, 0}
};

struct variable bgpPeerTable_variables[] =
{
  {BGPPEERIDENTIFIER, IPADDRESS, RONLY, bgpPeerTable, {1, 1}, 2},
  {BGPPEERSTATE, INTEGER, RONLY, bgpPeerTable, {1, 2}, 2},
  {BGPPEERADMINSTATUS, INTEGER, RONLY, bgpPeerTable, {1, 3}, 2},
  {BGPPEERNEGOTIATEDVERSION, INTEGER32, RONLY, bgpPeerTable, {1, 4}, 2},
  {BGPPEERLOCALADDR, IPADDRESS, RONLY, bgpPeerTable, {1, 5}, 2},
  {BGPPEERLOCALPORT, INTEGER, RONLY, bgpPeerTable, {1, 6}, 2},
  {BGPPEERREMOTEADDR, IPADDRESS, RONLY, bgpPeerTable, {1, 7}, 2},
  {BGPPEERREMOTEPORT, INTEGER, RONLY, bgpPeerTable, {1, 8}, 2},
  {BGPPEERREMOTEAS, INTEGER, RONLY, bgpPeerTable, {1, 9}, 2},
  {BGPPEERINUPDATES, COUNTER32, RONLY, bgpPeerTable, {1, 10}, 2},
  {BGPPEEROUTUPDATES, COUNTER32, RONLY, bgpPeerTable, {1, 11}, 2},
  {BGPPEERINTOTALMESSAGES, COUNTER32, RONLY, bgpPeerTable, {1, 12}, 2},
  {BGPPEEROUTTOTALMESSAGES, COUNTER32, RONLY, bgpPeerTable, {1, 13}, 2},
  {BGPPEERLASTERROR, OCTET_STRING, RONLY, bgpPeerTable, {1, 14}, 2},
  {BGPPEERFSMESTABLISHEDTRANSITIONS, COUNTER32, RONLY, bgpPeerTable, {1, 15}, 2},
  {BGPPEERFSMESTABLISHEDTIME, GAUGE32, RONLY, bgpPeerTable, {1, 16}, 2},
  {BGPPEERCONNECTRETRYINTERVAL, INTEGER, RONLY, bgpPeerTable, {1, 17}, 2},
  {BGPPEERHOLDTIME, INTEGER, RONLY, bgpPeerTable, {1, 18}, 2},
  {BGPPEERKEEPALIVE, INTEGER, RONLY, bgpPeerTable, {1, 19}, 2},
  {BGPPEERHOLDTIMECONFIGURED, INTEGER, RONLY, bgpPeerTable, {1, 20}, 2},
  {BGPPEERKEEPALIVECONFIGURED, INTEGER, RONLY, bgpPeerTable, {1, 21}, 2},
  {BGPPEERMINASORIGINATIONINTERVAL, INTEGER, RONLY, bgpPeerTable, {1, 22}, 2},
  {BGPPEERMINROUTEADVERTISEMENTINTERVAL, INTEGER, RONLY, bgpPeerTable, {1, 23}, 2},
  {BGPPEERINUPDATEELAPSEDTIME, GAUGE32, RONLY, bgpPeerTable, {1, 24}, 2}
};

struct variable bgpIdentifier_variables[] = 
{
  {0, IPADDRESS, RONLY, bgpIdentifier, {0}, 0}
};

struct variable bgpRcvdPathAttrTable_variables[] = 
{
  {BGPPATHATTRPEER, IPADDRESS, RONLY, bgpRcvdPathAttrTable, {1, 1}, 2},
  {BGPPATHATTRDESTNETWORK, IPADDRESS, RONLY, bgpRcvdPathAttrTable, {1, 2}, 2},
  {BGPPATHATTRORIGIN, INTEGER, RONLY, bgpRcvdPathAttrTable, {1, 3}, 2},
  {BGPPATHATTRASPATH, OCTET_STRING, RONLY, bgpRcvdPathAttrTable, {1, 4}, 2},
  {BGPPATHATTRNEXTHOP, IPADDRESS, RONLY, bgpRcvdPathAttrTable, {1, 5}, 2},
  {BGPPATHATTRINTERASMETRIC, INTEGER32, RONLY, bgpRcvdPathAttrTable, {1, 6}, 2}
};

struct variable bgp4PathAttrTable_variables[] = 
{
  {BGP4PATHATTRPEER, IPADDRESS, RONLY, bgp4PathAttrTable, {1, 1}, 2},
  {BGP4PATHATTRIPADDRPREFIXLEN, INTEGER, RONLY, bgp4PathAttrTable, {1, 2}, 2},
  {BGP4PATHATTRIPADDRPREFIX, IPADDRESS, RONLY, bgp4PathAttrTable, {1, 3}, 2},
  {BGP4PATHATTRORIGIN, INTEGER, RONLY, bgp4PathAttrTable, {1, 4}, 2},
  {BGP4PATHATTRASPATHSEGMENT, OCTET_STRING, RONLY, bgp4PathAttrTable, {1, 5}, 2},
  {BGP4PATHATTRNEXTHOP, IPADDRESS, RONLY, bgp4PathAttrTable, {1, 6}, 2},
  {BGP4PATHATTRMULTIEXITDISC, INTEGER, RONLY, bgp4PathAttrTable, {1, 7}, 2},
  {BGP4PATHATTRLOCALPREF, INTEGER, RONLY, bgp4PathAttrTable, {1, 8}, 2},
  {BGP4PATHATTRATOMICAGGREGATE, INTEGER, RONLY, bgp4PathAttrTable, {1, 9}, 2},
  {BGP4PATHATTRAGGREGATORAS, INTEGER, RONLY, bgp4PathAttrTable, {1, 10}, 2},
  {BGP4PATHATTRAGGREGATORADDR, IPADDRESS, RONLY, bgp4PathAttrTable, {1, 11}, 2},
  {BGP4PATHATTRCALCLOCALPREF, INTEGER, RONLY, bgp4PathAttrTable, {1, 12}, 2},
  {BGP4PATHATTRBEST, INTEGER, RONLY, bgp4PathAttrTable, {1, 13}, 2},
  {BGP4PATHATTRUNKNOWN, OCTET_STRING, RONLY, bgp4PathAttrTable, {1, 14}, 2}
};

struct variable bgpTraps_variables[] = 
{
  {0, INTEGER, RONLY, bgpTraps, {0}, 0}
};

#define SUBTREE_ARG(V)  V, sizeof V / sizeof *V, sizeof *V

struct subtree bgp_tree[] =
{
  {{BGP4MIB, 1}, 8, SUBTREE_ARG (bgpVersion_variables)},
  {{BGP4MIB, 2}, 8, SUBTREE_ARG (bgpLocalAs_variables)},
  {{BGP4MIB, 3}, 8, SUBTREE_ARG (bgpPeerTable_variables)},
  {{BGP4MIB, 4}, 8, SUBTREE_ARG (bgpIdentifier_variables)},
  {{BGP4MIB, 5}, 8, SUBTREE_ARG (bgpRcvdPathAttrTable_variables)},
  {{BGP4MIB, 6}, 8, SUBTREE_ARG (bgp4PathAttrTable_variables)},
  {{BGP4MIB, 7}, 8, SUBTREE_ARG (bgpTraps_variables)},
};

int
bgpVersion (struct variable *v, oid objid[], size_t *objid_len,
	    void **val, size_t *val_len, int exact)
{
  int ret;
  static char version[1];

  ret = smux_single_instance_check (v, objid, objid_len, exact);

  /* Wrong oid request. */
  if (ret != 0)
    return -1;

  /* Retrun BGP version.  Zebra bgpd only support version 4. */
  version[0] = (0x80 >> (BGP_VERSION_4 - 1));
  *val_len  = 1;
  *val = version;

  return 0;
}

int
bgpLocalAs (struct variable *v, oid objid[], size_t *objid_len,
	    void **val, size_t *val_len, int exact)
{
  int ret;
  static long localas;
  struct bgp *bgp;
  struct bgp *bgp_top_get ();

  ret = smux_single_instance_check (v, objid, objid_len, exact);

  /* Wrong oid request. */
  if (ret != 0)
    return -1;

  /* Get first bgp structure. */
  bgp = bgp_top_get ();
  if (!bgp)
    return -1;

  localas = bgp->as;

  *val_len = sizeof (localas);
  *val = &localas;

  return 0;
}

struct peer *
bgpPeerTable_lookup (struct variable *v, oid objid[], size_t *objid_len, 
		     struct in_addr *addr, int exact)
{
  struct peer *peer;

  if (exact)
    {
      /* Check the length. */
      if (*objid_len != v->name_len + sizeof (struct in_addr))
	return NULL;

      oid2in_addr (objid + v->name_len, sizeof (struct in_addr), addr);

      /* peer =  peer_lookup_addr_ipv4 (*addr); */
      return peer;
    }

  return NULL;
}

int
bgpPeerTable (struct variable *v, oid objid[], size_t *objid_len,
	      void **val, size_t *val_len, int exact)
{
  static struct in_addr addr;
  struct peer *peer;

  peer = bgpPeerTable_lookup (v, objid, objid_len, &addr, exact);
  if (! peer)
    return -1;

  switch (v->index)
    {
    case BGPPEERIDENTIFIER:
      break;
    case BGPPEERSTATE:
      break;
    case BGPPEERADMINSTATUS:
      break;
    case BGPPEERNEGOTIATEDVERSION:
      break;
    case BGPPEERLOCALADDR:
      break;
    case BGPPEERLOCALPORT:
      break;
    case BGPPEERREMOTEADDR:
      break;
    case BGPPEERREMOTEPORT:
      break;
    case BGPPEERREMOTEAS:
      break;
    case BGPPEERINUPDATES:
      break;
    case BGPPEEROUTUPDATES:
      break;
    case BGPPEERINTOTALMESSAGES:
      break;
    case BGPPEEROUTTOTALMESSAGES:
      break;
    case BGPPEERLASTERROR:
      break;
    case BGPPEERFSMESTABLISHEDTRANSITIONS:
      break;
    case BGPPEERFSMESTABLISHEDTIME:
      break;
    case BGPPEERCONNECTRETRYINTERVAL:
      break;
    case BGPPEERHOLDTIME:
      break;
    case BGPPEERKEEPALIVE:
      break;
    case BGPPEERHOLDTIMECONFIGURED:
      break;
      break;
    case BGPPEERKEEPALIVECONFIGURED:
      break;
    case BGPPEERMINASORIGINATIONINTERVAL:
      break;
    case BGPPEERMINROUTEADVERTISEMENTINTERVAL:
      break;
    case BGPPEERINUPDATEELAPSEDTIME:
      break;
    default:
      return -1;
      break;
    }  

  return -1;
}

int
bgpRcvdPathAttrTable (struct variable *v, oid objid[], size_t *objid_len,
		      void **val, size_t *val_len, int exact)
{
  return -1;
}

int
bgpIdentifier (struct variable *v, oid objid[], size_t *objid_len,
	       void **val, size_t *val_len, int exact)
{
  return -1;
}

int
bgp4PathAttrTable (struct variable *v, oid objid[], size_t *objid_len,
		   void **val, size_t *val_len, int exact)
{
  return -1;
}

int
bgpTraps (struct variable *v, oid objid[], size_t *objid_len,
	  void **val, size_t *val_len, int exact)
{
  return -1;
}

void
bgp_snmp_init ()
{
  smux_init (bgp_oid, sizeof (bgp_oid) / sizeof (oid));
  smux_tree_register (bgp_tree, sizeof (bgp_tree) / sizeof (struct subtree));
}
#endif /* HAVE_SNMP */
