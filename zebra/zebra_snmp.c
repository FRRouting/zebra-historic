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
#include "table.h"

#include "zebra/rib.h"


#define IPFWMIB 1,3,6,1,2,1,4,24

/* BGP4-MIB. */
oid ipfw_oid [] = { IPFWMIB };

/* Hook functions. */
int ipFwNumber ();
int ipFwTable ();
int ipCidrNumber ();
int ipCidrTable ();

/* ipForwardTable */
#define IPFORWARDDEST                         1
#define IPFORWARDMASK                         2
#define IPFORWARDPOLICY                       3
#define IPFORWARDNEXTHOP                      4
#define IPFORWARDIFINDEX                      5
#define IPFORWARDTYPE                         6
#define IPFORWARDPROTO                        7
#define IPFORWARDAGE                          8
#define IPFORWARDINFO                         9
#define IPFORWARDNEXTHOPAS                   10
#define IPFORWARDMETRIC1                     11
#define IPFORWARDMETRIC2                     12
#define IPFORWARDMETRIC3                     13
#define IPFORWARDMETRIC4                     14
#define IPFORWARDMETRIC5                     15

/* ipCidrRouteTable */
#define IPCIDRROUTEDEST                       1
#define IPCIDRROUTEMASK                       2
#define IPCIDRROUTETOS                        3
#define IPCIDRROUTENEXTHOP                    4
#define IPCIDRROUTEIFINDEX                    5
#define IPCIDRROUTETYPE                       6
#define IPCIDRROUTEPROTO                      7
#define IPCIDRROUTEAGE                        8
#define IPCIDRROUTEINFO                       9
#define IPCIDRROUTENEXTHOPAS                 10
#define IPCIDRROUTEMETRIC1                   11
#define IPCIDRROUTEMETRIC2                   12
#define IPCIDRROUTEMETRIC3                   13
#define IPCIDRROUTEMETRIC4                   14
#define IPCIDRROUTEMETRIC5                   15
#define IPCIDRROUTESTATUS                    16

#define INTEGER32 ASN_INTEGER
#define GAUGE32 ASN_INTEGER
#define ENUMERATION ASN_INTEGER
#define ROWSTATUS ASN_INTEGER
#define IPADDRESS ASN_IPADDRESS
#define OBJECTIDENTIFIER ASN_OBJECT_ID

struct variable ipFwNumber_variables[] = 
{
  {0, GAUGE32, RONLY, ipFwNumber, {0}, 0}
};

struct variable ipFwTable_variables[] =
{
  {IPFORWARDDEST, IPADDRESS, RONLY, ipFwTable, {1, 1}, 2},
  {IPFORWARDMASK, IPADDRESS, RONLY, ipFwTable, {1, 2}, 2},
  {IPFORWARDPOLICY, INTEGER32, RONLY, ipFwTable, {1, 3}, 2},
  {IPFORWARDNEXTHOP, IPADDRESS, RONLY, ipFwTable, {1, 4}, 2},
  {IPFORWARDIFINDEX, INTEGER32, RONLY, ipFwTable, {1, 5}, 2},
  {IPFORWARDTYPE, ENUMERATION, RONLY, ipFwTable, {1, 6}, 2},
  {IPFORWARDPROTO, ENUMERATION, RONLY, ipFwTable, {1, 7}, 2},
  {IPFORWARDAGE, INTEGER32, RONLY, ipFwTable, {1, 8}, 2},
  {IPFORWARDINFO, OBJECTIDENTIFIER, RONLY, ipFwTable, {1, 9}, 2},
  {IPFORWARDNEXTHOPAS, INTEGER32, RONLY, ipFwTable, {1, 10}, 2},
  {IPFORWARDMETRIC1, INTEGER32, RONLY, ipFwTable, {1, 11}, 2},
  {IPFORWARDMETRIC2, INTEGER32, RONLY, ipFwTable, {1, 12}, 2},
  {IPFORWARDMETRIC3, INTEGER32, RONLY, ipFwTable, {1, 13}, 2},
  {IPFORWARDMETRIC4, INTEGER32, RONLY, ipFwTable, {1, 14}, 2},
  {IPFORWARDMETRIC5, INTEGER32, RONLY, ipFwTable, {1, 15}, 2}
};

struct variable ipCidrNumber_variables[] = 
{
  {0, GAUGE32, RONLY, ipCidrNumber, {0}, 0}
};

struct variable ipCidrTable_variables[] = 
{
  {IPCIDRROUTEDEST, IPADDRESS, RONLY, ipCidrTable, {1, 1}, 2},
  {IPCIDRROUTEMASK, IPADDRESS, RONLY, ipCidrTable, {1, 2}, 2},
  {IPCIDRROUTETOS, INTEGER32, RONLY, ipCidrTable, {1, 3}, 2},
  {IPCIDRROUTENEXTHOP, IPADDRESS, RONLY, ipCidrTable, {1, 4}, 2},
  {IPCIDRROUTEIFINDEX, INTEGER32, RONLY, ipCidrTable, {1, 5}, 2},
  {IPCIDRROUTETYPE, ENUMERATION, RONLY, ipCidrTable, {1, 6}, 2},
  {IPCIDRROUTEPROTO, ENUMERATION, RONLY, ipCidrTable, {1, 7}, 2},
  {IPCIDRROUTEAGE, INTEGER32, RONLY, ipCidrTable, {1, 8}, 2},
  {IPCIDRROUTEINFO, OBJECTIDENTIFIER, RONLY, ipCidrTable, {1, 9}, 2},
  {IPCIDRROUTENEXTHOPAS, INTEGER32, RONLY, ipCidrTable, {1, 10}, 2},
  {IPCIDRROUTEMETRIC1, INTEGER32, RONLY, ipCidrTable, {1, 11}, 2},
  {IPCIDRROUTEMETRIC2, INTEGER32, RONLY, ipCidrTable, {1, 12}, 2},
  {IPCIDRROUTEMETRIC3, INTEGER32, RONLY, ipCidrTable, {1, 13}, 2},
  {IPCIDRROUTEMETRIC4, INTEGER32, RONLY, ipCidrTable, {1, 14}, 2},
  {IPCIDRROUTEMETRIC5, INTEGER32, RONLY, ipCidrTable, {1, 15}, 2},
  {IPCIDRROUTESTATUS, ROWSTATUS, RONLY, ipCidrTable, {1, 16}, 2}
};

#define SUBTREE_ARG(V)  V, sizeof V / sizeof *V, sizeof *V

struct subtree ipfw_tree[] =
{
  {{IPFWMIB, 1}, 9, SUBTREE_ARG (ipFwNumber_variables)},
  {{IPFWMIB, 2}, 9, SUBTREE_ARG (ipFwTable_variables)},
  {{IPFWMIB, 3}, 9, SUBTREE_ARG (ipCidrNumber_variables)},
  {{IPFWMIB, 4}, 9, SUBTREE_ARG (ipCidrTable_variables)}
};

int
ipFwNumber (struct variable *v, oid objid[], size_t *objid_len,
	    void **val, size_t *val_len, int exact)
{
  int ret;
  static int result[1];
  struct route_node *np;

  ret = smux_single_instance_check (v, objid, objid_len, exact);

  /* Wrong oid request. */
  if (ret != 0)
    return -1;

  /* Return number of routing entries. */
  result[0] = 0;
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    result[0]++;

  *val_len  = sizeof(int);
  *val = result;

  return 0;
}

int
ipCidrNumber (struct variable *v, oid objid[], size_t *objid_len,
	    void **val, size_t *val_len, int exact)
{
  int ret;
  static int result[1];
  struct route_node *np;

  ret = smux_single_instance_check (v, objid, objid_len, exact);

  /* Wrong oid request. */
  if (ret != 0)
    return -1;

  /* Return number of routing entries. */
  result[0] = 0;
  for (np = route_top (ipv4_rib_table); np; np = route_next (np))
    result[0]++;

  *val_len  = sizeof(int);
  *val = result;

  return 0;
}

int
in_addr_cmp(u_char *p1, u_char *p2)
{
  int i;

  for (i=0; i<4; i++)
    {
      if (*p1 < *p2)
        return -1;
      if (*p1 > *p2)
        return 1;
      p1++; p2++;
    }
  return 0;
}

int proto_trans(int type)
{
  switch (type)
    {
      case ZEBRA_ROUTE_SYSTEM:
        return 1; /* other */
      case ZEBRA_ROUTE_KERNEL:
        return 1; /* other */
      case ZEBRA_ROUTE_CONNECT:
        return 2; /* local interface */
      case ZEBRA_ROUTE_STATIC:
        return 3; /* static route */
      case ZEBRA_ROUTE_RIP:
        return 8; /* rip */
      case ZEBRA_ROUTE_RIPNG:
        return 1; /* shouldn't happen */
      case ZEBRA_ROUTE_OSPF:
        return 13; /* ospf */
      case ZEBRA_ROUTE_OSPF6:
        return 1; /* shouldn't happen */
      case ZEBRA_ROUTE_BGP:
        return 14; /* bgp */
      default:
        return 1; /* other */
    }
}

void
check_replace(struct route_node *np2, struct rib *rib2, 
              struct route_node **np, struct rib **rib)
{
  int proto, proto2;

  if (!*np)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  if (in_addr_cmp(&(*np)->p.u.prefix, &np2->p.u.prefix) < 0)
    return;
  if (in_addr_cmp(&(*np)->p.u.prefix, &np2->p.u.prefix) > 0)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  proto = proto_trans((*rib)->type);
  proto2 = proto_trans(rib2->type);

  if (proto2 > proto)
    return;
  if (proto2 < proto)
    {
      *np = np2;
      *rib = rib2;
      return;
    }

  if (in_addr_cmp(&(*rib)->u.gate4, &rib2->u.gate4) <= 0)
    return;

  *np = np2;
  *rib = rib2;
  return;
}

void
get_fwtable_route_node(struct variable *v, oid objid[], size_t *objid_len, 
		       int exact, struct route_node **np, struct rib **rib)
{
  struct in_addr dest;
  struct route_node *np2;
  struct rib *rib2;
  int proto;
  int policy;
  struct in_addr nexthop;
  u_char *pnt;
  int i;

/* Init index variables */

  pnt = (u_char *) &dest;
  for (i = 0; i < 4; i++)
    *pnt++ = 0;

  pnt = (u_char *) &nexthop;
  for (i = 0; i < 4; i++)
    *pnt++ = 0;

  proto = 0;
  policy = 0;
 
/* Init return variables */

  *np = NULL;
  *rib = NULL;

/* Short circuit exact matches of wrong length */

  if (exact && (*objid_len != v->name_len + 10))
    return;

/* Get INDEX information out of OID.
 * ipForwardDest, ipForwardProto, ipForwardPolicy, ipForwardNextHop
 */

  if (*objid_len > v->name_len)
    oid2in_addr (objid + v->name_len, MIN(4, *objid_len - v->name_len), &dest);

  if (*objid_len > v->name_len + 4)
    proto = objid[v->name_len + 4];

  if (*objid_len > v->name_len + 5)
    policy = objid[v->name_len + 5];

  if (*objid_len > v->name_len + 6)
    oid2in_addr (objid + v->name_len + 6, MIN(4, *objid_len - v->name_len - 6), 
		 &nexthop);

  /* Apply GETNEXT on not exact search */

  if (!exact && (*objid_len >= v->name_len + 10))
    {
      pnt = ((u_char *) &nexthop)+3;
      (*pnt)++;
    }

  /* For exact: search matching entry in rib table. */

  if (exact)
    {
      if (policy) /* Not supported (yet?) */
        return;
      for (*np = route_top (ipv4_rib_table); *np; *np = route_next (*np))
	{
	  if (!in_addr_cmp(&(*np)->p.u.prefix, &dest))
	    {
	      for (*rib = (*np)->info; *rib; *rib = (*rib)->next)
	        {
		  if (!in_addr_cmp(&(*rib)->u.gate4, &nexthop))
		    if (proto == proto_trans((*rib)->type))
		      return;
		}
	    }
	}
      return;
    }

/* Search next best entry */

  for (np2 = route_top (ipv4_rib_table); np2; np2 = route_next (np2))
    {

      /* Check destination first */
      if (in_addr_cmp(&np2->p.u.prefix, &dest) > 0)
        for (rib2 = np2->info; rib2; rib2 = rib2->next)
	  check_replace(np2, rib2, np, rib);

      if (in_addr_cmp(&np2->p.u.prefix, &dest) == 0)
        { /* have to look at each rib individually */
          for (rib2 = np2->info; rib2; rib2 = rib2->next)
	    {
	      int proto2, policy2;

	      proto2 = proto_trans(rib2->type);
	      policy2 = 0;

	      if (   (policy < policy2)
	          || ((policy == policy2) && (proto < proto2))
		  || ((policy == policy2) && (proto == proto2) &&
		      (in_addr_cmp(&rib2->u.gate4, &nexthop) >= 0)))
		check_replace(np2, rib2, np, rib);
	    }
	}
    }

  if (!*rib)
    return;

  policy = 0;
  proto = proto_trans((*rib)->type);

  *objid_len = v->name_len + 10;
  pnt = (u_char *) &(*np)->p.u.prefix;
  for (i = 0; i < 4; i++)
    objid[v->name_len + i] = *pnt++;

  objid[v->name_len + 4] = proto;
  objid[v->name_len + 5] = policy;
  pnt = (u_char *) &(*rib)->u.gate4;
  for (i = 0; i < 4; i++)
    objid[v->name_len + i + 6] = *pnt++;

  return;
}

int
ipFwTable (struct variable *v, oid objid[], size_t *objid_len,
	   void **val, size_t *val_len, int exact)
{
  struct route_node *np;
  struct rib *rib;
  static int result[2];
  static struct in_addr netmask;

/* XXX */
  if (objid[v->name_len - 1] != v->index)
    *objid_len = v->name_len;

  get_fwtable_route_node(v, objid, objid_len, exact, &np, &rib);
  if (!np)
    return -1;

/* XXX */
  objid[v->name_len - 1] = v->index;
  objid[v->name_len - 2] = 1;
  objid[v->name_len - 3] = 2;

  switch (v->index)
    {
    case IPFORWARDDEST:
      *val_len = 4;
      *val = &np->p.u.prefix;
      return 0;
      break;
    case IPFORWARDMASK:
      masklen2ip(np->p.prefixlen, &netmask);
      *val_len = 4;
      *val = &netmask;
      return 0;
      break;
    case IPFORWARDPOLICY:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDNEXTHOP:
      *val_len = 4;
      *val = &rib->u.gate4;
      return 0;
      break;
    case IPFORWARDIFINDEX:
      *val_len = sizeof(int);
      *val = &rib->u.ifindex;
      return 0;
      break;
    case IPFORWARDTYPE:
      if (IS_RIB_LINK (rib))
        result[0] = 3;
      else
        result[0] = 4;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDPROTO:
      result[0] = proto_trans(rib->type);
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDAGE:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDINFO:
      result[0] = 0;
      result[1] = 0;
      *val_len  = 2 * sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDNEXTHOPAS:
      result[0] = -1;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDMETRIC1:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDMETRIC2:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDMETRIC3:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDMETRIC4:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    case IPFORWARDMETRIC5:
      result[0] = 0;
      *val_len  = sizeof(int);
      *val = result;
      return 0;
      break;
    default:
      return -1;
      break;
    }  
  return -1;
}

int
ipCidrTable (struct variable *v, oid objid[], size_t *objid_len,
	     void **val, size_t *val_len, int exact)
{
  switch (v->index)
    {
    case IPCIDRROUTEDEST:
      break;
    default:
      return -1;
      break;
    }  
  return -1;
}

void
zebra_snmp_init ()
{
  smux_init (ipfw_oid, sizeof (ipfw_oid) / sizeof (oid));
  smux_tree_register (ipfw_tree, sizeof (ipfw_tree) / sizeof (struct subtree));
}
#endif /* HAVE_SNMP */
