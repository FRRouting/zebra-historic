/* RIP SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "table.h"
#include "smux.h"

#include "ripd/ripd.h"
#ifdef RIP_API
#include "ripd/ripd_api.h" /* RIPD_API */
#endif /* RIP_API */

/* RIPv2-MIB. */
#define RIPV2MIB 1,3,6,1,2,1,23

/* Zebra enterprise RIP MIB.  This variable is used for register
   RIPv2-MIB to SNMP agent under SMUX protocol.  */
#define RIPDOID 1,3,6,1,4,1,3317,1,2,3

/* RIPv2-MIB rip2Globals values. */
#define RIP2GLOBALROUTECHANGES  1
#define RIP2GLOBALQUERIES       2

/* RIPv2-MIB rip2IfStatEntry. */
#define RIP2IFSTATENTRY         1

/* RIPv2-MIB rip2IfStatTable. */
#define RIP2IFSTATADDRESS       1
#define RIP2IFSTATRCVBADPACKETS 2
#define RIP2IFSTATRCVBADROUTES  3
#define RIP2IFSTATSENTUPDATES   4
#define RIP2IFSTATSTATUS        5

/* RIPv2-MIB rip2IfConfTable. */
#define RIP2IFCONFADDRESS       1
#define RIP2IFCONFDOMAIN        2
#define RIP2IFCONFAUTHTYPE      3
#ifdef RIP_API
#  define Leaf_rip2IfConfAuthType_noAuthentication       1
#  define Leaf_rip2IfConfAuthType_simplePassword         2
#  define Leaf_rip2IfConfAuthType_md5                    3
#endif /* RIP_API */
#define RIP2IFCONFAUTHKEY       4
#define RIP2IFCONFSEND          5
#ifdef RIP_API
#  define Leaf_rip2IfConfSend_doNotSend                  1
#  define Leaf_rip2IfConfSend_ripVersion1                2
#  define Leaf_rip2IfConfSend_rip1Compatible             3
#  define Leaf_rip2IfConfSend_ripVersion2                4
#  define Leaf_rip2IfConfSend_ripV1Demand                5
#  define Leaf_rip2IfConfSend_ripV2Demand                6
#endif /* RIP_API */
#define RIP2IFCONFRECEIVE       6
#ifdef RIP_API 
#  define Leaf_rip2IfConfReceive_rip1                    1
#  define Leaf_rip2IfConfReceive_rip2                    2
#  define Leaf_rip2IfConfReceive_rip1OrRip2              3
#  define Leaf_rip2IfConfReceive_doNotRecieve            4
#endif /* RIP_API */
#define RIP2IFCONFDEFAULTMETRIC 7
#define RIP2IFCONFSTATUS        8
#define RIP2IFCONFSRCADDRESS    9

/* RIPv2-MIB rip2PeerTable. */
#define RIP2PEERADDRESS         1
#define RIP2PEERDOMAIN          2
#define RIP2PEERLASTUPDATE      3
#define RIP2PEERVERSION         4
#define RIP2PEERRCVBADPACKETS   5
#define RIP2PEERRCVBADROUTES    6

/* SNMP value hack. */
#define COUNTER     ASN_COUNTER
#define INTEGER     ASN_INTEGER
#define TIMETICKS   ASN_TIMETICKS
#define IPADDRESS   ASN_IPADDRESS
#define STRING      ASN_OCTET_STR

/* RIP Autentication string max. */
#ifdef RIP_API
#define MAX_AUTH_STRING 18  /* XXX */
#endif /* RIP_API */

/* Define SNMP local variables. */
SNMP_LOCAL_VARIABLES

/* RIP-MIB instances. */
oid rip_oid [] = { RIPV2MIB };
oid ripd_oid [] = { RIPDOID };

/* Interface cache table sorted by interface's address. */
struct route_table *rip_ifaddr_table;

/* Hook functions. */
static u_char *rip2Globals ();
static u_char *rip2IfStatEntry ();
static u_char *rip2IfConfAddress ();
static u_char *rip2PeerTable ();

struct variable rip_variables[] = 
{
  /* RIP Global Counters. */
  {RIP2GLOBALROUTECHANGES,    COUNTER, RONLY, rip2Globals,
   2, {1, 1}},
  {RIP2GLOBALQUERIES,         COUNTER, RONLY, rip2Globals,
   2, {1, 2}},
  /* RIP Interface Tables. */
  {RIP2IFSTATADDRESS,         IPADDRESS, RONLY, rip2IfStatEntry,
   3, {2, 1, 1}},
  {RIP2IFSTATRCVBADPACKETS,   COUNTER, RONLY, rip2IfStatEntry,
   3, {2, 1, 2}},
  {RIP2IFSTATRCVBADROUTES,    COUNTER, RONLY, rip2IfStatEntry,
   3, {2, 1, 3}},
  {RIP2IFSTATSENTUPDATES,     COUNTER, RONLY, rip2IfStatEntry,
   3, {2, 1, 4}},
  {RIP2IFSTATSTATUS,          COUNTER, RWRITE, rip2IfStatEntry,
   3, {2, 1, 5}},
  {RIP2IFCONFADDRESS,         IPADDRESS, RONLY, rip2IfConfAddress,
   /* RIP Interface Configuration Table. */
   3, {3, 1, 1}},
  {RIP2IFCONFDOMAIN,          STRING, RONLY, rip2IfConfAddress,
   3, {3, 1, 2}},
  {RIP2IFCONFAUTHTYPE,        COUNTER, RONLY, rip2IfConfAddress,
   3, {3, 1, 3}},
  {RIP2IFCONFAUTHKEY,         STRING, RONLY, rip2IfConfAddress,
   3, {3, 1, 4}},
  {RIP2IFCONFSEND,            COUNTER, RONLY, rip2IfConfAddress,
   3, {3, 1, 5}},
  {RIP2IFCONFRECEIVE,         COUNTER, RONLY, rip2IfConfAddress,
   3, {3, 1, 6}},
  {RIP2IFCONFDEFAULTMETRIC,   COUNTER, RONLY, rip2IfConfAddress,
   3, {3, 1, 7}},
  {RIP2IFCONFSTATUS,          COUNTER, RONLY, rip2IfConfAddress,
   3, {3, 1, 8}},
  {RIP2IFCONFSRCADDRESS,      IPADDRESS, RONLY, rip2IfConfAddress,
   3, {3, 1, 9}},
  {RIP2PEERADDRESS,           IPADDRESS, RONLY, rip2PeerTable,
   /* RIP Peer Table. */
   3, {4, 1, 1}},
  {RIP2PEERDOMAIN,            INTEGER, RONLY, rip2PeerTable,
   3, {4, 1, 2}},
  {RIP2PEERLASTUPDATE,        TIMETICKS, RONLY, rip2PeerTable,
   3, {4, 1, 3}},
  {RIP2PEERVERSION,           INTEGER, RONLY, rip2PeerTable,
   3, {4, 1, 4}},
  {RIP2PEERRCVBADPACKETS,     COUNTER, RONLY, rip2PeerTable,
   3, {4, 1, 5}},
  {RIP2PEERRCVBADROUTES,      COUNTER, RONLY, rip2PeerTable,
   3, {4, 1, 6}}
};

static u_char *
rip2Globals (struct variable *v, oid name[], size_t *length,
	     int exact, size_t *var_len, WriteMethod **write_method)
{
#ifdef RIP_API
  static rip_globals_t info;
#endif /* RIP_API */

  if (smux_header_generic(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

#ifdef RIP_API
  ripd_api_get_globals (&info);
#endif /* RIP_API */

  /* Retrun global counter. */
  switch (v->magic)
    {
    case RIP2GLOBALROUTECHANGES:
#ifdef RIP_API
      return SNMP_INTEGER (info.rip_global_route_changes);
#else
      return SNMP_INTEGER (rip_global_route_changes);
#endif /* RIP_API */
      break;
    case RIP2GLOBALQUERIES:
#ifdef RIP_API
      return SNMP_INTEGER (info.rip_global_queries);
#else
      return SNMP_INTEGER (rip_global_queries);
#endif /* RIP_API */
      break;
    default:
      return NULL;
      break;
    }
  return NULL;
}

void
rip_ifaddr_add (struct interface *ifp, struct connected *ifc)
{
  struct prefix *p;
  struct route_node *rn;

  p = ifc->address;

  if (p->family != AF_INET)
    return;

  rn = route_node_get (rip_ifaddr_table, p);
  rn->info = ifp;
}

void
rip_ifaddr_delete (struct interface *ifp, struct connected *ifc)
{
  struct prefix *p;
  struct route_node *rn;
  struct interface *i;

  p = ifc->address;

  if (p->family != AF_INET)
    return;

  rn = route_node_lookup (rip_ifaddr_table, p);
  i=rn->info;
  if (rn && !strncmp(i->name,ifp->name,INTERFACE_NAMSIZ))
    {
      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
    }
}

struct interface *
rip_ifaddr_lookup_next (struct in_addr *addr)
{
  struct prefix_ipv4 p;
  struct route_node *rn;
  struct interface *ifp;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.prefix = *addr;

  rn = route_node_get (rip_ifaddr_table, (struct prefix *) &p);

  for (rn = route_next (rn); rn; rn = route_next (rn))
    if (rn->info)
      break;

  if (rn && rn->info)
    {
      ifp = rn->info;
      *addr = rn->p.u.prefix4;
      route_unlock_node (rn);
      return ifp;
    }
  return NULL;
}

static struct interface *
rip2IfLookup (struct variable *v, oid name[], size_t *length, 
	      struct in_addr *addr, int exact)
{
  int len;
  struct interface *ifp;
  
  if (exact)
    {
      /* Check the length. */
      if (*length - v->namelen != sizeof (struct in_addr))
	return NULL;

      oid2in_addr (name + v->namelen, sizeof (struct in_addr), addr);

      return if_lookup_exact_address (*addr);
    }
  else
    {
      len = *length - v->namelen;
      if (len > 4) len = 4;

      oid2in_addr (name + v->namelen, len, addr);

      ifp = rip_ifaddr_lookup_next (addr);

      if (ifp == NULL)
	return NULL;

      oid_copy_addr (name + v->namelen, addr, sizeof (struct in_addr));

      *length = v->namelen + sizeof (struct in_addr);

      return ifp;
    }
  return NULL;
}

static struct rip_peer *
rip2PeerLookup (struct variable *v, oid name[], size_t *length, 
		struct in_addr *addr, int exact)
{
  int len;
  struct rip_peer *peer;
  
  if (exact)
    {
      /* Check the length. */
      if (*length - v->namelen != sizeof (struct in_addr) + 1)
	return NULL;

      oid2in_addr (name + v->namelen, sizeof (struct in_addr), addr);

      peer = rip_peer_lookup (addr);

      if (peer->domain == name[v->namelen + sizeof (struct in_addr)])
	return peer;

      return NULL;
    }
  else
    {
      len = *length - v->namelen;
      if (len > 4) len = 4;

      oid2in_addr (name + v->namelen, len, addr);

      len = *length - v->namelen;
      peer = rip_peer_lookup (addr);
      if (peer)
	{
	  if ((len < sizeof (struct in_addr) + 1) ||
	      (peer->domain > name[v->namelen + sizeof (struct in_addr)]))
	    {
	      oid_copy_addr (name + v->namelen, &peer->addr,
			     sizeof (struct in_addr));
	      name[v->namelen + sizeof (struct in_addr)] = peer->domain;
	      *length = sizeof (struct in_addr) + v->namelen + 1;
	      return peer;
	    }
        } 
      peer = rip_peer_lookup_next (addr);

      if (! peer)
	return NULL;

      oid_copy_addr (name + v->namelen, &peer->addr,
		     sizeof (struct in_addr));
      name[v->namelen + sizeof (struct in_addr)] = peer->domain;
      *length = sizeof (struct in_addr) + v->namelen + 1;

      return peer;
    }
  return NULL;
}

static u_char *
rip2IfStatEntry (struct variable *v, oid name[], size_t *length,
	         int exact, size_t *var_len, WriteMethod **write_method)
{
  struct interface *ifp;
  struct rip_interface *ri;
  static struct in_addr addr;
  static long valid = SNMP_VALID;

  memset (&addr, 0, sizeof (struct in_addr));
#ifdef RIP_API
  *write_method = NULL;
#endif /* RIP_API */
  
  /* Lookup interface. */
  ifp = rip2IfLookup (v, name, length, &addr, exact);
  if (! ifp)
    return NULL;

  /* Fetch rip_interface information. */
  ri = ifp->info;

  switch (v->magic)
    {
    case RIP2IFSTATADDRESS:
      return SNMP_IPADDRESS (addr);
      break;
    case RIP2IFSTATRCVBADPACKETS:
      *var_len = sizeof (long);
      return (u_char *) &ri->recv_badpackets;

    case RIP2IFSTATRCVBADROUTES:
      *var_len = sizeof (long);
      return (u_char *) &ri->recv_badroutes;

    case RIP2IFSTATSENTUPDATES:
      *var_len = sizeof (long);
      return (u_char *) &ri->sent_updates;

    case RIP2IFSTATSTATUS:
      *var_len = sizeof (long);
      v->type = ASN_INTEGER;
      return (u_char *) &valid;

    default:
      return NULL;

    }
  return NULL;
}

#ifdef RIP_API
long
rip2IfConf_SendVersion_2_SNMP (int version)
{
  long res;

  switch (version){
  case RI_RIP_VERSION_1_AND_2:
    res=Leaf_rip2IfConfSend_rip1Compatible;
    break;
  case RI_RIP_VERSION_2:
    res=Leaf_rip2IfConfSend_ripVersion2;
    break;
  case RI_RIP_VERSION_1:
    res=Leaf_rip2IfConfSend_ripVersion1;
    break;
  default:
    res=Leaf_rip2IfConfSend_doNotSend;
    break;
  }
  return res;
}

int
rip2IfConf_SNMP_2_SendVersion (long value)
{
  switch (value)
    {
    case Leaf_rip2IfConfSend_doNotSend:
      return RI_RIP_UNSPEC;
    case Leaf_rip2IfConfSend_ripVersion1:
      return RI_RIP_VERSION_1;
    case Leaf_rip2IfConfSend_ripVersion2:
      return RI_RIP_VERSION_2;

#if 1 /* XXX */
    case Leaf_rip2IfConfSend_ripV1Demand:
    case Leaf_rip2IfConfSend_ripV2Demand:
#endif
    default:
    case Leaf_rip2IfConfSend_rip1Compatible:
      return RI_RIP_VERSION_1_AND_2;
    }
}

long
rip2IfConf_ReceiveVersion_2_SNMP (int version)
{
  long res;
  
  switch(version){
  case RI_RIP_VERSION_1_AND_2:
    res=Leaf_rip2IfConfReceive_rip1OrRip2;
    break;
  case RI_RIP_VERSION_2:  
    res=Leaf_rip2IfConfReceive_rip2;
    break;
  case RI_RIP_VERSION_1:
    res=Leaf_rip2IfConfReceive_rip1;
    break;
  default:
    res=Leaf_rip2IfConfReceive_doNotRecieve;
    break;
  }
  return res;
}

int
rip2IfReceive_SNMP_2_SendVersion (long value)
{
  switch (value)
    {
    case Leaf_rip2IfConfReceive_rip1OrRip2:
      return RI_RIP_VERSION_1_AND_2;
    case Leaf_rip2IfConfReceive_rip2:
      return RI_RIP_VERSION_2;
    case Leaf_rip2IfConfReceive_rip1:
      return RI_RIP_VERSION_1;
    case Leaf_rip2IfConfReceive_doNotRecieve:
    default:
      return RI_RIP_UNSPEC;
    }
}

int
get_and_check_int (u_char *var_val,
                   u_char var_val_type,
                   size_t var_val_len,
                   long min_val,
                   long max_val,
                   long *intval)
{
  int     bigsize = SNMP_MAX_LEN;
  static char fun_name[] = "get_and_check_int";

  *intval = min_val;

  /* check type */
  if (var_val_type != ASN_INTEGER)
    {
      zlog_err ("%s: invalid type: %d", (char*) fun_name, (int) var_val_type);
      return SNMP_ERR_WRONGTYPE;
    }

  /* check size */
  if (var_val_len != sizeof (long))
    {
      zlog_err ("%s: invalid length: %d", (char*) fun_name, (int) var_val_len);
      return SNMP_ERR_WRONGLENGTH;
    }

  if (! asn_parse_int(var_val, &bigsize, &var_val_type,
                      intval, sizeof(long)))
    {
      zlog_err ("%s: wrong encoding", (char*) fun_name);
      return SNMP_ERR_WRONGENCODING;
    }

  if (max_val > min_val) 
    {/* check limits */
      if (*intval < min_val)
        {
          zlog_err ("%s: invalid value (small): %ld < %ld",
                    (char*) fun_name, (long) *intval, (long) min_val);
          return SNMP_ERR_BADVALUE;
        }

      if (*intval > max_val)
        {
          zlog_err ("%s: invalid value (big): %ld > %ld",
                    (char*) fun_name, (long) *intval, (long) max_val);
          return SNMP_ERR_BADVALUE;
        }
    }

  return SNMP_ERR_NOERROR;
}

int
get_and_check_string (u_char *var_val,
		      u_char var_val_type,
		      size_t var_val_len,
		      size_t buffer_max_size,
		      u_char should_zero_limited,
		      size_t *buffer_actual_size,
		      char *buffer)
{
  int     bigsize = SNMP_MAX_LEN;

  if (var_val_type != ASN_OCTET_STR)
    return SNMP_ERR_WRONGTYPE;

  
  if (should_zero_limited)
    buffer_max_size--;

  if (! asn_parse_string(var_val, &bigsize, &var_val_type, buffer, &buffer_max_size))
    {
      zlog_err ("get_string: asn_parse_string failed");
      return SNMP_ERR_WRONGENCODING;
    }

  if (buffer_actual_size)
    *buffer_actual_size = buffer_max_size;

  if (should_zero_limited)
    {
      buffer[buffer_max_size] = 0;
      if (buffer_actual_size)
        *buffer_actual_size += 1;
    }

  return SNMP_ERR_NOERROR;
}

int
act_rip2IfConfAddress (int action,
                       u_char  *var_val,
                       u_char      var_val_type,
                       size_t      var_val_len,
                       u_char      *statP,
                       struct interface *ifp,
                       int         leaf_id)
{
  long intval;
  int ret;
  int version;
  char auth_str[MAX_AUTH_STRING];

  ret = SNMP_ERR_NOERROR; /* default: we are optimists */

  switch (leaf_id)
    {
    case RIP2IFCONFDOMAIN:
      zlog_err ("Cannot write rip2IfConfDomain");
      ret = SNMP_ERR_GENERR;
      break;

    case RIP2IFCONFAUTHTYPE:
      ret = get_and_check_int (var_val, var_val_type, var_val_len,
			       Leaf_rip2IfConfAuthType_noAuthentication,
			       Leaf_rip2IfConfAuthType_md5,
			       &intval);
      if (SNMP_ERR_NOERROR == ret && COMMIT == action &&
	  CMD_SUCCESS != ripd_api_set_if_authentication_type (ifp, intval))
	{
	  ret = SNMP_ERR_GENERR;
	}
      break;

    case RIP2IFCONFAUTHKEY:
      ret = get_and_check_string (var_val, var_val_type, var_val_len,
				  MAX_AUTH_STRING - 1, 1, NULL,
				  auth_str);
      if (SNMP_ERR_NOERROR == ret && COMMIT == action &&
	  CMD_SUCCESS != ripd_api_set_if_authentication_string (ifp, auth_str))
	{
	  ret = SNMP_ERR_GENERR;
	}
      break;

    case RIP2IFCONFSEND:
      ret = get_and_check_int (var_val, var_val_type, var_val_len,
			       Leaf_rip2IfConfSend_doNotSend,
			       Leaf_rip2IfConfSend_ripV2Demand,
			       &intval);
      if (SNMP_ERR_NOERROR == ret && COMMIT == action)
	{
	  version = rip2IfConf_SNMP_2_SendVersion (intval);
	  if (CMD_SUCCESS != ripd_api_set_if_tx_version (ifp, version)) 
	    {
	      zlog_err ("ripd_api_set_if_tx_version failed\n");
	      ret = SNMP_ERR_GENERR;
	    } 
	}
      break;

    case RIP2IFCONFRECEIVE:
      ret = get_and_check_int (var_val, var_val_type, var_val_len,
			       Leaf_rip2IfConfReceive_rip1,
			       Leaf_rip2IfConfReceive_doNotRecieve,
			       &intval);
      if (SNMP_ERR_NOERROR == ret && COMMIT == action)
	{
	  version = rip2IfReceive_SNMP_2_SendVersion (intval);
	  if (CMD_SUCCESS != ripd_api_set_if_rx_version (ifp, version)) 
	    {
	      ret = SNMP_ERR_GENERR;
	    } 
	}
      break;

    case RIP2IFCONFDEFAULTMETRIC:
      ret = get_and_check_int (var_val, var_val_type, var_val_len,
			       0,
			       0,
			       &intval);
      zlog_err ("Cannot write rip2IfConfDefaultMetric");
      ret = SNMP_ERR_GENERR;
      break;

    case RIP2IFCONFSTATUS:
      zlog_err ("Cannot write rip2IfConfStatus");
      ret = SNMP_ERR_GENERR;
      break;

    case RIP2IFCONFSRCADDRESS:
      zlog_err ("Cannot write rip2IfConfSrcAddress");
      ret = SNMP_ERR_GENERR;
      break;

    default:
      zlog_err ("Unknown leaf=%d", (int) leaf_id);
      ret = SNMP_ERR_GENERR;
    }

  return ret;
}

int
write_rip2IfConfAddress (int action,
			 u_char  *var_val,
			 u_char   var_val_type,
			 size_t   var_val_len,
			 u_char  *statP,
			 oid     *name,
			 size_t   length)
{
  int              leaf_id;
  int              ret;
  struct in_addr   addr;
  struct interface      *ifp;

  oid2in_addr (name + length - sizeof (struct in_addr), sizeof (struct in_addr), &addr);
  leaf_id = (int) name[length - sizeof (struct in_addr) - 1];
  ifp = if_lookup_exact_address (addr);
  if (! ifp)
    return SNMP_ERR_NOSUCHNAME;

  ret = SNMP_ERR_NOERROR;

  switch (action)
    {
    case RESERVE1:
    case COMMIT:
      ret = act_rip2IfConfAddress (action, var_val, var_val_type,
				   var_val_len, statP, ifp,
				   leaf_id);
      break;

    case FREE:
      /* undo it */
      break;

    default:
      ret = SNMP_ERR_GENERR;
    } /* of switch by 'action' */

  return ret;
}

#else
static long
rip2IfConfSend (struct rip_interface *ri)
{
#define doNotSend       1
#define ripVersion1     2
#define rip1Compatible  3
#define ripVersion2     4
#define ripV1Demand     5
#define ripV2Demand     6

  if (! ri->running)
    return doNotSend;
    
  if (ri->ri_send & RIPv2)
    return ripVersion2;
  else if (ri->ri_send & RIPv1)
    return ripVersion1;
  else if (rip)
    {
      if (rip->version == RIPv2)
	return ripVersion2;
      else if (rip->version == RIPv1)
	return ripVersion1;
    }
  return doNotSend;
}

static long
rip2IfConfReceive (struct rip_interface *ri)
{
#define rip1            1
#define rip2            2
#define rip1OrRip2      3
#define doNotReceive    4

  if (! ri->running)
    return doNotReceive;

  if (ri->ri_receive == RI_RIP_VERSION_1_AND_2)
    return rip1OrRip2;
  else if (ri->ri_receive & RIPv2)
    return ripVersion2;
  else if (ri->ri_receive & RIPv1)
    return ripVersion1;
  else
    return doNotReceive;
}
#endif /* RIP_API */

static u_char *
rip2IfConfAddress (struct variable *v, oid name[], size_t *length,
	           int exact, size_t *val_len, WriteMethod **write_method)
{
  static struct in_addr addr;
  static long valid = SNMP_INVALID;
  static long domain = 0;
  static long config = 0;
  static u_int auth = 0;
#ifdef RIP_API  
  static char auth_str[MAX_AUTH_STRING];
#endif /* RIP_API */
  struct interface *ifp;
  struct rip_interface *ri;
#ifdef RIP_API
  int version, running;
#endif /* RIP_API */  

  memset (&addr, 0, sizeof (struct in_addr));
#ifdef RIP_API
  *write_method = write_rip2IfConfAddress;
#endif /* RIP_API */  
  
  /* Lookup interface. */
  ifp = rip2IfLookup (v, name, length, &addr, exact);
  if (! ifp)
    return NULL;

  /* Fetch rip_interface information. */
  ri = ifp->info;

  switch (v->magic)
    {
    case RIP2IFCONFADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;

    case RIP2IFCONFDOMAIN:
      *val_len = 2;
      return (u_char *) &domain;

    case RIP2IFCONFAUTHTYPE:
#ifdef RIP_API
      switch (ri->auth_type)
	{
	case RIP_NO_AUTH:
	  auth=Leaf_rip2IfConfAuthType_noAuthentication;
	  break;
	case RIP_AUTH_SIMPLE_PASSWORD:
	  auth=Leaf_rip2IfConfAuthType_simplePassword;
	  break;
	case RIP_AUTH_MD5:
	  auth=Leaf_rip2IfConfAuthType_md5;
	  break;
	default:
	  auth=Leaf_rip2IfConfAuthType_noAuthentication;
	  break;
	}
#else
      auth = ri->auth_type;
#endif /* RIP_API */
      *val_len = sizeof (long);
      v->type = ASN_INTEGER;
      return (u_char *)&auth;

    case RIP2IFCONFAUTHKEY:
#ifdef RIP_API
      ripd_api_get_if_authentication_string (ifp, MAX_AUTH_STRING,
                                             auth_str, NULL);
      *val_len = strlen (auth_str);
      return (u_char *) auth_str;
      break;
#else	
      *val_len = 0;
      return (u_char *) &domain;
#endif /* RIP_API */

    case RIP2IFCONFSEND:
#ifdef RIP_API
      ripd_api_get_if_tx_version (ifp, &version);
      config = rip2IfConf_SendVersion_2_SNMP (version);
#else
      config = rip2IfConfSend (ri);
#endif /* RIP_API */
      *val_len = sizeof (long);
      v->type = ASN_INTEGER;
      return (u_char *) &config;

    case RIP2IFCONFRECEIVE:
#ifdef RIP_API
      ripd_api_get_if_rx_version (ifp, &version);
      config = rip2IfConf_ReceiveVersion_2_SNMP (version);
#else
      config = rip2IfConfReceive (ri);
#endif /* RIP_API */
      *val_len = sizeof (long);
      v->type = ASN_INTEGER;
      return (u_char *) &config;

    case RIP2IFCONFDEFAULTMETRIC:
      *val_len = sizeof (long);
      v->type = ASN_INTEGER;
      /* RIPv2-MIB speaks of metric for default route.  that's not
	 what we do here.*/
      return (u_char *) &ifp->metric;

    case RIP2IFCONFSTATUS:
#ifdef RIP_API      
      ripd_api_get_if_running (ifp, &running);
      valid = running ? SNMP_VALID : SNMP_INVALID;
#endif /* RIP_API */
      *val_len = sizeof (long);
      v->type = ASN_INTEGER;
      return (u_char *) &valid;

    case RIP2IFCONFSRCADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &addr;

    default:
      return NULL;

    }
  return NULL;
}

static u_char *
rip2PeerTable (struct variable *v, oid name[], size_t *length,
	       int exact, size_t *val_len, WriteMethod **write_method)
{
  static struct in_addr addr;
  static int version;
  /* static time_t uptime; */

  struct rip_peer *peer;

  memset (&addr, 0, sizeof (struct in_addr));
  
  /* Lookup interface. */
  peer = rip2PeerLookup (v, name, length, &addr, exact);
  if (! peer)
    return NULL;

  switch (v->magic)
    {
    case RIP2PEERADDRESS:
      *val_len = sizeof (struct in_addr);
      return (u_char *) &peer->addr;

    case RIP2PEERDOMAIN:
      *val_len = sizeof (int);
      return (u_char *) &peer->domain;

    case RIP2PEERLASTUPDATE:
#if 0 
      /* We don't know the SNMP agent startup time. We have two choices here:
       * - assume ripd startup time equals SNMP agent startup time
       * - don't support this variable, at all
       * Currently, we do the latter...
       */
      *val_len = sizeof (time_t);
      uptime = peer->uptime; /* now - snmp_agent_startup - peer->uptime */
      return (u_char *) &uptime;
#else
      return (u_char *) NULL;
#endif

    case RIP2PEERVERSION:
      *val_len = sizeof (int);
      version = peer->version;
      return (u_char *) &version;

    case RIP2PEERRCVBADPACKETS:
      *val_len = sizeof (int);
      return (u_char *) &peer->recv_badpackets;

    case RIP2PEERRCVBADROUTES:
      *val_len = sizeof (int);
      return (u_char *) &peer->recv_badroutes;

    default:
      return NULL;

    }
  return NULL;
}

/* Register RIPv2-MIB. */
void
rip_snmp_init ()
{
  rip_ifaddr_table = route_table_init ();

  smux_init (ripd_oid, sizeof (ripd_oid) / sizeof (oid));
  REGISTER_MIB("mibII/rip", rip_variables, variable, rip_oid);
  smux_start ();
}
#endif /* HAVE_SNMP */
