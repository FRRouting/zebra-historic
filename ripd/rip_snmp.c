/* RIP SNMP support
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

#include "ripd/ripd.h"

/* RIPv2-MIB. */
oid rip_oid [] = { 1,3,6,1,2,1,23 };

/* Hook functions. */
int rip2Globals_hook ();
int rip2IfStatEntry_hook ();
int rip2IfConfAddress_hook ();
int rip2PeerTable_hook ();

/* RIPv2-MIB rip2Globals values. */
#define rip2GlobalRouteChanges  1
#define rip2GlobalQueries       2

/* RIPv2-MIB rip2IfStatEntry. */
#define rip2IfStatEntry         1

/* RIPv2-MIB rip2IfStatTable. */
#define rip2IfStatAddress       1
#define rip2IfStatRcvBadPackets 2
#define rip2IfStatRcvBadRoutes  3
#define rip2IfStatSentUpdates   4
#define rip2IfStatStatus        5

/* RIPv2-MIB rip2IfConfTable. */
#define rip2IfConfAddress       1
#define rip2IfConfAuthType      2
#define rip2IfConfAuthKey       3
#define rip2IfConfSend          4
#define rip2IfConfReceive       5
#define rip2IfConfDefaultMetric 6
#define rip2IfConfStatus        7
#define rip2IfConfSrcAddress    8

/* RIPv2-MIB rip2PeerTable. */
#define rip2PeerAddress         1
#define rip2PeerDomain          2
#define rip2PeerLastUpdate      3
#define rip2PeerVersion         4
#define rip2PeerRcvBadPackets   5
#define rip2PeerRcvBadRoutes    6

/* RIPv2-MIB . */
struct snmp_module rip2Globals_module[] =
{
  {rip2GlobalRouteChanges,   rip2Globals_hook, NULL},
  {rip2GlobalQueries,        rip2Globals_hook, NULL},
  {0,                        NULL,             NULL}
};

struct snmp_module rip2IfStatEntry_module[] =
{
  {rip2IfStatAddress,        rip2IfStatEntry_hook, NULL},
  {rip2IfStatRcvBadPackets,  rip2IfStatEntry_hook, NULL},
  {rip2IfStatRcvBadRoutes,   rip2IfStatEntry_hook, NULL},
  {rip2IfStatSentUpdates,    rip2IfStatEntry_hook, NULL},
  {rip2IfStatStatus,         rip2IfStatEntry_hook, NULL},
  {0,                        NULL,                 NULL}
};

struct snmp_module rip2IfStatTable_module[] = 
{
  {rip2IfStatEntry,          NULL,                 rip2IfStatEntry_module}
};

struct snmp_module rip2IfConfTable[] =
{
  {rip2IfConfAddress,        rip2IfConfAddress_hook, NULL},
  {rip2IfConfAuthType,       rip2IfConfAddress_hook, NULL},
  {rip2IfConfAuthKey,        rip2IfConfAddress_hook, NULL},
  {rip2IfConfSend,           rip2IfConfAddress_hook, NULL},
  {rip2IfConfReceive,        rip2IfConfAddress_hook, NULL},
  {rip2IfConfDefaultMetric,  rip2IfConfAddress_hook, NULL},
  {rip2IfConfStatus,         rip2IfConfAddress_hook, NULL},
  {rip2IfConfSrcAddress,     rip2IfConfAddress_hook, NULL},
  {0,                        NULL,                   NULL}
};

struct snmp_module rip2PeerTable[] =
{
  {rip2PeerAddress,          rip2PeerTable_hook, NULL},
  {rip2PeerDomain,           rip2PeerTable_hook, NULL},
  {rip2PeerLastUpdate,       rip2PeerTable_hook, NULL},
  {rip2PeerVersion,          rip2PeerTable_hook, NULL},
  {rip2PeerRcvBadPackets,    rip2PeerTable_hook, NULL},
  {rip2PeerRcvBadRoutes,     rip2PeerTable_hook, NULL},
  {0,                        NULL,               NULL}
};

struct snmp_module rip2_module[] =
{
  {1, NULL, rip2Globals_module},
  {2, NULL, rip2IfStatTable_module},
  {3, NULL, rip2IfConfTable},
  {4, NULL, rip2PeerTable},
  {0, NULL, NULL}
};

struct snmp_module start_module[] = 
{
  {23, NULL, rip2_module},
  {0,  NULL, NULL}
};

int
rip2Globals_hook (struct snmp_module *module, oid instid[], size_t instid_len,
		  u_char *val_type, void **val, size_t *val_len, int getnext)
{
  /* Check single instance. */
  if (instid_len != 1)
    return -1;
  if (instid[0] != 0)
    return -1;

  /* Retrun global counter. */
  switch (module->index)
    {
    case rip2GlobalRouteChanges:
      *val_type = ASN_INTEGER;
      *val_len  = sizeof (rip_global_route_changes);
      *val = &rip_global_route_changes;
      break;
    case rip2GlobalQueries:
      *val_type = ASN_INTEGER;
      *val_len  = sizeof (rip_global_queries);
      *val = &rip_global_queries;
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

/* 23.2.1 .1.0.0.0.0 */
/* .rip2(23).rip2IfStatTable(2).rip2IfStatEntry(1).rip2IfStatAddress(1).A.B.C.D  */
int
rip2IfStatEntry_hook (struct snmp_module *module, 
		      oid instid[], size_t instid_len,
		      u_char *val_type, void **val, size_t *val_len, 
		      int getnext)
{
  static long tmp = 123;
  static struct in_addr addr;

  zlog_info ("rip2IfStatTable_hook");

  /* Instance should be rip2IfStatAddress.  */
  if (instid_len != 4)
    return -1;

  oid2in_addr (instid, instid_len, &addr);

  switch (module->index)
    {
    case rip2IfStatAddress:
      *val_type = ASN_IPADDRESS;
      *val_len = sizeof (struct in_addr);
      *val = &addr;
      break;
    case rip2IfStatRcvBadPackets:
      *val_type = ASN_INTEGER;
      *val_len = sizeof (long);
      *val = &tmp;
      break;
    case rip2IfStatRcvBadRoutes:
      *val_type = ASN_INTEGER;
      *val_len = sizeof (long);
      *val = &tmp;
      break;
    case rip2IfStatSentUpdates:
      *val_type = ASN_INTEGER;
      *val_len = sizeof (long);
      *val = &tmp;
      break;
    case rip2IfStatStatus:
      *val_type = ASN_INTEGER;
      *val_len = sizeof (long);
      *val = &tmp;
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

int
rip2IfConfAddress_hook (struct snmp_module *module,
			oid instid[], size_t instid_len,
			u_char *val_type, void **val, size_t *val_len,
			int getnext)
{
  zlog_info ("rip2IfConfAddress_hook");
  zlog_info ("module index is: %d", module->index);

  switch (module->index)
    {
    case rip2IfConfAddress:
      break;
    case rip2IfConfAuthType:
      break;
    case rip2IfConfAuthKey:
      break;
    case rip2IfConfSend:
      break;
    case rip2IfConfReceive:
      break;
    case rip2IfConfDefaultMetric:
      break;
    case rip2IfConfStatus:
      break;
    case rip2IfConfSrcAddress:
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

int
rip2PeerTable_hook (struct snmp_module *module,
		    oid instid[], size_t instid_len,
		    u_char *val_type, void **val, size_t *val_len,
		    int getnext)
{
  zlog_info ("rip2PeerTable_hook");
  zlog_info ("module index is: %d", module->index);

  switch (module->index)
    {
    case rip2PeerAddress:
      break;
    case rip2PeerDomain:
      break;
    case rip2PeerLastUpdate:
      break;
    case rip2PeerVersion:
      break;
    case rip2PeerRcvBadPackets:
      break;
    case rip2PeerRcvBadRoutes:
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

int
rip_snmp (oid objid[], size_t objid_len, u_char *val_type, void **arg, 
	  size_t *arg_len, int getnext)
{
  int ret;
  int index;
  oid *instid;
  size_t instid_len;
  struct snmp_module *module, *newmod;

  zlog_info ("RIP oid size: %d", sizeof rip_oid / sizeof (oid));

  /* Check oid tree. */
  ret = memcmp (objid, rip_oid, sizeof (rip_oid));

  if (ret != 0)
    {
      zlog_info ("No this is not RIP tree");
      return -1;
    }

  /* Lookup MIB tree. */
  module = start_module;
  index = sizeof rip_oid / sizeof (oid);

  while(index < objid_len)
    {
      zlog_info ("Next MIB index is %d", objid[index]);
      
      newmod = snmp_lookup_module (module, objid[index]);

      if (newmod == NULL)
	break;

      index++;
      module = newmod;
    }

  instid = &(objid[index]);
  instid_len = objid_len - index;

  if (module)
    {
      /* zlog_info ("RIP module is %s", module->name); */

      if (module->func)
	return (*module->func) (module, instid, instid_len,
				val_type, arg, arg_len, getnext);
      else
	return -1; /* SMUX_NOSUCHINSTANCE */
    }
  else
    {
      zlog_info ("Can't find RIP module");
      return -1;
    }
}

/* Register RIPv2-MIB. */
void
rip_snmp_init ()
{
  smux_init (rip_snmp, rip_oid, sizeof (rip_oid) / sizeof (oid));
}
#endif /* HAVE_SNMP */
