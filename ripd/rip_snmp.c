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

#include "log.h"
#include "prefix.h"
#include "command.h"
#include "smux.h"

#include "ripd/ripd.h"

/* Hook functions. */
int rip2Globals_hook ();
int rip2IfStatTable_hook ();
int rip2IfConfAddress_hook ();
int rip2PeerTable_hook ();

struct snmp_module rip2Globals_module[] =
{
  {"rip2GlobalRouteChanges",  1, rip2Globals_hook, NULL},
  {"rip2GlobalQueries",       2, rip2Globals_hook, NULL},
  {NULL,                      0, NULL,             NULL}
};

struct snmp_module rip2IfStatTable_module[] =
{
  {"rip2IfStatAddress",       1, rip2IfStatTable_hook, NULL},
  {"rip2IfStatRcvBadPackets", 2, rip2IfStatTable_hook, NULL},
  {"rip2IfStatRcvBadRoutes",  3, rip2IfStatTable_hook, NULL},
  {"rip2IfStatSentUpdates",   4, rip2IfStatTable_hook, NULL},
  {"rip2IfStatStatus",        5, rip2IfStatTable_hook, NULL},
  {NULL,                      0, NULL,                 NULL}
};

struct snmp_module rip2IfConfTable[] =
{
  {"rip2IfConfAddress",       1, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfAuthType",      2, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfAuthKey",       3, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfSend",          4, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfReceive",       5, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfDefaultMetric", 6, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfStatus",        7, rip2IfConfAddress_hook, NULL},
  {"rip2IfConfSrcAddress",    8, rip2IfConfAddress_hook, NULL},
  {NULL,                      0, NULL,                   NULL}
};

struct snmp_module rip2PeerTable[] =
{
  {"rip2PeerAddress",         1, rip2PeerTable_hook, NULL},
  {"rip2PeerDomain",          2, rip2PeerTable_hook, NULL},
  {"rip2PeerLastUpdate",      3, rip2PeerTable_hook, NULL},
  {"rip2PeerVersion",         4, rip2PeerTable_hook, NULL},
  {"rip2PeerRcvBadPackets",   5, rip2PeerTable_hook, NULL},
  {"rip2PeerRcvBadRoutes",    6, rip2PeerTable_hook, NULL},
  {NULL,                      0, NULL,               NULL}
};

struct snmp_module rip2_module[] =
{
  {"rip2Globals",             1, NULL, rip2Globals_module},
  {"rip2IfStatTable",         2, NULL, NULL},
  {"rip2IfConfTable",         3, NULL, NULL},
  {"rip2PeerTable",           4, NULL, NULL},
  {NULL,                      0, NULL, NULL}
};

struct snmp_module start_module[] = 
{
  {"rip2",                   23, NULL, rip2_module},
  {NULL,                      0, NULL, NULL}
};

int
rip2Globals_hook (struct snmp_module *module, u_char *val_type, void **val, 
                  size_t *val_len, oid instid[], size_t instid_len)
{
  zlog_info ("rip2Globals_hook");

  zlog_info ("module index is: %d", module->index);

  if (instid_len != 1)
    return -1;
  if (instid[0] != 0)
    return -1;

  switch (module->index)
    {
    case 1:
      *val_type = ASN_INTEGER;
      *val_len  = sizeof (rip_global_route_changes);
      *val = &rip_global_route_changes;
      return 0;
    case 2:
      *val_type = ASN_INTEGER;
      *val_len  = sizeof (rip_global_queries);
      *val = &rip_global_queries;
      return 0;
    default:
      return -1;
    }
}

int
rip2IfStatTable_hook (struct snmp_module *module, u_char *val_type, void **val, 
                      size_t *val_len, oid instid[], size_t instid_len)
{
  zlog_info ("rip2IfStatTable_hook");
  return 0;
}

int
rip2IfConfAddress_hook (struct snmp_module *module, u_char *val_type, 
		void **val, size_t *val_len, oid instid[], size_t instid_len)
{
  zlog_info ("rip2IfConfAddress_hook");
  return 0;
}

int
rip2PeerTable_hook (struct snmp_module *module, u_char *val_type, void **val, 
                    size_t *val_len, oid instid[], size_t instid_len)
{
  zlog_info ("rip2PeerTable_hook");
  return 0;
}

struct snmp_module *
snmp_lookup_module (struct snmp_module *module, int index)
{
  int i;

  if (! module->entry)
    return NULL;

  module = module->entry;

  for (i = 0; i <= index; i++)
    {
      if (module[i].name == NULL)
	return NULL;

      if (module[i].index == index)
	return module + i;
    }
  return NULL;
}

int
rip_snmp (oid objid[], size_t objid_len, u_char *val_type, void **arg, 
	  size_t *arg_len)
{
  int ret;
  int index;
  oid rip_oid[] = { 1,3,6,1,2,1,23 };
  oid *instid;
  size_t instid_len;
  struct snmp_module *module, *newmod;

  zlog_info ("RIP oid size: %d", sizeof (rip_oid) / sizeof (oid));

  /* Check oid tree. */
  ret = memcmp (objid, rip_oid, sizeof (rip_oid));
  if (ret == 0)
    zlog_info ("OK this is RIP tree");
  else
    zlog_info ("No this is not RIP tree");


  /* Lookup MIB tree. */
  module = start_module;
  index = sizeof (rip_oid) / sizeof (oid);

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
      zlog_info ("RIP module is %s", module->name);
      if (module->func)
	return (*module->func) (module, val_type, arg, arg_len, instid, 
                                instid_len);
      else
	return -1; /* SMUX_NOSUCHINSTANCE */
    }
  else
    {
      zlog_info ("Can't find RIP module");
      return -1;
    }
}

void
rip_snmp_init ()
{
  smux_init (rip_snmp);
}
#endif /* HAVE_SNMP */
