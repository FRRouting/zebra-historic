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

#include "ospf6d.h"

/* Global logging stream variable */
ZLOG *zl;
char strbuf[16];

/* Strings for logging */
char *ifs_name[] =
{
  "NONE",
  "DOWN",
  "LOOPBACK",
  "WAITING",
  "POINTTOPOINT",
  "DROTHER",
  "BDR",
  "DR",
  NULL
};

char *nbs_name[] =
{
  "NONE",
  "DOWN",
  "ATTEMPT",
  "INIT",
  "TWOWAY",
  "EXSTART",
  "EXCHANGE",
  "LOADING",
  "FULL",
  NULL
};

char *mesg_name[] = 
{
  "NONE",
  "HELLO",
  "DATABASE DESCRIPTION",
  "LINK STATE REQUEST",
  "LINK STATE UPDATE",
  "LINK STATE ACK",
  NULL
};

char *lstype_name[] =
{
  "Router-LSA",
  "Network-LSA",
  "Inter-Area-Prefix-LSA",
  "Inter-Area-Router-LSA",
  "AS-External-LSA",
  "Group-Membership-LSA",
  "Type-7-LSA",
  "Link-LSA",
  "Intra-Area-Prefix-LSA",
  NULL
};

char *rlsatype_name[] =
{
  "PtoP",
  "Transit",
  "Stub",
  "virtual",
  NULL
};

char *print_lsahdr (struct lsa_hdr *lsh)
{
  static char buf[256], tmp[64];

  inet_ntop (AF_INET, &lsh->lsh_advrtr, tmp, sizeof (tmp));
  sprintf (buf, "LS type[(%s)] LS id[%lu] AdvRtr[%s] Len[%#x]",
           lstype_name[typeindex(lsh->lsh_type)],
           ntohl (lsh->lsh_id),
           tmp, ntohs (lsh->lsh_len));
  return buf;
}

void
ospf6_err (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_ERR, format, args);
  va_end (args);
  return;
}

void
ospf6_warn (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_WARNING, format, args);
  va_end (args);
  return;
}

void
ospf6_notice (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_NOTICE, format, args);
  va_end (args);
  return;
}

void
ospf6_info (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_INFO, format, args);
  va_end (args);
  return;
}

void
ospf6_debug (const char *format, ...)
{
  va_list args;

#ifdef DEBUG_OSPF6
  va_start (args, format);
  zlog (zl, LOG_DEBUG, format, args);
  va_end (args);
#endif
  return;
}

void
ospf6_log_init ()
{
  zl = openzlog (progname, ZLOG_STDOUT, 0,  /* xxx temporaly proto num */
                 LOG_CONS|LOG_NDELAY|LOG_PERROR|LOG_PID,
                 LOG_DAEMON);

  zlog_default = zl;

  /* Print OSPF6d start messages. */
  zlog (zl, LOG_INFO, "OSPF6d (%s) starts", ZEBRA_VERSION);
  return;
}

char *
inet4str (unsigned long id)
{
  inet_ntop (AF_INET, &id, strbuf, sizeof (strbuf));
  return(strbuf);
}

