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
char strbuf[16];

/* Strings for logging */
char *ifs_name[] =
{
  "NONE",
  "DOWN",
  "LOOPBACK",
  "WAITING",
  "PtoP",
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
  static char buf[256], tmp[64], tmp2[64];

  inet_ntop (AF_INET, &lsh->lsh_advrtr, tmp, sizeof (tmp));
  inet_ntop (AF_INET, &lsh->lsh_id, tmp2, sizeof (tmp2));

  sprintf (buf, "[%s,id:%s,Adv:%s]",
           lstype_name[typeindex(lsh->lsh_type)], tmp2, tmp);
  return buf;
}

void
ospf6_log_init ()
{
  int flag = 0;

  if (!daemon_mode)
    flag |= ZLOG_STDOUT;

  zlog_default = openzlog (progname, flag, ZLOG_OSPF6,
                 LOG_CONS|LOG_NDELAY|LOG_PERROR|LOG_PID,
                 LOG_DAEMON);

  return;
}

char *
inet4str (unsigned long id)
{
  inet_ntop (AF_INET, &id, strbuf, sizeof (strbuf));
  return(strbuf);
}

void
log_pointer (const char *format, ...)
{
#ifdef DEBUG_POINTER
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_DEBUG, format, args);
  return;
#endif /*DEBUG_POINTER*/
}

void
log_spf (const char *format, ...)
{
#ifdef DEBUG_SPF
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_DEBUG, format, args);
  return;
#endif /*DEBUG_SPF*/
}

