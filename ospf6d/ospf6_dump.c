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

/* Global logging buf */
char strbuf[1024];

/* Logging function switch */
struct ospf6_log o6log;

/* Strings for logging */
char *ifs_name[] =
{
  "None",
  "Down",
  "Loopback",
  "Waiting",
  "PtoP",
  "DROther",
  "BDR",
  "DR",
  NULL
};

char *nbs_name[] =
{
  "None",
  "Down",
  "Attempt",
  "Init",
  "Twoway",
  "ExStart",
  "ExChange",
  "Loading",
  "Full",
  NULL
};

char *mesg_name[] = 
{
  "None",
  "Hello",
  "DatabaseDescription",
  "LSRequest",
  "LSUpdate",
  "LSAck",
  NULL
};

char *lstype_name[] =
{
  "RouterLSA",
  "NetworkLSA",
  "InterAreaPrefixLSA",
  "InterAreaRouterLSA",
  "ASExternalLSA",
  "GroupMembershipLSA",
  "Type7LSA",
  "LinkLSA",
  "IntraAreaPrefixLSA",
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
#if 0
  inet_ntop (AF_INET, &lsh->lsh_id, tmp2, sizeof (tmp2));
#else
  sprintf (tmp2, "%lu", ntohl (lsh->lsh_id));
#endif

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

  /* default logging */
  o6log.interface = o6log_on;
  o6log.neighbor = o6log_on;
  o6log.ism = o6log_on;
  o6log.nsm = o6log_on;
  o6log.lsa = o6log_on;
  o6log.lsdb = o6log_on;
  o6log.dbex = o6log_on;
  o6log.network = o6log_on;
  o6log.packet = o6log_on;
  o6log.spf = o6log_on;
  o6log.rtable = o6log_on;
  o6log.zebra = o6log_on;
  /* for debug */
  o6log.debug = o6log_on;
  o6log.pointer = o6log_on;
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

void
o6log_off (const char *format, ...)
{
  return;
}

void
o6log_on (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_INFO, format, args);
  return;
}

