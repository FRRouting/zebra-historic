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


void
ospf6_err (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_ERR, format, args);
  return;
}

void
ospf6_warn (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_WARNING, format, args);
  return;
}

void
ospf6_notice (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_NOTICE, format, args);
  return;
}

void
ospf6_info (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zlog (zl, LOG_INFO, format, args);
  return;
}

void
ospf6_debug (const char *format, ...)
{
  va_list args;

#ifdef DEBUG_OSPF6
  va_start (args, format);
  zlog (zl, LOG_DEBUG, format, args);
#endif
  return;
}

void
ospf6_log_init ()
{
  zl = openzlog (progname, ZLOG_STDOUT, 0,  /* xxx temporaly proto num */
                 LOG_CONS|LOG_NDELAY|LOG_PERROR|LOG_PID,
                 LOG_DAEMON);

  /* Print OSPF6d start messages. */
  ospf6_info ("OSPF6d (%s) starts\n", ZEBRA_VERSION);
  return;
}

char *
inet4str (unsigned long id, char *buf, int size)
{
  inet_ntop (AF_INET, &id, buf, size);
  return(buf);
}

