/*
 * $Id: log.h,v 1.14 1999/02/22 13:57:31 developer Exp $
 *
 * Zebra logging funcions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_LOG_H
#define _ZEBRA_LOG_H

#include <syslog.h>

/* Prototypes. */
void log_init ();
void log_flush ();

void log (char *format, ...);
void log2 (char *format, ...);
void log_warn (char *format, ...);

char *log_open (char *);
void log_close ();
void log_rotate ();

/* Logging flag. */
extern int log_mode;

typedef enum 
{
  ZLOG_NONE,
  ZLOG_DEFAULT,
  ZLOG_ZEBRA,
  ZLOG_RIP,
  ZLOG_BGP,
  ZLOG_OSPF,
  ZLOG_RIPNG,  
} zlog_proto_t;

#define ZLOG_FILE		1
#define ZLOG_SYSLOG		2
#define ZLOG_STDOUT             4

#define ZLOG_PATH		"/var/log"

typedef struct _zlog 
{
  struct _zlog *next;
  struct _zlog *last;

  const char *ident;
  zlog_proto_t protocol;
  int flags;
  FILE *file;
  int syslog;
  int stat;
  int connected;
  int maskpri;		/* as per syslog setlogmask */
  int priority;		/* as per syslog priority */
  int facility;		/* as per syslog facility */
} ZLOG;

extern const char *zlog_proto_names[];

/* where to log if stream is NULL */
extern ZLOG *zlog_default;


ZLOG *openzlog(const char *progname, int flags, zlog_proto_t protocol,
	       int syslog_flags, int syslog_facility);

void zlog(ZLOG *zl, int priority, const char *format, ...);

void zlog_set_flag (ZLOG *zl, int flags);

int zlog_set_file (ZLOG *zl, int flags, char *filename);

#endif /* _ZEBRA_LOG_H */
