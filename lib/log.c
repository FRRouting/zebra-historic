/*
 * Logging of zebra
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

#include <zebra.h>

#include "log.h"
#include "memory.h"

/* If this mode is on then, log is output. */
int log_mode = 0;

/* Log filename. */
char *log_filename;

/* File pointer of logfile. */
FILE *logfp;

/* For time string format. */
#define TIME_BUF 27

/* Utility routine for current time printing. */
static void
time_print (FILE *fp)
{
  int ret;
  char buf [TIME_BUF];
  time_t clock;
  struct tm *tm;
  
  time (&clock);
  tm = localtime (&clock);

  ret = strftime (buf, TIME_BUF, "%Y/%m/%d %H:%M:%S", tm);
  if (ret == 0) {
    log_warn ("strftime error\n");
  }

  fprintf (fp, "%s ", buf);
}

/* Initialization of logfp. */
void
log_init ()
{
  logfp = stdout;
}

/* Flush output buffer of log file pointer. */
void
log_flush ()
{
  fflush (logfp);
}

/* Logging main routine. */
void
log (char *format, ...)
{
  va_list args;

  /* Current time print. */
  time_print (logfp);

  /* Print varargs. */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  /* Flush output. */
  log_flush (logfp);
}

/* This function is same with log function without not printing time
   string. */
void
log2 (char *format, ...)
{
  va_list args;

  /* Print varargs. */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  /* Flush output. */
  log_flush (logfp);
}

/* Print warning. */
void
log_warn (char *format, ...)
{
  va_list args;

  /* Current time print. */
  time_print (logfp);

  /* Print varargs. */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  /* Flush output. */
  log_flush (logfp);
}

/* Open logfile and return logfilename. */
char *
log_open (char *filename)
{
  FILE *fp;

  /* Open new file. */
  fp = fopen (filename, "a");
  if (fp == NULL)
    return NULL;

  /* Close old opened file. */
  if (logfp != stdout)
    log_close ();
    
  /* Set new file point to logfp. */
  logfp = fp;

  return filename;
}

/* Close logfile. */
void
log_close ()
{
  if (logfp == stdout)
    return;

  fflush (logfp);
  fclose (logfp);
}

/* Reopen log file. */
void
log_rotate ()
{
  if (logfp == stdout)
    return;

  log_close ();
  
  logfp = fopen (log_filename, "a");

  if (logfp == NULL)
    fprintf (stderr, "Can't open logfile %s\n", log_filename);
}

const char *zlog_proto_names[] = {
  "NONE",
  "DEFAULT",
  "ZEBRA",
  "RIP",
  "BGP",
  "OSPF",
  "RIPNG",
  "OSPF6",
  NULL,
};

ZLOG *zlog_default = NULL;

/* Wrapper routines until the real new log system works. */
void
zlog(ZLOG *zl, int priority, const char *format, ...)
{
  va_list args;

  va_start(args, format);

  if (zl == NULL)
    zl = zlog_default;
  
  if (zl->flags & ZLOG_SYSLOG)
    vsyslog(priority, format, args);
  else if (zl->flags & ZLOG_STDOUT)
    {
      time_print (stdout);
      vfprintf (stdout, format, args);
      fprintf (stdout, "\n");
      fflush (stdout);
    }
  else if (zl->flags & ZLOG_FILE)
    {
      time_print (zl->file);
      vfprintf (zl->file, format, args);
      fprintf (zl->file, "\n");
      fflush (zl->file);
    }
}

void
zvlog(ZLOG *zl, int priority, const char *format, va_list args)
{
  char zvformat[1024];

  if (zl == NULL)
    zl = zlog_default;
  
  snprintf (zvformat, sizeof (zvformat), "%s: %s",
            zlog_proto_names[zl->protocol], format);

  if (zl->flags & ZLOG_SYSLOG)
    vsyslog(priority, zvformat, args);
  else if (zl->flags & ZLOG_STDOUT)
    {
      time_print (stdout);
      vfprintf (stdout, zvformat, args);
      fprintf (stdout, "\n");
      fflush (stdout);
    }
  else if (zl->flags & ZLOG_FILE)
    {
      time_print (zl->file);
      vfprintf (zl->file, zvformat, args);
      fprintf (zl->file, "\n");
      fflush (zl->file);
    }
}

void
zvlog_err (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_ERR, format, args);
  return;
}

void
zvlog_warn (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_WARNING, format, args);
  return;
}

void
zvlog_notice (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_NOTICE, format, args);
  return;
}

void
zvlog_info (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_INFO, format, args);
  return;
}

void
zvlog_debug (const char *format, ...)
{
  va_list args;

  va_start (args, format);
  zvlog (NULL, LOG_DEBUG, format, args);
  return;
}

/*
 * open log stream
 */
ZLOG *
openzlog(const char *progname, int flags, zlog_proto_t protocol,
	 int syslog_flags, int syslog_facility)
{
  ZLOG *zl;

  zl = XMALLOC(MTYPE_ZLOG, sizeof (ZLOG));
  memset (zl, 0, sizeof (ZLOG));

  zl->ident = progname;
  zl->flags = flags;
  zl->protocol = protocol;
  zl->facility = syslog_facility;

  openlog (progname, syslog_flags, zl->facility);
  
  return zl;
}

void
closezlog(ZLOG *zl)
{
  closelog();
  fclose (zl->file);

  XFREE(MTYPE_ZLOG, zl);
}

/* Called from command.c. */
void
zlog_set_flag (ZLOG *zl, int flags)
{
  if (zl == NULL)
    zl = zlog_default;

  zl->flags = flags;
}

int
zlog_set_file (ZLOG *zl, int flags, char *filename)
{
  FILE *fp;

  if (zl == NULL)
    zl = zlog_default;

  fp = fopen (filename, "a");
  if (fp == NULL)
    return 0;

  zl->flags = ZLOG_FILE;
  zl->file = fp;

  return 1;
}
