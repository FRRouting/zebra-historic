/* Logging of zebra
   Copyright (C) 1997, 98 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <config.h>
#include "log.h"

FILE *logfp;
int log_mode = 1;

#define TIME_BUF 25
void
time_print (FILE *fp)
{
  time_t clock;
  struct tm *tm;
  char buf [TIME_BUF];
  int ret;
  
  time (&clock);
  tm = localtime (&clock);

  ret = strftime (buf, TIME_BUF, "%y/%m/%d %H:%M:%S", tm);
  if (ret == 0) {
    log_warn ("strftime error");
  }
  fprintf (fp, "%s: ", buf);
}

void
log_init ()
{
  logfp = stdout;
}

void
warning (char *format, ...)
{
  va_list args;

  if (!log_mode)
    return;

  /* log time print */
  time_print (logfp);

  /* vararg print */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  fflush (logfp);
}

void
log (char *format, ...)
{
  va_list args;

  if (!log_mode)
    return;

  /* log time print */
  time_print (logfp);

  /* vararg print */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  fflush (logfp);
}

void
log2 (char *format, ...)
{
  va_list args;

  if (!log_mode)
    return;

  /* vararg print */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  fflush (logfp);
}

void
log_warn (char *format, ...)
{
  va_list args;

  /* log time print */
  time_print (logfp);

  /* vararg print */
  va_start (args, format);
  vfprintf (logfp, format, args);
  va_end (args);

  fflush (logfp);
}

void
/* Close logfile. */
log_close ()
{
  if (logfp != stdout)
    {
      fflush (logfp);
      fclose (logfp);
    }
}

char *
log_open (char *filename)
{
  FILE *fp;

  fp = fopen (filename, "a");
  if (fp == NULL)
    return NULL;

  if (logfp != stdout)
    log_close ();
    
  logfp = fp;
  return filename;
}

void
log_flash ()
{
  fflush (logfp);
}
