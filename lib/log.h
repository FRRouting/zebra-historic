/* log.h
   Copyright (C) 1997 Kunihiro Ishiguro

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

#define LOG_RECV 0
#define LOG_SEND 1
#define LOG_RIP  2
#define LOG_BGP  3
#define LOG_ZEBRA 4
#define LOG_IRDP 5

extern int log_mode;

/* Prototypes */
char *log_open (char *);
void log (char *format, ...);
void log2 (char *format, ...);
void log_warn (char *format, ...);
