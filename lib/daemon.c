/* Command interpret routine for virtual terminal [aka TeletYpe] interface 
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

#include <config.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

/* Daemonize myself. */
void
daemon_me()
{
  pid_t pid;

  if ((pid = fork()) < 0) {
    perror("fork");
    exit (1);
  } else if (pid != 0) {
    exit (0);
  }

  /* Become session leader and get pid. */
  pid = setsid();

  chdir ("/");

  umask (0);
}
