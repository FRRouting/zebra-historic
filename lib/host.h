/* Host[Router] information header
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

/* Host configuration variable */
struct host
{
  /* Host name of this router. */
  char *name;

  /* Password for vty interface. */
  char *password;

  /* Enable password */
  char *enable;

#ifdef HAVE_PTHREAD
  /*   pthread_mutex_t mutex_lock; */
#endif /* HAVE_PTHREAD */  

  /* Log filename. */
  char *logfile;

  /* config file name of this host */
  char *config;
};

extern struct host host;
char *host_config_file ();
void host_config_set (char *);
