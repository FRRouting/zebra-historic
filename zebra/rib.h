/* Routing Information Base header
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

#include <sys/types.h>
#include <config.h>

/* This structure used when a route is added to rib */
struct rib_message {
  int message;			
  u_char family;		
  char * gateway;
  char * destination;
  char * mask;
};
#define RIB_ADD    1
#define RIB_DELETE 2

struct rt *rib_search_rt (int, struct rt *);
struct prefix_in *rib_search_prefix (int, struct prefix_in *);
struct prefix_in6 *rib_search_prefix_in6 (int, struct prefix_in6 *);
int rib_add_in (struct prefix_in *);
/* int rib_add_in6 (struct prefix_in6 *); */
