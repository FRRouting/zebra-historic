/*
 * Copyright (C) 1999 Yasuhiro Ohara
 * 
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any later
 * version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * GNU Zebra; see the file COPYING.  If not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef OSPF_AREA_H
#define OSPF_AREA_H

/* This file defines area parameters and data structures. */

#define AREA_RANGE_ADVERTISE     0
#define AREA_RANGE_NOT_ADVERTISE 1

#define AREA_NONE                0xffffffff

struct area
{
  struct ospf6   *ospf6;         /* back pointer */
  unsigned long   area_id;
  char            str[16];       /* Area ID string */
  unsigned char   options[3];    /* OSPF Option including external capability */
  list            ospf6_if_list; /* OSPF interface to this area */
  list            lsdb;
  unsigned long   stub_default_cost;

  signed long     router_lsa_seqnum;    /* Signed 32bit integer */
  signed long     network_lsa_seqnum;   /* Signed 32bit integer */
  signed long     link_lsa_seqnum;      /* Signed 32bit integer */
  signed long     intra_prefix_seqnum;  /* Signed 32bit integer */

  struct spftree  spftree;

  struct thread  *spf_calc;
  struct thread  *route_calc;

  struct ospf6_rtable rtable;           /* routing table for this area */
};

#endif /* OSPF_AREA_H */

