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

#ifndef OSPF6_DUMP_H
#define OSPF6_DUMP_H

/* Global logging stream variable */
extern char strbuf[16];

/* Strings for logging */
extern char   *ifs_name[];
extern char   *nbs_name[];
extern char   *mesg_name[];
extern char   *lstype_name[];
extern char   *rlsatype_name[];

/* Function Prototypes */
char *print_lsahdr (struct lsa_hdr *);
void ospf6_log_init ();
char *inet4str(unsigned long);
void log_pointer (const char *, ...);
void log_spf (const char *, ...);

#endif /* OSPF6_DUMP_H */

