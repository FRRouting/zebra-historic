/* SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#ifndef _ZEBRA_SNMP_H
#define _ZEBRA_SNMP_H

/* SNMP module structure. */
struct snmp_module
{
  /* Module name. */
  char *name;

  /* Module index. */
  int index;

  /* Module function. */
  int (*func) (struct snmp_module *, u_char *, void **, size_t *, 
               oid instid[], size_t);

  /* Link to lower module entry. */
  struct snmp_module *entry;
};

void smux_init (int (*func) (oid objid[], size_t, u_char *, void **, size_t *));

#endif /* _ZEBRA_SNMP_H */
