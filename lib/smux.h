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

#define SMUX_PORT_DEFAULT 199

#define SMUXMAXPKTSIZE    1500
#define SMUXMAXSTRLEN      256

#define SMUX_OPEN       (ASN_APPLICATION | ASN_CONSTRUCTOR | 0)
#define SMUX_CLOSE      (ASN_APPLICATION | ASN_CONSTRUCTOR | 1)
#define SMUX_RREQ       (ASN_APPLICATION | ASN_CONSTRUCTOR | 2)
#define SMUX_RRSP       (ASN_APPLICATION | ASN_PRIMITIVE | 3)
#define SMUX_SOUT       (ASN_APPLICATION | ASN_PRIMITIVE | 4)

#define SMUX_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0)
#define SMUX_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)
#define SMUX_GETRSP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)
#define SMUX_SET	(ASN_CONTEXT | ASN_CONSTRUCTOR | 3)

#define SMUX_MAX_FAILURE 3

/* SNMP variable */
struct variable
{
  /* Index of the MIB.*/
  u_char index;

  /* Type of variable. */
  char type;

  /* Access control list. */
  u_short acl;

  /* Callback function. */
  int (*func) (struct variable *, oid [], size_t *, void **, size_t *, int);

  /* Suffix of the MIB. */
  oid suffix[MAX_OID_LEN];
  u_char suffix_len;

  /* Real oid of the MIB. */
  oid name[MAX_OID_LEN];
  u_char name_len;
};

/* SNMP tree. */
struct subtree
{
  /* Tree's oid. */
  oid name[MAX_OID_LEN];
  u_char name_len;

  /* List of the variables. */
  struct variable *variables;

  /* Length of the variables list. */
  int variables_num;

  /* Width of the variables list. */
  int variables_width;
};

void smux_init (oid oid[], size_t);
void smux_tree_register (struct subtree *, size_t);
int smux_single_instance_check (struct variable *, oid [], size_t *, int);

int oid_compare (oid *, int, oid *, int);
void oid2in_addr (oid [], int, struct in_addr *);
void *oid_copy (void *, void *, size_t);
void oid_copy_addr (oid [], struct in_addr *, int);

#endif /* _ZEBRA_SNMP_H */
