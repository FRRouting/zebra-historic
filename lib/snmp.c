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

#include <zebra.h>

#ifdef HAVE_SNMP

#include <asn1.h>

#include "log.h"
#include "thread.h"

#ifndef INADDR_LOOPBACK
#define	INADDR_LOOPBACK	0x7f000001	/* Internet address 127.0.0.1.  */
#endif

#define SMUX_PORT_DEFAULT 199

#define SMUX_OPEN       (ASN_APPLICATION | ASN_CONSTRUCTOR | 0)
#define SMUX_CLOSE      (ASN_APPLICATION | ASN_CONSTRUCTOR | 1)
#define SMUX_RREQ       (ASN_APPLICATION | ASN_CONSTRUCTOR | 2)
#define SMUX_RRSP       (ASN_APPLICATION | ASN_PRIMITIVE | 3)
#define SMUX_SOUT       (ASN_APPLICATION | ASN_PRIMITIVE | 4)
#define SMUX_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0)
#define SMUX_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)
#define SMUX_GETRSP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)
#define SMUX_SET	(ASN_CONTEXT | ASN_CONSTRUCTOR | 3)

#define SMUXMAXPKTSIZE 1500
#define SMUXMAXSTRLEN  256

extern struct thread_master *master;

int
smux_sock ()
{
  int ret;
  int sock;
  struct sockaddr_in serv;
  struct servent *sp;
  
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      log_warn ("Can't make socket for SNMP");
      return -1;
    }

  memset (&serv, 0, sizeof (struct sockaddr_in));
  serv.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
  serv.sin_len = sizeof (struct sockaddr_in);
#endif /* HAVE_SIN_LEN */

  sp = getservbyname ("smux", "tcp");
  if (sp != NULL) 
    serv.sin_port = sp->s_port;
  else
    serv.sin_port = htons (SMUX_PORT_DEFAULT);

  serv.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

  ret = connect (sock, (struct sockaddr *) &serv, sizeof (struct sockaddr_in));
  if (ret < 0)
    {
      close (sock);
      log_warn ("Can't connect to SNMP agent with SMUX");
      return -1;
    }
  return sock;
}

void
smux_parse (char *ptr, int len)
{
  u_char type;
  char val;
  u_long errstat;

  ptr = asn_parse_header (ptr, &len, &type);
  printf ("type %d\n", type);
  printf ("smux rrsp %d\n", SMUX_RRSP);

  ptr = asn_parse_int (ptr, &len, &val, &errstat, sizeof (errstat));

  printf ("val %d\n", val);
}

int
smux_read (struct thread *t)
{
  int sock;
  int len;
  u_char buf[SMUXMAXPKTSIZE];

  sock = THREAD_FD (t);
  thread_add_read (master, smux_read, NULL, sock);

  /* Here it is. */
  printf ("smux_read\n");

  len = recv(sock, buf, SMUXMAXPKTSIZE, 0);
  if (len <= 0)
    {
      zlog_warn ("Can't read SMUX packet: %s", strerror (errno));
      return 0;
    }
  printf ("len %d\n", len);

  smux_parse (buf, len);

  return 0;
}

void
smux_open (int sock)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
  u_long version;
  oid oid_name[] = { 1,3,6,1,6,3,1 };
  u_char string1[] = "test1";
  u_char string2[] = "test";

  ptr = buf;
  len = BUFSIZ;

  /* SMUX Header. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_OPEN, 0);

  /* SMUX Open. */
  version = 0;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &version, sizeof (u_long));

  ptr = asn_build_objid (ptr, &len,
			 (u_char) 
			 (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			  oid_name, 7);

  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  string1, strlen (string1));
  
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  string2, strlen (string2));

  
  printf ("len %d\n", ptr - buf);

  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_OPEN, (ptr - buf) - 2);

  ret = send (sock, buf, (ptr - buf), 0);
}

void
smux_register (int sock)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
  oid oid_name[] = { 1,3,6,1,2,1,23 };
  long priority;
  long operation;

  ptr = buf;
  len = BUFSIZ;

  /* SMUX RReq Header. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_RREQ, 0);

  /* Register MIB tree. */
  ptr = asn_build_objid (ptr, &len,
			 (u_char) 
			 (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			  oid_name, 7);

  /* Priority. */
  priority = -1;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &priority, sizeof (u_long));

  /* Operation. */
  operation = 1;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &operation, sizeof (u_long));


  printf ("len %d\n", ptr - buf);

  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_RREQ, (ptr - buf) - 2);

  ret = send (sock, buf, (ptr - buf), 0);
}

void
smux_init ()
{
  int sock;

  sock = smux_sock ();

  if (sock < 0)
    return;

  printf ("connect to SMUX\n");

  thread_add_read (master, smux_read, NULL, sock);

  smux_open (sock);

  smux_register (sock);

  printf ("open SMUX\n");
}

#endif /* HAVE_SNMP */
