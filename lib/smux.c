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
#include <snmp.h>
#include <snmp_impl.h>

#include "smux.h"
#include "log.h"
#include "thread.h"

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

/* SMUX socket. */
int sock = -1;

/* SMUX read threads. */
struct thread *smux_read_thread;

/* SMUX connect thrads. */
struct thread *smux_connect_thread;

/* SMUX call back function. */
int (*snmp_call_back_func) (oid objid[], size_t, u_char *, void **, size_t *, int);

/* SMUX debug flag. */
int debug_smux = 1;

int
smux_sock ()
{
  int ret;
  struct sockaddr_in serv;
  struct servent *sp;
  
  sock = socket (AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
    {
      zlog_warn ("Can't make socket for SNMP");
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
      zlog_warn ("Can't connect to SNMP agent with SMUX");
      return -1;
    }
  return sock;
}

void
smux_var (char *ptr, int len, oid objid[], size_t *objid_len)
{
  int i;
  u_char type;
  u_char val_type;
  size_t val_len;
  u_char *val;

  if (debug_smux)
    zlog_info ("SMUX var parse: len %d", len);

  /* Parse header. */
  ptr = asn_parse_header (ptr, &len, &type);
  
  if (debug_smux)
    {
      zlog_info ("SMUX var parse: type %d len %d", type, len);
      zlog_info ("SMUX var parse: type must be %d", 
		 (ASN_SEQUENCE | ASN_CONSTRUCTOR));
    }

  /* Parse var option. */
  *objid_len = MAX_OID_LEN;
  ptr = snmp_parse_var_op(ptr, objid, objid_len, &val_type, 
			  &val_len, &val, &len);

  if (debug_smux)
    {
      zlog_info ("SMUX objid_len: %d", *objid_len);
      for (i = 0; i < *objid_len; i++)
	{
	  zlog_info ("%d: %d", i, objid[i]);
	}
    }

  if (debug_smux)
    zlog_info ("SMUX val_type: %d", val_type);

  /* Check request value type. */
  switch (val_type)
    {
    case ASN_NULL:
      /* In case of SMUX_GET or SMUX_GET_NEXT val_type is set to
         ASN_NULL. */
      zlog_info ("ASN_NULL");
      break;

    case ASN_INTEGER:
      zlog_info ("ASN_INTEGER");
      break;
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
      zlog_info ("ASN_COUNTER");
      break;
    case ASN_COUNTER64:
      zlog_info ("ASN_COUNTER64");
      break;
    case ASN_IPADDRESS:
      zlog_info ("ASN_IPADDRESS");
      break;
    case ASN_OCTET_STR:
      zlog_info ("ASN_OCTET_STR");
      break;
    case ASN_OPAQUE:
    case ASN_NSAP:
    case ASN_OBJECT_ID:
      zlog_info ("ASN_OPAQUE");
      break;
    case SNMP_NOSUCHOBJECT:
      zlog_info ("SNMP_NOSUCHOBJECT");
      break;
    case SNMP_NOSUCHINSTANCE:
      zlog_info ("SNMP_NOSUCHINSTANCE");
      break;
    case SNMP_ENDOFMIBVIEW:
      zlog_info ("SNMP_ENDOFMIBVIEW");
      break;
    case ASN_BIT_STR:
      zlog_info ("ASN_BIT_STR");
      break;
    default:
      zlog_info ("Unknown type");
      break;
    }
}

void
smux_getresp_send (oid objid[], size_t objid_len, long reqid, long errstat,
		   long errindex, u_char val_type, void *arg, size_t arg_len)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr, *h1, *h1e, *h2, *h2e;
  int len, length;

  ptr = buf;
  len = BUFSIZ;
  length = len;

  if (debug_smux)
    {
      zlog_info ("SMUX getresp");
      zlog_info ("SMUX getresp reqid: %d", reqid);
    }

  h1 = ptr;
  /* Place holder h1 for complete sequence */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_GETRSP, 0);
  h1e = ptr;
 
  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &reqid, sizeof (reqid));

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errstat, sizeof (errstat));

  ptr = asn_build_int (ptr, &len,
		       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &errindex, sizeof (errindex));

  h2 = ptr;
  /* Place holder h2 for one variable */
  ptr = asn_build_header (ptr, &len, 
			  (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			  0);
  h2e = ptr;

  ptr = snmp_build_var_op (ptr, objid, &objid_len, 
			   val_type, arg_len, arg, &len);

  /* Now variable size is known, fill in size */
  asn_build_header(h2,&length,(u_char)(ASN_SEQUENCE|ASN_CONSTRUCTOR),ptr-h2e);

  /* Fill in size of whole sequence */
  asn_build_header(h1,&length,(u_char)SMUX_GETRSP,ptr-h1e);

  if (debug_smux)
    zlog_info ("SMUX getresp send: %d", ptr - buf);
  
  ret = send (sock, buf, (ptr - buf), 0);
}

void
smux_answer (char *ptr, int len, oid objid[], size_t objid_len, long reqid,
	     int getnext)
{
  int i;
  int ret;
  u_char val_type;
  void *arg;
  size_t arg_len;

  if (debug_smux)
    {
      zlog_info ("SMUX answer for");
      zlog_info ("SMUX objid_len: %d", objid_len);
    }

#if 0
  for (i = 0; i < objid_len; i++)
    zlog_info ("%d: %d", i, objid[i]);
#endif /* 0 */

  ret = (*snmp_call_back_func) (objid, objid_len, &val_type, &arg, &arg_len, getnext);

  if (ret < 0)
    {
      if (debug_smux)
	zlog_info ("Not found return");
      smux_getresp_send (objid, objid_len, reqid, SNMP_NOSUCHOBJECT, 3, 
			 ASN_NULL, NULL, 0);
    }
  else
    {
      if (debug_smux)
	zlog_info ("Return value");
      smux_getresp_send (objid, objid_len, reqid, 0, 0, 
			 val_type, arg, arg_len);
    }
}

void
smux_get (char *ptr, int len, oid objid[], size_t *objid_len)
{
  u_char type;
  long reqid;
  long errstat;
  long errindex;

  if (debug_smux)
    zlog_info ("SMUX GET message parse: len %d", len);
  
  ptr = asn_parse_int (ptr, &len, &type, &reqid, sizeof (reqid));

  if (debug_smux)
    zlog_info ("SMUX GET reqid: %d len: %d", reqid, len);

  ptr = asn_parse_int (ptr, &len, &type, &errstat, sizeof (errstat));

  if (debug_smux)
    zlog_info ("SMUX GET errstat %d len: %d", errstat, len);

  ptr = asn_parse_int (ptr, &len, &type, &errindex, sizeof (errindex));

  if (debug_smux)
    zlog_info ("SMUX GET errindex %d len: %d", errindex, len);

  smux_var (ptr, len, objid, objid_len);

  smux_answer (ptr, len, objid, *objid_len, reqid, 0);
}

void
smux_getnext (char *ptr, int len, oid objid[], size_t *objid_len)
{
  int i;
  u_char type;
  long reqid;
  long errstat;
  long errindex;

  if (debug_smux)
    zlog_info ("SMUX GETNEXT message parse: len %d", len);
  
  ptr = asn_parse_int (ptr, &len, &type, &reqid, sizeof (reqid));

  if (debug_smux)
    zlog_info ("SMUX GETNEXT reqid: %d len: %d", reqid, len);

  ptr = asn_parse_int (ptr, &len, &type, &errstat, sizeof (errstat));

  if (debug_smux)
    zlog_info ("SMUX GETNEXT errstat %d len: %d", errstat, len);

  ptr = asn_parse_int (ptr, &len, &type, &errindex, sizeof (errindex));

  if (debug_smux)
    zlog_info ("SMUX GETNEXT errindex %d len: %d", errindex, len);

  smux_var (ptr, len, objid, objid_len);

  smux_answer (ptr, len, objid, *objid_len, reqid, 1);

#if 0
  for (i = 0; i < *objid_len; i++)
    zlog_info ("%d: %d", i, objid[i]);
#endif /* 0 */
}

void
smux_parse (char *ptr, int len)
{
  u_char type;
  char val;
  long errstat;
  oid objid[MAX_OID_LEN];
  size_t objid_len;

  if (debug_smux)
    zlog_info ("SMUX message recieved len: %d", len);

  ptr = asn_parse_header (ptr, &len, &type);

  if (debug_smux)
    zlog_info ("SMUX message recieved type: %d len: %d", type, len);

  switch (type)
    {
    case SMUX_OPEN:
      zlog_info ("SMUX_OPEN");
      break;
    case SMUX_CLOSE:
      zlog_info ("SMUX_CLOSE");
      break;
    case SMUX_RREQ:
      zlog_info ("SMUX_RREQ");
      break;
    case SMUX_RRSP:
      ptr = asn_parse_int (ptr, &len, &val, &errstat, sizeof (errstat));
      zlog_info ("SMUX RRSP val %d", val);
      break;
    case SMUX_SOUT:
      zlog_info ("SMUX_SOUT");
      break;
    case SMUX_GET:
      zlog_info ("SMUX_GET");
      smux_get (ptr, len, objid, &objid_len);
      break;
    case SMUX_GETNEXT:
      zlog_info ("SMUX_GETNEXT");
      smux_getnext (ptr, len, objid, &objid_len);
      break;
    case SMUX_GETRSP:
      zlog_info ("SMUX_GETRSP");
      break;
    case SMUX_SET:
      zlog_info ("SMUX_SET");
      break;
    default:
      zlog_info ("Unknown type: %d", type);
      break;
    }
}

int
smux_read (struct thread *t)
{
  int sock;
  int len;
  u_char buf[SMUXMAXPKTSIZE];

  sock = THREAD_FD (t);
  smux_read_thread = NULL;

  /* Here it is. */
  if (debug_smux)
    zlog_info ("smux_read");

  len = recv(sock, buf, SMUXMAXPKTSIZE, 0);
  if (len <= 0)
    {
      zlog_warn ("Can't read SMUX packet: %s", strerror (errno));
      return 0;
    }
  if (debug_smux)
    zlog_info ("len %d", len);

  smux_parse (buf, len);

  smux_read_thread = thread_add_read (master, smux_read, NULL, sock);

  return 0;
}

int
smux_open (int sock)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
  u_long version;
  oid oid_name[] = { 1,3,6,1,6,3,1 };
  /* gated uses  { 1,3,6,1,4,1,4,3,1,4 } */
  /* Below values should be configurable. */
  u_char string1[] = "test1";
  u_char string2[] = "test";

  ptr = buf;
  len = BUFSIZ;

  /* SMUX Header.  As placeholder. */
  ptr = asn_build_header (ptr, &len, (u_char) SMUX_OPEN, 0);

  /* SMUX Open. */
  version = 0;
  ptr = asn_build_int (ptr, &len, 
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &version, sizeof (u_long));

  /* SMUX connection oid. */
  ptr = asn_build_objid (ptr, &len,
			 (u_char) 
			 (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			  oid_name, sizeof oid_name / sizeof (oid));

  /**/
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  string1, strlen (string1));

  /**/
  ptr = asn_build_string (ptr, &len, 
			  (u_char)
			  (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
			  string2, strlen (string2));

  /* Fill in real SMUX header.  We exclude ASN header size (2). */
  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_OPEN, (ptr - buf) - 2);

  ret = send (sock, buf, (ptr - buf), 0);

  if (ret < 0)
    return ret;

  return 0;
}

void
smux_register (int sock, oid oid[], int oid_len)
{
  int ret;
  u_char buf[BUFSIZ];
  u_char *ptr;
  int len;
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
			 oid, oid_len);

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

  if (debug_smux)
    zlog_info ("smux_register: len %d", ptr - buf);
  
  len = BUFSIZ;
  asn_build_header (buf, &len, (u_char) SMUX_RREQ, (ptr - buf) - 2);

  ret = send (sock, buf, (ptr - buf), 0);
}

struct snmp_module *
snmp_lookup_module (struct snmp_module *module, int index)
{
  int i;

  if (! module->entry)
    return NULL;

  module = module->entry;

  for (i = 0; i <= index; i++)
    {
      if (module[i].index == 0)
	return NULL;

      if (module[i].index == index)
	return module + i;
    }
  return NULL;
}

void
smux_init (int (*func) (oid oid[], size_t, u_char *, void **, size_t *, int),
	   oid oid[], int oid_len)
{
  int ret;
  int sock;

  sock = smux_sock ();

  if (sock < 0)
    return;

  if (debug_smux)
    {
      zlog_info ("connect to SMUX");
      zlog_info ("smux_init: oid_len %d", oid_len);
    }

  smux_read_thread = thread_add_read (master, smux_read, NULL, sock);

  ret = smux_open (sock);
  if (ret < 0)
    return;

  smux_register (sock, oid, oid_len);

  if (debug_smux)
    zlog_info ("open SMUX\n");

  /* Register SNMP call back function. */
  snmp_call_back_func = func;
}

void
smux_stop ()
{
  if (smux_read_thread)
    thread_cancel (smux_read_thread);

  if (sock >= 0)
    close (sock);
}

void
oid2in_addr (oid oid[], int len, struct in_addr *addr)
{
  int i;
  u_char *pnt;
  
  if (len != 4)
    return;

  pnt = (u_char *) addr;

  for (i = 0; i < len; i++)
    *pnt++ = oid[i];
}
#endif /* HAVE_SNMP */
