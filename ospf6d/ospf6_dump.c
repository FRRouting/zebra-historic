/*
 * Logging function
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

#include "ospf6d.h"

/* Global logging buf */
char strbuf[1024];

/* Strings for logging */
char *ifs_name[] =
{
  "None",
  "Down",
  "Loopback",
  "Waiting",
  "PtoP",
  "DROther",
  "BDR",
  "DR",
  NULL
};

char *nbs_name[] =
{
  "None",
  "Down",
  "Attempt",
  "Init",
  "Twoway",
  "ExStart",
  "ExChange",
  "Loading",
  "Full",
  NULL
};

char *mesg_name[] = 
{
  "None",
  "Hello",
  "DBDesc",
  "LSReq",
  "LSUpdate",
  "LSAck",
  NULL
};

char *lstype_name[] =
{
  "Router-LSA",
  "Network-LSA",
  "Inter-Area-Prefix-LSA",
  "Inter-Area-Router-LSA",
  "AS-External-LSA",
  "Group-Membership-LSA",
  "Type-7-LSA",
  "Link-LSA",
  "Intra-Area-Prefix-LSA",
  NULL
};

char *rlsatype_name[] =
{
  "PoinToPoint",
  "Transit",
  "Stub",
  "Virtual Link",
  NULL
};

char *print_lsreq (struct ospf6_lsreq *lsreq)
{
  static char buf[256];
  char advrtr[64], id[64];
  char *type, unknown[64];

  inet_ntop (AF_INET, &lsreq->lsreq_advrtr, advrtr, sizeof (advrtr));
  snprintf (id, sizeof (id), "%u", (u_int32_t)ntohl (lsreq->lsreq_id));
  switch (ntohs (lsreq->lsreq_type))
    {
      case OSPF6_LSA_TYPE_ROUTER:
      case OSPF6_LSA_TYPE_NETWORK:
      case OSPF6_LSA_TYPE_LINK:
      case OSPF6_LSA_TYPE_INTRA_PREFIX:
      case OSPF6_LSA_TYPE_AS_EXTERNAL:
        type = lstype_name[typeindex(lsreq->lsreq_type)];
        break;
      default:
        snprintf (unknown, sizeof (unknown),
                  "Unknown(%#x)", ntohs (lsreq->lsreq_type));
        type = unknown;
        break;
    }

  snprintf (buf, sizeof (buf), "%s[id:%s,adv:%s]",
            type, id, advrtr);
  return buf;
}

void
ospf6_log_init ()
{
  int flag = 0;

  if (!daemon_mode)
    flag |= ZLOG_STDOUT;

  zlog_default = openzlog (progname, flag, ZLOG_OSPF6,
                 LOG_CONS|LOG_NDELAY|LOG_PERROR|LOG_PID,
                 LOG_DAEMON);
}


unsigned char ospf6_message_hello_dump;
unsigned char ospf6_message_dbdesc_dump;
unsigned char ospf6_message_lsreq_dump;
unsigned char ospf6_message_lsupdate_dump;
unsigned char ospf6_message_lsack_dump;
unsigned char ospf6_neighbor_dump;
unsigned char ospf6_interface_dump;
unsigned char ospf6_area_dump;
unsigned char ospf6_lsa_dump;
unsigned char ospf6_lsdb_dump;
unsigned char ospf6_zebra_dump;
unsigned char ospf6_config_dump;
unsigned char ospf6_dbex_dump;
unsigned char ospf6_spf_dump;
unsigned char ospf6_route_dump;
unsigned char ospf6_redistribute_dump;

char *
ospf6_message_name (unsigned char type)
{
  if (type >= MSGT_MAX)
    type = 0;
  return mesg_name [type];
}

static void
ospf6_dump_hello (struct iovec *message)
{
  struct ospf6_hello *hello;
  char dr_str[16], bdr_str[16];

  hello = (struct ospf6_hello *) (*message).iov_base;

  inet_ntop (AF_INET, &hello->dr, dr_str, sizeof (dr_str));
  inet_ntop (AF_INET, &hello->bdr, bdr_str, sizeof (bdr_str));

  zlog_info ("  Hello: IFID:%lu Priority:%d Option:%s",
             ntohl (hello->interface_id), hello->rtr_pri, "xxx");
  zlog_info ("         HelloInterval:%hu Deadinterval:%hu",
             ntohs (hello->hello_interval),
             ntohs (hello->router_dead_interval));
  zlog_info ("         DR:%s BDR:%s", dr_str, bdr_str);
}

static void
ospf6_dump_dbdesc (struct iovec *message)
{
  struct ospf6_dbdesc *dbdesc;
  char dbdesc_bit[4], *p;
  int i;
  char buffer[1024];

  dbdesc = (struct ospf6_dbdesc *) message[0].iov_base;
  p = dbdesc_bit;

  /* Initialize bit */
  if (DD_IS_IBIT_SET (dbdesc->bits))
    *p++ = 'I';
  /* More bit */
  if (DD_IS_MBIT_SET (dbdesc->bits))
    *p++ = 'M';
  /* Master/Slave bit */
  if (DD_IS_MSBIT_SET (dbdesc->bits))
    *p++ = 'm';
  else
    *p++ = 's';
  *p = '\0';

  zlog_info ("DbDesc: Option:%s IFMTU:%hu Bit:%s SeqNum:%lu",
             "xxx", ntohs (dbdesc->ifmtu),
             dbdesc_bit, ntohl (dbdesc->seqnum));

  for (i = 1; message[i].iov_base; i++)
    {
      ospf6_dump_lsa_header_print (buffer, sizeof (buffer),
        (struct ospf6_lsa_header *)message[i].iov_base);
      zlog_info ("DbDesc: %s", buffer);
    }
}

static void
ospf6_dump_lsreq (struct iovec *message)
{
  int i;
  zlog_info ("  LSReq:");
  for (i = 1; message[i].iov_base; i++)
    zlog_info ("        %s",
               print_lsreq ((struct ospf6_lsreq *) message[i].iov_base));
}

static void
ospf6_dump_lsupdate (struct iovec *message)
{
  int i;
  struct ospf6_lsupdate *lsupdate;

  lsupdate = (struct ospf6_lsupdate *) (*message).iov_base;
  zlog_info ("  LSUpdate: #%lu", ntohl (lsupdate->lsupdate_num));
  for (i = 1; message[i].iov_base; i++)
    ospf6_dump_lsa_hdr ((struct ospf6_lsa_hdr *) message[i].iov_base);
}

static void
ospf6_dump_lsack (struct iovec *message)
{
  int i;
  zlog_info ("  LSAck:");
  for (i = 0; message[i].iov_base; i++)
    ospf6_dump_lsa_hdr ((struct ospf6_lsa_hdr *) message[i].iov_base);
}

void
ospf6_dump_message (struct iovec *message)
{
  struct ospf6_header *o6hdr;
  char rtrid_str[16], areaid_str[16];

  assert (message[0].iov_len == sizeof (struct ospf6_header));
  o6hdr = (struct ospf6_header *) message[0].iov_base;

  inet_ntop (AF_INET, &o6hdr->router_id, rtrid_str, sizeof (rtrid_str));
  inet_ntop (AF_INET, &o6hdr->area_id, areaid_str, sizeof (areaid_str));

  zlog_info ("  OSPFv%d Type:%d Len:%hu RouterID:%s",
             o6hdr->version, o6hdr->type, ntohs (o6hdr->len), rtrid_str);
  zlog_info ("  AreaID:%s Cksum:%hx InstanceID:%d",
             areaid_str, ntohs (o6hdr->cksum), o6hdr->instance_id);

  switch (o6hdr->type)
    {
      case MSGT_HELLO:
        ospf6_dump_hello (&message[1]);
        break;
      case MSGT_DATABASE_DESCRIPTION:
        ospf6_dump_dbdesc (&message[1]);
        break;
      case MSGT_LINKSTATE_REQUEST:
        ospf6_dump_lsreq (&message[1]);
        break;
      case MSGT_LINKSTATE_UPDATE:
        ospf6_dump_lsupdate (&message[1]);
        break;
      case MSGT_LINKSTATE_ACK:
        ospf6_dump_lsack (&message[1]);
        break;
      default:
        break;
    }
}

void
ospf6_dump_lsa_header_print (char *buffer, int bufsize,
                             struct ospf6_lsa_header *lsa_header)
{
  char advrtr[64];

  inet_ntop (AF_INET, &lsa_header->advrtr, advrtr, sizeof (advrtr));
  snprintf (buffer, bufsize,
            "%s AdvRtr:%s Id:%lu Age:%d SeqNum:%#x Cksum:%#hx",
            ospf6_lsa_type_string (lsa_header->type),
            advrtr, (unsigned long) ntohl (lsa_header->ls_id),
            ntohs (lsa_header->age),
            ntohl (lsa_header->seqnum), lsa_header->checksum);
}

void
ospf6_dump_lsa_hdr (struct ospf6_lsa_hdr *lsa_hdr)
{
  char advrtr[64];

  inet_ntop (AF_INET, &lsa_hdr->lsh_advrtr, advrtr, sizeof (advrtr));
  zlog_info ("  %s AdvRtr:%s LS-ID:%lu",
             lstype_name[typeindex (lsa_hdr->lsh_type)],
             advrtr, ntohl (lsa_hdr->lsh_id));
  zlog_info ("    Age:%hu SeqNum:%#x Cksum:%#hx Len:%hu",
             ntohs (lsa_hdr->lsh_age), ntohl (lsa_hdr->lsh_seqnum),
             ntohs (lsa_hdr->lsh_cksum), ntohs (lsa_hdr->lsh_len));
}

void
ospf6_dump_lsa (struct ospf6_lsa *lsa)
{
  ospf6_lsa_age_current (lsa);
  ospf6_dump_lsa_hdr (lsa->lsa_hdr);
}

int
is_ospf6_message_dump (char type)
{
  switch (type)
    {
      case MSGT_HELLO:
        if (IS_OSPF6_DUMP_HELLO)
          return 1;
        break;
      case MSGT_DATABASE_DESCRIPTION:
        if (IS_OSPF6_DUMP_DBDESC)
          return 1;
        break;
      case MSGT_LINKSTATE_REQUEST:
        if (IS_OSPF6_DUMP_LSREQ)
          return 1;
        break;
      case MSGT_LINKSTATE_UPDATE:
        if (IS_OSPF6_DUMP_LSUPDATE)
          return 1;
        break;
      case MSGT_LINKSTATE_ACK:
        if (IS_OSPF6_DUMP_LSACK)
          return 1;
        break;
      default:
        break;
    }
  return 0;
}

struct _ospf6_dump ospf6_dump[] =
{
  {0, "hello"},
  {0, "dbdesc"},
  {0, "lsreq"},
  {0, "lsupdate"},
  {0, "lsack"},
  {0, "neighbor"},
  {0, "interface"},
  {0, "area"},
  {0, "lsa"},
  {0, "zebra"},
  {0, "config"},
  {0, "dbex"},
  {0, "spf"},
  {0, "route"},
  {0, "lsdb"},
  {0, "redistribute"}
};


DEFUN (debug_ospf6,
       debug_ospf6_cmd,
       "debug ospf6 " OSPF6_DUMP_TYPE_LIST,
       "Debugging information\n"
       OSPF6_STR
       )
{
  int i;

  if (! strcmp (argv[0], "all"))
    {
      for (i = 0; i < OSPF6_DUMP_MAX; i++)
        ospf6_dump[i].dump = 1;
      return CMD_SUCCESS;
    }

  for (i = 0; i < OSPF6_DUMP_MAX; i++)
    {
      if (strcmp (argv[0], ospf6_dump[i].string))
        continue;
      ospf6_dump[i].dump = 1;
      return CMD_SUCCESS;
    }
  return CMD_ERR_NO_MATCH;
}

DEFUN (no_debug_ospf6,
       no_debug_ospf6_cmd,
       "no debug ospf6 " OSPF6_DUMP_TYPE_LIST,
       NO_STR
       "Debugging information\n"
       OSPF6_STR
       )
{
  int i;

  if (! strcmp (argv[0], "all"))
    {
      for (i = 0; i < OSPF6_DUMP_MAX; i++)
        ospf6_dump[i].dump = 0;
      return CMD_SUCCESS;
    }

  for (i = 0; i < OSPF6_DUMP_MAX; i++)
    {
      if (strcmp (argv[0], ospf6_dump[i].string))
        continue;
      ospf6_dump[i].dump = 0;
      return CMD_SUCCESS;
    }
  return CMD_ERR_NO_MATCH;
}

DEFUN (show_debugging_ospf6,
       show_debugging_ospf6_cmd,
       "show debugging ospf6",
       SHOW_STR
       "Debugging infomation\n"
       OSPF6_STR)
{
  int i;
  vty_out (vty, "OSPF6 debugging status:%s", VTY_NEWLINE);
  for (i = 0; i < OSPF6_DUMP_MAX; i++)
    {
      vty_out (vty, "  OSPF6 Dump %s: %s%s", ospf6_dump[i].string,
               (ospf6_dump[i].dump ? "on " : "off"), VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""
};

int
ospf6_config_write_debug (struct vty *vty)
{
  int i;
  for (i = 0; i < OSPF6_DUMP_MAX; i++)
    {
      if (! ospf6_dump[i].dump)
        continue;
      vty_out (vty, "debug ospf6 %s%s", ospf6_dump[i].string, VTY_NEWLINE);
    }
  vty_out (vty, "!%s", VTY_NEWLINE);
  return 0;
}

/* Backward campatibility 2000/12/29 */

DEFUN (debug_ospf6_message,
       debug_ospf6_message_cmd,
       "debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)",
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )
{
  assert (argc);
  if (!strcmp (argv[0], "hello"))
    ospf6_dump[OSPF6_DUMP_HELLO].dump = 1;
  else if (!strcmp (argv[0], "dbdesc"))
    ospf6_dump[OSPF6_DUMP_DBDESC].dump = 1;
  else if (!strcmp (argv[0], "lsreq"))
    ospf6_dump[OSPF6_DUMP_LSREQ].dump = 1;
  else if (!strcmp (argv[0], "lsupdate"))
    ospf6_dump[OSPF6_DUMP_LSUPDATE].dump = 1;
  else if (!strcmp (argv[0], "lsack"))
    ospf6_dump[OSPF6_DUMP_LSACK].dump = 1;
  else if (!strcmp (argv[0], "all"))
    ospf6_dump[OSPF6_DUMP_HELLO].dump = ospf6_dump[OSPF6_DUMP_DBDESC].dump =
    ospf6_dump[OSPF6_DUMP_LSREQ].dump = ospf6_dump[OSPF6_DUMP_LSUPDATE].dump =
    ospf6_dump[OSPF6_DUMP_LSACK].dump = 1;
  else
    return CMD_ERR_NO_MATCH;

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_message,
       no_debug_ospf6_message_cmd,
       "no debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)",
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )
{
  assert (argc);
  if (!strcmp (argv[0], "hello"))
    ospf6_dump[OSPF6_DUMP_HELLO].dump = 0;
  else if (!strcmp (argv[0], "dbdesc"))
    ospf6_dump[OSPF6_DUMP_DBDESC].dump = 0;
  else if (!strcmp (argv[0], "lsreq"))
    ospf6_dump[OSPF6_DUMP_LSREQ].dump = 0;
  else if (!strcmp (argv[0], "lsupdate"))
    ospf6_dump[OSPF6_DUMP_LSUPDATE].dump = 0;
  else if (!strcmp (argv[0], "lsack"))
    ospf6_dump[OSPF6_DUMP_LSACK].dump = 0;
  else if (!strcmp (argv[0], "all"))
    ospf6_dump[OSPF6_DUMP_HELLO].dump = ospf6_dump[OSPF6_DUMP_DBDESC].dump =
    ospf6_dump[OSPF6_DUMP_LSREQ].dump = ospf6_dump[OSPF6_DUMP_LSUPDATE].dump =
    ospf6_dump[OSPF6_DUMP_LSACK].dump = 0;
  else
    return CMD_ERR_NO_MATCH;

  return CMD_SUCCESS;
}

void
ospf6_debug_init ()
{
  install_node (&debug_node, ospf6_config_write_debug);

  install_element (VIEW_NODE, &show_debugging_ospf6_cmd);
  install_element (ENABLE_NODE, &show_debugging_ospf6_cmd);

  install_element (CONFIG_NODE, &debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_message_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_cmd);
}

void
ospf6_dump_ddbit (unsigned char dd_bit, char *buf, size_t size)
{
  memset (buf, 0, size);
  if (DDBIT_IS_MASTER (dd_bit))
    strncat (buf, "Master", size - strlen (buf));
  else
    strncat (buf, "Slave", size - strlen (buf));
  if (DDBIT_IS_MORE (dd_bit))
    strncat (buf, ",More", size - strlen (buf));
  if (DDBIT_IS_INITIAL (dd_bit))
    strncat (buf, ",Initial", size - strlen (buf));
}

