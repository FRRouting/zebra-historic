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

#include "ospf6d.h"

int
is_ospf6_message_dump (char type)
{
  switch (type)
    {
      case OSPF6_MESSAGE_TYPE_UNKNOWN:
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_HELLO:
        if (IS_OSPF6_DUMP_HELLO)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_DBDESC:
        if (IS_OSPF6_DUMP_DBDESC)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSREQ:
        if (IS_OSPF6_DUMP_LSREQ)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSUPDATE:
        if (IS_OSPF6_DUMP_LSUPDATE)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSACK:
        if (IS_OSPF6_DUMP_LSACK)
          return 1;
        break;
      default:
        break;
    }
  return 0;
}
#define IS_OSPF6_DUMP_MESSAGE(x) (is_ospf6_message_dump(x))

struct ospf6_lsa_hdr *
attach_lsa_to_iov (struct ospf6_lsa *lsa, struct iovec *iov)
{
  assert (lsa && lsa->lsa_hdr);

  return ((struct ospf6_lsa_hdr *)
          iov_attach_last (iov, lsa->lsa_hdr,
                           ntohs (lsa->lsa_hdr->lsh_len)));
}

struct ospf6_lsa_hdr *
attach_lsa_hdr_to_iov (struct ospf6_lsa *lsa, struct iovec *iov)
{
  assert (lsa && lsa->lsa_hdr);

  return ((struct ospf6_lsa_hdr *)
          iov_attach_last (iov, lsa->lsa_hdr,
                           sizeof (struct ospf6_lsa_hdr)));
}

char *ospf6_message_type_string[] =
{
  "Unknown", "Hello", "DbDesc", "LSReq", "LSUpdate", "LSAck", NULL
};

static void
ospf6_message_log_unknown (struct iovec *message)
{
  zlog_info ("Message:  Unknown");
}

static void
ospf6_message_log_hello (struct iovec *message)
{
  struct ospf6_hello *hello;
  char dr_str[16], bdr_str[16];

  hello = (struct ospf6_hello *) (*message).iov_base;

  inet_ntop (AF_INET, &hello->dr, dr_str, sizeof (dr_str));
  inet_ntop (AF_INET, &hello->bdr, bdr_str, sizeof (bdr_str));

  zlog_info ("    IFID:%lu Priority:%d Option:%s",
             ntohl (hello->interface_id), hello->rtr_pri, "xxx");
  zlog_info ("    HelloInterval:%hu Deadinterval:%hu",
             ntohs (hello->hello_interval),
             ntohs (hello->router_dead_interval));
  zlog_info ("    DR:%s BDR:%s", dr_str, bdr_str);
}

static void
ospf6_message_log_dbdesc (struct iovec *message)
{
  struct ospf6_dbdesc *dbdesc;
  int i;
  char buffer[16];
  char lsa_id[128];

  dbdesc = (struct ospf6_dbdesc *) message[0].iov_base;
  ospf6_opt_capability_string (dbdesc->options, buffer, sizeof (buffer));

  zlog_info ("    Option:%s IFMTU:%hu Bit:%s%s%s SeqNum:%lu",
             buffer, ntohs (dbdesc->ifmtu),
             (DD_IS_IBIT_SET (dbdesc->bits) ? "I" : "-"),
             (DD_IS_MBIT_SET (dbdesc->bits) ? "M" : "-"),
             (DD_IS_MSBIT_SET (dbdesc->bits) ? "m" : "s"),
             ntohl (dbdesc->seqnum));

  for (i = 1; message[i].iov_base; i++)
    {
      ospf6_lsa_print_id ((struct ospf6_lsa_header *)message[i].iov_base,
                          lsa_id, sizeof (lsa_id));
      zlog_info ("    %s", lsa_id);
    }
}

static void
ospf6_message_log_lsreq (struct iovec *message)
{
  int i;
  struct ospf6_lsreq *lsreq;
  char adv_router[64];

  for (i = 0; message[i].iov_base; i++)
    {
      lsreq = (struct ospf6_lsreq *) message[i].iov_base;
      inet_ntop (AF_INET, &lsreq->lsreq_advrtr,
                 adv_router, sizeof (adv_router));
      zlog_info ("    %s[id:%d %s]",
                 ospf6_lsa_type_string (lsreq->lsreq_type),
                 ntohl (lsreq->lsreq_id), adv_router);
    }
}

static void
ospf6_message_log_lsupdate (struct iovec *message)
{
  int i, lsanum;
  struct ospf6_lsupdate *lsupdate;
  char lsa_id[64];
  struct ospf6_lsa_header *lsa_header;

  lsupdate = (struct ospf6_lsupdate *) (*message).iov_base;
  lsanum = ntohl (lsupdate->lsupdate_num);

  zlog_info ("    Number of LSA: #%lu", lsanum);

  for (i = 1; message[i].iov_base; i++)
    {
      lsa_header = (struct ospf6_lsa_header *) message[i].iov_base;

      while ((char *)lsa_header < (char *)message[i].iov_base
                                  + message[i].iov_len)
        {
          ospf6_lsa_print_id (lsa_header, lsa_id, sizeof (lsa_id));
          zlog_info ("    %s", lsa_id);
          lsa_header = OSPF6_LSA_NEXT (lsa_header);
        }
    }
}

static void
ospf6_message_log_lsack (struct iovec *message)
{
  int i;
  char lsa_id[64];

  for (i = 0; message[i].iov_base; i++)
    {
      ospf6_lsa_print_id ((struct ospf6_lsa_header *)message[i].iov_base,
                          lsa_id, sizeof (lsa_id));
      zlog_info ("    %s", lsa_id);
    }
}

struct {
  void (*message_log) (struct iovec *);
} ospf6_message_log_body [] =
{
  {ospf6_message_log_unknown},
  {ospf6_message_log_hello},
  {ospf6_message_log_dbdesc},
  {ospf6_message_log_lsreq},
  {ospf6_message_log_lsupdate},
  {ospf6_message_log_lsack},
};

static void
ospf6_message_log (struct iovec *message)
{
  struct ospf6_header *o6h;
  char router_id[16], area_id[16];

  assert (message[0].iov_len == sizeof (struct ospf6_header));
  o6h = (struct ospf6_header *) message[0].iov_base;

  inet_ntop (AF_INET, &o6h->router_id, router_id, sizeof (router_id));
  inet_ntop (AF_INET, &o6h->area_id, area_id, sizeof (area_id));

  zlog_info ("    OSPFv%d Type:%d Len:%hu RouterID:%s",
             o6h->version, o6h->type, ntohs (o6h->len), router_id);
  zlog_info ("    AreaID:%s Cksum:%hx InstanceID:%d",
             area_id, ntohs (o6h->cksum), o6h->instance_id);

  (* ospf6_message_log_body[o6h->type].message_log) (&message[1]);
}


struct ospf6_lsa_hdr *
ospf6_message_get_lsa_hdr (struct iovec *iov)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  lsa_hdr = (struct ospf6_lsa_hdr *) iov_detach_first (iov);
  return lsa_hdr;
}


/* used only when failed to allocate buffer for receive */
static void
ospf6_message_lsa_hdr_clear_buffer (struct iovec *iov)
{
  iov_free_all (MTYPE_OSPF6_LSA, iov);
  return;
}

/* allocate space for ospf6_lsa_hdr */
static int
ospf6_message_lsa_hdr_set_buffer (struct iovec *iov, size_t len)
{
  int i, lsa_hdr_num;

  /* assert len is multiple of ospf6_lsa_hdr size */
  assert (len % sizeof (struct ospf6_lsa_hdr) == 0);

  /* count LSA header number and make space for each of them */
  lsa_hdr_num = len / sizeof (struct ospf6_lsa_hdr);
  for (i = 0; i < lsa_hdr_num; i++)
    {
      if (!iov_prepend (MTYPE_OSPF6_LSA, iov,
                        sizeof (struct ospf6_lsa_hdr)))
        {
          ospf6_message_lsa_hdr_clear_buffer (iov);
          return -1;
        }
    }
  return 0;
}

/* free temporary space after LSAs are cut in pieces */
static void
ospf6_message_lsa_clear_buffer (struct iovec *iov)
{
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
  return;
}

/* allocate space for catch LSAs. this space is used temporary
   until LSAs are cut in pieces */
static int
ospf6_message_lsa_set_buffer (struct iovec *iov, size_t len)
{
  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, len))
    return -1;
  return 0;
}

/* used only when failed to receive packet */
static void
ospf6_message_clear_buffer (unsigned char msgtype, struct iovec *iov)
{
  switch (msgtype)
    {
      case OSPF6_MESSAGE_TYPE_HELLO:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case OSPF6_MESSAGE_TYPE_DBDESC:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      case OSPF6_MESSAGE_TYPE_LSREQ:
        iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
        break;

      case OSPF6_MESSAGE_TYPE_LSUPDATE:
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        ospf6_message_lsa_clear_buffer (iov);
        break;

      case OSPF6_MESSAGE_TYPE_LSACK:
        ospf6_message_lsa_hdr_clear_buffer (iov);
        break;

      default:
        iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
        break;
    }
  assert (iov_count (iov) == 0);
  return;
}

/* if failed, return -1. in this case, free all buffer */
static int
ospf6_message_set_buffer (unsigned char msgtype, unsigned short msglen,
                          struct iovec *iov)
{
  unsigned short left;

  /* substract ospf6_header size from left space to allocate */
  left = msglen - sizeof (struct ospf6_header);

  switch (msgtype)
    {
      case OSPF6_MESSAGE_TYPE_HELLO:
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, left))
          return -1;
        break;

      case OSPF6_MESSAGE_TYPE_DBDESC:
        left -= sizeof (struct ospf6_dbdesc);
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct ospf6_dbdesc)))
          {
            ospf6_message_lsa_hdr_clear_buffer (iov);
            return -1;
          }
        break;

      case OSPF6_MESSAGE_TYPE_LSREQ:
        assert (left % sizeof (struct ospf6_lsreq) == 0);
        while (left)
          {
            if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                              sizeof (struct ospf6_lsreq)))
              {
                iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
                return -1;
              }
            left -= sizeof (struct ospf6_lsreq);
          }
        break;

      case OSPF6_MESSAGE_TYPE_LSUPDATE:
        left -= sizeof (struct ospf6_lsupdate);
        if (ospf6_message_lsa_set_buffer (iov, left) < 0)
          return -1;
        if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov,
                          sizeof (struct ospf6_lsupdate)))
          {
            ospf6_message_lsa_clear_buffer (iov);
            return -1;
          }
        break;

      case OSPF6_MESSAGE_TYPE_LSACK:
        if (ospf6_message_lsa_hdr_set_buffer (iov, left) < 0)
          return -1;
        break;

      default:
        return -1;
    }

  if (!iov_prepend (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_header)))
    {
      ospf6_message_clear_buffer (msgtype, iov);
      return -1;
    }

  return 0;
}

int
ospf6_opt_is_mismatch (unsigned char opt, char *options1, char *options2)
{
  return (OSPF6_OPT_ISSET (options1, opt) ^ OSPF6_OPT_ISSET (options2, opt));
}


void
ospf6_process_unknown (struct iovec *iov,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       struct ospf6_interface *o6i,
                       u_int32_t router_id)
{
  zlog_warn ("unknown message type, drop");
  ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_UNKNOWN, iov);
}

void
ospf6_process_hello (struct iovec *iov,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_hello *hello;
  char changes = 0;
#define CHANGE_RTRPRI (1 << 0)
#define CHANGE_DR     (1 << 1)
#define CHANGE_BDR    (1 << 2)
  int twoway = 0, backupseen = 0, nbchange = 0;
  u_int32_t *router_id_ptr;
  int i, seenrtrnum = 0, router_id_space = 0;
  char strbuf[64];
  struct ospf6_neighbor *o6n = NULL;

  /* assert interface */
  assert (o6i);

  /* set hello pointer */
  hello = (struct ospf6_hello *) iov[0].iov_base;

  /* find neighbor. if cannot be found, create */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      o6n = ospf6_neighbor_create (router_id, o6i);
      o6n->ifid = ntohl (hello->interface_id);
      o6n->prevdr = o6n->dr = hello->dr;
      o6n->prevbdr = o6n->bdr = hello->bdr;
      o6n->priority = hello->rtr_pri;
      memcpy (&o6n->hisaddr, src, sizeof (struct in6_addr));
    }

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != o6i->hello_interval)
    {
      zlog_warn ("HelloInterval mismatch with %s", o6n->str);
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_HELLO, iov);
      return;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval)
      != o6i->dead_interval)
    {
      zlog_warn ("RouterDeadInterval mismatch with %s", o6n->str);
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_HELLO, iov);
      return;
    }

  /* check options */
  /* Ebit */
  if (ospf6_opt_is_mismatch (OSPF6_OPT_E, hello->options, o6i->area->options))
    {
      zlog_warn ("Ebit mismatch with %s", o6n->str);
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_HELLO, iov);
      return;
    }

  /* RouterPriority set */
  if (o6n->priority != hello->rtr_pri)
    {
      o6n->priority = hello->rtr_pri;
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s: RouterPriority changed", o6n->str);
      changes |= CHANGE_RTRPRI;
    }

  /* DR set */
  if (o6n->dr != hello->dr)
    {
      /* save previous dr, set current */
      o6n->prevdr = o6n->dr;
      o6n->dr = hello->dr;
      inet_ntop (AF_INET, &o6n->dr, strbuf, sizeof (strbuf));
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as DR", o6n->str, strbuf);
      changes |= CHANGE_DR;
    }

  /* BDR set */
  if (o6n->bdr != hello->bdr)
    {
      /* save previous bdr, set current */
      o6n->prevbdr = o6n->bdr;
      o6n->bdr = hello->bdr;
      inet_ntop (AF_INET, &o6n->bdr, strbuf, sizeof (strbuf));
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as BDR", o6n->str, strbuf);
      changes |= CHANGE_BDR;
    }

  /* TwoWay check */
  router_id_space = iov[0].iov_len - sizeof (struct ospf6_hello);
  assert (router_id_space % sizeof (u_int32_t) == 0);
  seenrtrnum = router_id_space / sizeof (u_int32_t);
  router_id_ptr = (u_int32_t *) (hello + 1);
  for (i = 0; i < seenrtrnum; i++)
    {
      if (*router_id_ptr == o6i->area->ospf6->router_id)
        twoway++;
      router_id_ptr++;
    }

  /* execute neighbor events */
  thread_execute (master, hello_received, o6n, 0);
  if (twoway)
    thread_execute (master, twoway_received, o6n, 0);
  else
    thread_execute (master, oneway_received, o6n, 0);

  /* BackupSeen check */
  if (o6i->state == IFS_WAITING)
    {
      if (hello->dr == hello->bdr == o6n->router_id)
        assert (0);
      else if (hello->bdr == o6n->router_id)
        backupseen++;
      else if (hello->dr == o6n->router_id && hello->bdr == 0)
        backupseen++;
    }

  /* NeighborChange check */
  if (changes & CHANGE_RTRPRI)
    nbchange++;
  if (changes & CHANGE_DR)
    if (o6n->prevdr == o6n->router_id || o6n->dr == o6n->router_id)
      nbchange++;
  if (changes & CHANGE_BDR)
    if (o6n->prevbdr == o6n->router_id || o6n->bdr == o6n->router_id)
      nbchange++;

  /* schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, o6i, 0);
  if (nbchange)
    thread_add_event (master, neighbor_change, o6i, 0);

  /* free hello space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

int
ospf6_dbdesc_is_master (struct ospf6_neighbor *o6n)
{
  char buf[64];

  if (o6n->router_id == ospf6->router_id)
    {
      inet_ntop (AF_INET, &o6n->hisaddr, buf, sizeof (buf));
      zlog_warn ("Message: Neighbor router-id conflicts: %s: %s",
                 o6n->str, buf);
      return -1;
    }
  else if (o6n->router_id > ospf6->router_id)
    return 0;
  return 1;
}

int
ospf6_dbdesc_is_duplicate (struct ospf6_dbdesc *received,
                           struct ospf6_dbdesc *last_received)
{
  if (memcmp (received->options, last_received->options, 3) != 0)
    return 0;
  if (received->ifmtu != last_received->ifmtu)
    return 0;
  if (received->bits != last_received->bits)
    return 0;
  if (received->seqnum != last_received->seqnum)
    return 0;
  return 1;
}

void
ospf6_process_dbdesc_master (struct iovec *iov, struct ospf6_neighbor *o6n)
{
  struct ospf6_dbdesc *dbdesc;
  struct ospf6_lsa_header *lsa_header;

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  switch (o6n->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        if (IS_OSPF6_DUMP_DBDESC)
          zlog_info ("DbDesc from %s Ignored: state less than Init",
                     o6n->str);
        ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
        return;

      case NBS_INIT:
        thread_execute (master, twoway_received, o6n, 0);
        if (o6n->state != NBS_EXSTART)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("DbDesc from %s Ignored: state less than ExStart",
                         o6n->str);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DDBIT_IS_SLAVE (dbdesc->bits) &&
            !DDBIT_IS_INITIAL (dbdesc->bits) &&
            ntohl (dbdesc->seqnum) == o6n->dbdesc_seqnum)
          {
            ospf6_dbex_prepare_summary (o6n);

            if (o6n->thread_dbdesc)
              thread_cancel (o6n->thread_dbdesc);
            o6n->thread_dbdesc = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, o6n, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  negotiation failed with %s", o6n->str);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &o6n->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        if (DDBIT_IS_MASTER (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, o6n->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != o6n->dbdesc_seqnum)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %lu expected",
                         o6n->dbdesc_seqnum);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc dropped by master */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &o6n->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         ospf6_neighbor_state_string[o6n->state]);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  while (iov_count (iov))
    {
      lsa_header = (struct ospf6_lsa_header *) iov_detach_first (iov);
      if (ospf6_dbex_check_dbdesc_lsa_header (lsa_header, o6n) < 0)
        {
          thread_add_event (master, seqnumber_mismatch, o6n, 0);
          iov_free_all (MTYPE_OSPF6_LSA, iov);
          return;
        }
    }

  /* increment dbdesc seqnum */
  o6n->dbdesc_seqnum++;

  /* more bit check */
  if (o6n->thread_dbdesc)
    thread_cancel (o6n->thread_dbdesc);
  if (!DD_IS_MBIT_SET (dbdesc->bits) && !DD_IS_MBIT_SET (o6n->dbdesc_bits))
    {
      thread_add_event (master, exchange_done, o6n, 0);
      o6n->thread_dbdesc = (struct thread *) NULL;
    }
  else
    o6n->thread_dbdesc = thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  /* save last received dbdesc , and free */
  memcpy (&o6n->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  return;
}

void
ospf6_process_dbdesc_slave (struct iovec *iov, struct ospf6_neighbor *o6n)
{
  struct ospf6_dbdesc *dbdesc;
  struct ospf6_lsa_header *lsa_header;

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  switch (o6n->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
        return;
      case NBS_INIT:
        thread_execute (master, twoway_received, o6n, 0);
        if (o6n->state != NBS_EXSTART)
          {
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DD_IS_IBIT_SET (dbdesc->bits) &&
            DD_IS_MBIT_SET (dbdesc->bits) &&
            DD_IS_MSBIT_SET (dbdesc->bits) &&
            iov_count (iov) == 1)
          {
            /* Master/Slave bit set to slave */
            DD_MSBIT_CLEAR (o6n->dbdesc_bits);
            /* Initialize bit clear */
            DD_IBIT_CLEAR (o6n->dbdesc_bits);
            /* sequence number set to master's */
            o6n->dbdesc_seqnum = ntohl (dbdesc->seqnum);
            ospf6_dbex_prepare_summary (o6n);

            if (o6n->thread_dbdesc)
              thread_cancel (o6n->thread_dbdesc);
            o6n->thread_dbdesc = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, o6n, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("negotiation failed");
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &o6n->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit dbdesc");

            if (o6n->thread_dbdesc)
              thread_cancel (o6n->thread_dbdesc);
            o6n->thread_dbdesc =
              thread_add_event (master, ospf6_send_dbdesc_retrans, o6n, 0);

            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        if (DDBIT_IS_SLAVE (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, o6n->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != o6n->dbdesc_seqnum + 1)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %lu expected",
                         o6n->dbdesc_seqnum + 1);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc cause slave to retransmit */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &o6n->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit");

            if (o6n->thread_dbdesc)
              thread_cancel (o6n->thread_dbdesc);
            o6n->thread_dbdesc =
              thread_add_event (master, ospf6_send_dbdesc_retrans, o6n, 0);

            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         ospf6_neighbor_state_string[o6n->state]);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* take dbdesc header from message */
  iov_detach_first (iov);

  /* process LSA headers */
  while (iov_count (iov))
    {
      lsa_header = (struct ospf6_lsa_header *) iov_detach_first (iov);
      if (ospf6_dbex_check_dbdesc_lsa_header (lsa_header, o6n) < 0)
        {
          thread_add_event (master, seqnumber_mismatch, o6n, 0);
          iov_free_all (MTYPE_OSPF6_LSA, iov);
          return;
        }
    }

  /* set dbdesc seqnum to master's */
  o6n->dbdesc_seqnum = ntohl (dbdesc->seqnum);

  if (o6n->thread_dbdesc)
    thread_cancel (o6n->thread_dbdesc);
  o6n->thread_dbdesc =
    thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  /* save last received dbdesc , and free */
  memcpy (&o6n->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));
  XFREE (MTYPE_OSPF6_MESSAGE, dbdesc);

  ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
  return;
}

void
ospf6_process_dbdesc (struct iovec *iov,
                      struct in6_addr *src,
                      struct in6_addr *dst,
                      struct ospf6_interface *o6i,
                      u_int32_t router_id)
{
  struct ospf6_neighbor *o6n;
  struct ospf6_dbdesc *dbdesc;
  int Im_master = 0;

  /* assert interface */
  assert (o6i);

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) iov[0].iov_base;

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
      if (IS_OSPF6_DUMP_DBDESC)
        zlog_info ("neighbor not found, reject");
      return;
    }

  /* interface mtu check */
    /* xxx */

  /* check am I master */
  Im_master = ospf6_dbdesc_is_master (o6n);
  if (Im_master < 0)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_DBDESC, iov);
      return; /* can't decide which is master, return */
    }

  if (Im_master)
    ospf6_process_dbdesc_master (iov, o6n);
  else
    ospf6_process_dbdesc_slave (iov, o6n);

  return;
}

void
ospf6_process_lsreq (struct iovec *iov,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_neighbor *o6n;
  struct ospf6_lsreq *lsreq;
  struct iovec response[MAXIOVLIST];
  struct ospf6_lsa *lsa;
  unsigned long lsanum = 0;
  struct ospf6_lsupdate *lsupdate;
  char adv_router[32];

  /* assert interface */
  assert (o6i);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSREQ, iov);
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* In states other than ExChange, Loading, or Full, the packet
     should be ignored. */
  if (o6n->state != NBS_EXCHANGE && o6n->state != NBS_LOADING
      && o6n->state != NBS_FULL)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSREQ, iov);
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* clear buffer for response LSUpdate packet */
  iov_clear (response, MAXIOVLIST);

  /* process each request */
  lsreq = (struct ospf6_lsreq *) iov_detach_first (iov);
  while (lsreq)
    {
      inet_ntop (AF_INET, &lsreq->lsreq_advrtr, adv_router,
                 sizeof (adv_router));

      /* find instance of database copy */
      lsa = ospf6_lsdb_lookup (lsreq->lsreq_type, lsreq->lsreq_id,
                               lsreq->lsreq_advrtr);
      if (!lsa)
        {
          if (IS_OSPF6_DUMP_LSREQ)
            zlog_info ("LSReq: Requested %s(%d %s) not found, BadLSReq",
                       ospf6_lsa_type_string(lsreq->lsreq_type),
                       lsreq->lsreq_id, adv_router);
          thread_add_event (master, bad_lsreq, o6n, 0);
          XFREE (MTYPE_OSPF6_MESSAGE, lsreq);
          ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSREQ, iov);
          return;
        }

      /* I/F MTU check */
      if (iov_totallen (response) + ntohs (lsa->lsa_hdr->lsh_len)
          > o6i->interface->mtu)
        break;

      attach_lsa_to_iov (lsa, response);
      lsanum++;
      lsreq = (struct ospf6_lsreq *) iov_detach_first (iov);
    }

  /* send response LSUpdate to this request */
  assert (lsanum == iov_count (response));
  if (iov_count (response))
    {
      lsupdate = (struct ospf6_lsupdate *)
                 iov_prepend (MTYPE_OSPF6_MESSAGE, response,
                              sizeof (struct ospf6_lsupdate));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (lsanum);

      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, response,
                          &o6n->hisaddr, o6i->if_id);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, response);
      iov_clear (iov, MAXIOVLIST);
    }

  return;
}

void
ospf6_process_lsupdate (struct iovec *iov,
                        struct in6_addr *src,
                        struct in6_addr *dst,
                        struct ospf6_interface *o6i,
                        u_int32_t router_id)
{
  struct ospf6_lsupdate *lsupdate;
  struct ospf6_neighbor *o6n;
  unsigned long lsanum;
  struct ospf6_lsa_header *lsa_header;

  /* assert interface */
  assert (o6i);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (! o6n)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSUPDATE, iov);
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (o6n->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSUPDATE, iov);
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* set linkstate update pointer */
  lsupdate = (struct ospf6_lsupdate *) iov[0].iov_base;

  /* save linkstate update info */
  lsanum = ntohl (lsupdate->lsupdate_num);

  /* statistics */
  o6n->ospf6_stat_received_lsa += lsanum;
  o6n->ospf6_stat_received_lsupdate++;

  /* decapsulation */
  lsupdate = (struct ospf6_lsupdate *) NULL;
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  /* RFC2328 Section 10.9: When the neighbor responds to these requests
     with the proper Link State Update packet(s), the Link state request
     list is truncated and a new Link State Request packet is sent. */

  /* process LSAs */
  for (lsa_header = (struct ospf6_lsa_header *) iov[0].iov_base;
       lsanum; lsanum--)
    {
      ospf6_dbex_receive_lsa (lsa_header, o6n);
      lsa_header = OSPF6_LSA_NEXT (lsa_header);
    }

  /* send new Link State Request packet if this LS Update packet
     can be recognized as a response to our previous request */
  if (! IN6_IS_ADDR_MULTICAST(dst) &&
      (o6n->state == NBS_EXCHANGE || o6n->state == NBS_LOADING))
    thread_add_event (master, ospf6_send_lsreq, o6n, 0);

  /* free LSA space */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  return;
}

void
ospf6_process_lsack (struct iovec *iov,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_neighbor *o6n;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct ospf6_lsa *lsa, *copy;

  /* assert interface */
  assert (o6i);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSACK, iov);
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (o6n->state < NBS_EXCHANGE)
    {
      ospf6_message_clear_buffer (OSPF6_MESSAGE_TYPE_LSACK, iov);
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* process each LSA header */
  while (iov[0].iov_base)
    {
      /* make each LSA header treated as LSA */
      lsa_hdr = (struct ospf6_lsa_hdr *) iov[0].iov_base;
      lsa_hdr->lsh_len = htons (sizeof (struct ospf6_lsa_header));

      /* detach from message */
      iov_detach_first (iov);

      /* find database copy */
      copy = ospf6_lsdb_lookup (lsa_hdr->lsh_type, lsa_hdr->lsh_id,
                                lsa_hdr->lsh_advrtr);

      /* if no database copy */
      if (!copy)
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("no database copy, ignore");
          continue;
        }

      /* if not on his retrans list */
      if (!ospf6_neighbor_retrans_lookup (copy, o6n))
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("not on %s's retranslist, ignore", o6n->str);
          continue;
        }

      /* create temporary LSA from Ack message */
      lsa = ospf6_lsa_create ((struct ospf6_lsa_header *) lsa_hdr);
      ospf6_lsa_lock (lsa);

      /* if the same instance, remove from retrans list.
         else, log and ignore */
      if (ospf6_lsa_check_recent (lsa, copy) == 0)
        ospf6_neighbor_retrans_remove (copy, o6n);
      else
        {
          /* Log the questionable acknowledgement,
             and examine the next one. */
          zlog_warn ("*** questionable acknowledge: "
                     "differ database copy by %s",
                     recent_reason);
        }

      /* release temporary LSA from Ack message */
      ospf6_lsa_unlock (lsa);
    }

  return;
}

struct {
  void (*process) (struct iovec *, struct in6_addr *, struct in6_addr *,
                   struct ospf6_interface *, u_int32_t);
} ospf6_message_process_type [] =
{
  {ospf6_process_unknown},
  {ospf6_process_hello},
  {ospf6_process_dbdesc},
  {ospf6_process_lsreq},
  {ospf6_process_lsupdate},
  {ospf6_process_lsack}
};

/* process ospf6 protocol header. then, call next process function
   for each message type */
static void 
ospf6_message_process (struct iovec *iov,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       struct ospf6_interface *o6i)
{
  struct ospf6_header *ospf6_header = NULL;
  u_char type;
  u_int32_t router_id;

  assert (iov);
  assert (o6i);
  assert (src);
  assert (dst);

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_header = (struct ospf6_header *) iov[0].iov_base;

  /* version check */
  if (ospf6_header->version != OSPF6_VERSION)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("version mismatch, drop");
      return;
    }

  /* area id check */
  if (ospf6_header->area_id != o6i->area->area_id)
    {
      if (ospf6_header->area_id == 0)
        {
          if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
            zlog_info ("virtual link not yet, drop");
          return;
        }

      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("area id mismatch, drop");
      return;
    }

  /* checksum */
    /* XXX */

  /* instance id check */
  if (ospf6_header->instance_id != o6i->instance_id)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("instance id mismatch, drop");
      return;
    }

  /* save message type and router id */
  type = (ospf6_header->type >= OSPF6_MESSAGE_TYPE_MAX ?
          OSPF6_MESSAGE_TYPE_UNKNOWN : ospf6_header->type);
  router_id = ospf6_header->router_id;

  /* trim ospf6_hdr */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

  o6i->message_stat[type].recv++;
  o6i->message_stat[type].recv_octet += ntohs (ospf6_header->len);

  /* futher process */
  (*ospf6_message_process_type[type].process) (iov, src, dst, o6i, router_id);

  /* check for memory leak */
  assert (iov_count (iov) == 0);

  return;
}

int
ospf6_receive (struct thread *thread)
{
  int sockfd;
  struct in6_addr src, dst;
  unsigned int ifindex;
  struct iovec message[MAXIOVLIST];
  struct ospf6_header *o6h;
  struct ospf6_interface *o6i;
  char srcname[64], dstname[64];
  unsigned char type;
  unsigned short len;

  /* get socket */
  sockfd = THREAD_FD (thread);

  iov_clear (message, MAXIOVLIST);

  /* peek ospf6 header */
  o6h = (struct ospf6_header *) iov_append (MTYPE_OSPF6_MESSAGE, message,
                                         sizeof (struct ospf6_header));
  ospf6_recvmsg_peek (&src, &dst, &ifindex, message);
  type = o6h->type;
  len = ntohs (o6h->len);
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);

  /* allocate buffer for this message */
  ospf6_message_set_buffer (type, len, message);

  /* receive message */
  ospf6_recvmsg (&src, &dst, &ifindex, message);

  o6i = ospf6_interface_lookup_by_index (ifindex, ospf6);
  if (!o6i || !o6i->area)
    {
      zlog_warn ("*** received interface ospf6 disabled");
      return 0;
    }

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, &dst, dstname, sizeof (dstname));
      inet_ntop (AF_INET6, &src, srcname, sizeof (srcname));
      zlog_info ("Receive %s on %s",
                 ospf6_message_type_string[type], o6i->interface->name);
      zlog_info ("    %s -> %s", srcname, dstname);
      ospf6_message_log (message);
    }

  /* process message */
  ospf6_message_process (message, &src, &dst, o6i);

  /* add next read thread */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  return 0;
}


/* send section */
void
ospf6_message_send (unsigned char type, struct iovec *message,
                    struct in6_addr *dst, u_int ifindex)
{
  struct ospf6_header *ospf6_hdr;
  struct ospf6_interface *o6i;
  char dstname[64], srcname[64];

  /* ospf6 interface lookup */
  o6i = ospf6_interface_lookup_by_index (ifindex, ospf6);
  assert (o6i);

  /* memory allocate for protocol header */
  ospf6_hdr = (struct ospf6_header *)
              iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                           sizeof (struct ospf6_header));
  if (!ospf6_hdr)
    {
      zlog_warn ("*** protocol header alloc failed: %s",
                 strerror (errno));
      return;
    }

  /* set each field, checksum xxx */
  ospf6_hdr->instance_id = o6i->instance_id;
  ospf6_hdr->version = OSPF6_VERSION;
  ospf6_hdr->type = type;
  ospf6_hdr->router_id = ospf6->router_id;
  ospf6_hdr->area_id = o6i->area->area_id;
  ospf6_hdr->len = htons (iov_totallen (message));

  /* statistics */
  if (type >= OSPF6_MESSAGE_TYPE_MAX)
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;
  o6i->message_stat[type].send++;
  o6i->message_stat[type].send_octet += ntohs (ospf6_hdr->len);

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, dst, dstname, sizeof (dstname));
      if (o6i->lladdr)
        inet_ntop (AF_INET6, o6i->lladdr, srcname, sizeof (srcname));
      else
        memcpy (srcname, "\"auto\"", sizeof (srcname));
      zlog_info ("Send %s on %s",
                 ospf6_message_type_string[type], o6i->interface->name);
      zlog_info ("    %s -> %s", srcname, dstname);
      ospf6_message_log (message);
    }

  /* send message */
  ospf6_sendmsg (o6i->lladdr, dst, &ifindex, message);

  /* free protocol header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);
}

static void
ospf6_message_send_new (u_char type, char *buffer, u_int size,
                        struct in6_addr *dst_addr, u_int ifindex)
{
  struct ospf6_interface *o6i;
  char dst_name[64], src_name[64];
  struct iovec message[3];
  struct ospf6_header ospf6_header;

  /* ospf6 interface lookup */
  o6i = ospf6_interface_lookup_by_index (ifindex, ospf6);
  assert (o6i);

  /* size check */
  if (size >= o6i->interface->mtu - sizeof (struct ospf6_header))
    {
      zlog_warn ("Send message failed: Packet too big: %d", size);
      return;
    }

  memset (&ospf6_header, 0, sizeof (struct ospf6_header));

  ospf6_header.instance_id = o6i->instance_id;
  ospf6_header.version = OSPF6_VERSION;
  ospf6_header.type = type;
  ospf6_header.router_id = ospf6->router_id;
  ospf6_header.area_id = o6i->area->area_id;
  ospf6_header.len = htons (size + sizeof (struct ospf6_header));
  /* XXX, ospf6_header.cksum */

  /* statistics */
  if (type >= OSPF6_MESSAGE_TYPE_MAX)
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;
  o6i->message_stat[type].send++;
  o6i->message_stat[type].send_octet += ntohs (ospf6_header.len);

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, dst_addr, dst_name, sizeof (dst_name));
      if (o6i->lladdr)
        inet_ntop (AF_INET6, o6i->lladdr, src_name, sizeof (src_name));
      else
        snprintf (src_name, sizeof (src_name), "Unknown");
      zlog_info ("Send %s on %s",
                 ospf6_message_type_string[type], o6i->interface->name);
      zlog_info ("    %s -> %s", src_name, dst_name);
      /* ospf6_message_log (message); */
    }

  message[0].iov_base = &ospf6_header;
  message[0].iov_len = sizeof (struct ospf6_header);
  message[1].iov_base = buffer;
  message[1].iov_len = size;
  message[2].iov_base = NULL;
  message[2].iov_len = 0;

  /* send message */
  ospf6_sendmsg (o6i->lladdr, dst_addr, &ifindex, message);
}


int
ospf6_send_hello (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  struct in6_addr dst;
  listnode n;
  struct ospf6_neighbor *o6n;
  struct ospf6_hello *hello;

  /* which ospf6 interface to send */
  o6i = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (o6i);

  /* check interface is up */
  if (o6i->state <= IFS_DOWN)
    {
      zlog_warn ("*** %s not enabled, stop send hello",
                 o6i->interface->name); 
      o6i->thread_send_hello = (struct thread *) NULL;
      return 0;
    }

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  /* set destionation */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);

  /* set neighbor router id */
  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      if (o6n->state < NBS_INIT)
        continue;
      iov_attach_last (message, &o6n->router_id, sizeof (u_int32_t));
    }

  /* allocate hello header */
  hello = (struct ospf6_hello *)
            iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                         sizeof (struct ospf6_hello));
  if (!hello)
    {
      zlog_warn ("*** hello alloc failed to %s: %s",
                 o6i->interface->name, strerror (errno));
      return -1;
    }

  /* set fields */
  hello->interface_id = htonl (o6i->if_id);
  hello->rtr_pri = o6i->priority;
  memcpy (hello->options, o6i->area->options, sizeof (hello->options));
  hello->hello_interval = htons (o6i->hello_interval);
  hello->router_dead_interval = htons (o6i->dead_interval);
  hello->dr = o6i->dr;
  hello->bdr = o6i->bdr;

  /* send hello */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_HELLO, message, &dst, o6i->interface->ifindex);

  /* free hello header */
  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);

  /* set next timer thread */
  o6i->thread_send_hello = thread_add_timer (master, ospf6_send_hello,
                                             o6i, o6i->hello_interval);

  return 0;
}

int
ospf6_send_hello_new (struct thread *thread)
{
  struct ospf6_interface *o6i;
  char *buffer;
  u_int bufsize, size;
  struct in6_addr dst_addr;
  struct ospf6_hello *hello;
  u_int32_t *router_id;
  listnode node;
  struct ospf6_neighbor *o6n;

  /* which ospf6 interface to send */
  o6i = (struct ospf6_interface *) THREAD_ARG (thread);
  assert (o6i);

  /* clear thread */
  o6i->thread_send_hello = (struct thread *) NULL;

  /* check interface is up */
  if (o6i->state <= IFS_DOWN)
    {
      zlog_warn ("Send Hello failed on %s: OSPFv3 not enabled",
                 o6i->interface->name); 
      return 0;
    }
 
  /* allocate buffer for Hello */
  bufsize = o6i->interface->mtu - sizeof (struct ospf6_header);
  buffer = XMALLOC (MTYPE_OSPF6_MESSAGE, bufsize);
  if (buffer == NULL)
    {
      zlog_warn ("Send Hello failed on %s: malloc failed",
                 o6i->interface->name);
      return 0;
    }
  memset (buffer, 0, bufsize);

  /* set destionation */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst_addr);

  /* set Hello */
  hello = (struct ospf6_hello *) buffer;
  hello->interface_id = htonl (o6i->if_id);
  hello->rtr_pri = o6i->priority;
  memcpy (hello->options, o6i->area->options, sizeof (hello->options));
  hello->hello_interval = htons (o6i->hello_interval);
  hello->router_dead_interval = htons (o6i->dead_interval);
  hello->dr = o6i->dr;
  hello->bdr = o6i->bdr;

  size = sizeof (struct ospf6_hello);
  router_id = (u_int32_t *) (hello + 1);

  /* set neighbor router id */
  for (node = listhead (o6i->neighbor_list); node; nextnode (node))
    {
      o6n = (struct ospf6_neighbor *) getdata (node);
      if (o6n->state < NBS_INIT)
        continue;

      *router_id++ = o6n->router_id;
      size += sizeof (u_int32_t);
    }

  /* send hello */
  ospf6_message_send_new (OSPF6_MESSAGE_TYPE_HELLO, buffer, size,
                          &dst_addr, o6i->interface->ifindex);

  /* free hello header */
  XFREE (MTYPE_OSPF6_MESSAGE, buffer);

  /* set next timer thread */
  o6i->thread_send_hello = thread_add_timer (master, ospf6_send_hello_new,
                                             o6i, o6i->hello_interval);

  return 0;
}



void
ospf6_dbdesc_seqnum_init (struct ospf6_neighbor *o6n)
{
  struct timeval tv;

  if (gettimeofday (&tv, (struct timezone *) NULL) < 0)
    tv.tv_sec = 1;

  o6n->dbdesc_seqnum = tv.tv_sec;

  if (IS_OSPF6_DUMP_DBDESC)
    zlog_info ("set dbdesc seqnum %lu for %s", o6n->dbdesc_seqnum, o6n->str);
}

int
ospf6_send_dbdesc_retrans (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);
  o6n->thread_dbdesc = (struct thread *) NULL;

  /* statistics */
  o6n->ospf6_stat_retrans_dbdesc++;

  /* if state less than ExStart, do nothing */
  if (o6n->state < NBS_EXSTART)
    return 0;

  /* send dbdesc */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_DBDESC, o6n->dbdesc_last_send,
                      &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* if master, set futher retransmission */
  if (DD_IS_MSBIT_SET (o6n->dbdesc_bits))
    o6n->thread_dbdesc =
      thread_add_timer (master, ospf6_send_dbdesc_retrans,
                        o6n, o6n->ospf6_interface->rxmt_interval);
  else
    o6n->thread_dbdesc = (struct thread *) NULL;

  return 0;
}

int
ospf6_send_dbdesc (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  u_short leftlen;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_header *lsa_header;
  listnode n;
  struct iovec message[MAXIOVLIST];
  struct ospf6_dbdesc *dbdesc;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);
  o6n->thread_dbdesc = (struct thread *) NULL;

  /* if state less than ExStart, do nothing */
  if (o6n->state < NBS_EXSTART)
    return 0;

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  /* xxx, how to limit packet length correctly? */
  /* use leftlen to make empty initial dbdesc */
  if (DD_IS_IBIT_SET (o6n->dbdesc_bits))
    leftlen = 0;
  else
    leftlen = DEFAULT_INTERFACE_MTU - sizeof (struct ospf6_header)
              - sizeof (struct ospf6_dbdesc);

  /* move LSA from summary list to message buffer */
  while (leftlen > sizeof (struct ospf6_lsa_header))
    {

      /* get first LSA from summary list */
      n = listhead (o6n->summarylist);
      if (n)
        lsa = (struct ospf6_lsa *) getdata (n);
      else
        {
          /* no more DbDesc to transmit */
          assert (list_isempty (o6n->summarylist));
          DD_MBIT_CLEAR (o6n->dbdesc_bits);
          if (IS_OSPF6_DUMP_DBDESC)
            zlog_info ("  More bit cleared");

          /* slave must schedule ExchangeDone on sending, here */
          if (!DD_IS_MSBIT_SET (o6n->dbdesc_bits))
            {
              if (!DD_IS_MBIT_SET (o6n->dbdesc_bits) &&
                  !DD_IS_MBIT_SET (o6n->last_dd.bits))
                thread_add_event (master, exchange_done, o6n, 0);
            }
          break;
        }

      /* allocate one message buffer piece */
      lsa_header = (struct ospf6_lsa_header *) iov_prepend (MTYPE_OSPF6_MESSAGE,
                message, sizeof (struct ospf6_lsa_header));
      if (!lsa_header)
        {
          zlog_warn ("*** allocate lsa_hdr failed, continue sending dbdesc");
          break;
        }

      /* take LSA from summary list */
      ospf6_neighbor_summary_remove (lsa, o6n);

      /* set age and add InfTransDelay */
      ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);

      /* copy LSA header */
      memcpy (lsa_header, lsa->lsa_hdr, sizeof (struct ospf6_lsa_header));

      /* left packet size */
      leftlen -= sizeof (struct ospf6_lsa_header);
    }

  /* make dbdesc */
  dbdesc = (struct ospf6_dbdesc *) iov_prepend (MTYPE_OSPF6_MESSAGE,
           message, sizeof (struct ospf6_dbdesc));
  if (!dbdesc)
    {
      zlog_warn ("*** allocate dbdesc failed, can't send new dbdesc");
      iov_free_all (MTYPE_OSPF6_MESSAGE, message);
      return 0;
    }

  /* if this is initial, set seqnum */
  if (DDBIT_IS_INITIAL (o6n->dbdesc_bits))
    ospf6_dbdesc_seqnum_init (o6n);

  /* set dbdesc */
  memcpy (dbdesc->options, o6n->ospf6_interface->area->options,
          sizeof (dbdesc->options));
  dbdesc->ifmtu = htons (DEFAULT_INTERFACE_MTU);
  dbdesc->bits = o6n->dbdesc_bits;
  dbdesc->seqnum = htonl (o6n->dbdesc_seqnum);

  /* clear previous dbdesc packet to send */
  iov_free_all (MTYPE_OSPF6_MESSAGE, o6n->dbdesc_last_send);

  /* send dbdesc */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_DBDESC, message, &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* set new dbdesc packet to send */
  iov_copy_all (o6n->dbdesc_last_send, message, MAXIOVLIST);

  /* if master, set retransmission */
  if (DD_IS_MSBIT_SET (o6n->dbdesc_bits))
    o6n->thread_dbdesc =
      thread_add_timer (master, ospf6_send_dbdesc_retrans,
                          o6n, o6n->ospf6_interface->rxmt_interval);
  else
    o6n->thread_dbdesc = (struct thread *) NULL;

  return 0;
}

int
ospf6_send_lsreq_rxmt (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  o6n->thread_rxmt_lsreq = (struct thread *) NULL;
      
  thread_add_event (master, ospf6_send_lsreq, o6n, 0);
  return 0;
}

int
ospf6_send_lsreq (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsreq *lsreq;
  struct ospf6_lsa *lsa;
  listnode n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  /* LSReq will be send only in ExStart or Loading */
  if (o6n->state != NBS_EXCHANGE && o6n->state != NBS_LOADING)
    return 0;

  /* cancel retransmit thread */
  if (o6n->thread_rxmt_lsreq)
    thread_cancel (o6n->thread_rxmt_lsreq);
  o6n->thread_rxmt_lsreq = (struct thread *) NULL;

  /* schedule loading_done if request list is empty */
  if (list_isempty (o6n->requestlist))
    {
      thread_add_event (master, loading_done, o6n, 0);
      return 0;
    }

  /* clear message buffer */
  iov_clear (message, MAXIOVLIST);

  for (n = listhead (o6n->requestlist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      assert (lsa->lsa_hdr);

      /* I/F MTU check */
      if (IS_OVER_MTU (message, o6n->ospf6_interface->ifmtu,
                       sizeof (struct ospf6_lsreq)))
        break;

      lsreq = (struct ospf6_lsreq *)
        iov_append (MTYPE_OSPF6_MESSAGE, message, sizeof (struct ospf6_lsreq));
      lsreq->lsreq_age_zero = 0;
      lsreq->lsreq_type = lsa->lsa_hdr->lsh_type;
      lsreq->lsreq_id = lsa->lsa_hdr->lsh_id;
      lsreq->lsreq_advrtr = lsa->lsa_hdr->lsh_advrtr;
    }

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSREQ, message, &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* set retransmit thread */
  o6n->thread_rxmt_lsreq =
    thread_add_timer (master, ospf6_send_lsreq_rxmt,
                      o6n, o6n->ospf6_interface->rxmt_interval);

  return 0;
}

int
ospf6_send_lsupdate_retrans (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsupdate *lsupdate;
  int lsanum = 0;
  listnode n;
  struct ospf6_lsa *lsa;

  o6n = THREAD_ARG (thread);
  assert (o6n);

  o6n->send_update = (struct thread *) NULL;
  iov_clear (message, MAXIOVLIST);

  if (o6n->ospf6_interface->state <= IFS_WAITING)
    return -1;

  for (n = listhead (o6n->retranslist); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (IS_OVER_MTU (message, o6n->ospf6_interface->ifmtu,
                       ntohs (lsa->lsa_hdr->lsh_len)))
        break;
      attach_lsa_to_iov (lsa, message);
      lsanum++;
    }

  if (lsanum == 0)
    return 0;

  lsupdate = (struct ospf6_lsupdate *)
               iov_prepend (MTYPE_OSPF6_MESSAGE, message,
                           sizeof (struct ospf6_lsupdate));
  if (!lsupdate)
    {
      zlog_warn ("*** iov_append () failed in lsupdate_retrans");
      return -1;
    }
  lsupdate->lsupdate_num = htonl (lsanum);

  /* statistics */
  o6n->ospf6_stat_retrans_lsupdate++;

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, message,
                      &o6n->hisaddr, o6n->ospf6_interface->if_id);

  iov_trim_head (MTYPE_OSPF6_MESSAGE, message);
  iov_clear (message, MAXIOVLIST);

  o6n->send_update = thread_add_timer (master, ospf6_send_lsupdate_retrans,
                                       o6n, o6n->ospf6_interface->rxmt_interval);
  return 0;
}

int
ospf6_send_lsack_delayed (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  listnode node, next;
  struct ospf6_lsa *lsa;

  o6i = THREAD_ARG (thread);
  assert (o6i);

  o6i->thread_send_lsack_delayed = (struct thread *) NULL;

  if (o6i->state <= IFS_WAITING)
    return 0;

  iov_clear (message, MAXIOVLIST);

  for (node = listhead (o6i->lsa_delayed_ack); node; node = next)
    {
      next = node->next;
      lsa = (struct ospf6_lsa *) getdata (node);
      if (IS_OVER_MTU (message, o6i->ifmtu, sizeof (struct ospf6_lsa_hdr)))
        break;
      attach_lsa_hdr_to_iov (lsa, message);
      ospf6_remove_delayed_ack (lsa, o6i);
    }

  if (iov_count (message) == 0)
    return 0;

  /* statistics */
  o6i->ospf6_stat_delayed_lsack++;

  switch (o6i->state)
    {
    case IFS_DR:
    case IFS_BDR:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &allspfrouters6.sin6_addr, o6i->if_id);
      break;
    default:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &alldrouters6.sin6_addr, o6i->if_id);
      break;
    }

  iov_clear (message, MAXIOVLIST);
  return 0;
}

int
ospf6_send_lsack (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  listnode node, next;
  struct ospf6_lsa *lsa;

  o6i = THREAD_ARG (thread);
  assert (o6i);

  o6i->thread_send_lsack_delayed = (struct thread *) NULL;

  if (o6i->state <= IFS_WAITING)
    return 0;

  iov_clear (message, MAXIOVLIST);

  for (node = listhead (o6i->lsa_delayed_ack); node; node = next)
    {
      next = node->next;
      lsa = (struct ospf6_lsa *) getdata (node);
      if (IS_OVER_MTU (message, o6i->ifmtu, sizeof (struct ospf6_lsa_hdr)))
        break;
      attach_lsa_hdr_to_iov (lsa, message);
      ospf6_remove_delayed_ack (lsa, o6i);
    }

  if (iov_count (message) == 0)
    return 0;

  /* statistics */
  o6i->ospf6_stat_delayed_lsack++;

  switch (o6i->state)
    {
    case IFS_DR:
    case IFS_BDR:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &allspfrouters6.sin6_addr, o6i->if_id);
      break;
    default:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &alldrouters6.sin6_addr, o6i->if_id);
      break;
    }

  iov_clear (message, MAXIOVLIST);
  return 0;
}

