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

#include <zebra.h>

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"

#include "ospf6_list.h"
#include "ospf6_lsa.h"
#include "ospf6_mesg.h"
#include "ospf6_neighbor.h"
#include "ospf6_nsm.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

void
ospf6_neighbor_stamp_hello (struct ospf6_neighbor *o6n)
{
}

int
ospf6_neighbor_last_dbdesc_release (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);
  memset (&o6n->last_dd, 0, sizeof (struct ospf6_dbdesc));
  return 0;
}




/* lookup lsa on lsa list of neighbor for dbdesc retransmit. */
struct ospf6_lsa *
ospf6_neighbor_dbdesc_lsa_lookup (struct ospf6_lsa *lsa,
                                  struct ospf6_neighbor *o6n)
{
  if (listnode_lookup (o6n->dbdesc_lsa, lsa))
    {
#ifndef NDEBUG
      if (!listnode_lookup (lsa->dbdesc_neighbor, o6n))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to summary list of neighbor */
void
ospf6_neighbor_dbdesc_lsa_add (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  if (ospf6_neighbor_summary_lookup (lsa, o6n))
    return;

  listnode_add (o6n->dbdesc_lsa, lsa);
  listnode_add (lsa->dbdesc_neighbor, o6n);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked to be send in dbdesc to neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove lsa from summary list of neighbor */
void
ospf6_neighbor_dbdesc_lsa_remove (struct ospf6_lsa *lsa,
                                  struct ospf6_neighbor *o6n)
{
  if (! ospf6_neighbor_dbdesc_lsa_lookup (lsa, o6n))
    return;

  listnode_delete (o6n->dbdesc_lsa, lsa);
  listnode_delete (lsa->dbdesc_neighbor, o6n);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from being send in dbdesc to neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove all lsa from summary list of neighbor */
void
ospf6_neighbor_dbdesc_lsa_remove_all (struct ospf6_neighbor *o6n)
{
  struct ospf6_lsa *lsa;
  listnode n;
  while (listcount (o6n->dbdesc_lsa))
    {
      n = listhead (o6n->dbdesc_lsa);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_neighbor_dbdesc_lsa_remove (lsa, o6n);
    }
  return;
}

/* lookup lsa on summary list of neighbor */
struct ospf6_lsa *
ospf6_neighbor_summary_lookup (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  if (listnode_lookup (o6n->summarylist, lsa))
    {
#ifndef NDEBUG
      if (! listnode_lookup (lsa->summary_nbr, o6n))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to summary list of neighbor */
void
ospf6_neighbor_summary_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *o6n)
{
  if (ospf6_neighbor_summary_lookup (lsa, o6n))
    return;

  listnode_add (o6n->summarylist, lsa);
  listnode_add (lsa->summary_nbr, o6n);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked from summary-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove lsa from summary list of neighbor */
void
ospf6_neighbor_summary_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  if (! ospf6_neighbor_summary_lookup (lsa, o6n))
    return;

  listnode_delete (o6n->summarylist, lsa);
  listnode_delete (lsa->summary_nbr, o6n);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from summary-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove all lsa from summary list of neighbor */
void
ospf6_neighbor_summary_remove_all (struct ospf6_neighbor *o6n)
{
  struct ospf6_lsa *lsa;
  listnode n;
  while (listcount (o6n->summarylist))
    {
      n = listhead (o6n->summarylist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_neighbor_summary_remove (lsa, o6n);
    }
  return;
}

/* lookup lsa on request list of neighbor */
/* this lookup is different from others, because this lookup is to find
   the same LSA instance of different memory space */
struct ospf6_lsa *
ospf6_neighbor_request_lookup (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  listnode n;
  struct ospf6_lsa *p;

  for (n = listhead (o6n->requestlist); n; nextnode (n))
    {
      p = (struct ospf6_lsa *) getdata (n);
      if (ospf6_lsa_issame ((struct ospf6_lsa_header *)p->lsa_hdr,
                            (struct ospf6_lsa_header *)lsa->lsa_hdr))
        {
#ifndef NDEBUG
          if (! listnode_lookup (p->request_nbr, o6n))
          assert (0);
#endif /* NDEBUG */
          return p;
        }
    }
  return NULL;
}

/* add lsa to request list of neighbor */
void
ospf6_neighbor_request_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *o6n)
{
  if (ospf6_neighbor_request_lookup (lsa, o6n))
    return;

  listnode_add (o6n->requestlist, lsa);
  listnode_add (lsa->request_nbr, o6n);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked from request-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove lsa from request list of neighbor */
void
ospf6_neighbor_request_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  if (! ospf6_neighbor_request_lookup (lsa, o6n))
    return;

  listnode_delete (o6n->requestlist, lsa);
  listnode_delete (lsa->request_nbr, o6n);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from request-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove all lsa from request list of neighbor */
void
ospf6_neighbor_request_remove_all (struct ospf6_neighbor *o6n)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (o6n->requestlist))
    {
      n = listhead (o6n->requestlist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_neighbor_request_remove (lsa, o6n);
    }
  return;
}

/* lookup lsa on retrans list of neighbor */
struct ospf6_lsa *
ospf6_neighbor_retrans_lookup (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  if (listnode_lookup (o6n->retranslist, lsa))
    {
#ifndef NDEBUG
      if (! listnode_lookup (lsa->retrans_nbr, o6n))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to retrans list of neighbor */
void
ospf6_neighbor_retrans_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *o6n)
{
  if (ospf6_neighbor_retrans_lookup (lsa, o6n))
    return;

  listnode_add (o6n->retranslist, lsa);
  listnode_add (lsa->retrans_nbr, o6n);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked from retrans-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  return;
}

/* remove lsa from retrans list of neighbor */
void
ospf6_neighbor_retrans_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  /* if not on retranslist, return */
  if (! ospf6_neighbor_retrans_lookup (lsa, o6n))
    return;

  /* remove from retrans list */
  listnode_delete (o6n->retranslist, lsa);
  listnode_delete (lsa->retrans_nbr, o6n);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from retrans-list in neighbor %s: %s (lock:%d)",
               o6n->str, lsa->str, lsa->lock);
#endif

  /* if this LSA is MaxAge, try to delete */
  if (ospf6_lsa_is_maxage (lsa))
    {
      struct ospf6_lsa_header *lsa_header =
        (struct ospf6_lsa_header *) lsa->lsa_hdr;

      if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
        ospf6_lsdb_check_maxage_linklocal ((struct ospf6_interface *)
                                            lsa->scope);
      else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
        ospf6_lsdb_check_maxage_area ((struct ospf6_area *) lsa->scope);
      else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
        ospf6_lsdb_check_maxage_as ((struct ospf6 *) lsa->scope);
    }
}

/* remove all lsa from retrans list of neighbor */
void
ospf6_neighbor_retrans_remove_all (struct ospf6_neighbor *o6n)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (o6n->retranslist))
    {
      n = listhead (o6n->retranslist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_neighbor_retrans_remove (lsa, o6n);
    }
  return;
}

void
ospf6_neighbor_thread_cancel_all (struct ospf6_neighbor *o6n)
{
  if (o6n->inactivity_timer)
    thread_cancel (o6n->inactivity_timer);
  o6n->inactivity_timer = (struct thread *) NULL;

  if (o6n->send_update)
    thread_cancel (o6n->send_update);
  o6n->send_update = (struct thread *) NULL;

  if (o6n->thread_dbdesc)
    thread_cancel (o6n->thread_dbdesc);
  o6n->thread_dbdesc = (struct thread *) NULL;

  if (o6n->thread_rxmt_lsreq)
    thread_cancel (o6n->thread_rxmt_lsreq);
  o6n->thread_rxmt_lsreq = (struct thread *) NULL;
}


void
ospf6_neighbor_list_remove_all (struct ospf6_neighbor *o6n)
{
  ospf6_neighbor_dbdesc_lsa_remove_all (o6n);
  ospf6_neighbor_summary_remove_all (o6n);
  ospf6_neighbor_request_remove_all (o6n);
  ospf6_neighbor_retrans_remove_all (o6n);
}

/* create ospf6_neighbor */
struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t router_id)
{
  struct ospf6_neighbor *new;

  new = (struct ospf6_neighbor *)
    XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct ospf6_neighbor));
  if (new == NULL)
    {
      zlog_warn ("neighbor: malloc failed");
      return NULL;
    }

  memset (new, 0, sizeof (struct ospf6_neighbor));

  new->state = OSPF6_NEIGHBOR_STATE_DOWN;

  new->rtr_id = router_id;
  inet_ntop (AF_INET, &router_id, new->str, sizeof (new->str));
  new->inactivity_timer = (struct thread *)NULL;

  new->summarylist = list_new ();
  new->retranslist = list_new ();
  new->requestlist = list_new ();

  new->dbdesc_lsa = list_new ();

  return new;
}

void
ospf6_neighbor_delete (struct ospf6_neighbor *o6n)
{
  ospf6_neighbor_thread_cancel_all (o6n);
  ospf6_neighbor_list_remove_all (o6n);

  list_free (o6n->dbdesc_lsa);
  list_free (o6n->summarylist);
  list_free (o6n->requestlist);
  list_free (o6n->retranslist);

  XFREE (MTYPE_OSPF6_NEIGHBOR, o6n);
}

struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t router_id,
                       struct ospf6_interface *o6i)
{
  listnode n;
  struct ospf6_neighbor *o6n;

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      if (o6n->rtr_id == router_id)
        return o6n;
    }
  return (struct ospf6_neighbor *) NULL;
}


/* vty functions */
/* show neighbor structure */
void
ospf6_neighbor_show_summary (struct vty *vty, struct ospf6_neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

/*
   vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
            "RouterID", "I/F-ID", "State", "DR",
            "BDR", "I/F", "State", VTY_NEWLINE);
*/

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]%s",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_interface->interface->name,
           ifs_name[nbr->ospf6_interface->state],
	   VTY_NEWLINE);
}

void
ospf6_neighbor_show (struct vty *vty, struct ospf6_neighbor *o6n)
{
  char hisaddr[64];
  inet_ntop (AF_INET6, &o6n->hisaddr, hisaddr, sizeof (hisaddr));
  vty_out (vty, " Neighbor %s, interface address %s%s",
                o6n->str, hisaddr, VTY_NEWLINE);
  vty_out (vty, "    In the area %s via interface %s(ifindex %d)%s",
                o6n->ospf6_interface->area->str,
                o6n->ospf6_interface->interface->name,
                o6n->ospf6_interface->interface->ifindex,
                VTY_NEWLINE);
  vty_out (vty, "    Neighbor priority is %d, State is %s, %d state changes%s",
                o6n->rtr_pri, nbs_name[o6n->state],
                o6n->ospf6_stat_state_changed, VTY_NEWLINE);
}

void
ospf6_neighbor_show_detail (struct vty *vty, struct ospf6_neighbor *o6n)
{
  char dbdesc_bit[64], hisdr[16], hisbdr[16];
  ospf6_neighbor_show (vty, o6n);

  inet_ntop (AF_INET, &o6n->dr, hisdr, sizeof (hisdr));
  inet_ntop (AF_INET, &o6n->bdr, hisbdr, sizeof (hisbdr));

  ospf6_dump_ddbit (o6n->dd_bits, dbdesc_bit, sizeof (dbdesc_bit));
  vty_out (vty, "    My DbDesc bit for this neighbor: %s%s",
                dbdesc_bit, VTY_NEWLINE);
  vty_out (vty, "    His Ifindex of myside: %lu%s",
                o6n->ifid, VTY_NEWLINE);
  vty_out (vty, "    His DRDecision: DR %s, BDR %s%s",
                hisdr, hisbdr, VTY_NEWLINE);
  ospf6_dump_ddbit (o6n->last_dd.bits, dbdesc_bit, sizeof (dbdesc_bit));
  vty_out (vty, "    Last received DbDesc: opt:%s"
                " ifmtu:%hu bit:%s seqnum:%lu%s",
                "xxx", ntohs (o6n->last_dd.ifmtu), dbdesc_bit,
                ntohl (o6n->last_dd.seqnum), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in DbDesc retransmitting: %d%s",
                listcount (o6n->dbdesc_lsa), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in SummaryList: %d%s",
                listcount (o6n->summarylist), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in RequestList: %d%s",
                listcount (o6n->requestlist), VTY_NEWLINE);
  vty_out (vty, "    Number of LSAs in RetransList: %d%s",
                listcount (o6n->retranslist), VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "SeqnumMismatch", o6n->ospf6_stat_seqnum_mismatch,
                "BadLSReq", o6n->ospf6_stat_bad_lsreq, VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "OnewayReceived", o6n->ospf6_stat_oneway_received,
                "InactivityTimer", o6n->ospf6_stat_inactivity_timer,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "DbDescRetrans", o6n->ospf6_stat_retrans_dbdesc,
                "LSReqRetrans", o6n->ospf6_stat_retrans_lsreq,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times%s",
                "LSUpdateRetrans", o6n->ospf6_stat_retrans_lsupdate,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "LSAReceived", o6n->ospf6_stat_received_lsa,
                "LSUpdateReceived", o6n->ospf6_stat_received_lsupdate,
                VTY_NEWLINE);
}

void
ospf6_neighbor_timestamp_hello (struct ospf6_neighbor *o6n)
{
  struct timeval now, interval;
  gettimeofday (&now, (struct timezone *) NULL);
  if (o6n->tv_last_hello_received.tv_sec)
    {
      ospf6_timeval_sub (&now, &o6n->tv_last_hello_received, &interval);
      zlog_info ("Hello Interval %s : %d msec",
                  o6n->str, interval.tv_sec * 1000 + interval.tv_usec % 1000);
    }
  o6n->tv_last_hello_received.tv_sec = now.tv_sec;
  o6n->tv_last_hello_received.tv_usec = now.tv_usec;
}


