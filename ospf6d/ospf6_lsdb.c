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


/* lookup delayed acknowledge list of ospf6_interface */
struct ospf6_lsa *
ospf6_lookup_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (listnode_lookup (o6i->lsa_delayed_ack, lsa))
    {
#ifndef NDEBUG
      if (! listnode_lookup (lsa->delayed_ack_if, o6i))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add to delayed acknowledge list of ospf6_interface */
void
ospf6_add_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (ospf6_lookup_delayed_ack (lsa, o6i))
    return;

  listnode_add (o6i->lsa_delayed_ack, lsa);
  listnode_add (lsa->delayed_ack_if, o6i);
  ospf6_lsa_lock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: locked to be send in delayed acknowledgement to interface %s: %s (%#x lock:%d)",
               o6i->interface->name, lsa->str, lsa, lsa->lock);
#endif
}

/* remove from delayed acknowledge list of ospf6_interface */
void
ospf6_remove_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  if (!ospf6_lookup_delayed_ack (lsa, o6i))
    return;

  listnode_delete (o6i->lsa_delayed_ack, lsa);
  listnode_delete (lsa->delayed_ack_if, o6i);
  ospf6_lsa_unlock (lsa);

#if 0
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("lsa: unlocked from being send in delayed acknowledgement to interface %s: %s (%#x lock:%d)",
               o6i->interface->name, lsa->str, lsa, lsa->lock);
#endif

}

void
ospf6_lsa_delayed_ack_remove_all (struct ospf6_lsa *lsa)
{
  listnode i;
  struct ospf6_interface *o6i;

  while (listcount (lsa->delayed_ack_if))
    {
      i = listhead (lsa->delayed_ack_if);
      o6i = (struct ospf6_interface *) getdata (i);
      ospf6_remove_delayed_ack (lsa, o6i);
    }
}


/* lsdb functions */

/* need two particular function for lookup */
/* to treat multiple router-lsa as one */
void
ospf6_lsdb_collect_type_advrtr (list l, unsigned short type,
                                unsigned long advrtr, void *scope)
{
  struct ospf6 *ospf6;
  struct area *area;
  struct ospf6_interface *o6if;
  listnode n;
  struct ospf6_lsa *lsa;

  assert (l && scope);
  switch (ospf6_lsa_get_scope_type (type))
    {
      case OSPF6_LSA_SCOPE_AREA:
        area = (struct area *) scope;
        for (n = listhead (area->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              listnode_add (l, lsa);
          }
        break;

      case OSPF6_LSA_SCOPE_LINKLOCAL:
        o6if = (struct ospf6_interface *)scope;
        for (n = listhead (o6if->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              listnode_add (l, lsa);
          }
        break;

      case OSPF6_LSA_SCOPE_AS:
        ospf6 = (struct ospf6 *) scope;
        for (n = listhead (ospf6->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              listnode_add (l, lsa);
          }
        break;

      case OSPF6_LSA_SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't collect advrtr from lsdb");
        break;
    }
  return;
}

/* new */

static void
ospf6_lsdb_changed (struct ospf6_lsa *lsa)
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6 *o6;
  struct ospf6_lsa_header *lsa_header;
  /* listnode n; */

  lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;
  switch (ntohs (lsa_header->type))
    {
    case OSPF6_LSA_TYPE_ROUTER:
    case OSPF6_LSA_TYPE_NETWORK:
      o6a = (struct ospf6_area *) lsa->scope;

      if (o6a->ospf6->route_calculation == (struct thread *) NULL)
        o6a->ospf6->route_calculation =
          thread_add_timer (master, ospf6_route_calculation, o6a->ospf6, 5);
      break;

    case OSPF6_LSA_TYPE_LINK:
      o6i = (struct ospf6_interface *) lsa->scope;
      o6a = (struct ospf6_area *) o6i->area;
      if (o6a->ospf6->route_calculation == (struct thread *) NULL)
        o6a->ospf6->route_calculation =
          thread_add_timer (master, ospf6_route_calculation, o6a->ospf6, 5);
      break;

    case OSPF6_LSA_TYPE_INTRA_PREFIX:
      o6a = (struct ospf6_area *) lsa->scope;
      if (o6a->ospf6->route_calculation == (struct thread *) NULL)
        o6a->ospf6->route_calculation =
          thread_add_timer (master, ospf6_route_calculation, o6a->ospf6, 5);
      break;

    case OSPF6_LSA_TYPE_AS_EXTERNAL:
      o6 = (struct ospf6 *) lsa->scope;

      if (o6->route_calculation == (struct thread *) NULL)
        o6->route_calculation =
          thread_add_timer (master, ospf6_route_calculation, o6, 5);
      break;

    default:
      break;
    }
}


static struct ospf6_lsa *
ospf6_lsdb_lookup_from_lsdb (u_int16_t type, u_int32_t ls_id,
                             u_int32_t advrtr, list lsdb)
{
  struct ospf6_lsa *lsa, *found;
  struct ospf6_lsa_header *lsa_header;
  listnode i;

  found = (struct ospf6_lsa *) NULL;
  for (i = listhead (lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);
      lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

      if (lsa_header->advrtr != advrtr)
        continue;
      if (lsa_header->ls_id != ls_id)
        continue;
      if (lsa_header->type != type)
        continue;
      found = lsa;
    }
  return found;
}

/* new ordinary lookup function */
struct ospf6_lsa *
ospf6_lsdb_lookup (u_int16_t type, u_int32_t ls_id,
                   u_int32_t advrtr, struct ospf6 *o6)
{
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;
  struct ospf6_lsa *found;
  listnode i, j;

  found = (struct ospf6_lsa *) NULL;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (type)))
    {
      for (i = listhead (o6->area_list); i; nextnode (i))
        {
          o6a = (struct ospf6_area *) getdata (i);
          for (j = listhead (o6a->if_list); j; nextnode (j))
            {
              o6i = (struct ospf6_interface *) getdata (j);
              found = ospf6_lsdb_lookup_from_lsdb (type, ls_id, advrtr,
                                                   o6i->lsdb);
              if (found)
                return found;
            }
        }
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (type)))
    {
      for (i = listhead (o6->area_list); i; nextnode (i))
        {
          o6a = (struct ospf6_area *) getdata (i);
          found = ospf6_lsdb_lookup_from_lsdb (type, ls_id, advrtr, o6a->lsdb);
          if (found)
            return found;
        }
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (type)))
    {
      found = ospf6_lsdb_lookup_from_lsdb (type, ls_id, advrtr, o6->lsdb);
      if (found)
        return found;
    }
  else
    {
      zlog_warn ("lsdb: lookup unknown scope: LSA type: %#x", ntohs (type));
    }

  return (struct ospf6_lsa *) NULL;
}

static void
ospf6_lsdb_add (struct ospf6_lsa *lsa, list lsdb)
{
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);

  /* set installed time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    zlog_warn ("gettimeofday () failed, can't set installed: %s",
               strerror (errno));
  lsa->installed = now.tv_sec;

  listnode_add (lsdb, lsa);
  ospf6_lsa_lock (lsa);

  if (IS_OSPF6_DUMP_LSDB)
    zlog_info ("lsdb: added %s (%#x lock:%d)", lsa->str, lsa, lsa->lock);

  ospf6_lsdb_changed (lsa);
}

static void
ospf6_lsdb_remove (struct ospf6_lsa *lsa, list lsdb)
{
#if 0
  assert (lsa->lock == 1);
#else
  if (lsa->lock != 1)
    {
      zlog_err ("lsdb: illegal LSA lock: %s %d", lsa->str, lsa->lock);
    }
#endif

  if (IS_OSPF6_DUMP_LSDB)
    zlog_info ("lsdb: removed %s (%#x lock:%d)", lsa->str, lsa, lsa->lock);

  listnode_delete (lsdb, lsa);
  ospf6_lsa_unlock (lsa);
}

void
ospf6_lsdb_remove_all (list lsdb)
{
  struct ospf6_lsa *lsa;
  listnode n;

  while (listcount (lsdb))
    {
      n = listhead (lsdb);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsa_remove_all_reference (lsa);
      if (lsa->lock)
        ospf6_lsdb_remove (lsa, lsdb);
    }
}

/* must replace old one when installing more recent LSA */
void
ospf6_lsdb_install (struct ospf6_lsa *new)
{
  list lsdb;
  struct ospf6_lsa *old;
  struct ospf6_lsa_header *lsa_header;

  struct ospf6 *as = NULL;
  struct ospf6_area *area = NULL;
  struct ospf6_interface *linklocal = NULL;

  lsa_header = (struct ospf6_lsa_header *) new->lsa_hdr;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
    {
      linklocal = (struct ospf6_interface *) new->scope;
      lsdb = linklocal->lsdb;
      if (IS_OSPF6_DUMP_LSDB)
        zlog_info ("lsdb: install %s in Link %s", new->str,
                   linklocal->interface->name);
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
    {
      area = (struct ospf6_area *) new->scope;
      lsdb = area->lsdb;
      if (IS_OSPF6_DUMP_LSDB)
        zlog_info ("lsdb: install %s in Area %s", new->str, area->str);
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
    {
      as = (struct ospf6 *) new->scope;
      lsdb = as->lsdb;
      if (IS_OSPF6_DUMP_LSDB)
        zlog_info ("lsdb: install %s in AS", new->str);
    }
  else
    {
      zlog_err ("lsdb: install failed: scope unknown: %s", new->str);
      return;
    }

  /* find old one, and replace */
  old = ospf6_lsdb_lookup_from_lsdb (lsa_header->type, lsa_header->ls_id,
                                     lsa_header->advrtr, lsdb);

  /* RFC 2328 section 13.2 last paragraph
        Also, any old instance of the LSA must be removed from the
        database when the new LSA is installed.  This old instance must
        also be removed from all neighbors' Link state retransmission
        lists (see Section 10).
     This seems to require removing all references to this LSA;
     not only retransmission list but also summarylist, list for delayed
     acknowledgement...  */
  if (old)
    ospf6_lsa_remove_all_reference (old);

  /* ospf6_remove_all_reference may have deleted the "old" LSA if the
     LSA is MaxAge LSA (by ospf6_lsdb_remove_maxage_lsa()).
     this can be checked by examining the lsa's lock, but
     it is a little illegal because the "old" lsa may have been free... */
  if (old && old->lock)
    ospf6_lsdb_remove (old, lsdb);

  ospf6_lsdb_add (new, lsdb);
}

/* maxage LSA remover */
/* from RFC2328 14.
    A MaxAge LSA must be removed immediately from the router's link
    state database as soon as both a) it is no longer contained on any
    neighbor Link state retransmission lists and b) none of the router's
    neighbors are in states Exchange or Loading.
 */
static void
ospf6_lsdb_remove_maxage_lsa (struct ospf6_lsa *lsa)
{
  list lsdb = NULL;
  struct ospf6 *o6;
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_lsa_header *lsa_header;

  lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

  /* assert MaxAge */
  assert (ospf6_lsa_is_maxage (lsa));

  /* assert this LSA is still on database */
  assert (ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                             lsa_header->advrtr, ospf6));

  /* delayed acknowledge may remain... clear reference */
  ospf6_lsa_delayed_ack_remove_all (lsa);

  /* log */
  if (IS_OSPF6_DUMP_LSDB)
    zlog_info ("lsdb: remove MaxAge LSA: %s", lsa->str);

  /* remove from lsdb. this will free lsa */
  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
    {
      o6i = (struct ospf6_interface *) lsa->scope;
      lsdb = o6i->lsdb;
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
    {
      o6a = (struct ospf6_area *) lsa->scope;
      lsdb = o6a->lsdb;
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
    {
      o6 = (struct ospf6 *) lsa->scope;
      lsdb = o6->lsdb;
    }

  ospf6_lsdb_remove (lsa, lsdb);
}

static void
ospf6_lsdb_check_maxage_lsdb (list lsdb)
{
  listnode n;
  struct ospf6_lsa *lsa;
  list l = list_new ();

  for (n = listhead (lsdb); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (ospf6_lsa_is_maxage (lsa) && listcount (lsa->retrans_nbr) == 0)
        listnode_add (l, lsa);
    }

  for (n = listhead (l); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_maxage_lsa (lsa);
    }

  list_delete (l);
}

void
ospf6_lsdb_check_maxage_linklocal (struct ospf6_interface *o6i)
{
  listnode i;
  struct ospf6_neighbor *o6n;

  /* immediately stop when (exchange|loading) neighbor found */
  for (i = listhead (o6i->neighbor_list); i; nextnode (i))
    {
      o6n = (struct ospf6_neighbor *) getdata (i);
      if (o6n->state == NBS_EXCHANGE || o6n->state == NBS_LOADING)
        return;
    }

  ospf6_lsdb_check_maxage_lsdb (o6i->lsdb);
}

void
ospf6_lsdb_check_maxage_area (struct ospf6_area *o6a)
{
  listnode i, j;
  struct ospf6_neighbor *o6n;
  struct ospf6_interface *o6i;

  /* immediately stop when (exchange|loading) neighbor found */
  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);
      for (j = listhead (o6i->neighbor_list); j; nextnode (j))
        {
          o6n = (struct ospf6_neighbor *) getdata (j);
          if (o6n->state == NBS_EXCHANGE || o6n->state == NBS_LOADING)
            return;
        }
    }

  ospf6_lsdb_check_maxage_lsdb (o6a->lsdb);
}

void
ospf6_lsdb_check_maxage_as (struct ospf6 *o6)
{
  listnode i, j, k;
  struct ospf6_neighbor *o6n;
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;

  /* immediately stop when (exchange|loading) neighbor found */
  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);
          for (k = listhead (o6i->neighbor_list); k; nextnode (k))
            {
              o6n = (struct ospf6_neighbor *) getdata (k);
              if (o6n->state == NBS_EXCHANGE || o6n->state == NBS_LOADING)
                return;
            }
        }
    }

  ospf6_lsdb_check_maxage_lsdb (o6->lsdb);
}

/* vty functions */
static void
show_ipv6_ospf6_dbsummary (struct vty *vty, struct ospf6 *o6)
{
  char buf[32];
  listnode i, j, k;
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_header *lsa_header;

  u_int MaxAgeTotal, ActiveTotal, Total;
  u_int MaxAgeArea, ActiveArea, TotalArea;
  u_int MaxAgeRouter, ActiveRouter, TotalRouter;
  u_int MaxAgeNetwork, ActiveNetwork, TotalNetwork;
  u_int MaxAgeIntraPrefix, ActiveIntraPrefix, TotalIntraPrefix;
  u_int MaxAgeInterRouter, ActiveInterRouter, TotalInterRouter;
  u_int MaxAgeInterPrefix, ActiveInterPrefix, TotalInterPrefix;
  u_int MaxAgeASExternal, ActiveASExternal, TotalASExternal;
  u_int MaxAgeLink, ActiveLink, TotalLink;

  MaxAgeTotal = ActiveTotal = Total
  = MaxAgeASExternal = ActiveASExternal = TotalASExternal
  = 0;

  inet_ntop (AF_INET, &o6->router_id, buf, sizeof (buf));
  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "        OSPFv3 Router with ID (%s) (Process ID %d)%s%s",
           buf, o6->process_id, VTY_NEWLINE, VTY_NEWLINE);

  for (k = listhead (o6->lsdb); k; nextnode (k))
    {
      lsa = (struct ospf6_lsa *) getdata (k);
      lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

      if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_AS_EXTERNAL)
	{
	  if (ospf6_lsa_is_maxage (lsa))
	    MaxAgeASExternal++;
	  else
	    ActiveASExternal++;
	}
    }

  vty_out (vty, "AS:%s", VTY_NEWLINE);
  vty_out (vty, "%8s %11s%s",
           " ", "AS-External", VTY_NEWLINE);
  vty_out (vty, "%8s %11d%s",
           "Active", ActiveASExternal, VTY_NEWLINE);
  vty_out (vty, "%8s %11d%s",
           "MaxAge", MaxAgeASExternal, VTY_NEWLINE);

  MaxAgeTotal += MaxAgeASExternal;
  ActiveTotal += ActiveASExternal;

  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);

      MaxAgeArea = ActiveArea = TotalArea
      = MaxAgeRouter = ActiveRouter = TotalRouter
      = MaxAgeNetwork = ActiveNetwork = TotalNetwork
      = MaxAgeIntraPrefix = ActiveIntraPrefix = TotalIntraPrefix
      = MaxAgeInterRouter = ActiveInterRouter = TotalInterRouter
      = MaxAgeInterPrefix = ActiveInterPrefix = TotalInterPrefix
      = 0;

      for (k = listhead (o6a->lsdb); k; nextnode (k))
        {
          lsa = (struct ospf6_lsa *) getdata (k);
          lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

          if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_ROUTER)
            if (ospf6_lsa_is_maxage (lsa))
              MaxAgeRouter++;
            else
              ActiveRouter++;
          else if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_NETWORK)
            if (ospf6_lsa_is_maxage (lsa))
              MaxAgeNetwork++;
            else
              ActiveNetwork++;
          else if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_INTER_ROUTER)
            if (ospf6_lsa_is_maxage (lsa))
              MaxAgeInterRouter++;
            else
              ActiveInterRouter++;
          else if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_INTER_PREFIX)
            if (ospf6_lsa_is_maxage (lsa))
              MaxAgeInterPrefix++;
            else
              ActiveInterPrefix++;
          else if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_INTRA_PREFIX)
	    {
	      if (ospf6_lsa_is_maxage (lsa))
		MaxAgeIntraPrefix++;
	      else
		ActiveIntraPrefix++;
	    }
        }

      MaxAgeArea = MaxAgeRouter + MaxAgeNetwork + MaxAgeInterRouter
                   + MaxAgeInterPrefix + MaxAgeIntraPrefix;
      ActiveArea = ActiveRouter + ActiveNetwork + ActiveInterRouter
                   + ActiveInterPrefix + ActiveIntraPrefix;
      TotalArea = MaxAgeArea + ActiveArea;

      vty_out (vty, "Area ID: %s%s", o6a->str, VTY_NEWLINE);
      vty_out (vty, "%8s %6s %7s %11s %11s %11s  %8s%s",
               " ", "Router", "Network", "IntraPrefix", "InterRouter",
               "InterPrefix", "SubTotal", VTY_NEWLINE);
      vty_out (vty, "%8s %6d %7d %11d %11d %11d  %8d%s",
               "Active", ActiveRouter, ActiveNetwork, ActiveIntraPrefix,
               ActiveInterRouter, ActiveInterPrefix, ActiveArea, VTY_NEWLINE);
      vty_out (vty, "%8s %6d %7d %11d %11d %11d  %8d%s",
               "MaxAge", MaxAgeRouter, MaxAgeNetwork, MaxAgeIntraPrefix,
               MaxAgeInterRouter, MaxAgeInterPrefix, MaxAgeArea, VTY_NEWLINE);
      vty_out (vty, "%8s %6d %7d %11d %11d %11d  %8d%s",
               "SubTotal", MaxAgeRouter + ActiveRouter,
                           MaxAgeNetwork + ActiveNetwork,
                           MaxAgeIntraPrefix + ActiveIntraPrefix,
                           MaxAgeInterRouter + ActiveInterRouter,
                           MaxAgeInterPrefix + ActiveInterPrefix,
                           MaxAgeArea + ActiveArea, VTY_NEWLINE);

      MaxAgeTotal += MaxAgeArea;
      ActiveTotal += ActiveArea;

      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);

          MaxAgeLink = ActiveLink = TotalLink = 0;

          for (k = listhead (o6i->lsdb); k; nextnode (k))
            {
              lsa = (struct ospf6_lsa *) getdata (k);
              lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

              if (ntohs (lsa_header->type) == OSPF6_LSA_TYPE_LINK)
		{
		  if (ospf6_lsa_is_maxage (lsa))
		    MaxAgeLink++;
		  else
		    ActiveLink++;
		}
            }

          vty_out (vty, "INTERFACE: %s%s", o6i->interface->name, VTY_NEWLINE);
          vty_out (vty, "%8s %4s%s",
                   " ", "Link", VTY_NEWLINE);
          vty_out (vty, "%8s %4d%s",
                   "Active", ActiveLink, VTY_NEWLINE);
          vty_out (vty, "%8s %4d%s",
                   "MaxAge", MaxAgeLink, VTY_NEWLINE);

          MaxAgeTotal += MaxAgeLink;
          ActiveTotal += ActiveLink;
        }
    }

  vty_out (vty, "        Total: %d LSAs (%d MaxAge-LSAs)%s",
           MaxAgeTotal + ActiveTotal, MaxAgeTotal, VTY_NEWLINE);
}

static void
show_ipv6_ospf6_lsdb (struct vty *vty, list lsdb)
{
  listnode i;
  struct ospf6_lsa *lsa;

  for (i = listhead (lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);
      ospf6_lsa_vty (vty, lsa);
    }
}

static void
show_ipv6_ospf6_lsdb_lsid (struct vty *vty, u_int32_t lsid)
{
  listnode i, j, k;
  /* struct ospf6 *o6; */
  struct area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_lsa *lsa;

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);
          for (k = listhead (o6i->lsdb); k; nextnode (k))
            {
              lsa = (struct ospf6_lsa *) getdata (k);

              if (lsa->lsa_hdr->lsh_id != lsid)
                continue;

              ospf6_lsa_vty (vty, lsa);
            }
        }
    }

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);
      for (j = listhead (o6a->lsdb); j; nextnode (j))
        {
          lsa = (struct ospf6_lsa *) getdata (j);

          if (lsa->lsa_hdr->lsh_id != lsid)
            continue;

          ospf6_lsa_vty (vty, lsa);
        }
    }

  for (i = listhead (ospf6->lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (lsa->lsa_hdr->lsh_id != lsid)
        continue;

      ospf6_lsa_vty (vty, lsa);
    }
}

static void
show_ipv6_ospf6_lsdb_advrtr (struct vty *vty, u_int32_t advrtr)
{
  listnode i, j, k;
  /* struct ospf6 *o6; */
  struct area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_lsa *lsa;

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);
          for (k = listhead (o6i->lsdb); k; nextnode (k))
            {
              lsa = (struct ospf6_lsa *) getdata (k);

              if (lsa->lsa_hdr->lsh_advrtr != advrtr)
                continue;

              ospf6_lsa_vty (vty, lsa);
            }
        }
    }

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct area *) getdata (i);
      for (j = listhead (o6a->lsdb); j; nextnode (j))
        {
          lsa = (struct ospf6_lsa *) getdata (j);

          if (lsa->lsa_hdr->lsh_advrtr != advrtr)
            continue;

          ospf6_lsa_vty (vty, lsa);
        }
    }

  for (i = listhead (ospf6->lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;

      ospf6_lsa_vty (vty, lsa);
    }
}

static void
show_ipv6_ospf6_lsdb_type (struct vty *vty, u_int16_t type, list lsdb)
{
  listnode i;
  struct ospf6_lsa *lsa;

  for (i = listhead (lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (lsa->lsa_hdr->lsh_type != type)
        continue;

      ospf6_lsa_vty (vty, lsa);
    }
}

static void
show_ipv6_ospf6_lsdb_type_advrtr (struct vty *vty, u_int16_t type,
                                  u_int32_t advrtr, list lsdb)
{
  listnode i;
  struct ospf6_lsa *lsa;

  for (i = listhead (lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (lsa->lsa_hdr->lsh_type != type)
        continue;
      if (lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;

      ospf6_lsa_vty (vty, lsa);
    }
}

static void
show_ipv6_ospf6_lsdb_type_advrtr_lsid (struct vty *vty, u_int16_t type,
                                       u_int32_t advrtr, u_int32_t lsid,
                                       list lsdb)
{
  listnode i;
  struct ospf6_lsa *lsa;

  for (i = listhead (lsdb); i; nextnode (i))
    {
      lsa = (struct ospf6_lsa *) getdata (i);

      if (lsa->lsa_hdr->lsh_type != type)
        continue;
      if (lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;
      if (lsa->lsa_hdr->lsh_id != lsid)
        continue;

      ospf6_lsa_vty (vty, lsa);
    }
}

DEFUN (show_ipv6_ospf6_database_dababase_summary,
       show_ipv6_ospf6_database_database_summary_cmd,
       "show ipv6 ospf6 database database-summary",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database Summary\n"
       "Summary of Database\n")
{
  show_ipv6_ospf6_dbsummary (vty, ospf6);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_type_advrtr_lsid,
       show_ipv6_ospf6_database_type_advrtr_lsid_cmd,
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external) advrtr A.B.C.D lsid <0-4294967295>",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       "Specify Advertising Router\n"
       "Advertising Router ID\n"
       "Specify Link State ID\n"
       "Link State ID\n"
       )
{
  listnode i, j;
  u_int16_t scope_type = 0;
  u_int16_t type = 0;
  u_int32_t advrtr = 0;
  u_int32_t lsid = 0;
  /*struct ospf6 *o6;*/
  struct area *o6a;
  struct ospf6_interface *o6i;

  if (strncmp (argv[0], "r", 1) == 0)
    type = htons (OSPF6_LSA_TYPE_ROUTER);
  else if (strncmp (argv[0], "n", 1) == 0)
    type = htons (OSPF6_LSA_TYPE_NETWORK);
  else if (strncmp (argv[0], "i", 1) == 0)
    type = htons (OSPF6_LSA_TYPE_INTRA_PREFIX);
  else if (strncmp (argv[0], "l", 1) == 0)
    type = htons (OSPF6_LSA_TYPE_LINK);
  else if (strncmp (argv[0], "a", 1) == 0)
    type = htons (OSPF6_LSA_TYPE_AS_EXTERNAL);

  if (argc > 1)
    inet_pton (AF_INET, argv[1], &advrtr);

  if (argc > 2)
    lsid = htonl (strtoul (argv[2], (char **) NULL, 10));

  scope_type = (ntohs (type) & OSPF6_LSA_SCOPE_MASK);

  switch (scope_type)
    {
      case OSPF6_LSA_SCOPE_AS:
        if (argc > 2)
          show_ipv6_ospf6_lsdb_type_advrtr_lsid (vty, type, advrtr,
                                                 lsid, ospf6->lsdb);
        else if (argc > 1)
          show_ipv6_ospf6_lsdb_type_advrtr (vty, type, advrtr,
                                            ospf6->lsdb);
        else
          show_ipv6_ospf6_lsdb_type (vty, type, ospf6->lsdb);
        break;

      case OSPF6_LSA_SCOPE_AREA:
        for (i = listhead (ospf6->area_list); i; nextnode (i))
          {
            o6a = (struct area *) getdata (i);
            if (argc > 2)
              show_ipv6_ospf6_lsdb_type_advrtr_lsid (vty, type, advrtr,
                                                     lsid, o6a->lsdb);
            else if (argc > 1)
              show_ipv6_ospf6_lsdb_type_advrtr (vty, type, advrtr,
                                                o6a->lsdb);
            else
              show_ipv6_ospf6_lsdb_type (vty, type, o6a->lsdb);
          }
        break;

      case OSPF6_LSA_SCOPE_LINKLOCAL:
        for (i = listhead (ospf6->area_list); i; nextnode (i))
          {
            o6a = (struct area *) getdata (i);
            for (j = listhead (o6a->if_list); j; nextnode (j))
              {
                o6i = (struct ospf6_interface *) getdata (j);
                if (argc > 2)
                  show_ipv6_ospf6_lsdb_type_advrtr_lsid (vty, type, advrtr,
                                                         lsid, o6i->lsdb);
                else if (argc > 1)
                  show_ipv6_ospf6_lsdb_type_advrtr (vty, type, advrtr,
                                                    o6i->lsdb);
                else
                  show_ipv6_ospf6_lsdb_type (vty, type, o6i->lsdb);
              }
          }
        break;

      default:
        break;
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database_type_advrtr_lsid,
       show_ipv6_ospf6_database_type_advrtr_cmd,
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external) advrtr A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       "Specify Advertising Router\n"
       "Advertising Router ID\n"
       )

ALIAS (show_ipv6_ospf6_database_type_advrtr_lsid,
       show_ipv6_ospf6_database_type_cmd,
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       )

DEFUN (show_ipv6_ospf6_database_scope,
       show_ipv6_ospf6_database_scope_cmd,
       "show ipv6 ospf6 database (as-scope|area-scope|linklocal-scope|)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "AS scoped LSAs\n"
       "Area scoped LSAs\n"
       "Linklocal scoped LSAs\n"
       )
{
  listnode i, j;
  struct ospf6 *o6;
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  int all, as_scope, area_scope, linklocal_scope;

  all = as_scope = area_scope = linklocal_scope = 0;
  if (argc == 0)
    all = 1;
  else if (strncmp (argv[0], "as", 2) == 0)
    as_scope = 1;
  else if (strncmp (argv[0], "ar", 2) == 0)
    area_scope = 1;
  else if (strncmp (argv[0], "li", 2) == 0)
    linklocal_scope = 1;
  else
    all = 1;
  
  o6 = ospf6;

  if (all || as_scope)
    show_ipv6_ospf6_lsdb (vty, o6->lsdb);
  if (as_scope)
    return CMD_SUCCESS;

  for (i = listhead (o6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);

      if (all || area_scope)
        show_ipv6_ospf6_lsdb (vty, o6a->lsdb);
      if (area_scope)
        continue;

      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);

          if (all || linklocal_scope)
            show_ipv6_ospf6_lsdb (vty, o6i->lsdb);
        }
    }

  return CMD_SUCCESS;
}      

ALIAS (show_ipv6_ospf6_database_scope,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       )

DEFUN (show_ipv6_ospf6_database_lsid,
       show_ipv6_ospf6_database_lsid_cmd,
       "show ipv6 ospf6 database lsid <0-4294967295>",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Specify Link State ID\n"
       "Link State ID\n"
       )
{
  u_int32_t ls_id;

  ls_id = htonl (strtol (argv[0], NULL, 10));
  show_ipv6_ospf6_lsdb_lsid (vty, ls_id);
  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database_advrtr,
       show_ipv6_ospf6_database_advrtr_cmd,
       "show ipv6 ospf6 database advrtr A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Specify Advertising Router\n"
       "Router ID\n"
       )
{
  u_int32_t advrtr;

  inet_pton (AF_INET, argv[0], &advrtr);
  show_ipv6_ospf6_lsdb_advrtr (vty, advrtr);
  return CMD_SUCCESS;
}

void
ospf6_lsdb_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_scope_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_lsid_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_advrtr_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_advrtr_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_advrtr_lsid_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_database_summary_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_scope_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_lsid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_advrtr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_advrtr_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_advrtr_lsid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_database_summary_cmd);
}

