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
lsa_change (struct ospf6_lsa *lsa)
{
  struct area *area;
  struct ospf6_if *o6if;

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
      area = (struct area *)lsa->scope;
      if (area->spf_calc == (struct thread *)NULL)
        area->spf_calc = thread_add_event (master, spf_calculation,
                                           area, 0);
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master,
                                             routing_table_calculation,
                                             area, 0);
      break;
    case LST_LINK_LSA:
      o6if = (struct ospf6_if *)lsa->scope;
      area = (struct area *) o6if->area;
      if (area->spf_calc == (struct thread *)NULL)
        area->spf_calc = thread_add_event (master, spf_calculation,
                                           area, 0);
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master,
                                             routing_table_calculation,
                                             area, 0);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      area = (struct area *)lsa->scope;
      if (area->route_calc == (struct thread *)NULL)
        area->route_calc = thread_add_event (master,
                                             routing_table_calculation,
                                             area, 0);
      break;
    default:
      break;
    }

  return 0;
}

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


/* lookup lsa on summary list of neighbor */
struct ospf6_lsa *
ospf6_lookup_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (list_lookup_node (nbr->summarylist, lsa))
    {
#ifndef NDEBUG
      if (!list_lookup_node (lsa->summary_nbr, nbr))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to summary list of neighbor */
void
ospf6_add_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_add_node (nbr->summarylist, lsa);
  list_add_node (lsa->summary_nbr, nbr);
  ospf6_lsa_lock (lsa);
  o6log.lsdb ("add %s to %s summary", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  return;
}

/* remove lsa from summary list of neighbor */
void
ospf6_remove_summary (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_delete_by_val (nbr->summarylist, lsa);
  list_delete_by_val (lsa->summary_nbr, nbr);
  o6log.lsdb ("remove %s from %s summary", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  ospf6_lsa_unlock (lsa);
  return;
}

/* remove all lsa from summary list of neighbor */
void
ospf6_remove_summary_all (struct neighbor *nbr)
{
  struct ospf6_lsa *lsa;
  listnode n;
  while (listcount (nbr->summarylist))
    {
      n = listhead (nbr->summarylist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_summary (lsa, nbr);
    }
  return;
}

/* lookup lsa on request list of neighbor */
  /* this lookup is different from others, because this lookup is to find
     the same LSA instance of different memory space */
struct ospf6_lsa *
ospf6_lookup_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *p;

  for (n = listhead (nbr->requestlist); n; nextnode (n))
    {
      p = (struct ospf6_lsa *) getdata (n);
      if (ospf6_lsa_issame (p->lsa_hdr, lsa->lsa_hdr))
        {
#ifndef NDEBUG
          if (!list_lookup_node (p->request_nbr, nbr))
          assert (0);
#endif /* NDEBUG */
          return p;
        }
    }
  return NULL;
}

/* add lsa to request list of neighbor */
void
ospf6_add_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_add_node (nbr->requestlist, lsa);
  list_add_node (lsa->request_nbr, nbr);
  ospf6_lsa_lock (lsa);
  o6log.lsdb ("add %s to %s request", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  return;
}

/* remove lsa from request list of neighbor */
void
ospf6_remove_request (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_delete_by_val (nbr->requestlist, lsa);
  list_delete_by_val (lsa->request_nbr, nbr);
  o6log.lsdb ("remove %s from %s request", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  ospf6_lsa_unlock (lsa);
  return;
}

/* remove all lsa from request list of neighbor */
void
ospf6_remove_request_all (struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (nbr->requestlist))
    {
      n = listhead (nbr->requestlist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_request (lsa, nbr);
    }
  return;
}

/* lookup lsa on retrans list of neighbor */
struct ospf6_lsa *
ospf6_lookup_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  if (list_lookup_node (nbr->retranslist, lsa))
    {
#ifndef NDEBUG
      if (!list_lookup_node (lsa->retrans_nbr, nbr))
        assert (0);
#endif /* NDEBUG */
      return lsa;
    }
  return NULL;
}

/* add lsa to retrans list of neighbor */
void
ospf6_add_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_add_node (nbr->retranslist, lsa);
  list_add_node (lsa->retrans_nbr, nbr);
  ospf6_lsa_lock (lsa);
  o6log.lsdb ("add %s to %s retrans", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  return;
}

/* remove lsa from retrans list of neighbor */
void
ospf6_remove_retrans (struct ospf6_lsa *lsa, struct neighbor *nbr)
{
  list_delete_by_val (nbr->retranslist, lsa);
  list_delete_by_val (lsa->retrans_nbr, nbr);
  o6log.lsdb ("remove %s from %s retrans", print_lsahdr (lsa->lsa_hdr),
              nbr->str);
  ospf6_lsa_unlock (lsa);
  return;
}

/* remove all lsa from retrans list of neighbor */
void
ospf6_remove_retrans_all (struct neighbor *nbr)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (nbr->retranslist))
    {
      n = listhead (nbr->retranslist);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_retrans (lsa, nbr);
    }
  return;
}


/* add to delayed acknowledge list of ospf6_if */
void
ospf6_add_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  list_add_node (o6if->delayed_ack, lsa);
  list_add_node (lsa->delayed_ack_if, o6if);
  ospf6_lsa_lock (lsa);
  return;
}

/* remove from delayed acknowledge list of ospf6_if */
void
ospf6_remove_delayed_ack (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  list_delete_by_val (o6if->delayed_ack, lsa);
  list_delete_by_val (lsa->delayed_ack_if, o6if);
  ospf6_lsa_unlock (lsa);
  return;
}


/* lsdb functions */

/* interface scope */
/* lookup from interface lsdb */
static struct ospf6_lsa *
ospf6_lsdb_lookup_interface (unsigned short type, unsigned long id,
                             unsigned long advrtr, struct ospf6_if *o6if)
{
  listnode n;
  struct ospf6_lsa *lsa;
  assert (ospf6_lsa_get_scope_type (type) == SCOPE_LINKLOCAL);
  for (n = listhead (o6if->linklocal_lsa); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (lsa->lsa_hdr->lsh_advrtr != advrtr)
        continue;
      if (lsa->lsa_hdr->lsh_id != id)
        continue;
      return lsa;
    }
  return NULL;
}

/* add to interface lsdb */
static void
ospf6_lsdb_add_interface (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  assert (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type)
          == SCOPE_LINKLOCAL);
  list_add_node (o6if->linklocal_lsa, lsa);
  ospf6_lsa_lock (lsa);
  o6log.lsdb ("lsdb_add %s to %s", print_lsahdr (lsa->lsa_hdr),
              o6if->interface->name);
  return;
}

/* remove from interface lsdb */
static void
ospf6_lsdb_remove_interface (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  assert (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type)
          == SCOPE_LINKLOCAL);
  o6log.lsdb ("lsdb_remove %s from %s", print_lsahdr (lsa->lsa_hdr),
              o6if->interface->name);
  list_delete_by_val (o6if->linklocal_lsa, lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

/* area scope */
  /* I wanna know the effection of database algorithm to the performance,
     so the algorithm of these functions is so poor, should be rewrited
     near future. */
/* lookup from area lsdb */
static struct ospf6_lsa *
ospf6_lsdb_lookup_area (unsigned short type, unsigned long id,
                        unsigned long advrtr, struct area *area)
{
  listnode n;
  struct ospf6_lsa *lsa;

  assert (area);
  for (n = listhead (area->lsdb); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      if (lsa->lsa_hdr->lsh_type == type &&
          lsa->lsa_hdr->lsh_id == id &&
          lsa->lsa_hdr->lsh_advrtr == advrtr)
        return lsa;
    }
  return NULL;
}

/* add to area lsdb */
static void
ospf6_lsdb_add_area (struct ospf6_lsa *lsa, struct area *area)
{
  assert (area);
  list_add_node (area->lsdb, lsa);
  ospf6_lsa_lock (lsa);
  o6log.lsdb ("lsdb_add %s to area %s", print_lsahdr (lsa->lsa_hdr),
              area->str);
  return;
}

/* remove from area lsdb */
static void
ospf6_lsdb_remove_area (struct ospf6_lsa *lsa, struct area *area)
{
  assert (area);
  o6log.lsdb ("lsdb_remove %s from area %s", print_lsahdr (lsa->lsa_hdr),
              area->str);
  list_delete_by_val (area->lsdb, lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

/* lsdb lookup */
  /* It is better to specify scope when lookup lsdb, because there may
     be the same LSAs in different scoped structure. this will happen
     when duplicate router id is mis-configured over a different scope. */

  /* need two particular function for lookup */
  /* to treat multiple router-lsa as one */
void
ospf6_lsdb_collect_type_advrtr (list l, unsigned short type,
                                unsigned long advrtr, void *scope)
{
  struct area *area;
  struct ospf6_if *o6if;
  listnode n;
  struct ospf6_lsa *lsa;

  assert (l && scope);
  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_AREA:
        area = (struct area *) scope;
        for (n = listhead (area->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            o6log.debug ("area lsdb %s", print_lsahdr (lsa->lsa_hdr));
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *)scope;
        for (n = listhead (o6if->linklocal_lsa); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            o6log.debug ("interface lsdb %s", print_lsahdr (lsa->lsa_hdr));
            if (lsa->lsa_hdr->lsh_type == type &&
                lsa->lsa_hdr->lsh_advrtr == advrtr)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't collect advrtr from lsdb");
        break;
    }
  return;
}

  /* to process all as-external-lsa, *-area-prefix-lsa */
void
ospf6_lsdb_collect_type (list l, unsigned short type, void *scope)
{
  struct ospf6_if *o6if;
  struct area *area;
  listnode n;
  struct ospf6_lsa *lsa;

  assert (l && scope);
  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_AREA:
        area = (struct area *) scope;
        for (n = listhead (area->lsdb); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            o6log.debug ("area lsdb %s", print_lsahdr (lsa->lsa_hdr));
            if (lsa->lsa_hdr->lsh_type == type)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_LINKLOCAL:
        /* used by show_ipv6_ospf6_database_link_cmd */
        o6if = (struct ospf6_if *) scope;
        for (n = listhead (o6if->linklocal_lsa); n; nextnode (n))
          {
            lsa = (struct ospf6_lsa *) getdata (n);
            o6log.debug ("interface lsdb %s", print_lsahdr (lsa->lsa_hdr));
            if (lsa->lsa_hdr->lsh_type == type)
              list_add_node (l, lsa);
          }
        break;

      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't collect advrtr from lsdb");
        break;
    }
  return;
}

  /* ordinary lookup function */
struct ospf6_lsa *
ospf6_lsdb_lookup (unsigned short type, unsigned long id,
                   unsigned long advrtr, void *scope)
{
  struct ospf6_if *o6if;
  struct area *area;
  struct ospf6_lsa *found;

  switch (ospf6_lsa_get_scope_type (type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) scope;
        found = ospf6_lsdb_lookup_interface (type, id, advrtr, o6if);
        return found;
      case SCOPE_AREA:
        area = (struct area *) scope;
        found = ospf6_lsdb_lookup_area (type, id, advrtr, area);
        return found;
      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't lookup lsdb");
        break;
    }
  return NULL;
}

void
ospf6_lsdb_add (struct ospf6_lsa *lsa)
{
  struct ospf6_if *o6if;
  struct area *area;
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);

  /* set installed time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    o6log.lsa ("gettimeofday () failed, can't set installed: %s",
               strerror (errno));
  lsa->installed = now.tv_sec;

  /* add appropriate scope */
  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) lsa->scope;
        ospf6_lsdb_add_interface (lsa, o6if);
        break;
      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_add_area (lsa, area);
        break;
      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't add lsdb");
        return;
    }
  lsa_change (lsa);
  return;
}

void
ospf6_lsdb_remove (struct ospf6_lsa *lsa)
{
  struct ospf6_if *o6if;
  struct area *area;
  listnode n;

  /* LSA going to be removed from lsdb should not be (delayed)
     acknowledged. I must prevent from being delayed acknowledged
     here */
  for (n = listhead (lsa->delayed_ack_if); n;
       n = listhead (lsa->delayed_ack_if))
    {
      o6if = (struct ospf6_if *) getdata (n);
      ospf6_remove_delayed_ack (lsa, o6if);
    }

  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) lsa->scope;
        ospf6_lsdb_remove_interface (lsa, o6if);
        break;
      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_remove_area (lsa, area);
        break;
      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsdb ("unsupported scope, can't add lsdb");
        return;
    }
  return;
}

/* initialize and finish function */
/* neighbor lsdb */
void
ospf6_lsdb_init_neighbor (struct neighbor *nbr)
{
  nbr->summarylist = list_init ();
  nbr->requestlist = list_init ();
  nbr->retranslist = list_init ();
  return;
}

void
ospf6_lsdb_finish_neighbor (struct neighbor *nbr)
{
  ospf6_remove_summary_all (nbr);
  list_delete_all (nbr->summarylist);
  ospf6_remove_request_all (nbr);
  list_delete_all (nbr->requestlist);
  ospf6_remove_retrans_all (nbr);
  list_delete_all (nbr->retranslist);
  return;
}

/* interface lsdb */
void
ospf6_lsdb_init_interface (struct ospf6_if *o6if)
{
  o6if->linklocal_lsa = list_init ();
  o6if->delayed_ack = list_init ();
  return;
}

void
ospf6_lsdb_finish_interface (struct ospf6_if *o6if)
{
  listnode n;
  struct ospf6_lsa *lsa;

  /* delayed ack list */
  while (listcount (o6if->delayed_ack))
    {
      n = listhead (o6if->delayed_ack);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_remove_delayed_ack (lsa, o6if);
    }
  list_delete_all (o6if->delayed_ack);

  /* interface lsdb */
  while (listcount (o6if->linklocal_lsa))
    {
      n = listhead (o6if->linklocal_lsa);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_interface (lsa, o6if);
    }
  list_delete_all (o6if->linklocal_lsa);

  return;
}

/* area lsdb */
void
ospf6_lsdb_init_area (struct area *area)
{
  area->lsdb = list_init ();
  return;
}

void
ospf6_lsdb_finish_area (struct area *area)
{
  listnode n;
  struct ospf6_lsa *lsa;
  while (listcount (area->lsdb))
    {
      n = listhead (area->lsdb);
      lsa = (struct ospf6_lsa *) getdata (n);
      ospf6_lsdb_remove_area (lsa, area);
    }
  list_delete_all (area->lsdb);
  return;
}

/* when installing more recent LSA, must detach less recent database copy
   from LS-lists of neighbors, and attach new one. */
void ospf6_lsdb_install (struct ospf6_lsa *new)
{
  listnode n;
  struct neighbor *nbr;
  struct ospf6_lsa *old;

  old = ospf6_lsdb_lookup (new->lsa_hdr->lsh_type,
                           new->lsa_hdr->lsh_id,
                           new->lsa_hdr->lsh_advrtr, new->scope);

  if (old)
    {
      while (listcount (old->summary_nbr))
        {
          n = listhead (old->summary_nbr);
          nbr = (struct neighbor *) getdata (n);
          ospf6_remove_summary (old, nbr);
          ospf6_add_summary (new, nbr);
        }
    
      /* xxx, request list should not be done this way, i think.
         because self-originated LSA will not appear on request list,
         and receiving new LSA (via flood) deletes the one
         on request list. */
    
      while (listcount (old->retrans_nbr))
        {
          n = listhead (old->retrans_nbr);
          nbr = (struct neighbor *) getdata (n);
          ospf6_remove_retrans (old, nbr);
          ospf6_add_retrans (new, nbr);
        }
    
      ospf6_lsdb_remove (old);
      ospf6_lsdb_add (new);
    }
  else
    ospf6_lsdb_add (new);

  return;
}
