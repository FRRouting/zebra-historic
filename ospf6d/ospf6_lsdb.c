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
lsa_delete_from_list (struct lsa_internal *lsi, list l)
{
  assert (lsi->lsh);
  free_lsa (lsi->lsh);
  free_lsa_internal_hdr (lsi);
  list_delete_by_val (l, lsi);
  return 0;
}

int
lsa_delete_all_list (list l)
{
  listnode n;
  struct lsa_internal *lsi;

  for (n = listhead (l); n; n = listhead (l))
    {
      lsi = (struct lsa_internal *) getdata (n);
      lsa_delete_from_list (lsi, l);
    }
  assert (list_isempty (l));
  return 0;
}

int
lsa_delete (struct lsa_internal *lsi)
{
  assert (lsi && lsi->lsh);
  switch (GET_LSASCOPE (lsi->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      assert (lsi->ospf6_if);
      lsa_delete_from_list (lsi, lsi->ospf6_if->linklocal_lsa);
      break;

    case SCOPE_AREA:
      assert (lsi->area);
      lsa_delete_from_list (lsi, lsi->area->lsdb
               [typeindex(lsi->lsh->lsh_type)][hash(lsi->lsh->lsh_id)]);
      break;

    case SCOPE_AS:
      break;

    case SCOPE_RESERVED:
    default:
      zvlog_debug ("Not Reached!?");
      break;
    }
  return 0;
}

int
lsa_change (struct lsa_internal *newp)
{
  switch (ntohs (newp->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
    case LST_LINK_LSA:
      if (newp->area->spf_calc == (struct thread *)NULL)
        newp->area->spf_calc = thread_add_event (master,
                                                 spf_calculation,
                                                 newp->area, 0);
      /* Fall through, not break */
    case LST_INTRA_AREA_PREFIX_LSA:
      if (newp->area->route_calc == (struct thread *)NULL)
        newp->area->route_calc = thread_add_event (master,
                                                   routing_table_calculation,
                                                   newp->area, 0);
      break;
    default:
      break;
    }

  return 0;
}

int
lsa_install (struct lsa_internal *newp)
{
  struct lsa_internal *oldp;
  struct lsa_hdr *newlsh;
  struct timeval now;
  listnode n;
  struct neighbor *nbr;

  assert (newp);

  newlsh = newp->lsh;

  gettimeofday (&now, (struct timezone *)NULL);

  oldp = lsa_lookup (newlsh->lsh_type, newlsh->lsh_id, newlsh->lsh_advrtr,
                     newp->area, newp->ospf6_if);
  if (oldp)
    {
      assert (oldp->lsh);
      log_pointer ("Find Old One[%#x] in lsa_install()", oldp);

      /* XXX Do I have to put on the neighbor's retranslist ?
         I think so */
      for (n = listhead (oldp->retransing_nbr);
           !list_isempty (oldp->retransing_nbr);
           n = listhead (oldp->retransing_nbr))
        {
          nbr = (struct neighbor *) getdata (n);
          attach_lsa_to_retranslist (newp, nbr);
          detach_lsa_from_retranslist (oldp, nbr);
        }

      lsa_delete (oldp);
    }

  switch (GET_LSASCOPE (newp->lsh->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        assert (newp->ospf6_if);
        list_add_node (newp->ospf6_if->linklocal_lsa, newp);
        break;
      case SCOPE_AREA:
        assert (newp->area);
        list_add_node (newp->area->lsdb[typeindex (newp->lsh->lsh_type)]
                                       [hash (newp->lsh->lsh_id)], newp);
        break;
      case SCOPE_AS:
        zvlog_warn ("Not yet");
        break;
      case SCOPE_RESERVED:
      default:
        zvlog_warn ("Not Reached!?");
        break;
    }

  log_pointer ("new LSA[ihdr:%#x][body:%#x] Installed!",
               newp, newp->lsh);

  newp->installed = now.tv_sec;

  lsa_change (newp);
  return 0;
}

list
lsa_lookup_by_advrtr (unsigned short lsa_type, unsigned long advrtr,
                      struct area *area)
{
  int i;
  struct lsa_internal *lsi;
  listnode n;
  list returnlist = NULL;

  returnlist = list_init ();
  for (i = 0; i < HASHVAL; i++)
    {
      for (n = listhead (area->lsdb[typeindex (lsa_type)][i]); n; nextnode (n))
        {
          lsi = (struct lsa_internal *)getdata (n);
          if (lsi->lsh->lsh_advrtr == advrtr)
            {
              list_add_node (returnlist, lsi);
              zvlog_debug ("%s found in lookup by advrtr",
                           print_lsahdr (lsi->lsh));
            }
        }
    }

  if (list_isempty (returnlist))
    {
      list_delete_all (returnlist);
      returnlist = NULL;
    }

  return returnlist;
}

/* LSA lookup (Argument's byte order is Network Byte order) */
struct lsa_internal *
lsa_lookup (unsigned short lsa_type, unsigned long lsid,
            unsigned long advrtr, struct area *area,
            struct ospf6_if *ospf6_if)
{
  listnode n;
  struct lsa_internal *lsi;

  switch (GET_LSASCOPE (lsa_type))
    {
    case SCOPE_LINKLOCAL:
      assert (ospf6_if);
      for (n = listhead (ospf6_if->linklocal_lsa); n; nextnode (n))
        {
          lsi = getdata (n);
          if (lsi->lsh->lsh_type == lsa_type &&
              lsi->lsh->lsh_id == lsid &&
              lsi->lsh->lsh_advrtr == advrtr)
            return lsi;
        }
      return (struct lsa_internal *)NULL;
    case SCOPE_AREA:
      for (n = listhead (area->lsdb[typeindex(lsa_type)][hash(lsid)]);
           n; nextnode (n))
        {
          lsi = getdata (n);
          if (lsi->lsh->lsh_type == lsa_type &&
              lsi->lsh->lsh_id == lsid &&
              lsi->lsh->lsh_advrtr == advrtr)
            return lsi;
        }
      return (struct lsa_internal *)NULL;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      zvlog_warn ("Not Reached!?");
      break;
    }
  return (struct lsa_internal *)NULL;
}

struct lsa_hdr *
attach_lsa_to_iov (struct lsa_internal *lsi, struct iovec *iov)
{
  assert (lsi && lsi->lsh);

  return ((struct lsa_hdr *)
          iov_attach_last (iov, lsi->lsh, ntohs (lsi->lsh->lsh_len)));
}

struct lsa_hdr *
attach_lsa_hdr_to_iov (struct lsa_internal *lsi, struct iovec *iov)
{
  assert (lsi && lsi->lsh);

  return ((struct lsa_hdr *)
          iov_attach_last (iov, lsi->lsh, sizeof (struct lsa_hdr)));
}

struct lsa_internal *
get_linklocal_lsa (rtr_id_t rtrid, struct ospf6_if *o6if)
{
  listnode n;
  struct lsa_internal *lsa;

  assert (rtrid && o6if);
  for (n = listhead (o6if->linklocal_lsa); n; nextnode (n))
    {
      lsa = getdata (n);
      if (lsa->lsh->lsh_advrtr == rtrid)
        return lsa;
    }
  return NULL;
}

struct lsa_internal *
lslist_lookup (struct lsa_internal *lsi, list l)
{
  listnode n;
  struct lsa_internal *p, *retlsa;
  int count = 0;

  retlsa = NULL;
  for (n = listhead (l); n; nextnode (n))
    {
      p = getdata (n);
      if (lsa_issame (lsi->lsh, p->lsh))
        {
          count++;
          retlsa = p;
        }
    }

  if (count != 0 && count != 1)
    o6log.lsdb ("!list includes duplicate lsa");

  return retlsa;
}

void
attach_lsa_to_retranslist (struct lsa_internal *lsi, struct neighbor *nbr)
{
  list_add_node (lsi->retransing_nbr, nbr);
  list_add_node (nbr->retranslist, lsi);
  o6log.dbex ("attach %s to %s's retranslist", print_lsahdr (lsi->lsh),
              nbr->str);
}

void
detach_lsa_from_retranslist (struct lsa_internal *lsi, struct neighbor *nbr)
{
  list_delete_by_val (lsi->retransing_nbr, nbr);
  list_delete_by_val (nbr->retranslist, lsi);
  o6log.dbex ("detach %s from %s's retranslist", print_lsahdr (lsi->lsh),
              nbr->str);
}

