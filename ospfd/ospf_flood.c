/*
 * OSPF Flooding -- RFC2328 Section 13.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 * 
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_asbr.h"


void
ospf_process_self_originated_lsa (struct ospf_lsa *new, struct ospf_area *area)
{
  struct network_lsa *nlsa;
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;

  zlog_info ("Z: Processing self-originated and installed LSA");

  /* If we're here, we installed a self-originated LSA
     that we received from a neighbor, i.e. it's more recent.
     We must see whether we want to originate it.
     If yes, we should use this LSA's sequence number
     and reoriginate a new instance.
     if not---we must flush this LSA from the domain. */

  switch (new->data->type)
    {
    case OSPF_ROUTER_LSA:
      zlog_info ("Z: It's a router-LSA");
 
      /* originate a new instance and schedule flooding */

      area->router_lsa_self = new; /* It shouldn't be necessary, but anyway */

/*      lsa = ospf_router_lsa (area);
      lsa = ospf_router_lsa_install (area, lsa);

      ospf_schedule_lsa_flood_area (area, lsa);
*/
      ospf_schedule_router_lsa_originate (area);
      return;

    case OSPF_NETWORK_LSA:
      zlog_info ("Z: It's a network-LSA");

      /* We must find the interface the LSA could
	 belong to.
	 If the interface is no more a broadcast type
	 or we're no more the DR, we flush the LSA
	 otherwise---create the new instance and
	 schedule flooding. */

      nlsa = (struct network_lsa *) new->data;

      /* Look through all interfaces, not just area,
	 since interface could be moved from one area
	 to another. */
      LIST_ITERATOR (ospf_top->iflist, node) 
        {
          ifp = getdata(node); 
          if (ifp == NULL)
	    continue; /* sanity check */

          oi = ifp->info;
          if (oi == NULL)
	    continue; /* sanity check */

          if (oi->address == NULL)
	    continue; /* sanity check */

          if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &new->data->id))
	    {
	      if (oi->area != area ||
		  oi->type != OSPF_IFTYPE_BROADCAST ||
		  !IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi)))
		{
		  ospf_schedule_lsa_flush_area (area, new);
		  return;
		}

	      oi->network_lsa_self = new;
/*	      lsa = ospf_network_lsa (oi);
	      lsa = ospf_network_lsa_install (oi, lsa);
	      ospf_schedule_lsa_flood_area (area, lsa);
*/
              ospf_schedule_network_lsa_originate (oi);
	      return;
	    }
        }

   case OSPF_SUMMARY_LSA:
   case OSPF_SUMMARY_LSA_ASBR:
     zlog_info ("Z: It's a summary-LSA");
     ospf_schedule_abr_task ();
     break;
   case OSPF_AS_EXTERNAL_LSA :
     zlog_info ("Z: It's an AS-external-LSA");
     ospf_schedule_asbr_check ();
     break;
  }
}

/* OSPF LSA flooding -- RFC2328 Section 13.(5). */
int
ospf_flood (struct ospf_neighbor *nbr, struct ospf_lsa *current,
	    struct ospf_lsa *new)
{
  struct ospf_interface *oi;
  time_t ts;

  oi = nbr->oi;

  /* Get current time. */
  ts = time (NULL);

  /* If there is already a database copy, and if the
     database copy was received via flooding and installed less
     than MinLSArrival seconds ago, discard the new LSA
     (without acknowledging it). */
  if (current && (ts - current->ts) < OSPF_MIN_LS_INTERVAL)
    return -1;

  /* Flood the new LSA out some subset of the router's interfaces.
     In some cases (e.g., the state of the receiving interface is
     DR and the LSA was received from a router other than the
     Backup DR) the LSA will be flooded back out the receiving
     interface. */
  ospf_flood_through (nbr, new);

  /* Remove the current database copy from all neighbors'
     Link state retransmission lists. */
  if (current)
    ospf_ls_retransmit_delete_nbr_all (current);

  /* Install the new LSA in the link state database
     (replacing the current database copy).  This may cause the
     routing table calculation to be scheduled.  In addition,
     timestamp the new LSA with the current time.  The flooding
     procedure cannot overwrite the newly installed LSA until
     MinLSArrival seconds have elapsed. */  
  if (!current || ospf_lsa_different (current, new))
    ospf_spf_calculate_schedule ();

  SET_FLAG (new->flags, OSPF_LSA_RECEIVED);
  ospf_lsa_is_self_originated (new); /* Let it set the flag */
  new = ospf_lsa_install (nbr, new);

  /* Acknowledge the receipt of the LSA by sending a Link State
     Acknowledgment packet back out the receiving interface. */
  /* ospf_ls_ack_send (nbr, new); */

  /* If this new LSA indicates that it was originated by the
     receiving router itself, the router must take special action,
     either updating the LSA or in some cases flushing it from
     the routing domain. */
  if (ospf_lsa_is_self_originated (new))
    ospf_process_self_originated_lsa (new, oi->area);

  return 0;
}


/* OSPF LSA flooding -- RFC2328 Section 13.3. */
void
ospf_flood_through_area (struct ospf_area * area,struct ospf_neighbor *inbr,
			 struct ospf_lsa *lsa)
{
  listnode node;

  for (node = listhead (area->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct ospf_neighbor *onbr;
      struct route_node *rn;
      list update;
      int flag;

      ifp = getdata (node);
      if (ospf_zlog)
	zlog_info ("Z: ospf_flood_through_area(): considering int %s",
		   ifp->name);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      /* Remember if new LSA is flooded out back. */
      flag = 0;

      /* Each of the neighbors attached to this interface are examined,
	 to determine whether they must receive the new LSA.  The following
	 steps are executed for each neighbor: */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  struct ospf_lsa *ls_req;
 
	  if (rn->info == NULL)
	    continue;

	  onbr = rn->info;
	  if (ospf_zlog)
	    zlog_info ("Z: ospf_flood_through_area(): considering nbr %s",
		       inet_ntoa (onbr->router_id));

	  /* If the neighbor is in a lesser state than Exchange, it
	     does not participate in flooding, and the next neighbor
	     should be examined. */
	  if (onbr->status < NSM_Exchange)
	    continue;

	  /* If the adjacency is not yet full (neighbor state is
	     Exchange or Loading), examine the Link state request
	     list associated with this adjacency.  If there is an
	     instance of the new LSA on the list, it indicates that
	     the neighboring router has an instance of the LSA
	     already.  Compare the new LSA to the neighbor's copy: */
	  if (onbr->status < NSM_Full)
	    {
	      if (ospf_zlog)
		zlog_info ("Z: ospf_flood_through_area(): nbr adj is not Full");

	      ls_req = ospf_ls_request_lookup (onbr, lsa);
	      if (ls_req != NULL)
		{
		  int ret;

		  ret = ospf_lsa_more_recent (ls_req, lsa);
		  /* The new LSA is less recent. */
		  if (ret > 0)
		    continue;
		  /* The two copies are the same instance, then delete
		     the LSA from the Link state request list. */
		  else if (ret == 0)
		    {
		      ospf_ls_request_delete (onbr, ls_req);
                      ospf_check_nbr_loading (onbr);
		      continue;
		    }
		  /* The new LSA is more recent.  Delete the LSA
		     from the Link state request list. */
		  else
		    {
		      ospf_ls_request_delete (onbr, ls_req);
		      ospf_check_nbr_loading (onbr);
		    }
		}
	    }

	  /* If the new LSA was received from this neighbor,
	     examine the next neighbor. */
          if (inbr)
 	    if (IPV4_ADDR_SAME (&inbr->router_id, &onbr->router_id))
	      continue;

	  /* Add the new LSA to the Link state retransmission list
	     for the adjacency. The LSA will be retransmitted
	     at intervals until an acknowledgment is seen from
	     the neighbor. */
	  ospf_ls_retransmit_add (onbr, lsa);
	  flag = 1;
	}

      /* LSA is more recent than database copy, but was not flooded
         back out receiving interface. */
      if (flag == 0)
	if (inbr && (oi->status != ISM_Backup || NBR_IS_DR (inbr)))
	  list_add_node (oi->ls_ack, ospf_lsa_dup (lsa));

      /* If in the previous step, the LSA was NOT added to any of
	 the Link state retransmission lists, there is no need to
	 flood the LSA out the interface. */

      /* If the new LSA was received on this interface, and it was
	 received from either the Designated Router or the Backup
	 Designated Router, chances are that all the neighbors have
	 received the LSA already. */
      if (inbr && (inbr->oi == oi))
	{
	  if (NBR_IS_DR (inbr) || NBR_IS_BDR (inbr))
	    continue;
	}

      /* If the new LSA was received on this interface, and the
	 interface state is Backup, examine the next interface.  The
	 Designated Router will do the flooding on this interface.
	 However, if the Designated Router fails the router will
	 end up retransmitting the updates. */
	else if (IPV4_ADDR_SAME (&oi->address->u.prefix4, &BDR (oi)))
	  continue;

      /* The LSA must be flooded out the interface. Send a Link State
	 Update packet (including the new LSA as contents) out the
	 interface.  The LSA's LS age must be incremented by InfTransDelay
	 (which	must be	> 0) when it is copied into the outgoing Link
	 State Update packet (until the LS age field reaches the maximum
	 value of MaxAge). */
         if (flag)
	   {
	     if (ospf_zlog)
	       zlog_info ("Z: ospf_flood_through_area(): sending upd to int %s", oi->ifp->name);
	     update = list_init ();
	     list_add_node (update, lsa);

	     ospf_ls_upd_send (oi->nbr_self, update,
			       OSPF_SEND_PACKET_INDIRECT);
	     list_free (update);
	   }
    }
}

void
ospf_flood_through_as (struct ospf_neighbor *inbr, struct ospf_lsa *lsa)
{
  struct ospf_area *area;
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      if (area->external_routing != OSPF_AREA_DEFAULT)
	continue;

      ospf_flood_through_area (area, inbr, lsa);
    }
}

void
ospf_flood_through (struct ospf_neighbor *inbr, struct ospf_lsa *lsa)
{
  switch (lsa->data->type)
    {
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA:
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      ospf_flood_through_area (inbr->oi->area, inbr, lsa);
      break;
    case OSPF_AS_EXTERNAL_LSA:
      ospf_flood_through_as (inbr, lsa);
      break;
    default:
      break;
    }
}


#if 1
void
tmp_log ( char *str, struct ospf_lsa *lsa)
{
  return;
  printf ("%s %s ", str, inet_ntoa (lsa->data->id));
  printf ("%s\n", inet_ntoa (lsa->data->adv_router));
}

void
new_lsdb_init (struct new_lsdb *lsdb)
{
  lsdb->type[1].db = route_table_init ();
  lsdb->type[2].db = route_table_init ();
  lsdb->type[3].db = route_table_init ();
  lsdb->type[4].db = route_table_init ();
  lsdb->type[5].db = route_table_init ();
}

void
lsdb_prefix_set (struct prefix_ls *lp, struct ospf_lsa *lsa)
{
  memset (lp, 0, sizeof (struct prefix_ls));
  lp->family = 0;
  lp->prefixlen = 64;
  lp->id = lsa->data->id;
  lp->adv_router = lsa->data->adv_router;
}

/* Add new LSA to lsdb. */
void
new_lsdb_add (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_get (table, (struct prefix *)&lp);
  if (! rn->info)
    {
      lsdb->type[lsa->data->type].count++;
      lsdb->total++;
    }
  /*
  else
    ospf_lsa_free (rn->info);
  */
  rn->info = lsa;
  tmp_log ("add", lsa);
}

void
new_lsdb_delete (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_lookup (table, (struct prefix *) &lp);
  if (rn)
    {
      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
      /* ospf_lsa_free (lsa); */
      lsdb->type[lsa->data->type].count--;
      lsdb->total--;
      tmp_log ("delete", lsa);
      return;
    }
  tmp_log ("can't delete", lsa);
}

void
new_lsdb_delete_all (struct new_lsdb *lsdb)
{
  struct route_table *table;
  struct route_node *rn;
  struct ospf_lsa *lsa;
  int i;

  for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++)
    {
      table = lsdb->type[i].db;
      for (rn = route_top (table); rn; rn = route_next (rn))
	if ((lsa = (rn->info)) != NULL)
	  {
	    rn->info = NULL;
	    route_unlock_node (rn);
	    ospf_lsa_free (lsa);
	    lsdb->type[i].count--;
	    lsdb->total--;
	  }
    }
}

struct ospf_lsa *
new_lsdb_lookup (struct new_lsdb *lsdb, struct ospf_lsa *lsa)
{
  struct route_table *table;
  struct prefix_ls lp;
  struct route_node *rn;
  struct ospf_lsa *find;

  table = lsdb->type[lsa->data->type].db;
  lsdb_prefix_set (&lp, lsa);
  rn = route_node_lookup (table, (struct prefix *) &lp);
  if (rn)
    {
      find = rn->info;
      route_unlock_node (rn);
      tmp_log ("lookup", lsa);
      return find;
    }
  tmp_log ("can't lookup", lsa);
  return NULL;
}

unsigned long
new_lsdb_count (struct new_lsdb *lsdb)
{
  return lsdb->total;
}

unsigned long
new_lsdb_isempty (struct new_lsdb *lsdb)
{
  return (lsdb->total == 0);
}

void
ospf_ls_request_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  new_lsdb_add (&nbr->ls_req, lsa);
}

unsigned long
ospf_ls_request_count (struct ospf_neighbor *nbr)
{
  return new_lsdb_count (&nbr->ls_req);
}

int
ospf_ls_request_isempty (struct ospf_neighbor *nbr)
{
  return new_lsdb_isempty (&nbr->ls_req);
}

/* Remove LSA from neighbor's ls-request list. */
void
ospf_ls_request_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  if (nbr->ls_req_last == lsa)
    nbr->ls_req_last = NULL;
  new_lsdb_delete (&nbr->ls_req, lsa);
  ospf_lsa_free (lsa);
}

/* Remove all LSA from neighbor's ls-requenst list. */
void
ospf_ls_request_delete_all (struct ospf_neighbor *nbr)
{
  nbr->ls_req_last = NULL;
  new_lsdb_delete_all (&nbr->ls_req);
}

/* Lookup LSA from neighbor's ls-request list. */
struct ospf_lsa *
ospf_ls_request_lookup (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  return new_lsdb_lookup (&nbr->ls_req, lsa);
}
#else
/* Add LSA header to be requested to neighbor's ls-request list. */
void
ospf_ls_request_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  list_add_node (nbr->ls_request, lsa);
}

unsigned long
ospf_ls_request_count (struct ospf_neighbor *nbr)
{
  return listcount (nbr->ls_request);
}

int
ospf_ls_request_isempty (struct ospf_neighbor *nbr)
{
  return list_isempty (nbr->ls_request);
}

/* Remove LSA header from neighbor's ls-request list. */
void
ospf_ls_request_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  list_delete_by_val (nbr->ls_request, lsa);
  ospf_lsa_free (lsa);
}

/* Remove all LSA header from neighbor's ls-requenst list. */
void
ospf_ls_request_delete_all (struct ospf_neighbor *nbr)
{
  listnode node;

  while ((node = listhead (nbr->ls_request)) != NULL)
    ospf_ls_request_delete (nbr, node->data);
}

/* Lookup LSA header from neighbor's ls-request list. */
struct ospf_lsa *
ospf_ls_request_lookup (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
  listnode node;
  struct ospf_lsa *find;

  for (node = listhead (nbr->ls_request); node; nextnode (node))
    {
      find = getdata (node);

      if (find->data->type == lsa->data->type &&
	  IPV4_ADDR_SAME (&find->data->id, &lsa->data->id) &&
	  IPV4_ADDR_SAME (&find->data->adv_router, &lsa->data->adv_router))
	return find;
    }

  return NULL;
}
#endif /* NEW_LS_REQUEST */

/* Management functions for neighbor's ls-request list. */

struct ospf_lsa *
ospf_ls_request_new (struct lsa_header *lsah)
{
  struct ospf_lsa *new;

zlog_info ("T: ospf_lsa_new() in ospf_ls_request_new");
  new = ospf_lsa_new ();
  new->data = ospf_lsa_data_new (OSPF_LSA_HEADER_SIZE);
  memcpy (new->data, lsah, OSPF_LSA_HEADER_SIZE);

  return new;
}

void
ospf_ls_request_free (struct ospf_lsa *lsa)
{
  assert (lsa);
  ospf_lsa_free (lsa);
}

/* Management functions for neighbor's ls-retransmit list. */

void
debug_ospf_ls_retransmit (struct ospf_neighbor *nbr)
{
  int i = 0;
  listnode n;

  zlog_info ("LLL: --------start---------");
  zlog_info ("LLL: nbr->router_id=%s", inet_ntoa (nbr->router_id));
  zlog_info ("LLL: ls_retransmit=%d", listcount (nbr->ls_retransmit));

  for (n = listhead (nbr->ls_retransmit); n; nextnode (n))
    {
      struct ospf_lsa *lsa;
      lsa = getdata (n);

      zlog_info ("LLL: lsa num %d", ++i);
      zlog_info ("LLL: lsa->flags=%x", lsa->flags);
      zlog_info ("LLL: lsa->ts=%x", lsa->ts);
      zlog_info ("LLL: lsa->data=%x", lsa->data);
      zlog_info ("LLL: lsa->ref=%d", lsa->ref);
    }
  zlog_info ("LLL: --------end---------");
}

/* Add LSA to be retransmitted to neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_add (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
  list_add_node (nbr->ls_retransmit, lsa);
  lsa->ref++;
#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
}

/* Remove LSA from neibghbor's ls-retransmit list. */
void
ospf_ls_retransmit_delete (struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
  list_delete_by_val (nbr->ls_retransmit, lsa);
  if (lsa->ref)
    lsa->ref--;
#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
}

/* Clear neighbor's ls-retransmit list. */
void
ospf_ls_retransmit_clear (struct ospf_neighbor *nbr)
{
  listnode node;
  listnode next;
  struct ospf_lsa *lsa;

#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
  for (node = listhead (nbr->ls_retransmit); node; node = next)
    {
      lsa = getdata (node);
      next = node->next;

      if (lsa->ref)
	lsa->ref--;
      list_delete_by_val (nbr->ls_retransmit, lsa);
    }
#ifdef DEBUG
  debug_ospf_ls_retransmit (nbr);
#endif /* DEBUG */
}

/* Lookup LSA from neighbor's ls-retransmit list. */
struct ospf_lsa *
ospf_ls_retransmit_lookup (struct ospf_neighbor *nbr, struct lsa_header *lsah)
{
  listnode node;
  struct ospf_lsa *lsr;		/* LSA to be retransmitted. */

  for (node = listhead (nbr->ls_retransmit); node; nextnode (node))
    {
      lsr = getdata (node);

      if (lsr->data->type == lsah->type &&
	  IPV4_ADDR_SAME (&lsr->data->id, &lsah->id) &&
	  IPV4_ADDR_SAME (&lsr->data->adv_router, &lsah->adv_router) &&
	  lsr->data->ls_seqnum == lsah->ls_seqnum)
	return lsr;
    }

  return NULL;
}

/* Remove the current database copy from all neighbors'
   Link state retransmission lists. */
void
ospf_ls_retransmit_delete_nbr_all (struct ospf_lsa *lsa)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_lsa *lsr;
  struct route_node *rn;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if ((nbr = rn->info) == NULL)
	    continue;

	  lsr = ospf_ls_retransmit_lookup (nbr, lsa->data);

	  /* If LSA find in ls-retransmit list, remove it. */
	  if (lsr != NULL)
	    ospf_ls_retransmit_delete (nbr, lsr);
	}
    }
}  

/* Add LSA to the current database copy of all neighbors'
   Link state retransmission lists. */
void
ospf_ls_retransmit_add_nbr_all (struct ospf_interface *ospfi,
				struct ospf_lsa *lsa)
{
  listnode node;
  struct route_node *rn;
  struct interface *ifp;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  struct ospf_lsa *lsr;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (!ospf_if_is_enable (ifp))
	continue;

      if (!OSPF_AREA_SAME (&ospfi->area, &oi->area))
	continue;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	{
	  if ((nbr = rn->info) == NULL)
	    continue;

	  if (nbr->status != NSM_Full)
	    continue;

	  /* If old LSA in ls-retransmit list, first remove it. */
	  if ((lsr = ospf_ls_retransmit_lookup (nbr, lsa->data)))
	    ospf_ls_retransmit_delete (nbr, lsr);

	  /* Then add new LSA to the neighbor's ls-retransmit list. */
	  ospf_ls_retransmit_add (nbr, lsa);
	}
    }
}

/* Sets ls_age to MaxAge and floods throu the area. 
   When we implement ASE routing, there will be anothe function
   flushing an LSA from the whole domain. */
void
ospf_lsa_flush_area (struct ospf_lsa *lsa, struct ospf_area *area)
{
  lsa->data->ls_age = htons (OSPF_LSA_MAX_AGE);
  ospf_flood_through_area (area, NULL, lsa);
  ospf_lsa_maxage (lsa);
}

void
ospf_lsa_flush_as (struct ospf_lsa *lsa)
{
  lsa->data->ls_age = htons (OSPF_LSA_MAX_AGE);
  ospf_flood_through_as (NULL, lsa);
  ospf_lsa_maxage (lsa);
}
