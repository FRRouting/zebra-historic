/*
 * OSPF LSDB support.
 * Copyright (C) 1999 Alex Zinin
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
 * 02111-1307, USA.  */

#include <zebra.h>

#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_lsdb.h"


void
id_to_prefix (struct in_addr id, struct prefix *p)
{
  p->family = AF_INET;
  p->prefixlen = IPV4_MAX_BITLEN;
  p->u.prefix4 = id;
}

void
get_lsa_prefix (struct ospf_lsa *lsa, struct prefix *p)
{
  id_to_prefix (lsa->data->id, p);
}


unsigned int
ospf_lsdb_hash_key (struct ospf_lsa *lsa)
{
  unsigned int key = 0;
  int length;
  caddr_t pnt;

  length = sizeof (struct in_addr) * 2; /* We take LS ID and Adv Router */
  pnt = (caddr_t) & (lsa->data->id);

  while (length)
    key += pnt[--length];

  return key %= HASHTABSIZE;
}

int
ospf_lsdb_hash_cmp (struct ospf_lsa *lsa1, struct ospf_lsa *lsa2)
{
  if ((lsa1->data->id.s_addr == lsa2->data->id.s_addr) &&
      (lsa1->data->adv_router.s_addr == lsa2->data->adv_router.s_addr))
    return 1;
  else
    return 0;
}


/* Allocate new lsdb object. */
struct ospf_lsdb *
ospf_lsdb_new (u_char lsdb_flags)
{
  struct ospf_lsdb *new;

  new = XMALLOC (MTYPE_OSPF_LSDB, sizeof (struct ospf_lsdb));
  bzero (new, sizeof (struct ospf_lsdb));

  new->flags = lsdb_flags;

  if (CHECK_FLAG (lsdb_flags, OSPF_LSDB_HASH))
    {
      new->hash = hash_new (HASHTABSIZE);
      new->hash->hash_key = ospf_lsdb_hash_key;
      new->hash->hash_cmp = ospf_lsdb_hash_cmp;
    }

  if (CHECK_FLAG (lsdb_flags, OSPF_LSDB_LIST))
    new->list = list_init ();

  if (CHECK_FLAG (lsdb_flags, OSPF_LSDB_RT))
    new->rt = route_table_init ();

  return new;
}

/* Iterator for LSDB data structure. */
struct ospf_lsa *
ospf_lsdb_iterator (struct ospf_lsdb *lsdb, void *p_arg, int int_arg, 
		    int (*callback) (struct ospf_lsa *, void *, int))
{
  struct ospf_lsa *lsa;

  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_iterator():Hey, your LSDB is none!");
      return NULL;
    }

  /* Iterate as linked list. */
  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_LIST) && lsdb->list)
    {
      listnode node;

      zlog_info ("Z: LSDB: iterating the list %p, listcount: %d",
		 lsdb->list, listcount (lsdb->list));

      for (node = listhead (lsdb->list); node; nextnode (node))
	{
	  if ((lsa = getdata (node)) == NULL)
	    continue;

	  zlog_info ("Z: LSDB: iterating: calling callback");
	  if (callback (lsa, p_arg, int_arg))
	    return lsa;
	}

      return NULL;
    }

  /* Iterate as route table. */
  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT) && lsdb->rt)
    {
      struct route_node *rn;

      for (rn = route_top (lsdb->rt); rn; rn = route_next (rn))
	{
	  if ((lsa = rn->info) == NULL)
	    continue;

	  zlog_info ("Z: LSDB: iterating: calling callback");
	  if (callback (lsa, p_arg, int_arg))
	    return lsa;
	}
      return NULL;
    }

  /* Iterate as hash. */
  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) && lsdb->hash)
    {
      int i;
      struct HashBacket *mp, *next;

      for (i = 0; i < HASHTABSIZE; i++)
	if ((mp = hash_head (lsdb->hash, i)) != NULL)
	  while (mp) 
	    {
	      next = mp->next;

	      if ((lsa = mp->data) == NULL)
		continue;

	      if (callback (lsa, p_arg, int_arg))
		return lsa;

	      mp = next;
	    }
      return NULL;
    }

  return NULL;
}

void ospf_lsdb_delete (struct ospf_lsdb *, struct ospf_lsa *);

int
lsdb_free (struct ospf_lsa *lsa, void *v, int i)
{
  struct ospf_lsdb *lsdb = (struct ospf_lsdb *) v;

  if (lsa == NULL)
    return 0;

  if (lsdb == NULL)
    return 0;

  ospf_lsdb_delete (lsdb, lsa);
  ospf_lsa_free (lsa);

  zlog_info("Z: ospf_lsa_free() in ospf_lsdb_free(): %x", lsa);

  return 0;
}

void
ospf_lsdb_free (struct ospf_lsdb *lsdb)
{
  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_free():Hey, your LSDB is none!");
      return;
    }

  ospf_lsdb_iterator (lsdb, lsdb, 0, lsdb_free);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) && lsdb->hash)
    hash_free (lsdb->hash);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_LIST) && lsdb->list) 
    list_delete_all (lsdb->list);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT) && lsdb->rt)
    route_table_finish (lsdb->rt);

  XFREE (MTYPE_OSPF_LSDB, lsdb);
}

int find_lsa (struct ospf_lsa *, void *, int);

struct ospf_lsa *
ospf_lsdb_add (struct ospf_lsdb *lsdb, struct ospf_lsa *new)
{
  struct ospf_lsa *lsa = NULL;
  int changed = 0;
  struct HashBacket *b;

  zlog_info ("Z: ospf_lsdb_add():Start");

  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_add():Hey, your LSDB is none!");
      return NULL;
    }

  if (new == NULL)
    {
      zlog_info ("Z: ospf_lsdb_add():Nothing to add, hah!");
      return NULL;
    }

  assert (new->data);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) && lsdb->hash) 
    {
      lsa = hash_search (lsdb->hash, new);
      if (lsa)
	{
	  ospf_lsa_data_free (lsa->data);

	  /* Set new LSA data. */
	  lsa->ts = new->ts;
	  lsa->originated = new->originated;
/*	  lsa->data = ospf_lsa_data_dup (new->data);
*/
          lsa->data = new->data;
          ospf_ls_retransmit_delete_nbr_all(new);
	  new->data = NULL;
          ospf_lsa_free(new);

          if (lsa->refresh_list)
             ospf_refresher_unregister_lsa (lsa);

          zlog_info("Z: ospf_lsa_free() in ospf_lsdb_add().1: %x", new);

	  changed = 1;
	}
      else
	{
	  b = hash_push (lsdb->hash, new);
	  if (b)
	    lsa = b->data;
	  else
	    lsa = NULL;
	}
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_LIST) && lsdb->list && !changed) 
    {
      zlog_info ("Z: LSDB: adding to the list %p, listcount: %d",
		 lsdb->list, listcount (lsdb->list));

      lsa = ospf_lsdb_iterator (lsdb, new, 0, find_lsa);
      zlog_info ("Z: LSDB: called iterator, found:%d", lsa != NULL);

      if (lsa)
	{
          zlog_info ("Z: LSDB: changing the old LSA");
	  ospf_lsa_data_free (lsa->data);

	  /* Set new LSA data. */
	  lsa->ts = new->ts;
	  lsa->originated = new->originated;

/*	  lsa->data = ospf_lsa_data_dup (new->data);
*/
          lsa->data = new->data;
          ospf_ls_retransmit_delete_nbr_all(new);
	  new->data = NULL;
          ospf_lsa_free(new);

          if (lsa->refresh_list)
             ospf_refresher_unregister_lsa (lsa);

          zlog_info("Z: ospf_lsa_free() in ospf_lsdb_add().2: %x", new);

	  changed = 1;
	}
      else
	{
	  zlog_info ("Z: LSDB: adding the new LSA");
	  list_add_node (lsdb->list, new);
	  zlog_info ("Z: LSDB: added, listcount:%d", listcount (lsdb->list));
	  lsa = new;
	}
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT) && lsdb->rt && !changed) 
    {
      struct route_node *rn;
      struct prefix p;

      get_lsa_prefix (new, &p);

      /*
      rn = route_node_get(lsdb->rt, &p);
      if (rn->info == NULL) 
	{
	  rn->info = new;
	  return new;
	}
      else 
	{
	  zlog_info("Z: Alarm ! LSDB RT contains an LSA with the same ID");
	  route_unlock_node(rn);
	  return NULL;
	}
      */

      rn = route_node_get (lsdb->rt, &p);

      if (rn->info != NULL)
	{
	  lsa = rn->info;
	  route_unlock_node (rn);

	  /* Free old LSA data. */
	  ospf_lsa_data_free (lsa->data);

	  /* Set new LSA data. */
	  lsa->ts = new->ts;
	  lsa->originated = new->originated;

/*	  lsa->data = ospf_lsa_data_dup (new->data);
*/
          lsa->data = new->data;
          ospf_ls_retransmit_delete_nbr_all(new);
	  new->data = NULL;
          ospf_lsa_free(new);

          if (lsa->refresh_list)
	    ospf_refresher_unregister_lsa (lsa);

          zlog_info("Z: ospf_lsa_free() in ospf_lsdb_add().3: %x", new);
	}
      else
	{
	  rn->info = new;

	  lsa = new;
	}
/*      return lsa; */
    }
     
  if (lsa == NULL)
    zlog_info ("Z: ospf_lsdb_add(): We had a problem with LSA installation");
  else
    {
      lsdb->count++;
      if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
	lsdb->count_self++;
    }

  zlog_info ("Z: ospf_lsdb_add():Stop");

/*  return new; */

  return lsa;
}

void
ospf_lsdb_delete (struct ospf_lsdb *lsdb, struct ospf_lsa *lsa)
{
  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_delete():Hey, your LSDB is none!");
      return;
    }

  if (lsa == NULL)
    {
      zlog_info ("Z: ospf_lsdb_delete():Nothing to delete, hah!");
      return;
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) && lsdb->hash) 
    hash_pull (lsdb->hash, lsa);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_LIST) && lsdb->list) 
    list_delete_by_val (lsdb->list, lsa);

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT) && lsdb->rt)
    {
      struct route_node *rn;
      struct prefix p;

      get_lsa_prefix (lsa, &p);
      rn = route_node_lookup (lsdb->rt, &p);
      rn->info = NULL;
      route_unlock_node (rn);
      route_unlock_node (rn);
    }

  lsdb->count--;

  if (CHECK_FLAG (lsa->flags, OSPF_LSA_SELF))
    lsdb->count_self--;
}

int
find_lsa (struct ospf_lsa *lsa1, void *v, int i)
{
  struct ospf_lsa *lsa2 = (struct ospf_lsa *) v;

  if (lsa1 == NULL)
    return 0;

  if (lsa2 == NULL)
    return 0;

  if (lsa1->data->id.s_addr == lsa2->data->id.s_addr && 
      lsa1->data->adv_router.s_addr == lsa2->data->adv_router.s_addr)
    return 1;

  return 0;
}


struct ospf_lsa *
ospf_lsdb_lookup (struct ospf_lsdb *lsdb, struct in_addr rid,
		  struct in_addr adv)
{
  struct ospf_lsa *lsa;
  struct ospf_lsa *found = NULL;

  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_lookup():Hey, your LSDB is none!");
      return NULL;
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) ||
      CHECK_FLAG (lsdb->flags, OSPF_LSDB_LIST))
    {
      lsa = ospf_lsa_new ();
      lsa->data = ospf_lsa_data_new (sizeof (struct lsa_header));

      lsa->data->id.s_addr = rid.s_addr;
      lsa->data->adv_router.s_addr = adv.s_addr;
    
      if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_HASH) && lsdb->hash) 
	found = hash_search (lsdb->hash, lsa);
      else
	found = ospf_lsdb_iterator (lsdb, lsa, 0, find_lsa);

      ospf_lsa_free (lsa);
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT))
    {
      struct route_node *rn;
      struct prefix p;

      id_to_prefix (rid, &p);
      rn = route_node_lookup (lsdb->rt, &p);
      if (rn)
	{
	  found = rn->info;
	  route_unlock_node (rn);
	}
      else
	found = NULL;
    }

  return found;
}

int
find_by_id (struct ospf_lsa *lsa, void *v, int i)
{
  if (lsa == NULL)
    return 0;

  if (IPV4_ADDR_SAME (&lsa->data->id, v))
    return 1;

  return 0;
}

struct ospf_lsa *
ospf_lsdb_lookup_by_id (struct ospf_lsdb *lsdb, struct in_addr lsid)
{
  struct ospf_lsa *found;

  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_lookup_by_id():Hey, your LSDB is none!");
      return NULL;
    }

  if (CHECK_FLAG (lsdb->flags, OSPF_LSDB_RT) && lsdb->rt) 
    {
      struct route_node *rn;
      struct prefix p;

      id_to_prefix (lsid, &p);
      rn = route_node_lookup (lsdb->rt, &p);
      if (rn)
	{
	  found = rn->info;
	  route_unlock_node (rn);
	}
      else
	found = NULL;
    }
  else
    found = ospf_lsdb_iterator (lsdb, &lsid, 0, find_by_id);

  return found;
}

struct ospf_lsa *
ospf_lsdb_lookup_by_header (struct ospf_lsdb *lsdb, struct ospf_lsa *lsa)
{
  if (lsdb == NULL)
    {
      zlog_info ("Z: ospf_lsdb_lookup_by_header():Hey, your LSDB is none!");
      return NULL;
    }

  if (lsa == NULL)
    {
      zlog_info ("Z: ospf_lsdb_lookup_by_header():Nothing to look for!");
      return NULL;
    }

  return ospf_lsdb_lookup (lsdb, lsa->data->id, lsa->data->adv_router);
}
