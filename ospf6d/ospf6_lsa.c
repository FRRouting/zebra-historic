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
  "PtoP",
  "Transit",
  "Stub",
  "virtual",
  NULL
};

char *print_lsahdr (struct lsa_hdr *lsh)
{
  static char buf[256], tmp[64];

  strncpy (tmp, inet_ntoa (*(struct in_addr *)&lsh->lsh_advrtr), sizeof (tmp));
  sprintf (buf, "LS type[(%s)] LS id[%lu] AdvRtr[%s] Len[%#x]",
	   lstype_name[typeindex(lsh->lsh_type)],
	   ntohl (lsh->lsh_id),
	   inet_ntoa (*(struct in_addr *)&lsh->lsh_advrtr),
	   ntohs (lsh->lsh_len));
  return buf;
}

struct lsa_hdr *
malloc_lsa (struct lsa_hdr *lsh)
{
  struct lsa_hdr *retval;
  retval = (struct lsa_hdr *)XMALLOC(MTYPE_OSPF_LSA, ntohs (lsh->lsh_len));
  bzero (retval, ntohs (lsh->lsh_len));
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Allocate LSA Body(%#x[%#x]) for %s\n", retval, ntohs (lsh->lsh_len),
       print_lsahdr (lsh));
#endif
  return retval;
}

void
free_lsa (struct lsa_hdr *lsh)
{
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Free LSA Body(%#x) for %s\n", lsh, print_lsahdr (lsh));
#endif
  XFREE (MTYPE_OSPF_LSA, lsh);
  return;
}

struct lsa_internal *
malloc_lsa_internal_hdr (struct lsa_hdr *lsh)
{
  struct lsa_internal *retval;
  retval = (struct lsa_internal *)
    XMALLOC (MTYPE_OSPF_LSA, sizeof (struct lsa_internal));
  bzero (retval, sizeof (struct lsa_internal));
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Allocate LSA Internal Hdr(%#x[%#x]) for %s\n", retval,
       sizeof (struct lsa_internal), print_lsahdr (lsh));
#endif
  return retval;
}

void
free_lsa_internal_hdr (struct lsa_internal *lsi)
{
  if (lsi->expire)
    {
      thread_cancel (lsi->expire);
      lsi->expire = (struct thread *)NULL;
    }
  if (lsi->refresh)
    {
      thread_cancel (lsi->refresh);
      lsi->refresh = (struct thread *)NULL;
    }
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Free LSA Internal Hdr(%#x) for %s\n", lsi, print_lsahdr (lsi->lsh));
#endif
  XFREE (MTYPE_OSPF_LSA, lsi);
  return;
}

/* This function may be seme as list_delete_all_node. */
int
list_clear_all (list l)
{
  listnode n;

  for (n = listhead (l); n; n = listhead (l))
    {
      list_delete_by_val (l, getdata (n));
    }
  return 0;
}

int
lsa_list_clear_all (list l)
{
  listnode n;

  for (n = listhead (l); n; n = listhead (l))
    {
      free_lsa_internal_hdr ((struct lsa_internal *) getdata (n));
      list_delete_by_val (l, getdata (n));
    }
  return 0;
}

int
prepare_neighbor_lsdb (struct neighbor *nbp)
{
  int i, type;
  struct area *area;
  struct lsa_internal *lsip;
  listnode n;

  assert (nbp);

#ifdef DEBUG_OSPF
  log ("PREPARE for %s\n", inet_ntoa (nbp->rtr_id));
#endif

  list_cleared_of_lsa (nbp);

  area = nbp->interface->area;
  assert (area);

  for (type = 0; type < AREALSTYPESIZE; type++)
    {
      for (i = 0; i < HASHVAL; i++)
	{
	  for (n = listhead (area->lsdb[type][i]); n; nextnode (n))
	    {
	      lsip = (struct lsa_internal *) getdata (n);
#ifdef DEBUG_OSPF
	      log ("Attache %s to Summary of %s\n", print_lsahdr (lsip->lsh),
		   inet_ntoa (nbp->rtr_id));
#endif
	      list_add_node (nbp->summarylist, lsip);
	    }
	}
    }

  for (n = listhead (nbp->interface->linklocal_lsa); n; nextnode (n))
    {
      lsip = (struct lsa_internal *) getdata (n);
      list_add_node (nbp->summarylist, lsip);
    }
  return 0;
}

int
lsi_delete_from_list (struct lsa_internal *lsi, list l)
{
  free_lsa (lsi->lsh);
  free_lsa_internal_hdr (lsi);
  list_delete_by_val (l, lsi);
  return 0;
}

int
lsi_delete (struct lsa_internal *lsi)
{
  assert (lsi && lsi->lsh);

  if (lsi->expire)
    {
      thread_cancel (lsi->expire);
      lsi->expire = (struct thread *)NULL;
    }
  if (lsi->refresh)
    {
      thread_cancel (lsi->refresh);
      lsi->refresh = (struct thread *)NULL;
    }
  switch (GET_LSASCOPE (lsi->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      assert (lsi->iface);
      lsi_delete_from_list (lsi, lsi->iface->linklocal_lsa);
      break;
    case SCOPE_AREA:
      assert (lsi->area);
      lsi_delete_from_list (lsi, lsi->area->lsdb[typeindex(lsi->lsh->lsh_type)]
			    [hash(lsi->lsh->lsh_id)]);
      break;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      log ("Not Reached!?\n");
      break;
    }

  return 0;
}

int
expire_lsa_age (struct thread *thread)
{
  struct lsa_internal *lsi;

  lsi = (struct lsa_internal *)THREAD_ARG  (thread);
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Expire lsi[%#x]\n", lsi);
#endif
  assert (lsi && lsi->lsh && lsi->area);

  lsi->expire = (struct thread *)NULL;

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Expire: %s\n", print_lsahdr (lsi->lsh));
#endif

  lsi_delete (lsi);

  return 0;
}

int
calc_lsa_age_internal (struct lsa_internal *lsi)
{
  struct timeval now;

  assert (lsi && lsi->lsh);

#ifdef DEBUG_LSA_PTR
  /*  log ("LSAPTR: Calucurate LSA age for internal[%#x]\n", lsi); */
#endif

  gettimeofday (&now, (struct timezone *)NULL);
  lsi->birth = now.tv_sec - ntohs (lsi->lsh->lsh_age);
  if (lsi->expire)
    {
      thread_cancel (lsi->expire);
      lsi->expire = NULL;
    }
  lsi->expire = thread_add_timer (master, expire_lsa_age, lsi,
				  lsi->birth + MAXAGE - now.tv_sec);
  return 0;
}

/* return 1 if MIN_LS_INTERVAL have past, else 0 */
int
past_min_ls_interval (struct lsa_internal *lsi)
{
  struct timeval now;

  assert (lsi && lsi->lsh);
  gettimeofday (&now, (struct timezone *)NULL);

  if (now.tv_sec - lsi->birth < MIN_LS_INTERVAL)
    return 0;

  return 1;
}

u_short
calc_lsa_age_external (struct lsa_internal *lsi)
{
  struct timeval now;
  int age;

  gettimeofday (&now, (struct timezone *)NULL);
  age = now.tv_sec - lsi->birth;
  if (age > MAXAGE)
    return MAXAGE;
  else
    return age;
}

/* In case to make LSA that's body is empty. This is used by DD and LSACK. */
struct lsa_internal *
make_lsa_hdr_internal (struct lsa_hdr *lsa, struct neighbor *from)
{
  struct lsa_internal *lsi;

  lsi = malloc_lsa_internal_hdr (lsa);
  lsi->lsh = lsa;

  lsi->from = from;
  lsi->iface = from->interface;
  lsi->area = from->interface->area;
  lsi->refresh = (struct thread *)NULL;
  calc_lsa_age_internal (lsi);

  return lsi;
}

struct lsa_internal *
make_lsa_internal (struct lsa_hdr *lsa, struct neighbor *from)
{
  struct lsa_internal *lsi;
  struct lsa_hdr *lsh;

  lsh = malloc_lsa (lsa);
  bcopy (lsa, lsh, ntohs (lsa->lsh_len));

  lsi= malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = from;
  lsi->iface = from->interface;
  lsi->area = from->interface->area;
  lsi->refresh = (struct thread *)NULL;
  calc_lsa_age_internal (lsi);

  return lsi;
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
	newp->area->spf_calc =
	  thread_add_event (master, spf_calculation, newp->area, 0);
      if (newp->area->route_calc == (struct thread *)NULL)
	newp->area->route_calc = 
	  thread_add_event (master, routing_table_calculation, newp->area, 0);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      if (newp->area->route_calc == (struct thread *)NULL)
	newp->area->route_calc = 
	  thread_add_event (master, routing_table_calculation, newp->area, 0);
      break;
    default:
      break;
    }

  return 0;
}

int
lsa_install (struct lsa_internal **newpp)
{
  struct lsa_internal *oldp, *newp;
  struct lsa_hdr *newlsh;
  struct timeval now;

  assert (newpp && *newpp);

#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Installing LSA[%s]\n", print_lsahdr ((*newpp)->lsh));
#endif

  newp = *newpp;
  newlsh = newp->lsh;

  gettimeofday (&now, (struct timezone *)NULL);

  /* check old LSA and if exists, we must reuse lsi_internal structure because of
     possibility that this LSA have atached to some-neighbor's LS list already */
  oldp = lsa_lookup (newlsh->lsh_type, newlsh->lsh_id, newlsh->lsh_advrtr,
		     newp->area, newp->iface);
  if (oldp)
    {
      assert (oldp->lsh);
#ifdef DEBUG_LSA_PTR
      log ("LSAPTR: Find Old One[%#x], Swap.\n", oldp);
#endif
      free_lsa (oldp->lsh);

      oldp->lsh = newp->lsh;
#ifdef DEBUG_LSA_PTR
      log ("LSAPTR: Attach LSA body[%#x] to internal[%#x] in lsa_install()\n",
	   newp->lsh, oldp);
#endif
      oldp->from = newp->from;
      oldp->iface = newp->iface;
      oldp->area = newp->area;

      /* Must recalcurate ages because timers have set with argument newp. */
      /* Expire, Age */
      if (oldp->expire)
	{
	  thread_cancel (oldp->expire);
	  oldp->expire = (struct thread *)NULL;
	}
      newp->lsh->lsh_age = htons (calc_lsa_age_external (newp));
      calc_lsa_age_internal (oldp);

      /* Refresh */
      if (oldp->refresh)
	{
	  thread_cancel (oldp->refresh);
	  oldp->refresh = (struct thread *)NULL;
	}
      if (newp->refresh)
	{
	  oldp->refresh = thread_add_timer (master, lsa_refresh, oldp,
					    newp->refresh->u.sands.tv_sec - now.tv_sec);
	}

      free_lsa_internal_hdr (newp);
#ifdef DEBUG_LSA_PTR
      log ("LSAPTR: LSA renewaled!\n");
#endif

      /* reset caller's newp */
      *newpp = oldp;
      newp = oldp;
    }
  else
    {
      switch (GET_LSASCOPE (newp->lsh->lsh_type))
	{
	case SCOPE_LINKLOCAL:
	  assert (newp->iface);
	  list_add_node (newp->iface->linklocal_lsa, newp);
	  break;
	case SCOPE_AREA:
	  assert (newp->area);
	  list_add_node
	    (newp->area->lsdb[typeindex (newp->lsh->lsh_type)][hash (newp->lsh->lsh_id)],
	     newp);
	  break;
	case SCOPE_AS:
	  break;
	case SCOPE_RESERVED:
	default:
	  log ("Not Reached!?\n");
	  break;
	}

#ifdef DEBUG_LSA_PTR
      log ("LSAPTR: new LSA[ihdr:%#x][body:%#x] Installed!\n",
	   newp, newp->lsh);
#endif
    }

  newp->installed = now.tv_sec;

  lsa_change (newp);

  return 0;
}

/* check which is more recent. if a is more recent, return -1
   if the same, return 0; otherwise(b is more recent), return 1 */
int
which_is_more_recent (struct lsa_internal *a, struct lsa_internal *b)
{
  int32_t seqnuma, seqnumb;
  int ab, ba;

  assert (a && a->lsh);
  assert (b && b->lsh);
  assert (lsa_issame (a->lsh, b->lsh));

  seqnuma = ntohl (a->lsh->lsh_seqnum) - (int32_t)INITIAL_SEQUENCE_NUMBER;
  seqnumb = ntohl (b->lsh->lsh_seqnum) - (int32_t)INITIAL_SEQUENCE_NUMBER;

  /* XXX, Care about Wrapping */
  if (seqnuma > seqnumb)
    {
#ifdef DEBUG_OSPF
      log ("Recent is decided by SeqNum.\n");
#endif
      return -1;
    }
  else if (seqnuma < seqnumb)
    {
#ifdef DEBUG_OSPF
      log ("Recent is decided by SeqNum.\n");
#endif
      return 1;
    }
  else
    {
      /* XXX Checksum */

      if (ntohs (a->lsh->lsh_age) == MAXAGE
	  && ntohs (b->lsh->lsh_age) != MAXAGE)
	{
#ifdef DEBUG_OSPF
	  log ("Recent is decided by MaxAge.\n");
#endif
	  return -1;
	}
      else if (ntohs (a->lsh->lsh_age) != MAXAGE
	       && ntohs (b->lsh->lsh_age) == MAXAGE)
	{
#ifdef DEBUG_OSPF
	  log ("Recent is decided by MaxAge.\n");
#endif
	  return 1;
	}
      else
	{
	  ab = calc_lsa_age_external (a) - calc_lsa_age_external (b);
	  ba = calc_lsa_age_external (b) - calc_lsa_age_external (a);
	  if (ab > MAX_AGE_DIFF)
	    {
#ifdef DEBUG_OSPF
	      log ("Recent is decided by Age diff(%d).\n", ab);
#endif
	      return 1;
	    }
	  else if (ba > MAX_AGE_DIFF)
	    {
#ifdef DEBUG_OSPF
	      log ("Recent is decided by Age diff(%d).\n", ba);
#endif
	      return -1;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
}

list
lsa_lookup_by_advrtr (u_int16_t lsa_type, u_int32_t advrtr, struct area *area)
{
  int i;
  struct lsa_internal *lsi;
  listnode n;
  list returnlist;

  returnlist = list_init ();
  for (i = 0; i < HASHVAL; i++)
    {
      for (n = listhead (area->lsdb[typeindex (lsa_type)][i]); n; nextnode (n))
	{
	  lsi = (struct lsa_internal *)getdata (n);
	  if (lsi->lsh->lsh_advrtr == advrtr)
	    list_add_node (returnlist, lsi);
	}
    }
  return returnlist;
}

/* LSA lookup (Argument's byte order is Network Byte order) */
struct lsa_internal *
lsa_lookup (u_int16_t lsa_type, u_int32_t lsid, u_int32_t advrtr,
	    struct area *area, struct ospf_if *iface)
{
  listnode n;
  struct lsa_internal *lsi;

  switch (GET_LSASCOPE (lsa_type))
    {
    case SCOPE_LINKLOCAL:
      assert (iface);
      for (n = listhead (iface->linklocal_lsa); n; nextnode (n))
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
      log ("Not Reached!?\n");
      break;
    }
}

int
lsatype_ok (struct lsa_hdr *lsh)
{
  switch (ntohs (lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
    case LST_LINK_LSA:
    case LST_INTRA_AREA_PREFIX_LSA:
      return 1;
    default:
      return 0;
    }
}

/* check validity and put lsa in reqestlist if needed.
   this function should return -1 if stub area and 
   if as-external-lsa contained. this is not yet */
int
check_neighbor_lsdb (struct iovec *iov, struct neighbor *nbp)
{
  int i, already;
  struct lsa_internal *have, *received, *lsi;
  listnode n;
  struct lsa_hdr *lshp;

  have = received = (struct lsa_internal *)NULL;

  if (iov->iov_base == NULL)
    return 0;

  for (i = 0; iov[i].iov_base; i++)
    {
      lshp = (struct lsa_hdr *)iov[i].iov_base;
#ifdef DEBUG_DATABASE_DESCRIPTION
      log ("DD: %s\n", print_lsahdr (lshp));
#endif

      if (!lsatype_ok (lshp))
	return -1;

      if (received)
	{
	  if (received->expire)
	    {
	      thread_cancel (received->expire);
	      received->expire = (struct thread *)NULL;
	    }
	  if (received->refresh)
	    {
	      thread_cancel (received->refresh);
	      received->refresh = (struct thread *)NULL;
	    }
	  free_lsa (received->lsh);
	  free_lsa_internal_hdr (received);
	}
      received = make_lsa_hdr_internal (lshp, nbp);
      have = lsa_lookup (lshp->lsh_type, lshp->lsh_id,
			 lshp->lsh_advrtr, nbp->interface->area, nbp->interface);
      if (have)
	{
	  if (which_is_more_recent (received, have) >= 0)
	    continue;
	}

      /* Search this in case already in Requestlist */
      already = 0;
      for (n = listhead (nbp->requestlist); n; nextnode (n))
	{
	  lsi = getdata (n);
	  if (lsa_issame (received->lsh, lsi->lsh))
	    {
	      already++;
	      break;
	    }
	}

      if (already)
	{
#ifdef DEBUG_OSPF
	  log ("Already Attached requestlist of %s:[%s]\n", inet_ntoa (nbp->rtr_id),
	       print_lsahdr (received->lsh));
#endif
	  continue;
	}
      else
	{
	  /* the LSA we have just received is newer.
	     attach requestlist. */
	  list_add_node (nbp->requestlist, received);
#ifdef DEBUG_OSPF
	  log ("Attache requestlist of %s:[%s]\n", inet_ntoa (nbp->rtr_id),
	       print_lsahdr (received->lsh));
#endif
	  received = (struct lsa_internal *)NULL;
	}
    }
  return 0;
}

int
proceed_summarylist (struct neighbor *nbp)
{
  int size;
  struct lsa_internal *p, *q;
  listnode n, m;

  for (n = listhead (nbp->dd_retrans), m = listhead (nbp->summarylist);
       n && m; nextnode (n), nextnode (m))
    {
      p = (struct lsa_internal *) getdata (n);
      q = (struct lsa_internal *) getdata (m);
      assert (p == q);
      list_delete_by_val (nbp->dd_retrans, p);
      list_delete_by_val (nbp->summarylist, q);
    }

  size = OSPFV3HDRLEN + sizeof (struct database_description);
  for (n = listhead(nbp->summarylist); n; nextnode (n))
    {
      p = (struct lsa_internal *)getdata (n);
      if (DEFAULT_INTERFACE_MTU - size <= sizeof (struct lsa_hdr))
	break;
      list_add_node (nbp->dd_retrans, p);
      size += sizeof (struct lsa_hdr);
    }

  if (!listcount (nbp->summarylist))
    {
      DD_MBIT_CLEAR (nbp->dd_bits);
    }

  return 0;
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

int
lsa_refresh (struct thread *thread)
{
  struct lsa_internal *lsi;

  assert (thread);
  lsi = (struct lsa_internal *)THREAD_ARG  (thread);
  assert (lsi && lsi->lsh);

  /* This flag will be used in originating_lsa() */
  lsi->refresh = THIS_IS_REFRESH;

  if (lsi->expire)
    {
      thread_cancel (lsi->expire);
      lsi->expire = (struct thread *)NULL;
    }

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Refresh: %s\n", print_lsahdr (lsi->lsh));
#endif

  switch (ntohs (lsi->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      assert (lsi->area);
      construct_router_lsa (lsi->area);
      break;
    case LST_NETWORK_LSA:
      assert (lsi->iface);
      construct_network_lsa (lsi->iface);
      break;
    case LST_LINK_LSA:
      assert (lsi->iface);
      construct_link_lsa (lsi->iface);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      assert (lsi->iface);
      construct_intra_prefix_lsa (lsi->iface);
      break;
    default:
      break;
    }
  return 0;
}

int
originating_lsa (struct lsa_internal **newpp)
{
  struct lsa_internal *oldp;
  struct lsa_internal *newp;

  newp = *newpp;

  oldp = lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id, newp->lsh->lsh_advrtr,
		    newp->area, newp->iface);
  if (oldp && oldp->refresh != THIS_IS_REFRESH)
    {
      if (newp->lsh->lsh_len == oldp->lsh->lsh_len &&
	  !bcmp (newp->lsh + 1, oldp->lsh + 1, ntohs (newp->lsh->lsh_len)))
	{
#ifdef DEBUG_OSPF
	  log ("LSAEVENT: LSA[%s] body No change, Not Installed.\n", 
	       print_lsahdr (newp->lsh));
#endif
	  free_lsa (newp->lsh);
	  free_lsa_internal_hdr (newp);
	  return;
	}
    }

  if (oldp && oldp->refresh == THIS_IS_REFRESH)
    oldp->refresh = (struct thread *)NULL;

  lsa_install (newpp);
  newp = *newpp;
  lsa_flood (newp);
  return;
}

/* xxx, We don't support sending multiple (seperate) Router-LSA yet,
   so Link State ID field of Router-LSA will be always the same */
int
construct_router_lsa (struct area *area)
{
  list described_link;
  listnode n, m;
  struct ospf_if *iface;
  struct neighbor *nbp;
  int space;
  char *lsa;
  struct lsa_hdr *lshp;
  struct lsa_internal *lsi;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  /* check needed space for LSA by looking up ospf_ifs.
     ospf_if to be described are collected. */
  described_link = list_init ();
  for (n = listhead (area->ospf_if_list);
       n;
       nextnode (n))
    {
      iface = (struct ospf_if *)getdata (n);
      assert (iface);

      if (iface->state <= IFS_LOOPBACK)
	continue;

      for (m = listhead (iface->nb_list);
	   m;
	   nextnode (m))
	{
	  nbp = (struct neighbor *)getdata (m);
	  assert (nbp);

	  if (nbp->state == NBS_FULL)
	    {
	      list_add_node (described_link, iface);
	      break;
	    }
	}
    }

  space = sizeof (struct lsa_hdr) + sizeof (struct router_lsa)
    + (sizeof (struct router_lsd) * listcount (described_link));

  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Alloc LSA body[%#x] for our Router-LSA\n", lsa);
#endif
  bzero (lsa, space);

  lshp = (struct lsa_hdr *) lsa;
  /* age later (after checksum) */
  lshp->lsh_age = 0;
  lshp->lsh_type = htons (LST_ROUTER_LSA);
  lshp->lsh_id = htonl (MY_ROUTER_LSA_ID);
  lshp->lsh_advrtr = id_val (area->ospf->router_id);
  lshp->lsh_seqnum = htonl((area->router_lsa_seqnum)++);
  /* checksum later */
  lshp->lsh_len = htons (space);

  rlsap = (struct router_lsa *) ((char *)lshp + sizeof (struct lsa_hdr));
  V3OPT_SET (rlsap->rlsa_options, V3OPT_V6);
  if (V3OPT_ISSET (area->options, V3OPT_E))
    V3OPT_SET (rlsap->rlsa_options, V3OPT_E);
  V3OPT_SET (rlsap->rlsa_options, V3OPT_R);

  /* XXX not yet */
  ROUTER_LSA_CLEAR (rlsap, ROUTER_LSA_BIT_W);
  ROUTER_LSA_CLEAR (rlsap, ROUTER_LSA_BIT_V);
  ROUTER_LSA_CLEAR (rlsap, ROUTER_LSA_BIT_E);
  ROUTER_LSA_CLEAR (rlsap, ROUTER_LSA_BIT_B);

  rlsdp = (struct router_lsd *) ((char *)rlsap + sizeof (struct router_lsa));
  for (n = listhead (described_link); n; nextnode (n))
    {
      iface = (struct ospf_if *)getdata (n);
      assert (iface);

      if (IS_IFTYPE_PTOP (iface))
	{
	  assert (listcount (iface->nb_list) == 1);
	  nbp = (struct neighbor *)getdata (listhead (iface->nb_list));
	  assert (nbp);
	  assert (nbp->state == NBS_FULL);

	  rlsdp->rlsd_type = LSDT_POINTTOPOINT;
	  rlsdp->rlsd_metric = htons (iface->cost);
	  rlsdp->rlsd_interface_id = iface->ifid;
	  rlsdp->rlsd_neighbor_interface_id = nbp->ifid;
	  rlsdp->rlsd_neighbor_router_id = id_val (nbp->rtr_id);

	  rlsdp++;
	}
      else if (IS_IFTYPE_BROADCAST (iface))
	{
	  if (iface->state == IFS_DR)
	    {
	      rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
	      rlsdp->rlsd_metric = htons (iface->cost);
	      rlsdp->rlsd_interface_id = iface->ifid;
	      rlsdp->rlsd_neighbor_interface_id = iface->ifid;
	      rlsdp->rlsd_neighbor_router_id = id_val (area->ospf->router_id);
	      rlsdp++;
	    }
	  else
	    {
	      rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
	      rlsdp->rlsd_metric = htons (iface->cost);
	      rlsdp->rlsd_interface_id = iface->ifid;
	      nbp = nb_lookup_by_nb_id (*(struct in_addr *)&iface->dr, iface->nb_list);
	      assert (nbp);
	      rlsdp->rlsd_neighbor_interface_id = nbp->ifid;
	      /* note, ifid of neighbor is stored in network byte order */
	      rlsdp->rlsd_neighbor_router_id = id_val (iface->dr);
	      rlsdp++;
	    }
	}
      else
	{
	  log ("BUG! Not Supported Type of Interface[%s] in construct_router_lsa()\n",
	       iface->ifname);
	  exit (-1);
	}
    }

  /* XXX! Calculate Checksum! */

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Construct Router-LSA\n");
#endif

  /* Router-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lshp);
  lsi->lsh = lshp;

  lsi->from = (struct neighbor *)NULL;
  lsi->iface = (struct ospf_if *)NULL;
  lsi->area = area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int
construct_network_lsa (struct ospf_if *iface)
{
  struct neighbor *nbp;
  listnode n;
  int attached_rtr;
  int space;
  struct lsa_hdr *lshp;
  char *lsa;
  rtr_id_t *p;
  struct network_lsa *nlsap;
  struct lsa_internal *lsi;

  assert (iface->state == IFS_DR);

  /* Is this link Transit ? */
  attached_rtr = 0;
  for (n = listhead (iface->nb_list); n; nextnode (n))
    {
      nbp = getdata (n);
      if (nbp->state == NBS_FULL)
	attached_rtr++;
    }

  if (attached_rtr == 0)
    return 0;

  space = sizeof (struct lsa_hdr) + sizeof (struct network_lsa)
    + sizeof (rtr_id_t) * (attached_rtr + 1);
  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Alloc LSA body[%#x] for our Network-LSA\n", lsa);
#endif
  bzero (lsa, space);

  lshp = (struct lsa_hdr *) lsa;
  /* age later (after checksum) */
  lshp->lsh_age = 0;
  lshp->lsh_type = htons (LST_NETWORK_LSA);
  lshp->lsh_id = iface->ifid;
#ifdef DEBUG_OSPF
  log ("Network-LSA LS-ID: %s\n", inet_ntoa (*(struct in_addr *)&iface->ifid));
#endif
  lshp->lsh_advrtr = id_val (iface->area->ospf->router_id);
  lshp->lsh_seqnum = htonl((iface->area->network_lsa_seqnum)++);
  /* checksum later */
  lshp->lsh_len = htons (space);

  nlsap = (struct network_lsa *)(lshp + 1);
  nlsap->nlsa_options[0] = iface->area->options[0];
  nlsap->nlsa_options[1] = iface->area->options[1];
  nlsap->nlsa_options[2] = iface->area->options[2];

  p = (rtr_id_t *) (nlsap + 1);

  for (n = listhead (iface->nb_list); n; nextnode (n))
    {
      nbp = getdata (n);
      if (nbp->state == NBS_FULL)
	{
	  id_val (*p) = id_val (nbp->rtr_id);
	  p++;
	}
    }
  id_val (*p) = id_val (iface->area->ospf->router_id);

  /* XXX! Calculate Checksum! */

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Construct Network-LSA\n");
#endif

  /* Network-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lshp);
  lsi->lsh = lshp;

  lsi->from = (struct neighbor *)NULL;
  lsi->iface = iface;
  lsi->area = iface->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int
construct_link_lsa (struct ospf_if *iface)
{
  int space;
  listnode i;
  int j;
  char *lsa;
  struct lsa_hdr *lshp;
  struct link_lsa *llsap;
  struct prefix *prefix;
  struct network *netp;
  struct in6_addr *linklocal, netmask, *network_prefix;
  struct lsa_internal *lsi;

  space = 0;
  linklocal = (struct in6_addr *)NULL;
  for (i = listhead (iface->networks); i; nextnode (i))
    {
      netp = getdata (i);
      if (IN6_IS_ADDR_LINKLOCAL (&netp->address))
	{
	  linklocal = &netp->address;
	  continue;
	}
      space += PREFIX_SPACE (netp->prefixlen) + sizeof (struct prefix);
    }
  space += sizeof (struct link_lsa) + sizeof (struct lsa_hdr);
  assert (linklocal);

  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Alloc LSA body[%#x] for our Link-LSA\n", lsa);
#endif
  bzero (lsa, space);
  lshp = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lshp->lsh_age = 0;
  lshp->lsh_type = htons (LST_LINK_LSA);
  lshp->lsh_id = iface->ifid;
#ifdef DEBUG_OSPF
  log ("Link-LSA LS-ID: %s\n", inet_ntoa (*(struct in_addr *)&iface->ifid));
#endif
  lshp->lsh_advrtr = id_val (iface->area->ospf->router_id);
  lshp->lsh_seqnum = htonl((iface->area->link_lsa_seqnum)++);
  /* checksum later */
  lshp->lsh_len = htons (space);

  llsap = (struct link_lsa *)(lshp + 1);
  llsap->llsa_rtr_pri = iface->rtr_pri;
  llsap->llsa_options[0] = iface->area->options[0];
  llsap->llsa_options[1] = iface->area->options[1];
  llsap->llsa_options[2] = iface->area->options[2];
  bcopy (linklocal, &llsap->llsa_linklocal, sizeof (llsap->llsa_linklocal));
  llsap->llsa_prefix_num = htonl (listcount (iface->networks) - 1); /* XXX */

  prefix = (struct prefix *)(llsap + 1);
  for (i = listhead (iface->networks); i; nextnode (i))
    {
      netp = getdata (i);
      if (IN6_IS_ADDR_LINKLOCAL (&netp->address))
	{
	  continue;
	}

      prefix->prefix_length = netp->prefixlen;
      /* XXX prefix->prefix_options */

      network_prefix = (struct in6_addr *)(prefix + 1);
      prefix2mask (netp->prefixlen, (void *)&netmask, sizeof (netmask));
      for (j = 0; j < PREFIX_SPACE (netp->prefixlen); j++)
	{
	  network_prefix->s6_addr32[j] =
	    netp->address.s6_addr32[j] & netmask.s6_addr32[j];
	}
      prefix = NEXT_PREFIX (prefix);
    }

  /* XXX! Calculate Checksum! */

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Construct Link-LSA\n");
#endif

  /* Link-LSA is now constructed.
     store this in appropriate place (Ospf_If Data Structure) */
  lsi = malloc_lsa_internal_hdr (lshp);
  lsi->lsh = lshp;

  lsi->from = (struct neighbor *)NULL;
  lsi->iface = iface;
  lsi->area = iface->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int construct_intra_prefix_lsa (struct ospf_if *iface)
{
  int i, already, space, fullnbnum;
  char *lsa;
  struct neighbor *nbp;
  struct lsa_internal *lsi;
  struct link_lsa *linklsa;
  struct prefix *p, *q;
  struct lsa_hdr *lshp;
  struct intra_area_prefix_lsa *intra_prefix_lsa;
  listnode n, m;
  list prefix_collection = list_init ();

  /* Count Full Neighbor */
  fullnbnum = 0;
  for (n = listhead (iface->nb_list); n; nextnode (n))
    {
      nbp = (struct neighbor *)getdata (n);
      if (nbp->state == NBS_FULL)
	fullnbnum++;
    }

  if (iface->state != IFS_DR && fullnbnum != 0)
    {
      /* Not Stub Network and Not DR. The LSA of this network will be
	 advertised by DR of this network. */
      return;
    }

  if (iface->state == IFS_DR)   /* I'm DR */
    {
      for (n = listhead (iface->nb_list); n; nextnode (n))
	{
	  nbp = getdata (n);
	  if (nbp->state == NBS_FULL)
	    {
	      lsi = lsa_lookup (htons (LST_LINK_LSA), nbp->ifid, id_val (nbp->rtr_id),
				iface->area, iface);
	      if (!lsi)
		{
#ifdef DEBUG_OSPF
		  log ("WARN: Full but Link-LSA not found: %s\n",
		       inet_ntoa (nbp->rtr_id));
#endif
		  continue;
		}

	      linklsa = (struct link_lsa *)(lsi->lsh + 1);
	      p = (struct prefix *)(linklsa + 1);
	      for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
		   i++, p = NEXT_PREFIX (p))
		{
		  if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
		    {
		      log ("v4mapped address, don't include Intra-Area-Prefix-LSA\n");
		      continue;
		    }

		  already = 0;
		  for (m = listhead (prefix_collection); m; nextnode (m))
		    {
		      q = (struct prefix *)getdata (m);
		      if (bcmp (p, q, PREFIX_SIZE (p)) == 0)
			already++;
		    }
		  if (already == 0)
		    list_add_node (prefix_collection, p);
		}
	    }
	}
      
      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), iface->ifid,
			id_val (iface->area->ospf->router_id),
			iface->area, iface);
      if (!lsi)
	{
#ifdef DEBUG_OSPF
	  log ("WARN: Link-LSA of Myself not found\n");
#endif
	}
      else
	{
#ifdef DEBUG_OSPF
	  log ("My Link-LSA: [%s]\n", print_lsahdr (lsi->lsh));
#endif
	  linklsa = (struct link_lsa *)(lsi->lsh + 1);
	  p = (struct prefix *)(linklsa + 1);
	  for (i = 0; i < ntohl (linklsa->llsa_prefix_num); i++, p = NEXT_PREFIX (p))
	    {
	      if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
		{
		  log ("v4mapped address of mine, don't include Intra-Area-Prefix-LSA\n");
		  continue;
		}

	      already = 0;
	      for (m = listhead (prefix_collection); m; nextnode (m))
		{
		  q = (struct prefix *)getdata (m);
		  if (bcmp (p, q, PREFIX_SIZE (p)) == 0)
		    already++;
		}
	      if (already == 0)
		list_add_node (prefix_collection, p);
	    }
	}
    }
  else if (listcount (iface->nb_list) == 0)
    {
      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), iface->ifid,
			id_val (iface->area->ospf->router_id),
			iface->area, iface);
      if (!lsi)
	{
#ifdef DEBUG_OSPF
	  log ("WARN: Link-LSA of Myself not found\n");
#endif
	}
      else
	{
#ifdef DEBUG_OSPF
	  log ("My Link-LSA: [%s]\n", print_lsahdr (lsi->lsh));
#endif
	  linklsa = (struct link_lsa *)(lsi->lsh + 1);
	  p = (struct prefix *)(linklsa + 1);
	  for (i = 0; i < ntohl (linklsa->llsa_prefix_num); i++, p = NEXT_PREFIX (p))
	    {
	      if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
		{
		  log ("v4mapped address of mine, don't include Intra-Area-Prefix-LSA\n");
		  continue;
		}

	      already = 0;
	      for (m = listhead (prefix_collection); m; nextnode (m))
		{
		  q = (struct prefix *)getdata (m);
		  if (bcmp (p, q, PREFIX_SIZE (p)) == 0)
		    already++;
		}
	      if (already == 0)
		list_add_node (prefix_collection, p);
	    }
	}
    }
  else
    {
      return;
    }

  if (!listcount (prefix_collection))
    {
#ifdef DEBUG_OSPF
      log ("LSAEVENT: No Network Address, Don't Construct Intra-Area-Prefix-LSA\n");
#endif
      return 0;
    }

  /* check necessary space */
  space = 0;
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = (struct prefix *)getdata (n);
      space += PREFIX_SIZE (p);
    }
  space += sizeof (struct intra_area_prefix_lsa) + sizeof (struct lsa_hdr);

  /* construct instance of LSA */
  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
#ifdef DEBUG_LSA_PTR
  log ("LSAPTR: Alloc LSA body[%#x] for our Intra-Area-Prefix-LSA\n", lsa);
#endif
  bzero (lsa, space);
  lshp = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lshp->lsh_age = 0;
  lshp->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);

  if (fullnbnum)   /* For Transit Network */
    lshp->lsh_id = iface->ifid;
  else             /* For Stub Network */
    lshp->lsh_id = htonl (MY_ROUTER_LSA_ID);

#ifdef DEBUG_OSPF
  log ("Intra-Area-Prefix-LSA LS-ID: %s\n",
       inet_ntoa (*(struct in_addr *)&iface->ifid));
#endif
  lshp->lsh_advrtr = id_val (iface->area->ospf->router_id);
  lshp->lsh_seqnum = htonl((iface->area->intra_prefix_seqnum)++);
  /* checksum later */
  lshp->lsh_len = htons (space);

  intra_prefix_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  intra_prefix_lsa->intra_prefix_num = htons (listcount (prefix_collection));

  if (fullnbnum)
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = iface->ifid;
    }
  else
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = htonl (MY_ROUTER_LSA_ID);
    }

  intra_prefix_lsa->intra_prefix_refer_advrtr =
    id_val (iface->area->ospf->router_id);

  q = (struct prefix *)(intra_prefix_lsa + 1);
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = getdata (n);
      bcopy (p, q, PREFIX_SIZE (p));
      q = NEXT_PREFIX (q);
    }

  /* XXX! Calculate Checksum! */

#ifdef DEBUG_OSPF
  log ("LSAEVENT: Construct Intra-Area-Prefix-LSA\n");
#endif

  /* Intra-Area-Prefix-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lshp);
  lsi->lsh = lshp;
  
  lsi->from = (struct neighbor *)NULL;
  lsi->iface = iface;
  lsi->area = iface->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

/* RFC2328 section 13 */
int
lsa_receive (struct lsa_hdr *lshp, struct neighbor *from)
{
  struct lsa_internal *newp, *oldp, **ackp, *lsi;
  struct neighbor *nbp;
  struct ospf_if *iface;
  struct timeval now;
  listnode n, m, l;
  int i, onrequest, ismore_recent, onretrans, acknowledge, acktype;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;

  newp = oldp = (struct lsa_internal *)NULL;
  ismore_recent = 1;
  acknowledge = 0;

  for (ackp = from->direct_ack; *ackp; ackp++)
    ;

  /* (1) */
  /* XXX LSA Checksum */

  /* (2) */
  switch (ntohs (lshp->lsh_type))
    {
    case LST_ROUTER_LSA:
    case LST_NETWORK_LSA:
    case LST_LINK_LSA:
    case LST_INTRA_AREA_PREFIX_LSA:
      break;
    case LST_INTER_AREA_PREFIX_LSA:
    case LST_INTER_AREA_ROUTER_LSA:
    case LST_AS_EXTERNAL_LSA:
    default:
      log ("Unknown LSA Type: %#x, Ignore\n", ntohs (lshp->lsh_type));
      return -1;
    }

  /* (3) */
  /* XXX, Ebit Missmatch: AS-External-LSA */

  /* (4) */
  /* XXX, if MaxAge LSA and if we have no instance */

  gettimeofday (&now, (struct timezone *)NULL);
  newp = make_lsa_internal (lshp, from);
  oldp = lsa_lookup (lshp->lsh_type, lshp->lsh_id, lshp->lsh_advrtr,
		     from->interface->area, from->interface);

  /* for later use by (6) and (7) */
  /* check sending neighbor's LS request list */
  onrequest = 0;
  for (n = listhead (from->requestlist); n; nextnode (n))
    {
      lsi = (struct lsa_internal *)getdata (n);
      assert (lsi->lsh);
      if (lsa_issame (newp->lsh, lsi->lsh))
	{
	  onrequest++;
	}
    }
  /* check sending neighbor's LS retrans list */
  onretrans = 0;
  if (oldp)
    {
      for (n = listhead (from->retranslist); n; nextnode (n))
	{
	  lsi = (struct lsa_internal *)getdata (n);
	  if (lsi == oldp)
	    onretrans++;
	}
      if (newp->lsh->lsh_seqnum == oldp->lsh->lsh_seqnum)
	acknowledge |= DUPLICATE;
    }

  /* (5) */
#ifdef DEBUG_LSA_PTR
  if (oldp)
    {
      log ("LSAPTR: AGE new[%d], old[%d]\n",
	   calc_lsa_age_external (newp),
	   calc_lsa_age_external (oldp));
    }
#endif
  if (!oldp || (ismore_recent = which_is_more_recent (newp, oldp)) < 0) 
    {
      /* (a) */
      if (oldp && now.tv_sec - oldp->installed <= MIN_LS_ARRIVAL)
	{
#ifdef DEBUG_LSA_PTR
	  log ("LSAPTR: LSA arrived less than MinLSArrival.\n");
#endif
	  if (newp->expire)
	    {
	      thread_cancel (newp->expire);
	      newp->expire = (struct thread *)NULL;
	    }
	  if (newp->refresh)
	    {
	      thread_cancel (newp->refresh);
	      newp->refresh = (struct thread *)NULL;
	    }
	  free_lsa (newp->lsh);
	  free_lsa_internal_hdr (newp);
	  return -1;
	}

      /* (b) */
      acknowledge |= lsa_flood (newp);

      /* (c) */
      if (oldp)
	{
	  for (n = listhead (oldp->area->ospf_if_list); n; nextnode (n))
	    {
	      iface = (struct ospf_if *)getdata (n);
	      for (m = listhead (iface->nb_list); m; nextnode (m))
		{
		  nbp = (struct neighbor *)getdata (m);
		  for (l = listhead (nbp->retranslist); l; nextnode (l))
		    {
		      lsi = (struct lsa_internal *) getdata (l);
		      if (lsi == oldp)
			{
#ifdef DEBUG_OSPF
			  log ("Delete %s from %s retranslist\n",
			       print_lsahdr (oldp->lsh), inet_ntoa (nbp->rtr_id));
#endif
			  list_delete_by_val (nbp->retranslist, oldp);
			}
		    }
		}
	    }
	}

      /* (d), which may cause routing table calculation */
      lsa_install (&newp);

      /* (e) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
	  *ackp++ = newp;
      else if (acktype == DELAYED_ACK)
	  delayed_ack (newp);

#ifdef DEBUG_OSPF
      if (acktype == DIRECT_ACK)
	log ("To ACK Direct\n");
      else if (acktype == DELAYED_ACK)
	log ("To ACK Delayed\n");
      else
	log ("NO ACK\n");
#endif

      /* (f) */
      /* XXX, Self Originated LSA */

    }
  else if (onrequest) /* (6) */
    {
      /* XXX, BadLSReq */
      log ("%s is on requestlist: BadLSReq\n", print_lsahdr (newp->lsh));
      if (newp->expire)
	{
	  thread_cancel (newp->expire);
	  newp->expire = (struct thread *)NULL;
	}
      if (newp->refresh)
	{
	  thread_cancel (newp->refresh);
	  newp->refresh = (struct thread *)NULL;
	}
      free_lsa (newp->lsh);
      free_lsa_internal_hdr (newp);
      thread_add_event (master, bad_lsreq, from, 0);
      return 0;
    }
  else if (ismore_recent == 0) /* (7) */
    {
      /* (a) Treat this LSA as an Ack: Implied Ack */
      if (onretrans)
	{
	  list_delete_by_val (from->retranslist, newp);
#ifdef DEBUG_OSPF
	  log ("IMPLIED ACK!!\n");
#endif
	  acknowledge |= IMPLIEDACK;
	}

      /* (b) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
	*ackp++ = newp;
      else if (acktype == DELAYED_ACK)
	delayed_ack (newp);

#ifdef DEBUG_OSPF
      if (acktype == DIRECT_ACK)
	log ("To ACK Direct\n");
      else if (acktype == DELAYED_ACK)
	log ("To ACK Delayed\n");
      else
	log ("NO ACK\n");
#endif

    }
  else /* (8) */
    {
      /* XXX, Seqnumber Wrapping */

      /* XXX, Send database copy of this LSA to this neighbor */
      assert (oldp);
      *ackp++ = oldp;
      if (newp->expire)
	{
	  thread_cancel (newp->expire);
	  newp->expire = (struct thread *)NULL;
	}
      if (newp->refresh)
	{
	  thread_cancel (newp->refresh);
	  newp->expire = (struct thread *)NULL;
	}
      free_lsa (newp->lsh);
      free_lsa_internal_hdr (newp);
    }
}

/* if we should resoponse to this LSA as direct acknowledgement,
   return 1, otherwise (delayed acknowledgement) return 0 */
/* RFC2328: Table 19: Sending link state acknowledgements. */
int 
ack_type (struct lsa_internal *newp, int acknowledge, int ismore_recent)
{
  struct ospf_if *iface;
  struct neighbor *nbp;
  listnode n, m;

  assert (newp->from && newp->from->interface);
  iface = newp->from->interface;

  if (acknowledge & FLOODBACK)
    return NO_ACK;
  else if (ismore_recent < 0 && !(acknowledge & FLOODBACK))
    {
      if (iface->state == IFS_BDR)
	{
	  if (id_val (iface->dr) == id_val (newp->from->rtr_id))
	    return DELAYED_ACK;
	  else
	    return NO_ACK;
	}
      else
	return DELAYED_ACK;
    }
  else if (acknowledge & DUPLICATE && acknowledge & IMPLIEDACK)
    {
      if (iface->state == IFS_BDR)
	{
	  if (id_val (iface->dr) == id_val (newp->from->rtr_id))
	    return DELAYED_ACK;
	  else
	    return NO_ACK;
	}
      else
	return NO_ACK;
    }
  else if (acknowledge & DUPLICATE && !(acknowledge & IMPLIEDACK))
    {
      return DIRECT_ACK;
    }
  else if (calc_lsa_age_external (newp) == MAXAGE)
    {
      if (lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
		      newp->lsh->lsh_advrtr, newp->area, newp->iface)
	  == (struct lsa_internal *)NULL)
	{
	  for (n = listhead (newp->area->ospf_if_list);
	       n;
	       nextnode (n))
	    {
	      iface = getdata (n);
	      for (m = listhead (iface->nb_list);
		   m;
		   nextnode (m))
		{
		  nbp = getdata (m);
		  if (nbp->state == NBS_EXCHANGE || nbp->state == NBS_LOADING)
		    return NO_ACK;
		}
	    }
	  return DIRECT_ACK;
	}
    }
  
  return NO_ACK;
}

int
delayed_ack (struct lsa_internal *lsip)
{
  struct lsa_internal **p;
  struct ospf_if *iface;

  iface = lsip->from->ospf_if;
  assert (iface);

  for (p = iface->delayed_ack; *p; p++)
    ;

  *p = lsip;

  if (iface->send_ack == (struct thread *)NULL)
    iface->send_ack = thread_add_event (master, send_linkstate_ack, iface,
					iface->rxmt_interval -1);

  return;
}

/* RFC2328 section 13.3 */
int
lsa_flood (struct lsa_internal *newp)
{
  struct neighbor *nbp;
  listnode n, m, l;
  struct ospf_if *iface;
  int i, onrequest, ismore_recent, addretrans;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;
  int retval = 0;
  struct lsa_internal *oldp, *lsi;
  list eligible_ifacelist;

  assert (newp && newp->lsh && newp->area);

#ifdef DEBUG_OSPF
  log ("FLOODING %s\n", print_lsahdr (newp->lsh));
#endif

  switch (GET_LSASCOPE (newp->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      eligible_ifacelist = list_init ();
      list_add_node (eligible_ifacelist, newp->iface);
      break;
    case SCOPE_AREA:
      eligible_ifacelist = list_init ();
      for (n = listhead (newp->area->ospf_if_list); n; nextnode (n))
	{
	  list_add_node (eligible_ifacelist, getdata (n));
	}
      break;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      log ("Not Reached!?\n");
      break;
    }

  /* for each eligible ospf_ifs */
  for (n = listhead (eligible_ifacelist);
       n;
       nextnode (n))
    {
      iface = (struct ospf_if *)getdata (n);
      addretrans = 0;

      /* (1) for each neighbor */
      for (m = listhead (iface->nb_list); m; nextnode (m))
	{
	  nbp = (struct neighbor *)getdata (m);

	  /* (a) */
	  if (nbp->state < NBS_EXCHANGE)
	    continue;  /* examin next neighbor */

	  /* (b) */
	  if (nbp->state == NBS_EXCHANGE
	      || nbp->state == NBS_LOADING)
	    {
	      onrequest = 0;
	      for (l = listhead (nbp->requestlist); l; nextnode (l))
		{
		  lsi = (struct lsa_internal *) getdata (l);
		  if (lsa_issame (lsi->lsh, newp->lsh))
		    {
		      onrequest++;
		      break;
		    }
		}
	      if (onrequest)
		{
		  ismore_recent = which_is_more_recent (newp, lsi);
		  if (ismore_recent > 0)
		    {
#ifdef DEBUG_OSPF
		      log ("Requesting LSA is newer on %s\n", inet_ntoa (nbp->rtr_id));
#endif
		      continue; /* examin next neighbor */
		    }
		  else if (ismore_recent == 0)
		    {
#ifdef DEBUG_OSPF
		      log ("The same instance,Delete from requestlist %s\n",
			   inet_ntoa (nbp->rtr_id));
#endif
		      if (lsi->expire)
			{
			  thread_cancel (lsi->expire);
			  lsi->expire = (struct thread *)NULL;
			}
		      if (lsi->refresh)
			{
			  thread_cancel (lsi->refresh);
			  lsi->refresh = (struct thread *)NULL;
			}
		      free_lsa (lsi->lsh);
		      free_lsa_internal_hdr (lsi);
		      list_delete_by_val (nbp->requestlist, lsi);
		      continue; /* examin next neighbor */
		    }
		  else /* ismore_recent < 0 (i.e. the new LSA is more recent) */
		    {
#ifdef DEBUG_OSPF
		      log ("Delete from requestlist: %s\n",
			   inet_ntoa (nbp->rtr_id));
#endif
		      free_lsa (lsi->lsh);
		      free_lsa_internal_hdr (lsi);
		      list_delete_by_val (nbp->requestlist, lsi);
		    }
		}
	    }

	  /* (c) */
	  if (newp->from == nbp)
	    continue; /* examin next neighbor */

	  /* (d) add retranslist */
	  oldp = lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
			     newp->lsh->lsh_advrtr, newp->area, newp->iface);
	  if (oldp)
	    {
	      list_add_node (nbp->retranslist, oldp);   /* XXXXXX */
	    }
	  else
	    {
	      list_add_node (nbp->retranslist, newp);
	    }
#ifdef DEBUG_OSPF
	  log ("FLOODING: Added to retranslist of %s\n", inet_ntoa (nbp->rtr_id));
#endif
	  addretrans++;
	  if (nbp->send_update == NULL)
	    {
	      nbp->send_update = thread_add_timer (master, send_linkstate_update, nbp,
						   nbp->interface->rxmt_interval);
	    }
	}

      /* (2) */
      if (addretrans == 0)
	continue; /* examin next interface */
      else if (newp->from && newp->from->interface == iface)
	retval = FLOODBACK;

      /* (3) */
      if (newp->from && newp->from->interface == iface)
	{
	  if (id_val (newp->from->rtr_id) == id_val (newp->from->interface->dr) ||
	      id_val (newp->from->rtr_id) == id_val (newp->from->interface->bdr))
	    continue; /* examin next interface */
	}

      /* (4) */
      if (newp->from && newp->from->interface == iface && iface->state == IFS_BDR)
	continue; /* examin next interface */

      /* (5) send LinkState Update */
      iov_clear (iov, MAXIOVLIST);
      newp->lsh->lsh_age =
	htons (calc_lsa_age_external (newp) + iface->inf_trans_delay);
      attach_lsa_to_iov (newp, iov);
      dst.sin6_len = sizeof (struct sockaddr_in6);
      dst.sin6_family = AF_INET6;
      dst.sin6_scope_id = if_nametoindex (nbp->interface->ifname);
      switch (iface->state)
	{
	case IFS_DR:
	case IFS_BDR:
	  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst.sin6_addr);
	  break;
	default:
	  inet_pton (AF_INET6, ALLDROUTERS6, &dst.sin6_addr);
	  break;
	}
      lsupdate = (struct linkstate_update *)
	iov_prepend (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update));
      assert (lsupdate);
      lsupdate->lsupdate_num = htonl (1);

      ospf_send (MSGT_LINKSTATE_UPDATE, iov, (struct sockaddr *)&dst, iface);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
    }

  return retval;
}


int show_router_lsa (struct vty *vty, void *data)
{
  int lsdnum;
  struct lsa_hdr *lshp;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  assert (data);
  lshp = (struct lsa_hdr *)data;
  rlsap = (struct router_lsa *)(lshp + 1);
  rlsdp = (struct router_lsd *)(rlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct lsa_hdr) - sizeof (struct router_lsa))
    / sizeof (struct router_lsd);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, " type[%s] cost[%hu] interface_id[%s]\r\n",
	       rlsatype_name[rlsdp->rlsd_type - 1],
	       ntohs(rlsdp->rlsd_metric),
	       inet_ntoa (*(struct in_addr *)&rlsdp->rlsd_interface_id));
      vty_out (vty, " NeighborIFID[%s]",
	       inet_ntoa (*(struct in_addr *)&rlsdp->rlsd_neighbor_interface_id));
      vty_out (vty, " NeighborRouter-ID[%s]\r\n",
	       inet_ntoa (*(struct in_addr *)&rlsdp->rlsd_neighbor_router_id));
      rlsdp++;
    }
}

int show_network_lsa (struct vty *vty, void *data)
{
  int lsdnum;
  struct lsa_hdr *lshp;
  struct network_lsa *nlsap;
  rtr_id_t *attached;

  assert (data);
  lshp = (struct lsa_hdr *)data;
  nlsap = (struct network_lsa *)(lshp + 1);
  attached = (rtr_id_t *)(nlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct lsa_hdr) - sizeof (struct network_lsa))
    / sizeof (rtr_id_t);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, " Attached Router[%s]\r\n", inet_ntoa (*attached++));
    }
}

int
show_link_lsa (struct vty *vty, void *data)
{
  struct lsa_hdr *lshp;
  struct link_lsa *llsap;
  char ntop_buf[2][INET6_ADDRSTRLEN];
  int prefixnum;
  struct in6_addr network_prefix;
  struct prefix *prefix;

  assert (data);
  lshp = (struct lsa_hdr *)data;
  llsap = (struct link_lsa *)(lshp + 1);
  prefixnum = ntohl (llsap->llsa_prefix_num);

  vty_out (vty, " linklocal[%s]\r\n",
	   inet_ntop (AF_INET6, (void *)&llsap->llsa_linklocal, ntop_buf[0],
		      sizeof (ntop_buf[0])));
  vty_out (vty, " # prefix [%d]\r\n", prefixnum);
  prefix = (struct prefix *)(llsap + 1);
  for (; prefixnum; prefixnum--)
    {
      bzero (&network_prefix, sizeof (network_prefix));
      vty_out (vty, " Prefix length [%d]\r\n", prefix->prefix_length);
      bcopy (prefix + 1, &network_prefix, PREFIX_SPACE (prefix->prefix_length));
      vty_out (vty, " Prefix [%s]\r\n",
	       inet_ntop (AF_INET6, (void *)&network_prefix, ntop_buf[1],
			  sizeof (ntop_buf[1])));
      prefix = NEXT_PREFIX (prefix);
    }
}

int show_intra_prefix_lsa (struct vty *vty, void *data)
{
  struct lsa_hdr *lshp;
  struct intra_area_prefix_lsa *iap_lsa;
  struct prefix *prefix;
  int prefixnum;
  struct in6_addr network_prefix;
  char ntop_buf[2][INET6_ADDRSTRLEN];

  bzero (ntop_buf[0], sizeof (ntop_buf[0]));
  bzero (ntop_buf[1], sizeof (ntop_buf[1]));

  assert (data);
  lshp = (struct lsa_hdr *)data;
  iap_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  prefixnum = ntohs (iap_lsa->intra_prefix_num);

  vty_out (vty, " # prefix [%d]\r\n", prefixnum);
  vty_out (vty, " Referenced[%s]\r\n", print_lsahdr ((struct lsa_hdr *)iap_lsa));

  prefix = (struct prefix *)(iap_lsa + 1);
  for (; prefixnum; prefixnum--)
    {
      bzero (&network_prefix, sizeof (network_prefix));
      vty_out (vty, " Prefix length [%d]\r\n", prefix->prefix_length);
      bcopy (prefix + 1, &network_prefix, PREFIX_SPACE (prefix->prefix_length));
      vty_out (vty, " Prefix [%s]\r\n",
	       inet_ntop (AF_INET6, (void *)&network_prefix, ntop_buf[1],
			  sizeof (ntop_buf[1])));
      prefix = NEXT_PREFIX (prefix);
    }
}

int
vty_lsdb (struct vty *vty, struct area *area)
{
  int type, i, j;
  struct lsa_hdr *lshp;
  struct lsa_internal *lsip;
  listnode m, n;
  struct ospf_if *iface;
  struct neighbor *nbp;

  for (type = 0; type < AREALSTYPESIZE; type++)
    {
      for (i = 0; i < HASHVAL; i++)
	{
	  for (n = listhead (area->lsdb[type][i]); n; nextnode (n))
	    {
	      lsip = (struct lsa_internal *) getdata (n);
	      assert (lsip && lsip->area);
	      lshp = lsip->lsh;
	      assert (lshp);
	      vty_out (vty, "%s LS age[%5d]\r\n",
		       print_lsahdr (lshp),
		       calc_lsa_age_external (lsip));
	      vty_out (vty, " LS SeqNum[%#10x,%d]\r\n",
		       ntohl(lshp->lsh_seqnum),ntohl(lshp->lsh_seqnum));
	      switch (ntohs (lshp->lsh_type))
		{
		case LST_ROUTER_LSA:
		  show_router_lsa (vty, (void *)lshp);
		  break;
		case LST_NETWORK_LSA:
		  show_network_lsa (vty, (void *)lshp);
		  break;
		case LST_LINK_LSA:
		  show_link_lsa (vty, (void *)lshp);
		  break;
		case LST_INTRA_AREA_PREFIX_LSA:
		  show_intra_prefix_lsa (vty, (void *)lshp);
		  break;
		default:
		  break;
		}
	    }
	}
    }

  for (n = listhead (area->ospf_if_list); n; nextnode (n))
    {
      iface = (struct ospf_if *) getdata (n);
      for (m = listhead (iface->linklocal_lsa); m; nextnode (m))
	{
	  lsip = (struct lsa_internal *) getdata (m);
	  lshp = lsip->lsh;
	  vty_out (vty, "%s LS age[%5d]\r\n",
		   print_lsahdr (lshp),
		   calc_lsa_age_external (lsip));
	  vty_out (vty, " LS SeqNum[%#10x,%d]\r\n",
		   ntohl(lshp->lsh_seqnum),ntohl(lshp->lsh_seqnum));
	  show_link_lsa (vty, (void *)lsip->lsh);
	}
    }
}

