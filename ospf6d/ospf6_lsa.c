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

static struct lsa_hdr *
malloc_lsa (struct lsa_hdr *lsh)
{
  struct lsa_hdr *retval;
  retval = (struct lsa_hdr *)XMALLOC(MTYPE_OSPF_LSA, ntohs (lsh->lsh_len));
  memset (retval, 0, ntohs (lsh->lsh_len));
  ospf6_debug ("LSAPTR: Allocate LSA Body(%#x[%#x]) for %s\n",
               retval, ntohs (lsh->lsh_len), print_lsahdr (lsh));
  return retval;
}

void
free_lsa (struct lsa_hdr *lsh)
{
  ospf6_debug ("LSAPTR: Free LSA Body(%#x) for %s\n",
               lsh, print_lsahdr (lsh));
  XFREE (MTYPE_OSPF_LSA, lsh);
  return;
}

static struct lsa_internal *
malloc_lsa_internal_hdr (struct lsa_hdr *lsh)
{
  struct lsa_internal *retval;
  retval = (struct lsa_internal *)
    XMALLOC (MTYPE_OSPF_LSA, sizeof (struct lsa_internal));
  memset (retval, 0, sizeof (struct lsa_internal));
  ospf6_debug ("LSAPTR: Allocate LSA Internal Hdr(%#x[%#x]) for %s\n",
               retval, sizeof (struct lsa_internal), print_lsahdr (lsh));
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
  ospf6_debug ("LSAPTR: Free LSA Internal Hdr(%#x) for %s\n",
               lsi, print_lsahdr (lsi->lsh));
  XFREE (MTYPE_OSPF_LSA, lsi);
  return;
}

int
lsa_list_delete_all (list l)
{
  listnode n;
  struct lsa_internal *lsi;

  for (n = listhead (l); n; n = listhead (l))
    {
      lsi = (struct lsa_internal *) getdata (n);
      free_lsa (lsi->lsh);
      free_lsa_internal_hdr (lsi);
    }
  list_delete_all_node (l);
  return 0;
}

int
lsi_delete_from_list (struct lsa_internal *lsi, list l)
{
  assert (lsi->lsh);
  free_lsa (lsi->lsh);
  free_lsa_internal_hdr (lsi);
  list_delete_by_val (l, lsi);
  return 0;
}

int
lsi_delete (struct lsa_internal *lsi)
{
  assert (lsi && lsi->lsh);
  switch (GET_LSASCOPE (lsi->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      assert (lsi->ospf6_if);
      lsi_delete_from_list (lsi, lsi->ospf6_if->linklocal_lsa);
      break;
    case SCOPE_AREA:
      assert (lsi->area);
      lsi_delete_from_list (lsi, lsi->area->lsdb
               [typeindex(lsi->lsh->lsh_type)][hash(lsi->lsh->lsh_id)]);
      break;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      ospf6_debug ("Not Reached!?\n");
      break;
    }

  return 0;
}

int
prepare_neighbor_lsdb (struct neighbor *nbr)
{
  int i, type;
  struct area *area;
  struct lsa_internal *lsi;
  listnode n;

  assert (nbr);

  ospf6_debug ("PREPARE for %s\n", nbr->str);

  list_cleared_of_lsa (nbr);

  area = nbr->ospf6_if->area;
  assert (area);

  for (type = 0; type < AREALSTYPESIZE; type++)
    {
      for (i = 0; i < HASHVAL; i++)
        {
          for (n = listhead (area->lsdb[type][i]); n; nextnode (n))
            {
              lsi = (struct lsa_internal *) getdata (n);
              ospf6_debug ("Attache %s to Summary of %s\n",
                           print_lsahdr (lsi->lsh), nbr->str);
              list_add_node (nbr->summarylist, lsi);
            }
        }
    }

  for (n = listhead (nbr->ospf6_if->linklocal_lsa); n; nextnode (n))
    {
      lsi = (struct lsa_internal *) getdata (n);
      list_add_node (nbr->summarylist, lsi);
    }
  return 0;
}

int
expire_lsa_age (struct thread *thread)
{
  struct lsa_internal *lsi;

  lsi = (struct lsa_internal *)THREAD_ARG  (thread);
  ospf6_debug ("LSAPTR: Expire lsi[%#x]\n", lsi);
  assert (lsi && lsi->lsh && lsi->area);

  lsi->expire = (struct thread *)NULL;
  ospf6_debug ("LSAEVENT: Expire: %s\n", print_lsahdr (lsi->lsh));
  lsi_delete (lsi);

  return 0;
}

int
calc_lsa_age_internal (struct lsa_internal *lsi)
{
  struct timeval now;

  assert (lsi && lsi->lsh);

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

unsigned short
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
  lsi->ospf6_if = from->ospf6_if;
  lsi->area = from->ospf6_if->area;
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
  lsi->ospf6_if = from->ospf6_if;
  lsi->area = from->ospf6_if->area;
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
        newp->area->spf_calc = thread_add_event (master,
                                                 spf_calculation,
                                                 newp->area, 0);
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
lsa_install (struct lsa_internal **newpp)
{
  struct lsa_internal *oldp, *newp;
  struct lsa_hdr *newlsh;
  struct timeval now;

  assert (newpp && *newpp);

  ospf6_debug ("LSAPTR: Installing LSA[%s]\n", print_lsahdr ((*newpp)->lsh));

  newp = *newpp;
  newlsh = newp->lsh;

  gettimeofday (&now, (struct timezone *)NULL);

  /* check old LSA and if exists, we must reuse lsi_internal structure
     because of possibility that this LSA have atached to some-neighbor's
     LS list already */
  oldp = lsa_lookup (newlsh->lsh_type, newlsh->lsh_id, newlsh->lsh_advrtr,
                     newp->area, newp->ospf6_if);
  if (oldp)
    {
      assert (oldp->lsh);
      ospf6_debug ("LSAPTR: Find Old One[%#x], Swap.\n", oldp);
      free_lsa (oldp->lsh);
      oldp->lsh = newp->lsh;
      ospf6_debug ("LSAPTR: Attach LSA body[%#x] to internal[%#x]"
                   "in lsa_install()\n", newp->lsh, oldp);
      oldp->from = newp->from;
      oldp->ospf6_if = newp->ospf6_if;
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
          oldp->refresh =
            thread_add_timer (master, lsa_refresh, oldp,
                              newp->refresh->u.sands.tv_sec - now.tv_sec);
        }

      free_lsa_internal_hdr (newp);
      ospf6_debug ("LSAPTR: LSA renewaled!\n");

      /* reset caller's newp */
      *newpp = oldp;
      newp = oldp;
    }
  else
    {
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
          zlog (NULL, LOG_WARNING, "Not yet");
          break;
        case SCOPE_RESERVED:
        default:
          zlog (NULL, LOG_WARNING, "Not Reached!?");
          break;
        }

      ospf6_debug ("LSAPTR: new LSA[ihdr:%#x][body:%#x] Installed!\n",
                   newp, newp->lsh);
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
  signed long seqnuma, seqnumb;
  int ab, ba;

  assert (a && a->lsh);
  assert (b && b->lsh);
  assert (lsa_issame (a->lsh, b->lsh));

  seqnuma = ntohl (a->lsh->lsh_seqnum) - (int32_t)INITIAL_SEQUENCE_NUMBER;
  seqnumb = ntohl (b->lsh->lsh_seqnum) - (int32_t)INITIAL_SEQUENCE_NUMBER;

  /* XXX, Care about Wrapping */
  if (seqnuma > seqnumb)
    {
      ospf6_debug ("Recent is decided by SeqNum.\n");
      return -1;
    }
  else if (seqnuma < seqnumb)
    {
      ospf6_debug ("Recent is decided by SeqNum.\n");
      return 1;
    }
  else
    {
      /* XXX Checksum */

      if (ntohs (a->lsh->lsh_age) == MAXAGE
                 && ntohs (b->lsh->lsh_age) != MAXAGE)
        {
          ospf6_debug ("Recent is decided by MaxAge.\n");
          return -1;
        }
      else if (ntohs (a->lsh->lsh_age) != MAXAGE
               && ntohs (b->lsh->lsh_age) == MAXAGE)
        {
          ospf6_debug ("Recent is decided by MaxAge.\n");
          return 1;
        }
      else
        {
          ab = calc_lsa_age_external (a) - calc_lsa_age_external (b);
          ba = calc_lsa_age_external (b) - calc_lsa_age_external (a);
          if (ab > MAX_AGE_DIFF)
            {
              ospf6_debug ("Recent is decided by Age diff(%d).\n", ab);
              return 1;
            }
          else if (ba > MAX_AGE_DIFF)
            {
              ospf6_debug ("Recent is decided by Age diff(%d).\n", ba);
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
lsa_lookup_by_advrtr (unsigned short lsa_type, unsigned long advrtr,
                      struct area *area)
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
      zlog (NULL, LOG_WARNING, "Not Reached!?");
      break;
    }
  return (struct lsa_internal *)NULL;
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
check_neighbor_lsdb (struct iovec *iov, struct neighbor *nbr)
{
  int i, already;
  struct lsa_internal *have, *received, *lsi;
  listnode n;
  struct lsa_hdr *lsh;

  have = received = (struct lsa_internal *)NULL;

  if (!iov->iov_base)
    return 0;

  for (i = 0; iov[i].iov_base; i++)
    {
      lsh = (struct lsa_hdr *)iov[i].iov_base;
      ospf6_debug ("recvDD: %s\n", print_lsahdr (lsh));

      if (!lsatype_ok (lsh))
        assert (0);

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
      received = make_lsa_hdr_internal (lsh, nbr);
      have = lsa_lookup (lsh->lsh_type, lsh->lsh_id,
                         lsh->lsh_advrtr, nbr->ospf6_if->area,
                         nbr->ospf6_if);
      if (have)
        {
          if (which_is_more_recent (received, have) >= 0)
            continue;
        }

      /* Search this in case already in Requestlist */
      already = 0;
      for (n = listhead (nbr->requestlist); n; nextnode (n))
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
          ospf6_debug ("Already Attached requestlist of %s:[%s]\n",
                        nbr->str, print_lsahdr (received->lsh));
          continue;
        }

        /* the LSA we have just received is newer.
           attach requestlist. */
        list_add_node (nbr->requestlist, received);
        ospf6_debug ("Attache requestlist of %s:[%s]\n",
                     nbr->str, print_lsahdr (received->lsh));
        received = (struct lsa_internal *)NULL;
    }
  return 0;
}

int
proceed_summarylist (struct neighbor *nbr)
{
  int size;
  struct lsa_internal *p, *q;
  listnode n, m;

  for (n = listhead (nbr->dd_retrans), m = listhead (nbr->summarylist);
       n && m; nextnode (n), nextnode (m))
    {
      p = (struct lsa_internal *) getdata (n);
      q = (struct lsa_internal *) getdata (m);
      assert (p == q);
      list_delete_by_val (nbr->dd_retrans, p);
      list_delete_by_val (nbr->summarylist, q);
    }

  size = sizeof (struct ospf6_hdr) + sizeof (struct database_description);
  for (n = listhead(nbr->summarylist); n; nextnode (n))
    {
      p = (struct lsa_internal *)getdata (n);
      if (DEFAULT_INTERFACE_MTU - size <= sizeof (struct lsa_hdr))
        break;
      list_add_node (nbr->dd_retrans, p);
      size += sizeof (struct lsa_hdr);
    }

  if (list_isempty (nbr->summarylist))
    {
      DD_MBIT_CLEAR (nbr->dd_bits);
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

  lsi->refresh = (struct thread *)NULL;
  if (lsi->expire)
    {
      thread_cancel (lsi->expire);
      lsi->expire = (struct thread *)NULL;
    }

  ospf6_debug ("LSAEVENT: Refresh: %s\n", print_lsahdr (lsi->lsh));

  switch (ntohs (lsi->lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      assert (lsi->area);
      construct_router_lsa (lsi->area);
      break;
    case LST_NETWORK_LSA:
      assert (lsi->ospf6_if);
      construct_network_lsa (lsi->ospf6_if);
      break;
    case LST_LINK_LSA:
      assert (lsi->ospf6_if);
      construct_link_lsa (lsi->ospf6_if);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      assert (lsi->ospf6_if);
      construct_intra_prefix_lsa (lsi->ospf6_if);
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

  oldp = lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
                     newp->lsh->lsh_advrtr, newp->area, newp->ospf6_if);
  if (oldp && oldp->refresh)
    {
      if (newp->lsh->lsh_len == oldp->lsh->lsh_len &&
          !memcmp (newp->lsh + 1, oldp->lsh + 1,
                   ntohs (newp->lsh->lsh_len) - sizeof (struct lsa_hdr)))
        {
          ospf6_debug ("LSAEVENT: LSA[%s] body No change, Not Installed.\n",
                        print_lsahdr (newp->lsh));
          free_lsa (newp->lsh);
          free_lsa_internal_hdr (newp);
          return 0;
        }
    }

  lsa_install (newpp);
  newp = *newpp;
  lsa_flood (newp);
  return 0;
}

/* xxx, We don't support sending multiple (seperate) Router-LSA yet,
   so Link State ID field of Router-LSA will be always the same */
int
construct_router_lsa (struct area *area)
{
  list described_link;
  listnode n, m;
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  int space;
  char *lsa;
  struct lsa_hdr *lsh;
  struct lsa_internal *lsi;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  /* check needed space for LSA by looking up ospf_ifs.
     ospf_if to be described are collected. */
  described_link = list_init ();
  for (n = listhead (area->ospf6_if_list);
       n;
       nextnode (n))
    {
      ospf6_if = (struct ospf6_if *)getdata (n);
      assert (ospf6_if);

      if (ospf6_if->state <= IFS_LOOPBACK)
        continue;

      for (m = listhead (ospf6_if->nbr_list);
           m;
           nextnode (m))
        {
          nbr = (struct neighbor *)getdata (m);
          assert (nbr);

          if (nbr->state == NBS_FULL)
            {
              list_add_node (described_link, ospf6_if);
              break;
            }
        }
    }

  space = sizeof (struct lsa_hdr) + sizeof (struct router_lsa)
    + (sizeof (struct router_lsd) * listcount (described_link));

  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  ospf6_debug ("LSAPTR: Alloc LSA body[%#x] for our Router-LSA\n", lsa);
  memset (lsa, 0, space);

  lsh = (struct lsa_hdr *) lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_ROUTER_LSA);
  lsh->lsh_id = htonl (MY_ROUTER_LSA_ID);
  lsh->lsh_advrtr = area->ospf6->router_id;
  lsh->lsh_seqnum = htonl((area->router_lsa_seqnum)++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  rlsap = (struct router_lsa *) ((char *)lsh + sizeof (struct lsa_hdr));
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
      ospf6_if = (struct ospf6_if *)getdata (n);
      assert (ospf6_if);

      if (if_is_pointopoint (ospf6_if->interface))
        {
          assert (listcount (ospf6_if->nbr_list) == 1);
          nbr = (struct neighbor *)getdata (listhead (ospf6_if->nbr_list));
          assert (nbr);
          if (nbr->state != NBS_FULL)
            continue;

          rlsdp->rlsd_type = LSDT_POINTTOPOINT;
          rlsdp->rlsd_metric = htons (ospf6_if->cost);
          rlsdp->rlsd_interface_id = ospf6_if->ifid;
          rlsdp->rlsd_neighbor_interface_id = nbr->ifid;
          rlsdp->rlsd_neighbor_router_id = nbr->rtr_id;

          rlsdp++;
        }
      else if (if_is_broadcast (ospf6_if->interface))
        {
          if (ospf6_if->state == IFS_DR)
            {
              rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
              rlsdp->rlsd_metric = htons (ospf6_if->cost);
              rlsdp->rlsd_interface_id = ospf6_if->ifid;
              rlsdp->rlsd_neighbor_interface_id = ospf6_if->ifid;
              rlsdp->rlsd_neighbor_router_id = area->ospf6->router_id;
              rlsdp++;
            }
          else
            {
              rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
              rlsdp->rlsd_metric = htons (ospf6_if->cost);
              rlsdp->rlsd_interface_id = ospf6_if->ifid;
              nbr = nbr_lookup (ospf6_if->dr, ospf6_if->area->ospf6);
              assert (nbr);
              rlsdp->rlsd_neighbor_interface_id = nbr->ifid;
              rlsdp->rlsd_neighbor_router_id = ospf6_if->dr;
              rlsdp++;
            }
        }
      else
        {
          zlog (NULL, LOG_ERR,
		"Not Supported Type of Interface: %s",
		ospf6_if->interface->name);
          continue;
        }
    }

  /* XXX Checksum */

  ospf6_info ("LSAEVENT: Construct Router-LSA\n");

  /* Router-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = (struct ospf6_if *)NULL;
  lsi->area = area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int
construct_network_lsa (struct ospf6_if *ospf6_if)
{
  struct neighbor *nbr;
  listnode n;
  int attached_rtr;
  int space;
  struct lsa_hdr *lsh;
  char *lsa;
  rtr_id_t *p;
  struct network_lsa *nlsap;
  struct lsa_internal *lsi;

  assert (ospf6_if->state == IFS_DR);

  /* Is this link Transit ? */
  attached_rtr = 0;
  for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state == NBS_FULL)
        attached_rtr++;
    }

  if (!attached_rtr)
    return 0;

  space = sizeof (struct lsa_hdr) + sizeof (struct network_lsa)
    + sizeof (rtr_id_t) * (attached_rtr + 1);
  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  ospf6_debug ("LSAPTR: Alloc LSA body[%#x] for our Network-LSA\n", lsa);
  memset (lsa, 0, space);

  lsh = (struct lsa_hdr *) lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_NETWORK_LSA);
  lsh->lsh_id = ospf6_if->ifid;
  ospf6_debug ("Network-LSA LS-ID: %s\n",
               inet4str (ospf6_if->ifid));
  lsh->lsh_advrtr = ospf6_if->area->ospf6->router_id;
  lsh->lsh_seqnum = htonl(ospf6_if->area->network_lsa_seqnum++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  nlsap = (struct network_lsa *)(lsh + 1);
  memcpy (nlsap->nlsa_options, ospf6_if->area->options,
          sizeof (nlsap->nlsa_options));

  p = (rtr_id_t *) (nlsap + 1);

  for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor * ) getdata (n);
      if (nbr->state == NBS_FULL)
        {
          *p = nbr->rtr_id;
          p++;
        }
    }
  *p = ospf6_if->area->ospf6->router_id;

  /* XXX! Calculate Checksum! */

  ospf6_debug ("LSAEVENT: Construct Network-LSA\n");

  /* Network-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh,
                                   lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int
construct_link_lsa (struct ospf6_if *ospf6_if)
{
  int space;
  listnode i;
  char *lsa;
  struct lsa_hdr *lsh;
  struct link_lsa *llsap;
  struct ospf6_prefix *p;
  struct connected *c;
  struct in6_addr *linklocal, *network_prefix;
  struct lsa_internal *lsi;

  space = 0;
  linklocal = (struct in6_addr *)NULL;
  for (i = listhead (ospf6_if->interface->connected); i; nextnode (i))
    {
      c = (struct connected *) getdata (i);
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        {
          linklocal = &c->address->u.prefix6;
          continue;
        }
      space += OSPF6_PREFIX_SPACE (c->address->prefixlen)
               + sizeof (struct ospf6_prefix);
    }
  space += sizeof (struct link_lsa) + sizeof (struct lsa_hdr);
  assert (linklocal);

  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  ospf6_debug ("LSAPTR: Alloc LSA body[%#x] for our Link-LSA\n", lsa);
  memset (lsa, 0, space);
  lsh = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_LINK_LSA);
  lsh->lsh_id = ospf6_if->ifid;
  ospf6_debug ("Link-LSA LS-ID: %s\n", inet4str (ospf6_if->ifid));
  lsh->lsh_advrtr = ospf6_if->area->ospf6->router_id;
  lsh->lsh_seqnum = htonl(ospf6_if->area->link_lsa_seqnum++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  llsap = (struct link_lsa *)(lsh + 1);
  llsap->llsa_rtr_pri = ospf6_if->rtr_pri;
  memcpy (llsap->llsa_options, ospf6_if->area->options,
          sizeof llsap->llsa_options);
  memcpy (linklocal, &llsap->llsa_linklocal, sizeof (llsap->llsa_linklocal));
  llsap->llsa_prefix_num =
    htonl (listcount (ospf6_if->interface->connected) - 1); /* XXX */

  p = (struct ospf6_prefix *)(llsap + 1);
  for (i = listhead (ospf6_if->interface->connected); i; nextnode (i))
    {
      c = (struct connected *) getdata (i);
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        continue;

      p->o6p_prefix_len = c->address->prefixlen;
      /* XXX p->o6p_prefix_options */

      network_prefix = (struct in6_addr *)(p + 1);
      memcpy (network_prefix, &c->address->u.prefix6,
              OSPF6_PREFIX_SPACE (c->address->prefixlen));
      p = OSPF6_NEXT_PREFIX (p);
    }

  /* XXX! Calculate Checksum! */

  ospf6_debug ("LSAEVENT: Construct Link-LSA\n");

  /* Link-LSA is now constructed.
     store this in appropriate place (Ospf6_If Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

int construct_intra_prefix_lsa (struct ospf6_if *ospf6_if)
{
  int i, already, space, fullnbnum;
  char *lsa;
  struct neighbor *nbr;
  struct lsa_internal *lsi;
  struct link_lsa *linklsa;
  struct ospf6_prefix *p, *q;
  struct lsa_hdr *lsh;
  struct intra_area_prefix_lsa *intra_prefix_lsa;
  listnode n, m;
  list prefix_collection = list_init ();

  /* Count Full Neighbor */
  fullnbnum = 0;
  for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state == NBS_FULL)
        fullnbnum++;
    }

  if (ospf6_if->state != IFS_DR && fullnbnum != 0)
    {
      /* Not Stub Network and Not DR. The LSA of this network will be
         advertised by DR of this network. */
      return 0;
    }

  if (ospf6_if->state == IFS_DR)   /* I'm DR */
    {
      for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
        {
          nbr = (struct neighbor *) getdata (n);
          if (nbr->state != NBS_FULL)
            continue;

          lsi = lsa_lookup (htons (LST_LINK_LSA), nbr->ifid,
                            nbr->rtr_id, ospf6_if->area, ospf6_if);
          if (!lsi)
            {
              zlog (NULL, LOG_WARNING,"WARN: Full but Link-LSA not found: %s",
                          nbr->str);
              continue;
            }

          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {
              if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
                {
                  ospf6_notice ("v4mapped address, don't include"
                                "Intra-Area-Prefix-LSA\n");
                  continue;
                }

              already = 0;
              for (m = listhead (prefix_collection); m; nextnode (m))
                {
                  q = (struct ospf6_prefix *) getdata (m);
                  if (memcmp (p, q, OSPF6_PREFIX_SIZE (p)) == 0)
                    already++;
                }
              if (already == 0)
                list_add_node (prefix_collection, p);
            }

        }
      
      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), ospf6_if->ifid,
                        ospf6_if->area->ospf6->router_id,
                        ospf6_if->area, ospf6_if);
      if (!lsi)
        {
          zlog (NULL, LOG_WARNING, "WARN: Link-LSA of Myself not found");
        }
      else
        {
          ospf6_debug ("My Link-LSA: [%s]\n", print_lsahdr (lsi->lsh));
          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {
              if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
                {
                  ospf6_debug ("v4mapped address of mine, don't"
                               " include Intra-Area-Prefix-LSA\n");
                  continue;
                }

              already = 0;
              for (m = listhead (prefix_collection); m; nextnode (m))
                {
                  q = (struct ospf6_prefix *)getdata (m);
                  if (memcmp (p, q, OSPF6_PREFIX_SIZE (p)) == 0)
                    already++;
                }
              if (already == 0)
                list_add_node (prefix_collection, p);
            }
        }
    }
  else if (list_isempty (ospf6_if->nbr_list))
    {
      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), ospf6_if->ifid,
                        ospf6_if->area->ospf6->router_id,
                        ospf6_if->area, ospf6_if);
      if (!lsi)
        {
          zlog (NULL, LOG_WARNING, "WARN: Link-LSA of Myself not found");
        }
      else
        {
          ospf6_debug ("My Link-LSA: [%s]\n", print_lsahdr (lsi->lsh));
          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {
              if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
                {
                  ospf6_debug ("v4mapped address of mine,"
                               " don't include Intra-Area-Prefix-LSA\n");
                  continue;
                }

              already = 0;
              for (m = listhead (prefix_collection); m; nextnode (m))
                {
                  q = (struct ospf6_prefix *) getdata (m);
                  if (bcmp (p, q, OSPF6_PREFIX_SIZE (p)) == 0)
                    already++;
                }
              if (already == 0)
                list_add_node (prefix_collection, p);
            }
        }
    }
  else
    {
      return 0;
    }

  if (!listcount (prefix_collection))
    {
      ospf6_debug ("LSAEVENT: No Network Address,"
                   " Don't Construct Intra-Area-Prefix-LSA\n");
      return 0;
    }

  /* check necessary space */
  space = 0;
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = (struct ospf6_prefix *)getdata (n);
      space += OSPF6_PREFIX_SIZE (p);
    }
  space += sizeof (struct intra_area_prefix_lsa) + sizeof (struct lsa_hdr);

  /* construct instance of LSA */
  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  ospf6_debug ("LSAPTR: Alloc LSA body[%#x]"
               " for our Intra-Area-Prefix-LSA\n", lsa);
  memset (lsa, 0, space);
  lsh = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);

  if (fullnbnum)   /* For Transit Network */
    lsh->lsh_id = ospf6_if->ifid;
  else             /* For Stub Network */
    lsh->lsh_id = htonl (MY_ROUTER_LSA_ID);

  ospf6_debug ("Intra-Area-Prefix-LSA LS-ID: %s\n",
               inet4str (ospf6_if->ifid));
  lsh->lsh_advrtr = ospf6_if->area->ospf6->router_id;
  lsh->lsh_seqnum = htonl(ospf6_if->area->intra_prefix_seqnum++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  intra_prefix_lsa = (struct intra_area_prefix_lsa *)(lsh + 1);
  intra_prefix_lsa->intra_prefix_num = htons (listcount (prefix_collection));

  if (fullnbnum)
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = ospf6_if->ifid;
    }
  else
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = htonl (MY_ROUTER_LSA_ID);
    }

  intra_prefix_lsa->intra_prefix_refer_advrtr =
       ospf6_if->area->ospf6->router_id;

  q = (struct ospf6_prefix *)(intra_prefix_lsa + 1);
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      memcpy (p, q, OSPF6_PREFIX_SIZE (p));
      q = OSPF6_NEXT_PREFIX (q);
    }

  /* XXX! Calculate Checksum! */

  ospf6_debug ("LSAEVENT: Construct Intra-Area-Prefix-LSA\n");

  /* Intra-Area-Prefix-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;
  
  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  calc_lsa_age_internal (lsi);

  originating_lsa (&lsi);
  return 0;
}

/* RFC2328 section 13 */
int
lsa_receive (struct lsa_hdr *lsh, struct neighbor *from)
{
  struct lsa_internal *newp, *oldp, *lsi;
  struct neighbor *nbr;
  struct ospf6_if *ospf6_if;
  struct timeval now;
  listnode n, m, l;
  int onrequest, ismore_recent, onretrans, acknowledge, acktype;

  newp = oldp = (struct lsa_internal *)NULL;
  ismore_recent = 1;
  acknowledge = 0;

  /* (1) */
  /* XXX LSA Checksum */

  /* (2) */
  switch (ntohs (lsh->lsh_type))
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
      zlog (NULL, LOG_ERR, "Unsupported LSA Type: %#x, Ignore",
	    ntohs (lsh->lsh_type));
      return -1;
    }

  /* (3) */
  /* XXX, Ebit Missmatch: AS-External-LSA */

  /* (4) */
  /* XXX, if MaxAge LSA and if we have no instance */

  gettimeofday (&now, (struct timezone *)NULL);
  newp = make_lsa_internal (lsh, from);
  oldp = lsa_lookup (lsh->lsh_type, lsh->lsh_id, lsh->lsh_advrtr,
                     from->ospf6_if->area, from->ospf6_if);

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
  if (oldp)
    {
      ospf6_debug ("LSAPTR: AGE new[%d], old[%d]\n",
                  calc_lsa_age_external (newp),
                  calc_lsa_age_external (oldp));
    }
  if (!oldp || (ismore_recent = which_is_more_recent (newp, oldp)) < 0) 
    {
      /* (a) */
      if (oldp && now.tv_sec - oldp->installed <= MIN_LS_ARRIVAL)
        {
          ospf6_notice ("LSAPTR: LSA arrived less than MinLSArrival.\n");
          lsi_delete (newp);
          return -1;
        }

      /* (b) */
      acknowledge |= lsa_flood (newp);

      /* (c) */
      if (oldp)
        {
          for (n = listhead (oldp->area->ospf6_if_list); n; nextnode (n))
            {
              ospf6_if = (struct ospf6_if *)getdata (n);
              for (m = listhead (ospf6_if->nbr_list); m; nextnode (m))
                {
                  nbr = (struct neighbor *)getdata (m);
                  l = list_lookup_node (nbr->retranslist, oldp);
                  if (!l)
                    continue;
                  ospf6_debug ("Delete [%s] from %s retranslist\n",
                               print_lsahdr (oldp->lsh), nbr->str);
                  list_delete_by_val (nbr->retranslist, oldp);
                }
            }
        }

      /* (d), which may cause routing table calculation */
      lsa_install (&newp);

      /* (e) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          ospf6_debug ("To ACK Direct\n");
          list_add_node (from->direct_ack, newp);
        }
      else if (acktype == DELAYED_ACK)
        {
          ospf6_debug ("To ACK Delayed\n");
          delayed_ack (newp);
        }
      else
        ospf6_debug ("No ACK\n");

      /* (f) */
      /* XXX, Self Originated LSA */

    }
  else if (onrequest) /* (6) */
    {
      /* XXX, BadLSReq */
      ospf6_debug ("%s is on requestlist: BadLSReq\n",
                   print_lsahdr (newp->lsh));
      lsi_delete (newp);
      thread_add_event (master, bad_lsreq, from, 0);
      return 0;
    }
  else if (ismore_recent == 0) /* (7) */
    {
      /* (a) Treat this LSA as an Ack: Implied Ack */
      if (onretrans)
        {
          ospf6_debug ("IMPLIED ACK!!\n");
          list_delete_by_val (from->retranslist, newp);
          acknowledge |= IMPLIEDACK;
        }

      /* (b) */
      acktype = ack_type (newp, acknowledge, ismore_recent);
      if (acktype == DIRECT_ACK)
        {
          ospf6_debug ("To ACK Direct\n");
          list_add_node (from->direct_ack, newp);
        }
      else if (acktype == DELAYED_ACK)
        {
          ospf6_debug ("To ACK Delayed\n");
          delayed_ack (newp);
        }
      else
        ospf6_debug ("No ACK\n");
    }
  else /* (8) */
    {
      /* XXX, Seqnumber Wrapping */

      /* XXX, Send database copy of this LSA to this neighbor */
      assert (oldp);
      list_add_node (from->direct_ack, oldp);
      lsi_delete (newp);
    }
  return 0;
}

/* if we should resoponse to this LSA as direct acknowledgement,
   return 1, otherwise (delayed acknowledgement) return 0 */
/* RFC2328: Table 19: Sending link state acknowledgements. */
int 
ack_type (struct lsa_internal *newp, int acknowledge, int ismore_recent)
{
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  listnode n, m;

  assert (newp->from && newp->from->ospf6_if);
  ospf6_if = newp->from->ospf6_if;

  if (acknowledge & FLOODBACK)
    return NO_ACK;
  else if (ismore_recent < 0 && !(acknowledge & FLOODBACK))
    {
      if (ospf6_if->state == IFS_BDR)
        {
          if (ospf6_if->dr == newp->from->rtr_id)
            return DELAYED_ACK;
          else
            return NO_ACK;
        }
      else
        return DELAYED_ACK;
    }
  else if (acknowledge & DUPLICATE && acknowledge & IMPLIEDACK)
    {
      if (ospf6_if->state == IFS_BDR)
        {
          if (ospf6_if->dr == newp->from->rtr_id)
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
                      newp->lsh->lsh_advrtr, newp->area, newp->ospf6_if)
          == (struct lsa_internal *)NULL)
        {
          for (n = listhead (newp->area->ospf6_if_list);
               n;
               nextnode (n))
            {
              ospf6_if = (struct ospf6_if *) getdata (n);
              for (m = listhead (ospf6_if->nbr_list);
                   m;
                   nextnode (m))
                {
                  nbr = (struct neighbor *) getdata (m);
                  if (nbr->state == NBS_EXCHANGE || nbr->state == NBS_LOADING)
                    return NO_ACK;
                }
            }
          return DIRECT_ACK;
        }
    }
  
  return NO_ACK;
}

int
delayed_ack (struct lsa_internal *lsi)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = lsi->from->ospf6_if;
  assert (ospf6_if);

  list_add_node (ospf6_if->delayed_ack, lsi);

  if (ospf6_if->send_ack == (struct thread *)NULL)
    ospf6_if->send_ack = thread_add_timer (master, send_linkstate_ack,
                                           ospf6_if,
                                           ospf6_if->rxmt_interval);

  return 0;
}

/* RFC2328 section 13.3 */
int
lsa_flood (struct lsa_internal *newp)
{
  struct neighbor *nbr = (struct neighbor *)NULL;
  listnode n, m, l;
  struct ospf6_if *ospf6_if;
  int onrequest, ismore_recent, addretrans;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;
  struct linkstate_update *lsupdate;
  int retval = 0;
  struct lsa_internal *oldp, *lsi = (struct lsa_internal *)NULL;
  list eligible_ifacelist;

  assert (newp && newp->lsh && newp->area);

  ospf6_info ("FLOODING %s\n", print_lsahdr (newp->lsh));

  eligible_ifacelist = list_init ();
  switch (GET_LSASCOPE (newp->lsh->lsh_type))
    {
    case SCOPE_LINKLOCAL:
      list_add_node (eligible_ifacelist, newp->ospf6_if);
      break;
    case SCOPE_AREA:
      for (n = listhead (newp->area->ospf6_if_list); n; nextnode (n))
        list_add_node (eligible_ifacelist, getdata (n));
      break;
    case SCOPE_AS:
      break;
    case SCOPE_RESERVED:
    default:
      ospf6_debug ("Not Reached!?\n");
      break;
    }

  /* for each eligible ospf_ifs */
  for (n = listhead (eligible_ifacelist);
       n;
       nextnode (n))
    {
      ospf6_if = (struct ospf6_if *)getdata (n);
      addretrans = 0;

      /* (1) for each neighbor */
      for (m = listhead (ospf6_if->nbr_list); m; nextnode (m))
        {
          nbr = (struct neighbor *) getdata (m);

          /* (a) */
          if (nbr->state < NBS_EXCHANGE)
            continue;  /* examin next neighbor */

          /* (b) */
          if (nbr->state == NBS_EXCHANGE
              || nbr->state == NBS_LOADING)
            {
              onrequest = 0;
              for (l = listhead (nbr->requestlist); l; nextnode (l))
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
                      ospf6_debug ("Requesting LSA is newer on %s\n",
                                   nbr->str);
                      continue; /* examin next neighbor */
                    }
                  else if (ismore_recent == 0)
                    {
                      ospf6_debug ("The same instance,Delete from"
                                   " requestlist %s\n", nbr->str);
                      list_delete_by_val (nbr->requestlist, lsi);
                      lsi_delete (lsi);
                      continue; /* examin next neighbor */
                    }
                  else /* ismore_recent < 0(the new LSA is more recent) */
                    {
                      ospf6_debug ("Delete from requestlist: %s\n",
                                   nbr->str);
                      list_delete_by_val (nbr->requestlist, lsi);
                      lsi_delete (lsi);
                    }
                }
            }

          /* (c) */
          if (newp->from == nbr)
            continue; /* examin next neighbor */

          /* (d) add retranslist */
          oldp = lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
                             newp->lsh->lsh_advrtr, newp->area,
                             newp->ospf6_if);
          if (oldp)
            {
              list_add_node (nbr->retranslist, oldp);   /* XXXXXX */
            }
          else
            {
              list_add_node (nbr->retranslist, newp);
            }
          ospf6_debug ("FLOODING: Added to retranslist of %s\n",
                       nbr->str);

          addretrans++;
          if (nbr->send_update == (struct thread *) NULL)
            {
              nbr->send_update = thread_add_timer
                (master, send_linkstate_update, nbr,
                nbr->ospf6_if->rxmt_interval);
            }
        }

      /* (2) */
      if (addretrans == 0)
        continue; /* examin next interface */
      else if (newp->from && newp->from->ospf6_if == ospf6_if)
        retval = FLOODBACK;

      /* (3) */
      if (newp->from && newp->from->ospf6_if == ospf6_if)
        {
          if (newp->from->rtr_id == newp->from->ospf6_if->dr ||
              newp->from->rtr_id == newp->from->ospf6_if->bdr)
            continue; /* examin next interface */
        }

      /* (4) */
      if (newp->from && newp->from->ospf6_if == ospf6_if
          && ospf6_if->state == IFS_BDR)
        continue; /* examin next interface */

      /* (5) send LinkState Update */
      iov_clear (iov, MAXIOVLIST);
      newp->lsh->lsh_age =
        htons (calc_lsa_age_external (newp) + ospf6_if->inf_trans_delay);
      attach_lsa_to_iov (newp, iov);
      dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
      dst.sin6_len = sizeof (struct sockaddr_in6);
      dst.sin6_scope_id = if_nametoindex (nbr->ospf6_if->interface->name);
#endif /* SIN6_LEN */
      switch (ospf6_if->state)
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

      ospf6_send (MSGT_LINKSTATE_UPDATE, iov,
                 (struct sockaddr *)&dst, ospf6_if);
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

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct lsa_hdr)
            - sizeof (struct router_lsa)) / sizeof (struct router_lsd);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, " type[%s] cost[%hu] interface_id[%s]\r\n",
               rlsatype_name[rlsdp->rlsd_type - 1],
               ntohs(rlsdp->rlsd_metric),
               inet4str (rlsdp->rlsd_interface_id));
      vty_out (vty, " NeighborIFID[%s]",
               inet4str (rlsdp->rlsd_neighbor_interface_id));
      vty_out (vty, " NeighborRouter-ID[%s]\r\n",
               inet4str (rlsdp->rlsd_neighbor_router_id));
      rlsdp++;
    }
  return 0;
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

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct lsa_hdr)
            - sizeof (struct network_lsa)) / sizeof (rtr_id_t);
  assert (lsdnum >= 0);

  for (; lsdnum; lsdnum --)
    {
      vty_out (vty, " Attached Router[%s]\r\n", inet4str (*attached++));
    }
  return 0;
}

int
show_link_lsa (struct vty *vty, void *data)
{
  struct lsa_hdr *lshp;
  struct link_lsa *llsap;
  char ntop_buf[2][INET6_ADDRSTRLEN];
  int prefixnum;
  struct in6_addr network_prefix;
  struct ospf6_prefix *prefix;

  assert (data);
  lshp = (struct lsa_hdr *)data;
  llsap = (struct link_lsa *)(lshp + 1);
  prefixnum = ntohl (llsap->llsa_prefix_num);

  vty_out (vty, " linklocal[%s]\r\n",
           inet_ntop (AF_INET6, (void *)&llsap->llsa_linklocal,
                      ntop_buf[0], sizeof (ntop_buf[0])));
  vty_out (vty, " # prefix [%d]\r\n", prefixnum);
  prefix = (struct ospf6_prefix *)(llsap + 1);
  for (; prefixnum; prefixnum--)
    {
      memset (&network_prefix, 0, sizeof (network_prefix));
      vty_out (vty, " Prefix length [%d]\r\n", prefix->o6p_prefix_len);
      memcpy (prefix + 1, &network_prefix,
              OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len));
      vty_out (vty, " Prefix [%s]\r\n",
               inet_ntop (AF_INET6, (void *)&network_prefix, ntop_buf[1],
                          sizeof (ntop_buf[1])));
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int show_intra_prefix_lsa (struct vty *vty, void *data)
{
  struct lsa_hdr *lshp;
  struct intra_area_prefix_lsa *iap_lsa;
  struct ospf6_prefix *prefix;
  int prefixnum;
  struct in6_addr network_prefix;
  char ntop_buf[2][INET6_ADDRSTRLEN];

  memset (ntop_buf[0], 0, sizeof (ntop_buf[0]));
  memset (ntop_buf[1], 0, sizeof (ntop_buf[1]));

  assert (data);
  lshp = (struct lsa_hdr *)data;
  iap_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  prefixnum = ntohs (iap_lsa->intra_prefix_num);

  vty_out (vty, " # prefix [%d]\r\n", prefixnum);
  vty_out (vty, " Referenced[%s]\r\n", print_lsahdr ((struct lsa_hdr *)iap_lsa));

  prefix = (struct ospf6_prefix *)(iap_lsa + 1);
  for (; prefixnum; prefixnum--)
    {
      memset (&network_prefix, 0, sizeof (network_prefix));
      vty_out (vty, " Prefix length [%d]\r\n", prefix->o6p_prefix_len);
      memcpy (prefix + 1, &network_prefix,
              OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len));
      vty_out (vty, " Prefix [%s]\r\n",
               inet_ntop (AF_INET6, (void *)&network_prefix, ntop_buf[1],
                          sizeof (ntop_buf[1])));
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int
vty_lsdb (struct vty *vty, struct area *area)
{
  int type, i;
  struct lsa_hdr *lshp;
  struct lsa_internal *lsip;
  listnode m, n;
  struct ospf6_if *ospf6_if;

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
                       ntohl(lshp->lsh_seqnum), ntohl(lshp->lsh_seqnum));
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

  for (n = listhead (area->ospf6_if_list); n; nextnode (n))
    {
      ospf6_if = (struct ospf6_if *) getdata (n);
      for (m = listhead (ospf6_if->linklocal_lsa); m; nextnode (m))
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
  return 0;
}

