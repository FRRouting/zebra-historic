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

void
lsa_expire_cancel (struct lsa_internal *lsa)
{
  if (lsa->expire)
    {
      thread_cancel (lsa->expire);
      lsa->expire = (struct thread *)NULL;
    }
  return;
}

void
lsa_refresh_cancel (struct lsa_internal *lsa)
{
  o6log.debug ("%s: refresh timer canceled", print_lsahdr (lsa->lsh));
  if (lsa->refresh)
    {
      thread_cancel (lsa->refresh);
      lsa->refresh = (struct thread *)NULL;
    }
  return;
}

static struct lsa_hdr *
malloc_lsa (struct lsa_hdr *lsh)
{
  struct lsa_hdr *retval;
  retval = (struct lsa_hdr *)XMALLOC(MTYPE_OSPF_LSA, ntohs (lsh->lsh_len));
  memset (retval, 0, ntohs (lsh->lsh_len));

  log_pointer ("Allocate LSA Body(%#x[%#x]) for %s",
               retval, ntohs (lsh->lsh_len), print_lsahdr (lsh));

  return retval;
}

void
free_lsa (struct lsa_hdr *lsh)
{
  log_pointer ("Free LSA Body(%#x) for %s",
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

  log_pointer ("Allocate LSA Internal Hdr(%#x[%#x]) for %s",
               retval, sizeof (struct lsa_internal), print_lsahdr (lsh));

  return retval;
}

void
free_lsa_internal_hdr (struct lsa_internal *lsi)
{
  lsa_expire_cancel (lsi);
  lsa_refresh_cancel (lsi);

  assert (lsi->retransing_nbr);
  list_delete_all (lsi->retransing_nbr);

  log_pointer ("Free LSA Internal Hdr(%#x) for %s",
               lsi, print_lsahdr (lsi->lsh));

  XFREE (MTYPE_OSPF_LSA, lsi);
  return;
}

int
expire_lsa_age (struct thread *thread)
{
  struct lsa_internal *lsi;

  lsi = (struct lsa_internal *)THREAD_ARG  (thread);
  assert (lsi && lsi->lsh && lsi->area);

  assert (lsi->refresh == NULL);
  lsi->expire = (struct thread *)NULL;
  o6log.lsa ("expire! %s", print_lsahdr (lsi->lsh));
  lsa_delete (lsi);

  return 0;
}

int
calc_lsa_age_internal (struct lsa_internal *lsi)
{
  struct timeval now;

  assert (lsi && lsi->lsh);

  gettimeofday (&now, (struct timezone *)NULL);
  lsi->birth = now.tv_sec - ntohs (lsi->lsh->lsh_age);
  lsa_expire_cancel (lsi);
  lsi->expire = thread_add_timer (master, expire_lsa_age, lsi,
                                  lsi->birth + MAXAGE - now.tv_sec);
  return 0;
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
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  return lsi;
}

struct lsa_internal *
make_lsa_internal (struct lsa_hdr *lsa, struct neighbor *from)
{
  struct lsa_internal *lsi;
  struct lsa_hdr *lsh;

  lsh = malloc_lsa (lsa);
  memcpy (lsh, lsa, ntohs (lsa->lsh_len));

  lsi= malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = from;
  lsi->ospf6_if = from->ospf6_if;
  lsi->area = from->ospf6_if->area;
  lsi->refresh = (struct thread *)NULL;
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  return lsi;
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
      zvlog_debug ("Recent is decided by SeqNum");
      return -1;
    }
  else if (seqnuma < seqnumb)
    {
      zvlog_debug ("Recent is decided by SeqNum");
      return 1;
    }
  else
    {
      /* XXX Checksum */

      if (ntohs (a->lsh->lsh_age) == MAXAGE
                 && ntohs (b->lsh->lsh_age) != MAXAGE)
        {
          zvlog_debug ("Recent is decided by MaxAge");
          return -1;
        }
      else if (ntohs (a->lsh->lsh_age) != MAXAGE
               && ntohs (b->lsh->lsh_age) == MAXAGE)
        {
          zvlog_debug ("Recent is decided by MaxAge");
          return 1;
        }
      else
        {
          ab = calc_lsa_age_external (a) - calc_lsa_age_external (b);
          ba = calc_lsa_age_external (b) - calc_lsa_age_external (a);
          if (ab > MAX_AGE_DIFF)
            {
              zvlog_debug ("Recent is decided by Age diff(%d)", ab);
              return 1;
            }
          else if (ba > MAX_AGE_DIFF)
            {
              zvlog_debug ("Recent is decided by Age diff(%d)", ba);
              return -1;
            }
          else
            {
              return 0;
            }
        }
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

int
lsa_refresh (struct thread *thread)
{
  struct lsa_internal *lsi;

  assert (thread);
  lsi = (struct lsa_internal *)THREAD_ARG  (thread);
  assert (lsi && lsi->lsh);

  lsi->refresh = (struct thread *)NULL;
  lsa_expire_cancel (lsi);

  o6log.lsa ("refresh %s", print_lsahdr (lsi->lsh));
  construct_lsa (lsi);

  return 0;
}

int
originating_lsa (struct lsa_internal *newp)
{
  struct lsa_internal *oldp;

  assert (newp->lsh->lsh_advrtr == newp->area->ospf6->router_id);
  o6log.lsa ("originating %s", print_lsahdr (newp->lsh));

  oldp = lsa_lookup (newp->lsh->lsh_type, newp->lsh->lsh_id,
                     newp->lsh->lsh_advrtr, newp->area, newp->ospf6_if);
  if (oldp && oldp->refresh)
    {
      if (newp->lsh->lsh_len == oldp->lsh->lsh_len &&
          !memcmp (newp->lsh + 1, oldp->lsh + 1,
                   ntohs (newp->lsh->lsh_len) - sizeof (struct lsa_hdr)))
        {
          o6log.lsa ("don't install %s: body not changed",
                     print_lsahdr (newp->lsh));
          free_lsa (newp->lsh);
          free_lsa_internal_hdr (newp);
          return 0;
        }
    }

  lsa_flood (newp);
  lsa_install (newp);
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

  o6log.lsa ("construct RouterLSA");

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
  o6log.pointer ("pointer %#x for my RouterLSA", lsa);
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
          rlsdp->rlsd_interface_id = htonl (ospf6_if->ifid);
          rlsdp->rlsd_neighbor_interface_id = htonl (nbr->ifid);
          rlsdp->rlsd_neighbor_router_id = nbr->rtr_id;

          rlsdp++;
        }
      else if (if_is_broadcast (ospf6_if->interface))
        {
          if (ospf6_if->state == IFS_DR)
            {
              rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
              rlsdp->rlsd_metric = htons (ospf6_if->cost);
              rlsdp->rlsd_interface_id = htonl (ospf6_if->ifid);
              rlsdp->rlsd_neighbor_interface_id = htonl (ospf6_if->ifid);
              rlsdp->rlsd_neighbor_router_id = area->ospf6->router_id;
              rlsdp++;
            }
          else
            {
              rlsdp->rlsd_type = LSDT_TRANSIT_NETWORK;
              rlsdp->rlsd_metric = htons (ospf6_if->cost);
              rlsdp->rlsd_interface_id = htonl (ospf6_if->ifid);
              nbr = nbr_lookup (ospf6_if->dr, ospf6_if->area->ospf6);
              assert (nbr);
              rlsdp->rlsd_neighbor_interface_id = htonl (nbr->ifid);
              rlsdp->rlsd_neighbor_router_id = ospf6_if->dr;
              rlsdp++;
            }
        }
      else
        {
          zvlog_err ("Not supported type of interface: %s",
                     ospf6_if->interface->name);
          continue;
        }
    }

  /* XXX Checksum */

  /* Router-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = (struct ospf6_if *)NULL;
  lsi->area = area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  originating_lsa (lsi);
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

  o6log.lsa ("construct NetworkLSA");

  /* Is this link Transit ? */
  attached_rtr = 0;
  for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
    {
      nbr = (struct neighbor *) getdata (n);
      if (nbr->state == NBS_FULL)
        attached_rtr++;
    }

  if (!attached_rtr)
    {
      o6log.lsa ("%s connected to stublink", ospf6_if->interface->name);
      return 0;
    }

  space = sizeof (struct lsa_hdr) + sizeof (struct network_lsa)
          + sizeof (rtr_id_t) * (attached_rtr + 1);
  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  o6log.pointer ("pointer %#x for my NetworkLSA", lsa);
  memset (lsa, 0, space);

  lsh = (struct lsa_hdr *) lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_NETWORK_LSA);
  lsh->lsh_id = htonl (ospf6_if->ifid);
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

  /* Network-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh,
                                   lsi, LS_REFRESH_TIME);
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  originating_lsa (lsi);
  return 0;
}

int
construct_link_lsa (struct ospf6_if *ospf6_if)
{
  int space, already;
  listnode i, j;
  char *lsa;
  struct lsa_hdr *lsh;
  struct connected *c;
  struct link_lsa *llsap;
  struct ospf6_prefix *p;
  struct in6_addr *linklocal, *network_prefix;
  struct lsa_internal *lsi;
  int prefixnum;
  list adv_list;
  struct prefix *prefix, prefixbuf;

  o6log.lsa ("construct LinkLSA");

  adv_list = list_init ();

  /* see through connected list to make advertise prefix list
     and linklocal address */
  space = prefixnum = 0;
  linklocal = (struct in6_addr *)NULL;
  for (i = listhead (ospf6_if->interface->connected); i; nextnode (i))
    {
      c = (struct connected *) getdata (i);

      if (c->address->family != AF_INET6)
        continue;
      if (IN6_IS_ADDR_LOOPBACK (&c->address->u.prefix6))
        continue;
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        {
          linklocal = &c->address->u.prefix6;
          continue;
        }

      prefix_copy (&prefixbuf, c->address);
      apply_mask_ipv6 ((struct prefix_ipv6 *)&prefixbuf);
      prefix2str (&prefixbuf, strbuf, sizeof (strbuf));

      /* check for duplicate prefixes */
      already = 0;
      for (j = listhead (adv_list); j; nextnode (j))
        {
          prefix = getdata (j);
          if (prefix_cmp (prefix, c->address) == 0)
            {
              already++;
              break;
            }
        }
      if (already)
        {
          o6log.lsa ("duplicate prefix %s not inserted", strbuf);
          continue;
        }

      o6log.lsa ("advertise %s in LinkLSA", strbuf);
      list_add_node (adv_list, c->address);
      space += OSPF6_PREFIX_SPACE (c->address->prefixlen)
               + sizeof (struct ospf6_prefix);
      prefixnum++;
    }
  space += sizeof (struct link_lsa) + sizeof (struct lsa_hdr);
  assert (linklocal); /* xxx */

  lsa = XMALLOC (MTYPE_OSPF_LSA, space);
  o6log.pointer ("pointer %#x for my LinkLSA", lsa);
  memset (lsa, 0, space);
  lsh = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_LINK_LSA);
  lsh->lsh_id = htonl (ospf6_if->ifid);
  lsh->lsh_advrtr = ospf6_if->area->ospf6->router_id;
  lsh->lsh_seqnum = htonl(ospf6_if->area->link_lsa_seqnum++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  llsap = (struct link_lsa *)(lsh + 1);
  llsap->llsa_rtr_pri = ospf6_if->rtr_pri;
  memcpy (llsap->llsa_options, ospf6_if->area->options,
          sizeof llsap->llsa_options);
  memcpy (&llsap->llsa_linklocal, linklocal, sizeof (llsap->llsa_linklocal));
  llsap->llsa_prefix_num = htonl (prefixnum);

  p = (struct ospf6_prefix *)(llsap + 1);
  for (i = listhead (adv_list); i; nextnode (i))
    {
      prefix = (struct prefix *) getdata (i);
      prefix_copy (&prefixbuf, prefix);
      apply_mask_ipv6 ((struct prefix_ipv6 *)&prefixbuf);

      p->o6p_prefix_len = prefix->prefixlen;
      /* XXX p->o6p_prefix_options */

      network_prefix = (struct in6_addr *)(p + 1);
      memcpy (network_prefix, &prefixbuf.u.prefix6,
              OSPF6_PREFIX_SPACE (prefixbuf.prefixlen));
      p = OSPF6_NEXT_PREFIX (p);
    }

  /* XXX! Calculate Checksum! */

  /* Link-LSA is now constructed.
     store this in appropriate place (Ospf6_If Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;

  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  originating_lsa (lsi);
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

  o6log.lsa ("construct IntraAreaPrefixLSA");

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
      o6log.lsa ("not DR on transit link %s", ospf6_if->interface->name);
      return 0;
    }

  if (ospf6_if->state == IFS_DR)   /* I'm DR */
    {
      for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
        {
          nbr = (struct neighbor *) getdata (n);
          if (nbr->state != NBS_FULL)
            continue;

          lsi = lsa_lookup (htons (LST_LINK_LSA), htonl (nbr->ifid),
                            nbr->rtr_id, ospf6_if->area, ospf6_if);
          if (!lsi)
            {
              o6log.lsa ("full but LinkLSA not found for %s", nbr->str);
              continue;
            }

          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {
              if (IN6_IS_ADDR_V4MAPPED ((struct in6_addr *)(p + 1)))
                {
                  o6log.lsa ("v4mapped address ignored");
                  continue;
                }

              already = 0;
              for (m = listhead (prefix_collection); m; nextnode (m))
                {
                  q = (struct ospf6_prefix *) getdata (m);
                  if (memcmp (p, q, OSPF6_PREFIX_SIZE (p)) == 0)
                    already++;
                }
              if (already == 0 && ntohl (linklsa->llsa_prefix_num))
                list_add_node (prefix_collection, p);
            }

        }

      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), htonl (ospf6_if->ifid),
                        ospf6_if->area->ospf6->router_id,
                        ospf6_if->area, ospf6_if);
      if (!lsi)
        {
          o6log.lsa ("can't find my LinkLSA");
        }
      else
        {
          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {

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
  else if (list_isempty (ospf6_if->nbr_list)) /* XXX */
    {
      /* this is for not DR on stub link. if I don't advertise
         prefixes of this link, nobody will. */

      /* Link-LSA of myself */
      lsi = lsa_lookup (htons (LST_LINK_LSA), htonl (ospf6_if->ifid),
                        ospf6_if->area->ospf6->router_id,
                        ospf6_if->area, ospf6_if);
      if (!lsi)
        {
          o6log.lsa ("can't find my LinkLSA");
        }
      else
        {
          linklsa = (struct link_lsa *)(lsi->lsh + 1);
          p = (struct ospf6_prefix *)(linklsa + 1);
          for (i = 0; i < ntohl (linklsa->llsa_prefix_num);
               i++, p = OSPF6_NEXT_PREFIX (p))
            {
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
      o6log.lsa ("no need to construct IntraAreaPrefixLSA");
      return 0;
    }

  if (!listcount (prefix_collection))
    {
      o6log.lsa ("no prefix to advertise");
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
  o6log.pointer ("pointer %#x for my IntraAreaPrefixLSA", lsa);
  memset (lsa, 0, space);
  lsh = (struct lsa_hdr *)lsa;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);

/* XXX I don't know appropreate value for LS-ID */
#if 0
  if (fullnbnum)   /* For Transit Network */
    lsh->lsh_id = htonl (ospf6_if->ifid);
  else             /* For Stub Network */
    lsh->lsh_id = htonl (MY_ROUTER_LSA_ID);
#else
  lsh->lsh_id = htonl (ospf6_if->ifid);
#endif

  lsh->lsh_advrtr = ospf6_if->area->ospf6->router_id;
  lsh->lsh_seqnum = htonl(ospf6_if->area->intra_prefix_seqnum++);
  /* checksum later */
  lsh->lsh_len = htons (space);

  intra_prefix_lsa = (struct intra_area_prefix_lsa *)(lsh + 1);
  intra_prefix_lsa->intra_prefix_num =
      htons (listcount (prefix_collection));

  if (fullnbnum)
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = htonl (ospf6_if->ifid);
    }
  else
    {
      intra_prefix_lsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      intra_prefix_lsa->intra_prefix_refer_lsid = htonl (0);
    }

  intra_prefix_lsa->intra_prefix_refer_advrtr
    = ospf6_if->area->ospf6->router_id;

  q = (struct ospf6_prefix *)(intra_prefix_lsa + 1);
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = (struct ospf6_prefix *) getdata (n);
      memcpy (q, p, OSPF6_PREFIX_SIZE (p));
      q->o6p_prefix_metric = htons (ospf6_if->cost);
      q = OSPF6_NEXT_PREFIX (q);
    }

  /* XXX! Calculate Checksum! */

  /* Intra-Area-Prefix-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsi = malloc_lsa_internal_hdr (lsh);
  lsi->lsh = lsh;
  lsi->from = (struct neighbor *)NULL;
  lsi->ospf6_if = ospf6_if;
  lsi->area = ospf6_if->area;
  lsi->refresh = thread_add_timer (master, lsa_refresh, lsi, LS_REFRESH_TIME);
  lsi->retransing_nbr = list_init ();
  calc_lsa_age_internal (lsi);

  originating_lsa (lsi);
  return 0;
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
      vty_out (vty, "     type[%s] cost[%hu] interface_id[%s]\r\n",
               rlsatype_name[rlsdp->rlsd_type - 1],
               ntohs(rlsdp->rlsd_metric),
               inet4str (rlsdp->rlsd_interface_id));
      vty_out (vty, "     NeighborIFID[%s]",
               inet4str (rlsdp->rlsd_neighbor_interface_id));
      vty_out (vty, "     NeighborRouter-ID[%s]\r\n",
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
      vty_out (vty, "     Attached Router[%s]\r\n", inet4str (*attached++));
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

  vty_out (vty, "     linklocal[%s]\r\n",
           inet_ntop (AF_INET6, (void *)&llsap->llsa_linklocal,
                      ntop_buf[0], sizeof (ntop_buf[0])));
  vty_out (vty, "     # prefix [%d]\r\n", prefixnum);
  prefix = (struct ospf6_prefix *)(llsap + 1);
  for (; prefixnum; prefixnum--)
    {
      memset (&network_prefix, 0, sizeof (network_prefix));
      vty_out (vty, "     Prefix length [%d]\r\n", prefix->o6p_prefix_len);
      memcpy (&network_prefix, prefix + 1,
              OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len));
      vty_out (vty, "     Prefix [%s]\r\n",
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

  vty_out (vty, "     # prefix [%d]\r\n", prefixnum);
  vty_out (vty, "     Referenced[%s]\r\n",
           print_lsahdr ((struct lsa_hdr *)iap_lsa));

  prefix = (struct ospf6_prefix *)(iap_lsa + 1);
  for (; prefixnum; prefixnum--)
    {
      memset (&network_prefix, 0, sizeof (network_prefix));
      vty_out (vty, "     Prefix length [%d]\r\n", prefix->o6p_prefix_len);
      memcpy (&network_prefix, prefix + 1,
              OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len));
      vty_out (vty, "     Prefix [%s]\r\n",
               inet_ntop (AF_INET6, (void *)&network_prefix, ntop_buf[1],
                          sizeof (ntop_buf[1])));
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int
vty_lsa (struct vty *vty, struct lsa_internal *lsi)
{
  struct lsa_hdr *lsh;

  assert (lsi && lsi->area);
  lsh = lsi->lsh;
  assert (lsh);

  vty_out (vty, "%s\r\n", print_lsahdr (lsh));
  vty_out (vty, "    LS age[%d] LS SeqNum[%#x]\r\n",
           calc_lsa_age_external (lsi),
           ntohl(lsh->lsh_seqnum));
  switch (ntohs (lsh->lsh_type))
    {
    case LST_ROUTER_LSA:
      show_router_lsa (vty, (void *)lsh);
      break;
    case LST_NETWORK_LSA:
      show_network_lsa (vty, (void *)lsh);
      break;
    case LST_LINK_LSA:
      show_link_lsa (vty, (void *)lsh);
      break;
    case LST_INTRA_AREA_PREFIX_LSA:
      show_intra_prefix_lsa (vty, (void *)lsh);
      break;
    default:
      break;
    }
  return 0;
}

struct router_lsd *
get_router_lsd (rtr_id_t rtrid, struct lsa_internal *lsa)
{
  unsigned short lsh_len;
  struct router_lsa *rlsa;
  struct router_lsd *rlsd;

  if (ntohs (lsa->lsh->lsh_type) != LST_ROUTER_LSA)
    return NULL;

  lsh_len = ntohs (lsa->lsh->lsh_len);
  rlsa = (struct router_lsa *)(lsa->lsh + 1);
  rlsd = (struct router_lsd *)(rlsa + 1);

  for ( ; (char *)rlsd < (char *)lsa + lsh_len; rlsd++)
    if (rtrid == rlsd->rlsd_neighbor_router_id)
      return rlsd;

  return NULL;
}

unsigned long
get_ifindex_to_router (rtr_id_t rtrid, struct lsa_internal *lsa)
{
  struct router_lsd *rlsd;

  assert (lsa);
  switch (ntohs (lsa->lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        rlsd = get_router_lsd (rtrid, lsa);
        if (!rlsd)
          return 0;
        else
          return (ntohl (rlsd->rlsd_interface_id));
      case LST_NETWORK_LSA:
        return (ntohl (lsa->lsh->lsh_id));
      default:
        return 0;
    }
  return 0;
}



/* Back pointer check, Is X's reference field bound to y? */
#define x_ipl(x) ((struct intra_area_prefix_lsa *)LSH_NEXT((x)->lsh))
#define is_reference_network_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsh->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == (y)->lsh->lsh_id &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsh->lsh_advrtr)
  /* referencing router's ifid must be 0,
     see draft-ietf-ospf-ospfv6-06.txt */
#define is_reference_router_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsh->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == htonl (0) &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsh->lsh_advrtr)

/* return list of LSAs that referencing this LSA(internal to area) */
list
get_referencing_lsa (struct lsa_internal *lsa)
{
  char tmpbuf[64];
  list tmplist, retlist = list_init ();
  listnode n;
  struct lsa_internal *x;

  assert (lsa->area);
  switch (ntohs (lsa->lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        tmplist = lsa_lookup_by_advrtr (htons (LST_INTRA_AREA_PREFIX_LSA),
                                        lsa->lsh->lsh_advrtr, lsa->area);
        if (tmplist)
          {
            for (n = listhead (tmplist); n; nextnode (n))
              {
                x = getdata (n);
                if (is_reference_router_ok (x, lsa))
                  {
                    memcpy (tmpbuf, print_lsahdr (x->lsh), sizeof (tmpbuf));
                    o6log.lsa ("%s references %s",
                               tmpbuf,
                               print_lsahdr (lsa->lsh));
                    list_add_node (retlist, x);
                  }
              }
            list_delete_all (tmplist);
          }
        break;

      case LST_NETWORK_LSA:
        x = lsa_lookup (htons (LST_INTRA_AREA_PREFIX_LSA),
                        lsa->lsh->lsh_id, lsa->lsh->lsh_advrtr,
                        lsa->area, NULL);
        if (x && is_reference_network_ok (x, lsa))
          {
            o6log.lsa ("%s references %s",
                       print_lsahdr (x->lsh),
                       print_lsahdr (lsa->lsh));
            list_add_node (retlist, x);
          }
        break;

      default:
        break;
    }

  if (list_isempty (retlist))
    {
      o6log.lsa ("no lsa references %s", print_lsahdr (lsa->lsh));
      list_delete_all (retlist);
      retlist = NULL;
    }

  /* don't forget to list_delete_all () later */
  return retlist;
}

int
is_self_originated (struct lsa_internal *p)
{
  if (p->lsh->lsh_advrtr == p->area->ospf6->router_id)
    return 1;
  return 0;
}

void
update_ls_seqnum (struct lsa_internal *p)
{
  signed long seqnum;

  seqnum = ntohl (p->lsh->lsh_seqnum) + 1;
  switch (ntohs (p->lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        p->area->router_lsa_seqnum = seqnum;
        break;
      case LST_NETWORK_LSA:
        p->area->network_lsa_seqnum = seqnum;
        break;
      case LST_INTRA_AREA_PREFIX_LSA:
        p->area->intra_prefix_seqnum = seqnum;
        break;
      case LST_LINK_LSA:
        p->area->link_lsa_seqnum = seqnum;
        break;
      default:
        break;
    }
  o6log.lsa ("seqnum for %s updated to %d(%#x)",
             lstype_name [typeindex (p->lsh->lsh_type)],
             seqnum, seqnum);
  return;
}

void
construct_lsa (struct lsa_internal *lsa)
{
  switch (ntohs (lsa->lsh->lsh_type))
    {
      case LST_ROUTER_LSA:
        assert (lsa->area);
        construct_router_lsa (lsa->area);
        break;

      case LST_NETWORK_LSA:
        assert (lsa->ospf6_if);
        construct_network_lsa (lsa->ospf6_if);
        break;

      case LST_INTRA_AREA_PREFIX_LSA:
        assert (lsa->ospf6_if);
        construct_intra_prefix_lsa (lsa->ospf6_if);
        break;

      case LST_LINK_LSA:
        assert (lsa->ospf6_if);
        construct_link_lsa (lsa->ospf6_if);
        break;

      default:
        break;
    }
  return;
}

