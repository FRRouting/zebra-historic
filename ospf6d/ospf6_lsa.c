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

/* return 1 if MIN_LS_INTERVAL have past, else 0 */
int
past_min_ls_interval (struct ospf6_lsa *lsa)
{
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);
  gettimeofday (&now, (struct timezone *)NULL);

  if (now.tv_sec - lsa->birth < MIN_LS_INTERVAL)
    return 0;

  return 1;
}

/* check which is more recent. if a is more recent, return -1;
   if the same, return 0; otherwise(b is more recent), return 1 */
int
which_is_more_recent (struct ospf6_lsa *a, struct ospf6_lsa *b)
{
  signed long seqnuma, seqnumb;
  int ab, ba;

  assert (a && a->lsa_hdr);
  assert (b && b->lsa_hdr);
  assert (ospf6_lsa_issame (a->lsa_hdr, b->lsa_hdr));

  seqnuma = ((signed long) ntohl (a->lsa_hdr->lsh_seqnum))
              - (signed long)INITIAL_SEQUENCE_NUMBER;
  seqnumb = ((signed long) ntohl (b->lsa_hdr->lsh_seqnum))
              - (signed long)INITIAL_SEQUENCE_NUMBER;

  /* XXX, care about LS sequence number wrapping */
  if (seqnuma > seqnumb)
    {
      o6log.lsa ("a is more recent (seqnum)");
      o6log.debug ("a:%d(%#x), b:%d(%#x)",
                   seqnuma, ntohl (a->lsa_hdr->lsh_seqnum),
                   seqnumb, ntohl (b->lsa_hdr->lsh_seqnum));
      return -1;
    }
  else if (seqnuma < seqnumb)
    {
      o6log.lsa ("b is more recent (seqnum)");
      o6log.debug ("a:%d(%#x), b:%d(%#x)",
                   seqnuma, ntohl (a->lsa_hdr->lsh_seqnum),
                   seqnumb, ntohl (b->lsa_hdr->lsh_seqnum));
      return 1;
    }
  else
    {
      /* XXX Checksum */

      if (ntohs (a->lsa_hdr->lsh_age) == MAXAGE
                 && ntohs (b->lsa_hdr->lsh_age) != MAXAGE)
        {
          o6log.lsa ("a is more recent (MaxAge)");
          return -1;
        }
      else if (ntohs (a->lsa_hdr->lsh_age) != MAXAGE
               && ntohs (b->lsa_hdr->lsh_age) == MAXAGE)
        {
          o6log.lsa ("b is more recent (MaxAge)");
          return 1;
        }
      else
        {
          ab = ospf6_age_current (a) - ospf6_age_current (b);
          ba = ospf6_age_current (b) - ospf6_age_current (a);
          if (ab > MAX_AGE_DIFF)
            {
              o6log.lsa ("b is more recent (Age)");
              return 1;
            }
          else if (ba > MAX_AGE_DIFF)
            {
              o6log.lsa ("a is more recent (Age)");
              return -1;
            }
          else
            {
              o6log.lsa ("the same instance");
              return 0;
            }
        }
    }
}

void
originating_lsa (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *have;
  struct area *area;
  struct ospf6_if *o6if;
  struct ospf6 *ospf6;

  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) lsa->scope;
        area = o6if->area;
        ospf6 = area->ospf6;
        break;

      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6 = area->ospf6;
        break;

      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        o6log.lsa ("unsupported scope, can't originate");
        return;
    }

  assert (lsa->lsa_hdr->lsh_advrtr == ospf6->router_id);
  o6log.lsa ("originating %s", print_lsahdr (lsa->lsa_hdr));

  have = ospf6_lsdb_lookup (lsa->lsa_hdr->lsh_type, lsa->lsa_hdr->lsh_id,
                            lsa->lsa_hdr->lsh_advrtr, lsa->scope);
  if (have)
    {
      /* this indicate this origination is not caused by refresh */
      if (have->refresh)
        {
          /* if body not changed, do not originate */
          if (ntohs (have->lsa_hdr->lsh_len) == ntohs (lsa->lsa_hdr->lsh_len)
              && !memcmp (have->lsa_hdr + 1, lsa->lsa_hdr + 1,
                          ntohs (have->lsa_hdr->lsh_len)))
            {
              o6log.lsa ("body no change, don't originate %s",
                         print_lsahdr (have->lsa_hdr));
              return;
            }
        }
    }

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  return;
}

/* xxx, We don't support sending multiple (seperate) Router-LSA yet,
   so Link State ID field of Router-LSA will be always the same */
void
construct_router_lsa (struct area *area)
{
#if 0
  list described_link;
  listnode n, m;
  struct ospf6_if *ospf6_if;
  struct neighbor *nbr;
  int space;
  char *lsabody;
  struct ospf6_lsa_hdr *lsh;
  struct ospf6_lsa *lsa;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  o6log.lsa ("construct RouterLSA");

  /* check needed space for LSA by looking up ospf6_ifs.
     ospf6_if to be described are collected. */
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

  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct router_lsa)
    + (sizeof (struct router_lsd) * listcount (described_link));

  lsabody = XMALLOC (MTYPE_OSPF6_LSA, space);
  o6log.pointer ("pointer %#x for my RouterLSA", lsabody);
  memset (lsabody, 0, space);

  lsh = (struct ospf6_lsa_hdr *) lsabody;
  /* age later (after checksum) */
  lsh->lsh_age = 0;
  lsh->lsh_type = htons (LST_ROUTER_LSA);
  lsh->lsh_id = htonl (MY_ROUTER_LSA_ID);
  lsh->lsh_advrtr = area->ospf6->router_id;
  area->router_lsa_seqnum++;
  lsh->lsh_seqnum = htonl(area->router_lsa_seqnum);
  /* checksum later */
  lsh->lsh_len = htons (space);

  rlsap = (struct router_lsa *) ((char *)lsh + sizeof (struct ospf6_lsa_hdr));
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
          o6log.lsa ("not supported type of interface: %s",
                      ospf6_if->interface->name);
          continue;
        }
    }

  /* XXX Checksum */

  /* Router-LSA is now constructed.
     store this in appropriate place (Area Data Structure) */
  lsa = make_ospf6_lsa (lsh);
  lsa->scope = (void *) area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);
#else
  struct ospf6_lsa *lsa;
  lsa = ospf6_make_router_lsa (area);
#endif

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_network_lsa (struct ospf6_if *ospf6_if)
{
#if 0
  struct neighbor *nbr;
  listnode n;
  int attached_rtr;
  int space;
  struct ospf6_lsa_hdr *lsh;
  char *lsabody;
  rtr_id_t *p;
  struct network_lsa *nlsap;
  struct ospf6_lsa *lsa;

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
      return;
    }

  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct network_lsa)
          + sizeof (rtr_id_t) * (attached_rtr + 1);
  lsabody = XMALLOC (MTYPE_OSPF_LSA, space);
  o6log.pointer ("pointer %#x for my NetworkLSA", lsabody);
  memset (lsabody, 0, space);

  lsh = (struct ospf6_lsa_hdr *) lsabody;
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
  lsa = make_ospf6_lsa (lsh);
  lsa->scope = (void *) ospf6_if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh,
                                   lsa, LS_REFRESH_TIME);
#else
  struct ospf6_lsa *lsa;
  lsa = ospf6_make_network_lsa (ospf6_if);
  if (!lsa)
    return;
#endif

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_link_lsa (struct ospf6_if *ospf6_if)
{
#if 0
  int space;
  listnode i;
  char *lsabody;
  struct ospf6_lsa_hdr *lsh;
  struct connected *c;
  struct link_lsa *llsap;
  struct ospf6_prefix *p1, *p2;
  struct in6_addr *linklocal;
  struct ospf6_lsa *lsa;
  int prefixnum;

  /* get linklocal address of this interface */
  linklocal = (struct in6_addr *)NULL;
  for (i = listhead (ospf6_if->interface->connected); i; nextnode (i))
    {
      c = (struct connected *) getdata (i);

      if (c->address->family != AF_INET6)
        continue;

      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        {
          linklocal = &c->address->u.prefix6;

#ifdef KAME
          /* save Kame, clear ifindex included in address */
          if (linklocal->s6_addr8[1] & 0x0f)
            linklocal->s6_addr8[1] &= ~((char)0x0f);
#endif /* KAME */

          break;
        }

    }
  assert (linklocal); /* xxx */

  /* get prefix number */
  prefixnum = listcount (ospf6_if->prefix_connected);

  /* get space needed for all prefix */
  space = 0;
  for (i = listhead (ospf6_if->prefix_connected); i; nextnode (i))
    {
      p1 = (struct ospf6_prefix *) getdata (i);
      space += OSPF6_PREFIX_SIZE (p1);
    }

  space += sizeof (struct link_lsa) + sizeof (struct ospf6_lsa_hdr);

  lsabody = XMALLOC (MTYPE_OSPF6_LSA, space);
  o6log.pointer ("pointer %#x for my LinkLSA", lsabody);
  memset (lsabody, 0, space);
  lsh = (struct ospf6_lsa_hdr *)lsabody;
  lsh->lsh_age = 0; /* age later (after checksum) */
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

  p1 = (struct ospf6_prefix *)(llsap + 1);
  space -= sizeof (struct link_lsa) + sizeof (struct ospf6_lsa_hdr);
  for (i = listhead (ospf6_if->prefix_connected); i; nextnode (i))
    {
      p2 = (struct ospf6_prefix *) getdata (i);
      ospf6_prefix_copy (p1, p2, space);
      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* XXX! Calculate Checksum! */

  /* Link-LSA is now constructed.
     store this in appropriate place (Ospf6_If Data Structure) */
  lsa = make_ospf6_lsa (lsh);
  lsa->scope = (void *) ospf6_if;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);
#else
  struct ospf6_lsa *lsa;
  lsa = ospf6_make_link_lsa (ospf6_if);
  if (!lsa)
    return;
#endif

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_intra_prefix_lsa (struct ospf6_if *ospf6_if)
{
#if 0
  int i, already, space, fullnbnum;
  char *lsabody;
  struct neighbor *nbr;
  struct ospf6_lsa *lsa;
  struct link_lsa *linklsa;
  struct ospf6_prefix *p, *q;
  struct ospf6_lsa_hdr *lsh;
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
      return;
    }

  if (ospf6_if->state == IFS_DR)   /* I'm DR */
    {
      for (n = listhead (ospf6_if->nbr_list); n; nextnode (n))
        {
          nbr = (struct neighbor *) getdata (n);
          if (nbr->state != NBS_FULL)
            continue;

          lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (nbr->ifid),
                                   nbr->rtr_id, (void *) nbr->ospf6_if);
          if (!lsa)
            {
              o6log.lsa ("full but LinkLSA not found for %s", nbr->str);
              continue;
            }

          linklsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
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
      lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (ospf6_if->ifid),
                               ospf6_if->area->ospf6->router_id,
                               (void *)ospf6_if);
      if (!lsa)
        {
          o6log.lsa ("can't find my LinkLSA");
        }
      else
        {
          linklsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
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
      lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (ospf6_if->ifid),
                               ospf6_if->area->ospf6->router_id,
                               (void *)ospf6_if);
      if (!lsa)
        {
          o6log.lsa ("can't find my LinkLSA");
        }
      else
        {
          linklsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
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
      return;
    }

  if (!listcount (prefix_collection))
    {
      o6log.lsa ("no prefix to advertise");
      return;
    }

  /* check necessary space */
  space = 0;
  for (n = listhead (prefix_collection); n; nextnode (n))
    {
      p = (struct ospf6_prefix *)getdata (n);
      space += OSPF6_PREFIX_SIZE (p);
    }
  space += sizeof (struct intra_area_prefix_lsa)
           + sizeof (struct ospf6_lsa_hdr);

  /* construct instance of LSA */
  lsabody = XMALLOC (MTYPE_OSPF_LSA, space);
  o6log.pointer ("pointer %#x for my IntraAreaPrefixLSA", lsabody);
  memset (lsabody, 0, space);
  lsh = (struct ospf6_lsa_hdr *)lsabody;
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
  lsh->lsh_seqnum = htonl (ospf6_if->area->intra_prefix_seqnum++);
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
  lsa = make_ospf6_lsa (lsh);
  lsa->scope = (void *) ospf6_if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);
#else
  struct ospf6_lsa *lsa;
  lsa = ospf6_make_intra_prefix_lsa (ospf6_if);
#endif

  ospf6_lsa_flood (lsa);
  ospf6_lsdb_install (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

int show_router_lsa (struct vty *vty, void *data)
{
  int lsdnum;
  struct ospf6_lsa_hdr *lshp;
  struct router_lsa *rlsap;
  struct router_lsd *rlsdp;

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  rlsap = (struct router_lsa *)(lshp + 1);
  rlsdp = (struct router_lsd *)(rlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct ospf6_lsa_hdr)
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
  struct ospf6_lsa_hdr *lshp;
  struct network_lsa *nlsap;
  rtr_id_t *attached;

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  nlsap = (struct network_lsa *)(lshp + 1);
  attached = (rtr_id_t *)(nlsap + 1);

  lsdnum = (ntohs (lshp->lsh_len) - sizeof (struct ospf6_lsa_hdr)
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
  struct ospf6_lsa_hdr *lshp;
  struct link_lsa *llsap;
  int prefixnum;
  struct ospf6_prefix *prefix;
  char o6p_str[128], linklocal_str[128];

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  llsap = (struct link_lsa *)(lshp + 1);
  prefixnum = ntohl (llsap->llsa_prefix_num);

  inet_ntop (AF_INET6, (void *)&llsap->llsa_linklocal, linklocal_str,
             sizeof (linklocal_str));
  vty_out (vty, "     linklocal[%s] #prefix[%d]\r\n",
           linklocal_str, prefixnum);
  prefix = (struct ospf6_prefix *)(llsap + 1);
  for (; prefixnum; prefixnum--)
    {
      ospf6_prefix_str (prefix, o6p_str, sizeof (o6p_str));
      vty_out (vty, "     Prefix [%s]\r\n", o6p_str);
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int show_intra_prefix_lsa (struct vty *vty, void *data)
{
  struct ospf6_lsa_hdr *lshp;
  struct intra_area_prefix_lsa *iap_lsa;
  struct ospf6_prefix *prefix;
  unsigned short prefixnum;
  char o6p_str[128];

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  iap_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  prefixnum = ntohs (iap_lsa->intra_prefix_num);

  vty_out (vty, "     # prefix [%d]\r\n", prefixnum);
  vty_out (vty, "     Referenced[%s]\r\n",
           print_ls_reference ((struct ospf6_lsa_hdr *)iap_lsa));

  prefix = (struct ospf6_prefix *)(iap_lsa + 1);
  for (; prefixnum; prefixnum--)
    {
      ospf6_prefix_str (prefix, o6p_str, sizeof (o6p_str));
      vty_out (vty, "     Prefix [%s]\r\n", o6p_str);
      prefix = OSPF6_NEXT_PREFIX (prefix);
    }
  return 0;
}

int show_as_external_lsa (struct vty *vty, void *data)
{
  struct ospf6_lsa_hdr *lsa_hdr;
  struct as_external_lsa *aselsa;
  struct in6_addr in6;
  char o6p_str[128];
  char ase_bits_str[8], *bitsp;

  assert (data);
  lsa_hdr = (struct ospf6_lsa_hdr *)data;
  aselsa = (struct as_external_lsa *)(lsa_hdr + 1);

  /* bits */
  bitsp = ase_bits_str;
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_E))
    *bitsp++ = 'E';
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_F))
    *bitsp++ = 'F';
  if (ASE_LSA_ISSET (aselsa, ASE_LSA_BIT_T))
    *bitsp++ = 'T';
  *bitsp = '\0';

  vty_out (vty, "     bits:%s, metric:%hu\r\n",
           ase_bits_str, ntohs (aselsa->ase_metric));

  memset (&in6, 0, sizeof (in6));
  memcpy (&in6, (void *)(aselsa + 1),
          OSPF6_PREFIX_SPACE (aselsa->ase_prefix_len));
  inet_ntop (AF_INET6, &in6, o6p_str, sizeof (o6p_str));

  vty_out (vty, "     opt:xxx, %s/%d\r\n", o6p_str, aselsa->ase_prefix_len);
  return 0;
}

int
vty_lsa (struct vty *vty, struct ospf6_lsa *lsa)
{
  struct ospf6_lsa_hdr *lsh;

  assert (lsa);
  lsh = lsa->lsa_hdr;
  assert (lsh);

  vty_out (vty, "%s\r\n", print_lsahdr (lsh));
  vty_out (vty, "    LS age[%d] LS SeqNum[%#x]\r\n",
           ospf6_age_current (lsa),
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
      case LST_AS_EXTERNAL_LSA:
        show_as_external_lsa (vty, (void *)lsh);
        break;
      default:
        break;
    }
  return 0;
}

struct router_lsd *
get_router_lsd (rtr_id_t rtrid, struct ospf6_lsa *lsa)
{
  unsigned short lsh_len;
  struct router_lsa *rlsa;
  struct router_lsd *rlsd;

  if (ntohs (lsa->lsa_hdr->lsh_type) != LST_ROUTER_LSA)
    return NULL;

  lsh_len = ntohs (lsa->lsa_hdr->lsh_len);
  rlsa = (struct router_lsa *)(lsa->lsa_hdr + 1);
  rlsd = (struct router_lsd *)(rlsa + 1);

  for ( ; (char *)rlsd < (char *)lsa + lsh_len; rlsd++)
    if (rtrid == rlsd->rlsd_neighbor_router_id)
      return rlsd;

  return NULL;
}

unsigned long
get_ifindex_to_router (rtr_id_t rtrid, struct ospf6_lsa *lsa)
{
  struct router_lsd *rlsd;
  char rtrid_str[64];

  assert (lsa);
  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        rlsd = get_router_lsd (rtrid, lsa);
        if (!rlsd)
          {
            inet_ntop (AF_INET, &rtrid, rtrid_str, sizeof (rtrid_str));
            o6log.lsa ("can't find ifindex from %s to %s",
                       print_lsahdr (lsa->lsa_hdr), rtrid_str); 
            return 0;
          }
        else
          return (ntohl (rlsd->rlsd_interface_id));
      case LST_NETWORK_LSA:
        return (ntohl (lsa->lsa_hdr->lsh_id));
      default:
        return 0;
    }
  return 0;
}



/* Back pointer check, Is X's reference field bound to y? */
#define x_ipl(x) ((struct intra_area_prefix_lsa *)LSH_NEXT((x)->lsa_hdr))
#define is_reference_network_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == (y)->lsa_hdr->lsh_id &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)
  /* referencing router's ifid must be 0,
     see draft-ietf-ospf-ospfv6-06.txt */
#define is_reference_router_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == htonl (0) &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)

/* return list of LSAs that referencing this LSA(internal to area) */
void
get_referencing_lsa (list l, struct ospf6_lsa *lsa)
{
  char tmpbuf[64];
  list m;
  listnode n;
  struct ospf6_lsa *x;
  struct area *area;

  assert (lsa->scope);
  m = list_init ();
  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) lsa->scope;
        ospf6_lsdb_collect_type_advrtr (m, htons (LST_INTRA_AREA_PREFIX_LSA),
                                        lsa->lsa_hdr->lsh_advrtr,
                                        (void *) area);
        for (n = listhead (m); n; nextnode (n))
          {
            x = getdata (n);
            if (is_reference_router_ok (x, lsa))
              {
                memcpy (tmpbuf, print_lsahdr (x->lsa_hdr), sizeof (tmpbuf));
                o6log.lsa ("%s references %s",
                           tmpbuf, print_lsahdr (lsa->lsa_hdr));
                list_add_node (l, x);
              }
          }
        break;

      case LST_NETWORK_LSA:
        area = (struct area *) lsa->scope;
        x = ospf6_lsdb_lookup (htons (LST_INTRA_AREA_PREFIX_LSA),
                               lsa->lsa_hdr->lsh_id,
                               lsa->lsa_hdr->lsh_advrtr, (void *)area);
        if (x && is_reference_network_ok (x, lsa))
          {
            memcpy (tmpbuf, print_lsahdr (x->lsa_hdr), sizeof (tmpbuf));
            o6log.lsa ("%s references %s",
                       tmpbuf, print_lsahdr (lsa->lsa_hdr));
            list_add_node (l, x);
          }
        break;

      default:
        break;
    }

  list_delete_all (m);

  return;
}

int
is_self_originated (struct ospf6_lsa *p)
{
  struct area *area;
  struct ospf6_if *o6if;
  struct ospf6 *ospf6;

  /* get top level ospf6 structure */
  switch (ospf6_lsa_get_scope_type (p->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        o6if = (struct ospf6_if *) p->scope;
        ospf6 = o6if->area->ospf6;
        break;
      case SCOPE_AREA:
        area = (struct area *) p->scope;
        ospf6 = area->ospf6;
        break;
      case SCOPE_AS:
      case SCOPE_RESERVED:
      default:
        return 0;
    }

  /* check router id */
  if (p->lsa_hdr->lsh_advrtr == ospf6->router_id)
    return 1;
  return 0;
}

void
update_ls_seqnum (struct ospf6_lsa *p)
{
  signed long seqnum;
  struct area *area = NULL;
  struct ospf6_if *o6if;
  struct interface *ifp;

  seqnum = ntohl (p->lsa_hdr->lsh_seqnum) + 1;
  switch (ntohs (p->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) p->scope;
        area->router_lsa_seqnum = seqnum;
        break;
      case LST_NETWORK_LSA:
        ifp = if_lookup_by_index (ntohl (p->lsa_hdr->lsh_id));
        o6if = (struct ospf6_if *) ifp->info;
        o6if->network_lsa_seqnum = seqnum;
        break;
      case LST_INTRA_AREA_PREFIX_LSA:
        ifp = if_lookup_by_index (ntohl (p->lsa_hdr->lsh_id));
        o6if = (struct ospf6_if *) ifp->info;
        o6if->intra_prefix_seqnum = seqnum;
        break;
      case LST_LINK_LSA:
        o6if = (struct ospf6_if *) p->scope;
        o6if->link_lsa_seqnum = seqnum;
        break;
      default:
        break;
    }
  o6log.lsa ("seqnum for %s updated to %#x",
             lstype_name [typeindex (p->lsa_hdr->lsh_type)], seqnum);
  return;
}

struct ospf6_lsa *
reconstruct_lsa (struct ospf6_lsa *lsa)
{
  struct area *area;
  struct ospf6_if *o6if;
  unsigned long ifindex;
  struct interface *ifp;
  struct ospf6_lsa *new = NULL;

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) lsa->scope;
        assert (area);
        new = ospf6_make_router_lsa (area);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_NETWORK_LSA:
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            o6log.lsa ("interface not found: index %d", ifindex);
            return (struct ospf6_lsa *) NULL;
          }
        o6if = (struct ospf6_if *) ifp->info;
        assert (o6if);
        new = ospf6_make_network_lsa (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_INTRA_AREA_PREFIX_LSA:
        /* XXX, assume LS-ID has addressing semantics */
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            o6log.lsa ("interface not found: index %d", ifindex);
            return (struct ospf6_lsa *) NULL;
          }
        o6if = (struct ospf6_if *) ifp->info;
        assert (o6if);
        new = ospf6_make_intra_prefix_lsa (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_LINK_LSA:
        o6if = (struct ospf6_if *) lsa->scope;
        assert (o6if);
        new = ospf6_make_link_lsa (o6if);
        if (!new)
          break;
        ospf6_lsa_flood (new);
        ospf6_lsdb_install (new);
        ospf6_lsa_unlock (new);
        break;

      case LST_AS_EXTERNAL_LSA:
        new = ospf6_refresh_as_external_lsa (lsa);
        break;

      default:
        break;
    }

  return new;
}


/* new */

/* allocate memory for lsa data */
static struct ospf6_lsa_hdr *
malloc_ospf6_lsa_data (unsigned int size)
{
  struct ospf6_lsa_hdr *new;

  new = (struct ospf6_lsa_hdr *) XMALLOC (MTYPE_OSPF6_LSA, size);
  if (new)
    memset (new, 0, size);

  return new;
}

/* free memory of lsa data */
static void
free_ospf6_lsa_data (struct ospf6_lsa_hdr *data)
{
  XFREE (MTYPE_OSPF6_LSA, data);
  return;
}

/* allocate memory for struct ospf6_lsa */
static struct ospf6_lsa *
malloc_ospf6_lsa ()
{
  struct ospf6_lsa *new;

  new = (struct ospf6_lsa *) XMALLOC (MTYPE_OSPF6_LSA,
                                      sizeof (struct ospf6_lsa));
  if (new)
    memset (new, 0, sizeof (struct ospf6_lsa));

  return new;
}

/* free memory of struct ospf6_lsa */
static void
free_ospf6_lsa (struct ospf6_lsa *lsa)
{
  XFREE (MTYPE_OSPF6_LSA, lsa);
  return;
}

/* increment reference counter of  struct ospf6_lsa */
void
ospf6_lsa_lock (struct ospf6_lsa *lsa)
{
  lsa->lock++;
  return;
}

/* decrement reference counter of  struct ospf6_lsa */
void
ospf6_lsa_unlock (struct ospf6_lsa *lsa)
{
  /* decrement reference counter */
  lsa->lock--;

  /* if no reference, do delete */
  if (lsa->lock == 0)
    {
      /* log deletion */
      o6log.lsa ("free LSA %s", print_lsahdr (lsa->lsa_hdr));

      /* threads */
      if (lsa->expire)
        thread_cancel (lsa->expire);
      if (lsa->refresh)
        thread_cancel (lsa->refresh);

      /* lists */
      assert (list_isempty (lsa->summary_nbr));
      list_delete_all (lsa->summary_nbr);
      assert (list_isempty (lsa->request_nbr));
      list_delete_all (lsa->request_nbr);
      assert (list_isempty (lsa->retrans_nbr));
      list_delete_all (lsa->retrans_nbr);
      assert (list_isempty (lsa->delayed_ack_if));
      list_delete_all (lsa->delayed_ack_if);

      /* do free */
      free_ospf6_lsa_data (lsa->lsa_hdr);
      free_ospf6_lsa (lsa);
    }

  return;
}


/* ospf6_lsa expired */
void
ospf6_maxage_remove (struct ospf6_lsa *lsa)
{
  struct area *area = (struct area *) NULL;
  struct ospf6 *ospf6 = (struct ospf6 *) NULL;
  list area_list;
  listnode n;

  /* if age still under MaxAge, do nothing */
  if (ospf6_age_current (lsa) != MAXAGE)
    return;

  o6log.lsa ("check MaxAge %s", print_lsahdr (lsa->lsa_hdr));

  area_list = list_init ();

  /* get area */
  switch (ospf6_lsa_get_scope_type (lsa->lsa_hdr->lsh_type))
    {
      case SCOPE_LINKLOCAL:
        area = ((struct ospf6_if *) lsa->scope)->area;
        ospf6 = area->ospf6;
        list_add_node (area_list, area);
        break;
      case SCOPE_AREA:
        area = (struct area *) lsa->scope;
        ospf6 = area->ospf6;
        list_add_node (area_list, area);
        break;
      case SCOPE_AS:
        ospf6 = (struct ospf6 *) lsa->scope;
        for (n = listhead (ospf6->area_list); n; nextnode (n))
          list_add_node (area_list, getdata (n));
        break;
      default:
        o6log.lsa ("unsupported scope in ospf6_maxage_remove()");
        assert (0);
        break;
    }

  /* assert this LSA is still on database */
  assert (ospf6_lsdb_lookup (lsa->lsa_hdr->lsh_type, lsa->lsa_hdr->lsh_id,
                             lsa->lsa_hdr->lsh_advrtr, lsa->scope));

  if (lsa->lock != 1)
    {
      o6log.lsa ("still included in someone's retrans list");
      return; /* this indicate some retrans list include this LSA */
    }

  for (n = listhead (area_list); n; nextnode (n))
    {
      area = (struct area *) getdata (n);

      if (count_nbr_in_state (NBS_EXCHANGE, area) == 0 &&
          count_nbr_in_state (NBS_LOADING, area) == 0)
        {
          /* remove from database. this will free this LSA */
          o6log.lsa ("no neighbor state Loading or Exchange");
          if (ospf6_lookup_maxage (lsa, ospf6))
            ospf6_remove_maxage (lsa, ospf6);
          ospf6_lsdb_remove (lsa);
        }
      else
        {
          /* save this LSA in area data structure, if it has not been */
          if (!ospf6_lookup_maxage (lsa, ospf6))
            {
              o6log.lsa ("removing this LSA is "
                         "waiting for state of neighbors");
              ospf6_add_maxage (lsa, ospf6);
            }
        }
    }

  return;
}

int
ospf6_lsa_expire (struct thread *thread)
{
  struct ospf6_lsa *lsa;

  lsa = (struct ospf6_lsa *) THREAD_ARG (thread);
  assert (lsa && lsa->lsa_hdr);

  o6log.lsa ("!expire %s", print_lsahdr (lsa->lsa_hdr));
  lsa->expire = (struct thread *) NULL;

  /* reflood lsa */
  ospf6_lsa_flood (lsa);

  /* delete from scoped lsdb */
  ospf6_maxage_remove (lsa);

  /* do nothing about lslists. wait event */

  return 0;
}

int
ospf6_lsa_refresh (struct thread *thread)
{
  struct ospf6_lsa *lsa;

  assert (thread);
  lsa = (struct ospf6_lsa *) THREAD_ARG  (thread);
  assert (lsa && lsa->lsa_hdr);

  /* this will be used later as flag in originating_lsa() */
  lsa->refresh = (struct thread *)NULL;

  o6log.lsa ("refresh %s", print_lsahdr (lsa->lsa_hdr));
  if (reconstruct_lsa (lsa) == NULL)
    o6log.lsa ("refresh failed");

  return 0;
}


/* ospf6 ages */
/* calculate birth and set expire timer */
static void
ospf6_age_set (struct ospf6_lsa *lsa)
{
  struct timeval now;

  assert (lsa && lsa->lsa_hdr);

  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    o6log.lsa ("gettimeofday () failed, may fail ages: %s",
               strerror (errno));

  lsa->birth = now.tv_sec - ntohs (lsa->lsa_hdr->lsh_age);
  lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                  lsa->birth + MAXAGE - now.tv_sec);
  return;
}

/* get current age */
unsigned short
ospf6_age_current (struct ospf6_lsa *lsa)
{
  struct timeval now;
  unsigned short age;

  /* current time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    o6log.lsa ("gettimeofday () failed, may fail ages: %s",
               strerror (errno));

  /* calculate age */
  age = now.tv_sec - lsa->birth;

  /* if over MAXAGE, set to it */
  if (age > MAXAGE)
    age = MAXAGE;

  return age;
}

/* update age field of lsa_hdr, add InfTransDelay */
void
ospf6_age_update_to_send (struct ospf6_lsa *lsa, struct ospf6_if *o6if)
{
  unsigned short age;
  age = ospf6_age_current (lsa) + o6if->inf_trans_delay;
  if (age > MAXAGE)
    age = MAXAGE;
  lsa->lsa_hdr->lsh_age = htons (age);
  return;
}

void
ospf6_premature_aging (struct ospf6_lsa *lsa)
{
  o6log.lsa ("premature aging %s", print_lsahdr (lsa->lsa_hdr));

  if (lsa->expire)
    thread_cancel (lsa->expire);
  lsa->expire = (struct thread *) NULL;
  if (lsa->refresh)
    thread_cancel (lsa->refresh);
  lsa->refresh = (struct thread *) NULL;

  lsa->birth = 0;
  thread_execute (master, ospf6_lsa_expire, lsa, 0);
}


/* make data of ospf6_lsa(copy buffer) */
struct ospf6_lsa_hdr *
make_ospf6_lsa_data (struct ospf6_lsa_hdr *hdr, int size)
{
  struct ospf6_lsa_hdr *lsa_hdr = malloc_ospf6_lsa_data (size);
  if (lsa_hdr)
    memcpy (lsa_hdr, hdr, size);
  return lsa_hdr;
}

/* make ospf6_lsa */
struct ospf6_lsa *
make_ospf6_lsa (struct ospf6_lsa_hdr *hdr)
{
  struct ospf6_lsa *lsa = malloc_ospf6_lsa ();

  /* increment reference counter */
  ospf6_lsa_lock (lsa);

  lsa->lsa_hdr = hdr;

  /* calculate birth and expire of this lsa */
  ospf6_age_set (lsa);

  /* list init */
  lsa->summary_nbr = list_init ();
  lsa->request_nbr = list_init ();
  lsa->retrans_nbr = list_init ();
  lsa->delayed_ack_if = list_init ();

  /* log appearance */
  o6log.pointer ("allocate LSA %#x", lsa);

  /* leave other members */
  return lsa;
}

unsigned short
ospf6_lsa_get_type (struct ospf6_lsa *lsa)
{
  assert (lsa && lsa->lsa_hdr);
  return (ntohs (lsa->lsa_hdr->lsh_type));
}

unsigned short
ospf6_lsa_get_scope_type (unsigned short type)
{
  return (ntohs (type) & SCOPE_MASK);
}

void
ospf6_lsa_clear_flag (struct ospf6_lsa *lsa)
{
  assert (lsa && lsa->lsa_hdr);
  lsa->flags = 0;
  return;
}

void
ospf6_lsa_set_flag (struct ospf6_lsa *lsa, unsigned char flag)
{
  assert (lsa && lsa->lsa_hdr);
  lsa->flags |= flag;
  return;
}

int
ospf6_lsa_test_flag (struct ospf6_lsa *lsa, unsigned char flag)
{
  assert (lsa && lsa->lsa_hdr);
  return (lsa->flags & flag);
}

/* test LSAs identity */
int
ospf6_lsa_issame (struct ospf6_lsa_hdr *lsh1, struct ospf6_lsa_hdr *lsh2)
{
  assert (lsh1 && lsh2);
  if (lsh1->lsh_advrtr != lsh2->lsh_advrtr)
    return 0;
  if (lsh1->lsh_id != lsh2->lsh_id)
    return 0;
  if (lsh1->lsh_type != lsh2->lsh_type)
    return 0;
  return 1;
}

/* calculate LS sequence number for my new LSA.
   return value is network byte order */
static signed long
ospf6_seqnum_new (unsigned short type, unsigned long id,
                  unsigned long advrtr, void *scope)
{
  struct ospf6_lsa *lsa;
  signed long seqnum;

  /* get current database copy */
  lsa = ospf6_lsdb_lookup (type, id, advrtr, scope);

  /* if current database copy not found, return InitialSequenceNumber */
  if (!lsa)
    seqnum = INITIAL_SEQUENCE_NUMBER;
  else
    seqnum = (signed long) ntohl (lsa->lsa_hdr->lsh_seqnum) + 1;

  return (htonl (seqnum));
}


/* make lsa functions */
/* these "make lsa" functions bellow returns lsa that has one empty lock.
   so unlock within caller function */

/* set field of rlsd from ospf6_if */
static void
ospf6_router_lsd_set (struct router_lsd *rlsd, struct ospf6_if *o6if)
{
  assert (o6if);

  /* common field for each link type */
  rlsd->rlsd_metric = htons (o6if->cost);
  rlsd->rlsd_interface_id = htonl (o6if->ifid);

  /* set LS description for each link type */
  if (if_is_pointopoint (o6if->interface))
    {
      struct neighbor *nbr;

      /* pointopoint specific assertion */
      assert (listcount (o6if->nbr_list) == 1);
      nbr = (struct neighbor *) getdata (listhead (o6if->nbr_list));
      assert (nbr && nbr->state == NBS_FULL);

      rlsd->rlsd_type = LSDT_POINTTOPOINT;
      rlsd->rlsd_neighbor_interface_id = htonl (nbr->ifid);
      rlsd->rlsd_neighbor_router_id = nbr->rtr_id;
    }
  else /* if (if_is_broadcast (o6if->interface)) */
    {
      /* else, assume this is broadcast. other types not supported */
      rlsd->rlsd_type = LSDT_TRANSIT_NETWORK;

      /* different neighbor field between DR and others */
      if (o6if->state == IFS_DR)
        {
          rlsd->rlsd_neighbor_interface_id = htonl (o6if->ifid);
          rlsd->rlsd_neighbor_router_id = o6if->area->ospf6->router_id;
        }
      else
        {
          /* find DR */
          struct neighbor *dr;
          dr = nbr_lookup (o6if->dr, o6if->area->ospf6);
          assert (dr);
          rlsd->rlsd_neighbor_interface_id = htonl (dr->ifid);
          rlsd->rlsd_neighbor_router_id = dr->rtr_id;
        }
    }
  return;
}

struct ospf6_lsa *
ospf6_make_router_lsa (struct area *area)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct router_lsa *rlsa;
  struct router_lsd *rlsd;
  struct ospf6_if *o6if;
  listnode i;
  list described_link = list_init ();
  size_t space;

  /* get links to describe */
  for (i = listhead (area->ospf6_if_list); i; nextnode (i))
    {
      o6if = (struct ospf6_if *) getdata (i);
      assert (o6if);

      /* if interface is not enabled, ignore */
      if (o6if->state <= IFS_LOOPBACK)
        continue;

      /* if interface is stub, ignore */
      if (ospf6_if_count_full_nbr (o6if))
        list_add_node (described_link, o6if);
    }

  /* get space needed for my RouterLSA */
  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct router_lsa)
          + (sizeof (struct router_lsd) * listcount (described_link));

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_ROUTER_LSA);
  lsa_hdr->lsh_id = htonl (MY_ROUTER_LSA_ID);
  lsa_hdr->lsh_advrtr = area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set router_lsa */
  rlsa = (struct router_lsa *) (lsa_hdr + 1);
    /* options */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_V6);  /* V6bit set */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_R);   /* Rbit set */
  V3OPT_SET (rlsa->rlsa_options, V3OPT_E);   /* Ebit set */
    /* router lsa bits, xxx not yet */
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_W);
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_V);
  ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_B);
  if (area->ospf6->redist_static || area->ospf6->redist_ripng ||
      area->ospf6->redist_bgp)
    ROUTER_LSA_SET (rlsa, ROUTER_LSA_BIT_E);
  else
    ROUTER_LSA_CLEAR (rlsa, ROUTER_LSA_BIT_E);

  /* set LS description for each link */
  rlsd = (struct router_lsd *) (rlsa + 1);
  for (i = listhead (described_link); i; nextnode (i))
    {
      o6if = (struct ospf6_if *) getdata (i);
      assert (o6if);
      ospf6_router_lsd_set (rlsd++, o6if);
    }

  /* age calculation, scope, etc */
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  /* free temporary list */
  list_delete_all (described_link);

  return lsa;
}

struct ospf6_lsa *
ospf6_make_network_lsa (struct ospf6_if *o6if)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct network_lsa *nlsa;
  rtr_id_t *nlsd; /* LS description of NetworkLSA is Router ID */
  listnode i;
  size_t space;
  int fullnbrnum;
  struct neighbor *nbr;

  assert (o6if);

  /* If not DR, return NULL */
  if (o6if->state != IFS_DR)
    {
      o6log.lsa ("%s isn't DR, don't make NetworkLSA",
                 o6if->interface->name);
      return (struct ospf6_lsa *) NULL;
    }

  /* count full neighbor */
  fullnbrnum = ospf6_if_count_full_nbr (o6if);

  /* if this link is stub, return NULL */
  if (!fullnbrnum)
    {
      o6log.lsa ("%s is stub, don't make NetworkLSA",
                 o6if->interface->name);
      return (struct ospf6_lsa *) NULL;
    }

  /* get space needed for my NetworkLSA */
    /* + 1 for my router id */
  space = sizeof (struct ospf6_lsa_hdr) + sizeof (struct network_lsa)
          + (sizeof (rtr_id_t) * (fullnbrnum + 1));

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_NETWORK_LSA);
  lsa_hdr->lsh_id = htonl (o6if->ifid);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if->area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set network_lsa */
  nlsa = (struct network_lsa *) (lsa_hdr + 1);
    /* xxx, set options to logical OR of all link lsa's options.
       this not yet, currently copy from mine */
  memcpy (nlsa->nlsa_options, o6if->area->options,
          sizeof (nlsa->nlsa_options));

  /* set router id for each full neighbor */
  nlsd = (rtr_id_t *) (nlsa + 1);
  for (i = listhead (o6if->nbr_list); i; nextnode (i))
    {
      nbr = (struct neighbor *) getdata (i);
      assert (nbr);
      if (nbr->state == NBS_FULL)
        *nlsd++ = nbr->rtr_id;
    }
  /* set my router id */
  *nlsd = o6if->area->ospf6->router_id;

  /* age calculation, scope, etc */
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  return lsa;
}

struct ospf6_lsa *
ospf6_make_link_lsa (struct ospf6_if *o6if)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct link_lsa *llsa;
  struct ospf6_prefix *p1, *p2; /* LS description is ospf6 prefix */
  listnode i;
  size_t space;
  unsigned long prefixnum, fail = 0;

  assert (o6if);

  /* get prefix number */
  prefixnum = listcount (o6if->prefix_connected);

  /* get space needed for my LinkLSA */
  space = 0;
  for (i = listhead (o6if->prefix_connected); i; nextnode (i))
    {
      p1 = (struct ospf6_prefix *) getdata (i);
      space += OSPF6_PREFIX_SIZE (p1);
    }
  space += sizeof (struct ospf6_lsa_hdr) + sizeof (struct link_lsa);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_LINK_LSA);
  lsa_hdr->lsh_id = htonl (o6if->ifid);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set link_lsa */
  llsa = (struct link_lsa *) (lsa_hdr + 1);
    /* set router priority */
  llsa->llsa_rtr_pri = o6if->rtr_pri;
    /* set options by copying from mine */
  memcpy (llsa->llsa_options, o6if->area->options,
          sizeof (llsa->llsa_options));
    /* if set linklocal address fails, set fail flag */
  if (ospf6_if_get_linklocal (&llsa->llsa_linklocal, o6if) < 0)
    fail++;
  llsa->llsa_prefix_num = htonl (prefixnum);

  /* set ospf6 prefixes */
  p1 = (struct ospf6_prefix *)(llsa + 1);
  space -= sizeof (struct link_lsa) + sizeof (struct ospf6_lsa_hdr);
  for (i = listhead (o6if->prefix_connected); i; nextnode (i))
    {
      char debug_str[128];
      p2 = (struct ospf6_prefix *) getdata (i);

      /* copy p2 to p1 */
      ospf6_prefix_copy (p1, p2, space);
      space -= OSPF6_PREFIX_SIZE(p2);

      ospf6_prefix_str (p1, debug_str, sizeof (debug_str));
      o6log.lsa ("advertise LinkLSA: %s", debug_str);

      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* age calculation, scope, etc */
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  /* in case fail to get linklocal address */
  if (fail)
    {
      o6log.lsa ("failed to find %s linklocal, don't make LinkLSA",
                 o6if->interface->name);
      ospf6_lsa_unlock (lsa);
      return (struct ospf6_lsa *) NULL;
    }

  return lsa;
}

struct ospf6_lsa *
ospf6_make_intra_prefix_lsa (struct ospf6_if *o6if)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct intra_area_prefix_lsa *iaplsa;
  struct ospf6_prefix *p1, *p2; /* LS description is ospf6 prefix */
  listnode n;
  size_t space;
  list advertise = list_init ();
  struct link_lsa *llsa;
  unsigned short prefixnum;
  int i;
  struct neighbor *nbr;

  assert (o6if);

  /* if not stub and not DR, don't make IntraAreaPrefixLSA */
  if (ospf6_if_count_full_nbr (o6if) != 0 && o6if->state != IFS_DR)
    {
      o6log.lsa ("%s is not stub, don't make IntraAreaPrefixLSA",
                 o6if->interface->name);
      list_delete_all (advertise);
      return (struct ospf6_lsa *)NULL;
    }

  /* get all prefix that is to be advertised for this interface */
  if (o6if->state == IFS_DR)
    {
      /* if DR, care about prefix advertised with LinkLSA
         by another router */
      for (n = listhead (o6if->nbr_list); n; nextnode (n))
        {
          nbr = (struct neighbor *) getdata (n);

          /* if not full, ignore this neighbor */
          if (nbr->state != NBS_FULL)
            continue;

          /* get LinkLSA of this neighbor. if not found, log and ignore */
          lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (nbr->ifid),
                                   nbr->rtr_id, (void *)o6if);
          if (!lsa)
            {
              o6log.lsa ("LinkLSA not found for full neighbor %s",
                         nbr->str);
              continue;
            }

          llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
          p1 = (struct ospf6_prefix *)(llsa + 1);
          /* for each prefix listed in this LinkLSA */
          for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
            {
              /* add to advertise list. duplicate won't be added */
              ospf6_prefix_add (advertise, p1);
              p1 = OSPF6_NEXT_PREFIX (p1);
            }
        }
    }

  /* add prefixes in my LinkLSA to advertise list */
  lsa = ospf6_lsdb_lookup (htons (LST_LINK_LSA), htonl (o6if->ifid),
                           o6if->area->ospf6->router_id, (void *)o6if);
  if (!lsa)
    o6log.lsa ("LinkLSA of mine not found for %s", o6if->interface->name);
  else
    {
      llsa = (struct link_lsa *)(lsa->lsa_hdr + 1);
      p1 = (struct ospf6_prefix *)(llsa + 1);
      /* for each prefix listed in my LinkLSA */
      for (i = 0; i < ntohl (llsa->llsa_prefix_num); i++)
        {
          /* add to advertise list. duplicate won't be added */
          ospf6_prefix_add (advertise, p1);
          p1 = OSPF6_NEXT_PREFIX (p1);
        }
    }

  /* get prefix number */
  prefixnum = listcount (advertise);

  /* if no prefix, no need to make IntraAreaPrefixLSA */
  if (!prefixnum)
    {
      o6log.lsa ("no prefix to advertise for %s, "
                 "don't make IntraAreaPrefixLSA",
                 o6if->interface->name);
      list_delete_all (advertise);
      return (struct ospf6_lsa *)NULL;
    }

  /* get space needed for my IntraAreaPrefixLSA */
  space = 0;
  for (n = listhead (advertise); n; nextnode (n))
    {
      p1 = (struct ospf6_prefix *) getdata (n);
      space += OSPF6_PREFIX_SIZE (p1);
    }
  space += sizeof (struct ospf6_lsa_hdr)
          + sizeof (struct intra_area_prefix_lsa);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_INTRA_AREA_PREFIX_LSA);
  lsa_hdr->lsh_id = htonl (o6if->ifid);
  lsa_hdr->lsh_advrtr = o6if->area->ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)o6if->area);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set intra_area_prefix_lsa */
  iaplsa = (struct intra_area_prefix_lsa *) (lsa_hdr + 1);
    /* set prefix num */
  iaplsa->intra_prefix_num = htons (prefixnum);
    /* set referrenced lsa */
  if (o6if->state == IFS_DR && ospf6_if_count_full_nbr (o6if))
    {
      /* refer to NetworkLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_NETWORK_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (o6if->ifid);
    }
  else
    {
      /* refer to RouterLSA */
      iaplsa->intra_prefix_refer_lstype = htons (LST_ROUTER_LSA);
      iaplsa->intra_prefix_refer_lsid = htonl (0);
    }
  iaplsa->intra_prefix_refer_advrtr = o6if->area->ospf6->router_id;

  /* set ospf6 prefixes */
  p1 = (struct ospf6_prefix *)(iaplsa + 1);
  space -= sizeof (struct intra_area_prefix_lsa)
           + sizeof (struct ospf6_lsa_hdr);
  for (n = listhead (advertise); n; nextnode (n))
    {
      char debug_str[128];
      p2 = (struct ospf6_prefix *) getdata (n);

      /* copy p2 to p1 */
      ospf6_prefix_copy (p1, p2, space);
      space -= OSPF6_PREFIX_SIZE(p2);

      ospf6_prefix_str (p1, debug_str, sizeof (debug_str));
      o6log.lsa ("advertise IntraAreaPrefixLSA: %s", debug_str);

      p1 = OSPF6_NEXT_PREFIX (p1);
    }

  /* age calculation, scope, etc */
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) o6if->area;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  list_delete_all (advertise);
  return lsa;
}

unsigned long
ospf6_as_external_lsid (struct prefix_ipv6 *prefix, struct ospf6 *ospf6)
{
  struct ospf6_rtentry *r;
  struct ospf6_lsa *lsa;

  assert (ospf6);

  /* find current lsa from redist table */
  r = rtable_lookup (DTYPE_PREFIX, (union dest_id *)prefix,
                     ospf6->redist_table.current_top);

  /* if current lsa not found, return max LS-ID currently used + 1 */
  if (!r)
    {
      /* increment max LS-ID and return */
      ospf6->ase_ls_id++;
      return ospf6->ase_ls_id;
    }

  lsa = r->ls_origin;
  assert (lsa);
  return (ntohl (lsa->lsa_hdr->lsh_id));
}

struct ospf6_lsa *
ospf6_make_as_external_lsa (unsigned long lsid,
                            struct ospf6_prefix *prefix, struct ospf6 *ospf6)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_hdr *lsa_hdr;
  struct as_external_lsa *aselsa;
  struct ospf6_prefix *p; /* LS description is ospf6 prefix */
  size_t space;

  assert (ospf6);

  /* get space needed for my ASExternalLSA */
  space = sizeof (struct ospf6_lsa_hdr)
          + sizeof (struct as_external_lsa)
          + OSPF6_PREFIX_SPACE (prefix->o6p_prefix_len);

  /* malloc buffer */
  lsa_hdr = malloc_ospf6_lsa_data (space);

  /* set lsa header */
  lsa_hdr->lsh_age = 0;
  lsa_hdr->lsh_type = htons (LST_AS_EXTERNAL_LSA);
  lsa_hdr->lsh_id = htonl (lsid);
  lsa_hdr->lsh_advrtr = ospf6->router_id;
  lsa_hdr->lsh_seqnum = ospf6_seqnum_new (lsa_hdr->lsh_type,
                                          lsa_hdr->lsh_id,
                                          lsa_hdr->lsh_advrtr,
                                          (void *)ospf6);
  /* xxx, checksum */
  lsa_hdr->lsh_len = htons (space);

  /* set as_external_lsa */
  aselsa = (struct as_external_lsa *) (lsa_hdr + 1);

  /* xxx, set ase_bits */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_E); /* type1 or type2 */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_F); /* forwarding address */
  ASE_LSA_CLEAR (aselsa, ASE_LSA_BIT_T); /* external route tag */

  /* xxx, don't know how to use ase_pre_metric */
  aselsa->ase_pre_metric = 0;

  /* xxx, set metric. related to E bit */
  aselsa->ase_metric = prefix->o6p_prefix_metric;

  /* set ospf6 prefix */
  p = (struct ospf6_prefix *)(&aselsa->ase_prefix_len);
  space -= sizeof (unsigned char) + sizeof (unsigned char)
           + sizeof (unsigned short) + sizeof (struct ospf6_lsa_hdr);
  ospf6_prefix_copy (p, prefix, space);

  /* set ase_refer_lstype */
  aselsa->ase_refer_lstype = 0;

  /* age calculation, scope, etc */
  lsa = make_ospf6_lsa (lsa_hdr);
  lsa->scope = (void *) ospf6;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  return lsa;
}

struct ospf6_lsa *
ospf6_refresh_as_external_lsa (struct ospf6_lsa *lsa)
{
  struct ospf6 *ospf6;
  unsigned long lsid;
  struct prefix_ipv6 prefix;
  struct as_external_lsa *aselsa;
  struct ospf6_lsa *new;
  struct ospf6_rtentry *r;
  struct ospf6_prefix *o6p;

  ospf6 = (struct ospf6 *) lsa->scope;
  lsid = ntohl (lsa->lsa_hdr->lsh_id);

  /* make ospf6_prefix */
  memset (&prefix, 0, sizeof (struct prefix_ipv6));
  aselsa = (struct as_external_lsa *) (lsa->lsa_hdr + 1);
  prefix.family = AF_INET6;
  prefix.prefixlen = aselsa->ase_prefix_len;
  memcpy (&prefix.prefix, (void *)(aselsa + 1),
          OSPF6_PREFIX_SPACE (prefix.prefixlen));
  o6p = ospf6_prefix_make (ntohs (aselsa->ase_metric), &prefix);

  /* find current lsa from redist table */
  r = rtable_lookup (DTYPE_PREFIX, (union dest_id *)&prefix,
                     ospf6->redist_table.current_top);
  if (!r)
    {
      /* can't find rtentry, so this must be
         flushed from database by premature aging */
      return (struct ospf6_lsa *)NULL;
    }

  new = ospf6_make_as_external_lsa (lsid, o6p, ospf6);
  ospf6_prefix_free (o6p);
  if (!new)
    return (struct ospf6_lsa *) NULL;

  /* change rtentry's reference to new */
  r->ls_origin = new;

  ospf6_lsa_flood (new);
  ospf6_lsdb_install (new);

  /* unlock refreshed lsa */
  ospf6_lsa_unlock (new);

  return lsa;
}

