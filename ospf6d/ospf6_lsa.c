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

  lsabody = XMALLOC (MTYPE_OSPF_LSA, space);
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

  originating_lsa (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_network_lsa (struct ospf6_if *ospf6_if)
{
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

  originating_lsa (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_link_lsa (struct ospf6_if *ospf6_if)
{
  int space, already;
  listnode i, j;
  char *lsabody;
  struct ospf6_lsa_hdr *lsh;
  struct connected *c;
  struct link_lsa *llsap;
  struct ospf6_prefix *p;
  struct in6_addr *linklocal, *network_prefix;
  struct ospf6_lsa *lsa;
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
  space += sizeof (struct link_lsa) + sizeof (struct ospf6_lsa_hdr);
  assert (linklocal); /* xxx */

  lsabody = XMALLOC (MTYPE_OSPF_LSA, space);
  o6log.pointer ("pointer %#x for my LinkLSA", lsabody);
  memset (lsabody, 0, space);
  lsh = (struct ospf6_lsa_hdr *)lsabody;
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
  lsa = make_ospf6_lsa (lsh);
  lsa->scope = (void *) ospf6_if;
  lsa->from = (struct neighbor *) NULL;
  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  originating_lsa (lsa);
  ospf6_lsa_unlock (lsa);
  return;
}

void
construct_intra_prefix_lsa (struct ospf6_if *ospf6_if)
{
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

  originating_lsa (lsa);
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
  char ntop_buf[2][INET6_ADDRSTRLEN];
  int prefixnum;
  struct in6_addr network_prefix;
  struct ospf6_prefix *prefix;

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
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
  struct ospf6_lsa_hdr *lshp;
  struct intra_area_prefix_lsa *iap_lsa;
  struct ospf6_prefix *prefix;
  int prefixnum;
  struct in6_addr network_prefix;
  char ntop_buf[2][INET6_ADDRSTRLEN];

  memset (ntop_buf[0], 0, sizeof (ntop_buf[0]));
  memset (ntop_buf[1], 0, sizeof (ntop_buf[1]));

  assert (data);
  lshp = (struct ospf6_lsa_hdr *)data;
  iap_lsa = (struct intra_area_prefix_lsa *)(lshp + 1);
  prefixnum = ntohs (iap_lsa->intra_prefix_num);

  vty_out (vty, "     # prefix [%d]\r\n", prefixnum);
  vty_out (vty, "     Referenced[%s]\r\n",
           print_lsahdr ((struct ospf6_lsa_hdr *)iap_lsa));

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

  assert (lsa);
  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        rlsd = get_router_lsd (rtrid, lsa);
        if (!rlsd)
          return 0;
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

  seqnum = ntohl (p->lsa_hdr->lsh_seqnum) + 1;
  switch (ntohs (p->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) p->scope;
        area->router_lsa_seqnum = seqnum;
        break;
      case LST_NETWORK_LSA:
        area = (struct area *) p->scope;
        area->network_lsa_seqnum = seqnum;
        break;
      case LST_INTRA_AREA_PREFIX_LSA:
        area = (struct area *) p->scope;
        area->intra_prefix_seqnum = seqnum;
        break;
      case LST_LINK_LSA:
        o6if = (struct ospf6_if *) p->scope;
        o6if->area->link_lsa_seqnum = seqnum;
        break;
      default:
        break;
    }
  o6log.lsa ("seqnum for %s updated to %d(%#x)",
             lstype_name [typeindex (p->lsa_hdr->lsh_type)],
             seqnum, seqnum);
  return;
}

void
reconstruct_lsa (struct ospf6_lsa *lsa)
{
  struct area *area;
  struct ospf6_if *o6if;
  unsigned long ifindex;
  struct interface *ifp;

  switch (ntohs (lsa->lsa_hdr->lsh_type))
    {
      case LST_ROUTER_LSA:
        area = (struct area *) lsa->scope;
        assert (area);
        construct_router_lsa (area);
        break;

      case LST_NETWORK_LSA:
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            o6log.lsa ("interface not found: index %d", ifindex);
            return;
          }
        o6if = (struct ospf6_if *) ifp->if_data;
        assert (o6if);
        construct_network_lsa (o6if);
        break;

      case LST_INTRA_AREA_PREFIX_LSA:
        /* XXX, assume LS-ID has addressing semantics */
        ifindex = ntohl (lsa->lsa_hdr->lsh_id);
        ifp = if_lookup_by_index (ifindex);
        if (!ifp)
          {
            o6log.lsa ("interface not found: index %d", ifindex);
            return;
          }
        o6if = (struct ospf6_if *) ifp->if_data;
        assert (o6if);
        construct_intra_prefix_lsa (o6if);
        break;

      case LST_LINK_LSA:
        o6if = (struct ospf6_if *) lsa->scope;
        assert (o6if);
        construct_link_lsa (o6if);
        break;

      default:
        break;
    }
  return;
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
      o6log.pointer ("free LSA %#x", lsa);

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
  ospf6_lsdb_remove (lsa);

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
  reconstruct_lsa (lsa);

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

