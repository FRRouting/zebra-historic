/* OSPF Link State Advertisement
   Copyright (C) 1999 Toshiaki Takada

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"

/* LSA Type String. */
char *ospf_lsa_type_str[] =
{
  NULL,
  "router-LSA",
  "network-LSA",
  "summary-LSA",
  "summary-LSA",
  "AS-external-LSA",
};



/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX		     4102
#define LSA_CHECKSUM_OFFSET    15

u_int16_t
ospf_lsa_checksum (struct ospf_lsa *lsa)
{
  u_char *sp, *ep, *p, *q;
  int c0 = 0, c1 = 0;
  int x, y;
  u_int16_t length;

  lsa->checksum = 0;
  length = ntohs (lsa->length) - 2;
  sp = (char *) &lsa->options;

  for (ep = sp + length; sp < ep; sp = q)
    {
      q = sp + MODX;
      if (q > ep)
	q = ep;
      for (p = sp; p < q; p++)
	{
	  c0 += *p;
	  c1 += c0;
	}
      c0 %= 255;
      c1 %= 255;
    }

  /* r = (c1 << 8) + c0; */
  x = ((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  lsa->checksum = x + (y << 8);

  return (lsa->checksum);
}

/* free LSA. */
void
ospf_lsa_free (struct ospf_lsa *lsa)
{
  XFREE (MTYPE_OSPF_LSA, lsa);
}

/* Originate Router-LSA. */
struct ospf_lsa *
ospf_router_lsa (struct ospf_interface *oi)
{
  struct ospf_lsa *lsa, *new;
  listnode node;
  struct stream *s;
  int flag = 0;
  u_int16_t links = 0;
  int link_type = 0;
  int length = 0;
  u_int32_t putp;

  s = stream_new (oi->ifp->mtu);
  lsa = (struct ospf_lsa *) STREAM_DATA (s);

  lsa->ls_age = 0;
  lsa->options = oi->options;
  lsa->type = (u_char) OSPF_ROUTER_LSA;
  lsa->id = ospf_top->router_id;
  lsa->adv_router = ospf_top->router_id;
  lsa->ls_seqnum = htonl (ospf_top->ls_seqnum);

  ospf_top->ls_seqnum++;

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  /* set bit V if virtual link endpoint. */
  /* set bit E if AS boundary router. */
  /* set bit B if Area Border Router. */
  stream_putc (s, flag);

  stream_putc (s, 0);
  
  /* keep pointer to # links. */
  putp = s->putp;
  ospf_output_forward (s, 2);
  length += 4;

  /* Link Information. */
  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *o;
      struct in_addr link_id, link_data;
      u_int16_t link_cost = 0;

      ifp = getdata (node);
      o = ifp->if_data;

      if (o->flag != OSPF_IF_ENABLE)
	continue;

      if (o->area == NULL)
	continue;

      /* Area check. */
      if (IPV4_ADDR_CMP (&o->area->area_id, &oi->area->area_id))
	continue;

      /* if status is Down. */
      /*      if (o->status == ISM_Down)
	      continue; */

      /* Describe link. */
      switch (o->type)
	{
	case OSPF_IFTYPE_POINTOPOINT:
	  break;
	case OSPF_IFTYPE_BROADCAST:
	case OSPF_IFTYPE_NBMA:
	  if (o->status == ISM_Waiting)
	    {
	      struct in_addr mask;

	      /* Describe Type 3 Link. */
	      link_type = LSA_LINK_TYPE_STUB;
	      masklen2ip (o->address->prefixlen, &mask);
	      link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	      link_data = mask;
	      link_cost = o->output_cost;
	    }
	  else if (ospf_nbr_count (oi->nbrs, NSM_Full))
	    {
	      /* Describe Type 2 link. */
	      link_type = LSA_LINK_TYPE_TRANSIT;
	      link_id = o->d_router;
	      link_data = o->address->u.prefix4;
	      link_cost = o->output_cost;
	    }
	  else
	    {
	      struct in_addr mask;

	      link_type = LSA_LINK_TYPE_STUB;
	      masklen2ip (o->address->prefixlen, &mask);
	      link_id.s_addr = o->address->u.prefix4.s_addr & mask.s_addr;
	      link_data = mask;
	      link_cost = o->output_cost;
	    }
	  break;
	case OSPF_IFTYPE_POINTOMULTIPOINT:
	  break;
	case OSPF_IFTYPE_VIRTUALLINK:
	  break;
	}

      stream_put_ipv4 (s, link_id.s_addr);	/* Link ID. */
      stream_put_ipv4 (s, link_data.s_addr);	/* Link Data. */
      stream_putc (s, link_type);		/* Type. */
      stream_putc (s, (u_char) 0);		/* # TOS. */
      stream_putw (s, link_cost);		/* metric. */
      /* TOS based routing is not supported. */

      links++;
      length += 12;
    }

  /* Set # links. */
  stream_putw_at (s, putp, links);

  /* Set length. */
  lsa->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsa);

  /* Copy LSA to store. */
  new = (struct ospf_lsa *) XMALLOC (MTYPE_OSPF_LSA, length);
  memcpy (new, lsa, length);
  stream_free (s);

  return new;
}

/* Originate Network-LSA. */
struct ospf_lsa *
ospf_network_lsa (struct ospf_interface *oi)
{
  struct ospf *ospf;
  struct ospf_lsa *lsa, *new;
  struct in_addr mask;
  struct route_node *rn;
  struct stream *s;
  struct ospf_neighbor *nbr;
  int length;

  ospf = oi->ospf;

  s = stream_new (oi->ifp->mtu);
  lsa = (struct ospf_lsa *) s->data;

  /* LS age should be 0. */
  lsa->options = oi->options;
  lsa->type = (u_char) OSPF_NETWORK_LSA;

  lsa->id = oi->d_router;

  lsa->adv_router = ospf->router_id;
  lsa->ls_seqnum = htonl (ospf->ls_seqnum++);

  ospf_output_forward (s, OSPF_LSA_HEADER_SIZE);
  length = OSPF_LSA_HEADER_SIZE;

  masklen2ip (oi->address->prefixlen, &mask);

  /* Put Network Mask. */
  stream_put_ipv4 (s, mask.s_addr);
  length += 4;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    {
      if (rn->info == NULL)
	continue;
      nbr = rn->info;

      /* this is myself. */
      if (IPV4_ADDR_SAME (&nbr->router_id, &ospf_top->router_id))
	continue;

      stream_put_ipv4 (s, nbr->router_id.s_addr);
      length += 4;
    }

  /* Set length. */
  lsa->length = htons (length);

  /* Set Checksum. */
  ospf_lsa_checksum (lsa);

  /* Copy LSA to store. */
  new = (struct ospf_lsa *) XMALLOC (MTYPE_OSPF_LSA, length);
  memcpy (new, lsa, length);
  stream_free (s);

  return new;
}

/* Add router-LSA to an area. */
void
ospf_add_router_lsa (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct route_node *rn;
  struct prefix p;

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = lsa->id;

  rn = route_node_get (ROUTER_LSA (area), &p);
  if (rn->info != NULL)
    {
#ifdef DEBUG
      zlog (NULL, LOG_INFO, "There is already router-LSA for %s",
	    inet_ntoa (lsa->id));
#endif
      route_unlock_node (rn);
    /*  ospf_lsa_free (rn->info); */
    }
  rn->info = lsa;

  return;
}

/* Add network-LSA to an area. */
void
ospf_add_network_lsa (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct route_node *rn;
  struct prefix p;
  
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = lsa->id;

  rn = route_node_get (NETWORK_LSA (area), &p);
  if (rn->info)
    {
#ifdef DEBUG
      zlog (NULL, LOG_WARNING, "There is already network-LSA for %s",
	    inet_ntoa (lsa->id));
#endif
      route_unlock_node (rn);
      ospf_lsa_free (rn->info);
    }
  rn->info = lsa;

  return;
}

void
ospf_add_summary_lsa (struct ospf_area *area, struct ospf_lsa *lsa)
{
  return;
}

struct ospf_lsa *
ospf_lsa_lookup (struct ospf_area *area, u_int32_t type, struct in_addr id)
{
  struct route_node *rn;
  struct ospf_lsa *match;
  struct prefix p;

  match = NULL;
  switch (type)
    {
    case OSPF_ROUTER_LSA:
    case OSPF_NETWORK_LSA:
      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = id;
      rn = route_node_get (area->lsa[type - 1], &p);
      if (rn->info != NULL)
	{
	  route_unlock_node (rn);
	  match = (struct ospf_lsa *) rn->info;
	}
      break;
    case OSPF_SUMMARY_LSA:
    case OSPF_SUMMARY_LSA_ASBR:
      break;
    case OSPF_AS_EXTERNAL_LSA:
      break;
    default:
      break;
    }

  return match;
}

struct ospf_lsa *
ospf_lsa_lookup_by_header (struct ospf_area *area, struct ospf_lsa *lsa)
{
  struct ospf_lsa *match;

  match = ospf_lsa_lookup (area, lsa->type, lsa->id);

  return match;
}

listnode
ospf_lsa_lookup_from_list (list list, u_char type,
			   struct in_addr id, struct in_addr adv_router)
{
  listnode node;
  struct ospf_lsa *lsa;

  for (node = listhead (list); node; nextnode (node))
    {
      lsa = getdata (node);

      if (lsa->type == type && IPV4_ADDR_SAME (&lsa->id, &id) &&
	  IPV4_ADDR_SAME (&lsa->adv_router, &adv_router))
	return node;
    }

  return NULL;
}

/* return +n, l1 is more recent.
   return -n, l2 is more recent.
   return 0, l1 and l2 is identical. */
int
ospf_lsa_more_recent (struct ospf_lsa *l1, struct ospf_lsa *l2)
{
  int r;

  if (l1 == NULL && l2 == NULL)
    return 0;
  if (l1 == NULL)
    return -1;
  if (l2 == NULL)
    return 1;

  /* compare LS sequence number. */
  r = ntohl (l1->ls_seqnum) - ntohl (l2->ls_seqnum);
  if (r)
    return r;

  /* compare LS checksum. */
  r = ntohs (l1->checksum) - ntohs (l2->checksum);
  if (r)
    return r;

  /* compare LS age. */
  if (ntohs (l1->ls_age) == OSPF_LSA_MAX_AGE &&
      ntohs (l2->ls_age) != OSPF_LSA_MAX_AGE)
    return 1;
  else if (ntohs (l1->ls_age) != OSPF_LSA_MAX_AGE &&
	   ntohs (l2->ls_age) == OSPF_LSA_MAX_AGE)
    return -1;

  /* compare LS age with MaxAgeDiff. */
  if (ntohs (l1->ls_age) - ntohs (l2->ls_age) > OSPF_LSA_MAX_AGE_DIFF)
    return 1;
  else if (ntohs (l2->ls_age) - ntohs (l1->ls_age) > OSPF_LSA_MAX_AGE_DIFF)
    return -1;

  /* LSAs are identical. */
  return 0;
}

int
ospf_lsa_count (struct ospf_area *area)
{
  int count = 0;
  struct route_node *rn;

  /* Count router-LSAs. */
  for (rn = route_top (ROUTER_LSA (area)); rn; rn = route_next (rn))
    if (rn->info == NULL)
      continue;
    else
      count++;

  /* Count network-LSAs. */
  for (rn = route_top (NETWORK_LSA (area)); rn; rn = route_next (rn))
    if (rn->info == NULL)
      continue;
    else
      count++;

  /* Count summary-LSAs. */
  /*
  for (rn = route_top (area->lsa[3]); rn; rn = route_next (rn))
    if (rn->info == NULL)
      continue;
    else
      count++;
  */
  return count;
}


void
show_ip_ospf_database_all (struct vty *vty)
{
  listnode node;
  struct route_node *rn;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area;
      struct ospf_lsa *lsa;

      area = getdata (node);

      /* show Router-LSAs. */
      vty_out (vty, "                Router Link States (Area %s)\r\n\r\n",
	       inet_ntoa (area->area_id));
      vty_out (vty, "Link ID         ADV Router      Age         Seq#       Checksum Link count\r\n");

      for (rn = route_top (ROUTER_LSA (area)); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  lsa = (struct ospf_lsa *) rn->info;

	  vty_out (vty, "%-15s ", inet_ntoa (lsa->id));
	  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x   %-d\r\n",
		   inet_ntoa (lsa->adv_router), ntohs (lsa->ls_age),
		       ntohl (lsa->ls_seqnum), ntohs (lsa->checksum),
		   0);
	}
      vty_out (vty, "\r\n");

      /* show Network-LSAs. */
      vty_out (vty, "                Router Link States (Area %s)\r\n\r\n",
	       inet_ntoa (area->area_id));
      vty_out (vty, "Link ID         ADV Router      Age         Seq#       Checksum\r\n");
      for (rn = route_top (NETWORK_LSA (area)); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  lsa = (struct ospf_lsa *) rn->info;

	  vty_out (vty, "%-15s ", inet_ntoa (lsa->id));
	  vty_out (vty, "%-15s %-11d 0x%08x 0x%04x\r\n",
		   inet_ntoa (lsa->adv_router), ntohs (lsa->ls_age),
		       ntohl (lsa->ls_seqnum), ntohs (lsa->checksum));
	}
      vty_out (vty, "\r\n");
    }
}

void
show_ip_ospf_database_network (struct vty *vty)
{
  listnode node;
  struct route_node *rn;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area;
      struct ospf_lsa *lsa;
      struct network_lsa *nl;
      int length, i;

      area = getdata (node);

      vty_out (vty, "                Net Link States (Area %s)\r\n\r\n",
	       inet_ntoa (area->area_id));

      for (rn = route_top (NETWORK_LSA (area)); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  lsa = (struct ospf_lsa *) rn->info;
	  nl = (struct network_lsa *) rn->info;

	  vty_out (vty, "  LS age: %d\r\n", ntohs (lsa->ls_age));
	  vty_out (vty, "  Options: %d\r\n", lsa->options);
	  vty_out (vty, "  LS Type: Network Links\r\n");
	  vty_out (vty, "  Link State ID: %s "
		   "(address of Designated Router)\r\n", inet_ntoa (lsa->id));
	  vty_out (vty, "  Advertising Router: %s\r\n",
		   inet_ntoa (lsa->adv_router));
	  vty_out (vty, "  LS Seq Number: %08x\r\n", ntohl (lsa->ls_seqnum));
	  vty_out (vty, "  Checksum: 0x%04x\r\n", lsa->checksum);
	  vty_out (vty, "  Length: %d\r\n", ntohs (lsa->length));
	  vty_out (vty, "  Network Mask: /%d\r\n",
		   ip_masklen (nl->mask));

	  length = ntohs (lsa->length) - OSPF_LSA_HEADER_SIZE - 4;

	  for (i = 0; length > 0; i++, length -= 4)
	    vty_out (vty, "        Attached Router: %s\r\n",
		     inet_ntoa (nl->routers[i]));
	}
      vty_out (vty, "\r\n");
    }
}

void
show_ip_ospf_database_router (struct vty *vty)
{
  listnode node;
  struct route_node *rn;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area;
      struct ospf_lsa *lsa;
      struct router_lsa *rl;
      
      area = getdata (node);

      vty_out (vty, "\r\n                Router Link States (Area %s)\r\n\r\n",
	       inet_ntoa (area->area_id));

      for (rn = route_top (ROUTER_LSA (area)); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;

	  lsa = (struct ospf_lsa *) rn->info;
	  rl = (struct router_lsa *) rn->info;

	  vty_out (vty, "  LS age: %d\r\n", ntohs (lsa->ls_age));
	  vty_out (vty, "  Options: %d\r\n", lsa->options);
	  vty_out (vty, "  LS Type: Router Links\r\n");
	  vty_out (vty, "  Link State ID: %s\r\n", inet_ntoa (lsa->id));
	  vty_out (vty, "  Advertising Router: %s\r\n",
		   inet_ntoa (lsa->adv_router));
	  vty_out (vty, "  LS Seq Number: %08x\r\n", ntohl (lsa->ls_seqnum));
	  vty_out (vty, "  Checksum: 0x%04x\r\n", lsa->checksum);
	  vty_out (vty, "  Length: %d\r\n", ntohs (lsa->length));
	  
	  vty_out (vty, "   Number of Links: %d\r\n", ntohs (rl->links));
	  vty_out (vty, "\r\n\r\n");
	}
      vty_out (vty, "\r\n");
    }
}

DEFUN (show_ip_ospf_database,
       show_ip_ospf_database_cmd,
       "show ip ospf database",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n")
{
  vty_out (vty, "\r\n       OSPF Router with ID (%s)\r\n\r\n",
	   inet_ntoa (ospf_top->router_id));

  /* show all LSA. */
  if (argc == 0)
    show_ip_ospf_database_all (vty);
  else if (argc == 1)
    if (strncmp (argv[0], "n", 1) == 0)
      show_ip_ospf_database_network (vty);
    else if (strncmp (argv[0], "r", 1) == 0)
      show_ip_ospf_database_router (vty);
    else
      return CMD_WARNING;

  return CMD_SUCCESS;
}
       
ALIAS (show_ip_ospf_database,
       show_ip_ospf_database_type_cmd,
       "show ip ospf database (network|router)",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "Network link states\n"
       "Router link states\n")

/* Install LSA related commands. */
void
ospf_lsa_init ()
{
  install_element (VIEW_NODE, &show_ip_ospf_database_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_database_type_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_database_type_cmd);
}
