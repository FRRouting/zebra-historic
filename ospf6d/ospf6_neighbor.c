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
delete_ospf6_nbr (struct neighbor *nbr)
{
}

int
neighbor_thread_cancel (struct neighbor *nbr)
{
  if (nbr->inactivity_timer)
    thread_cancel (nbr->inactivity_timer);
  if (nbr->send_dd)
    thread_cancel (nbr->send_dd);
  if (nbr->send_lsreq)
    thread_cancel (nbr->send_lsreq);
  if (nbr->send_update)
    thread_cancel (nbr->send_update);

  nbr->inactivity_timer = nbr->send_dd = nbr->send_lsreq = nbr->send_update
    = (struct thread *)NULL;

  /* new */
  if (nbr->thread_dbdesc_retrans)
    thread_cancel (nbr->thread_dbdesc_retrans);
  nbr->thread_dbdesc_retrans = (struct thread *) NULL;

  return 0;
}

int
list_cleared_of_lsa (struct neighbor *nbr)
{
  list_delete_all_node (nbr->dd_retrans);
  ospf6_lsdb_finish_neighbor (nbr);
  ospf6_lsdb_init_neighbor (nbr);
  return 0;
}

int
free_last_dd (struct thread *thread)
{
  struct neighbor *nbr;

  nbr = (struct neighbor *)THREAD_ARG (thread);
  assert (nbr);
  memset (&nbr->last_dd, 0, sizeof (struct ospf6_dbdesc));
  return 0;
}

/* count neighbor which is in "state" in this area*/
unsigned int
count_nbr_in_state (state_t state, struct area *area)
{
  listnode n, o;
  struct ospf6_if *o6if;
  struct neighbor *nbr;
  unsigned int count = 0;

  for (n = listhead (area->if_list); n; nextnode (n))
    {
      o6if = (struct ospf6_if *) getdata (n);
      for (o = listhead (o6if->nbr_list); o; nextnode (o))
        {
          nbr = (struct neighbor *) getdata (o);
          if (nbr->state == state)
            count++;
        }
    }
  return count;
}

void
ospf6_ipv4_nexthop_from_linklocal (struct in6_addr *in6, struct in_addr *in4,
                                   u_int ifindex)
{
  struct interface *ifp;
  struct ospf6_if *o6if;
  listnode n;
  struct ospf6_lsa *lsa;
  struct link_lsa *llsa;
  unsigned long prefixnum;
  struct ospf6_prefix *o6p;

  memset (in4, 0, sizeof (struct in_addr));

  ifp = if_lookup_by_index (ifindex);
  if (!ifp)
    {
      zlog_warn ("  *** can't find interface (ifindex: %d)", ifindex);
      return;
    }
  o6if = (struct ospf6_if *) ifp->info;
  if (!o6if)
    {
      zlog_warn ("  *** can't find ospf6_if (ifindex: %d)", ifindex);
      return;
    }

  /* find neighbor from linklocal address */
  for (n = listhead (o6if->linklocal_lsa); n; nextnode (n))
    {
      lsa = (struct ospf6_lsa *) getdata (n);
      llsa = (struct link_lsa *) LSH_NEXT (lsa->lsa_hdr);
      if (memcmp (&llsa->llsa_linklocal, in6, sizeof (struct in6_addr)))
        return;
      prefixnum = ntohl (llsa->llsa_prefix_num);

      zlog_info (" Debug IPv4 prefixnum %d", prefixnum);

      for (o6p = (struct ospf6_prefix *) (llsa + 1);
           (char *) o6p < (char *) lsa->lsa_hdr
                          + ntohs (lsa->lsa_hdr->lsh_len) && prefixnum;
           o6p = OSPF6_NEXT_PREFIX (o6p), prefixnum--)
        {
          struct in6_addr tmp;
          if (!IN6_IS_ADDR_V4MAPPED (&tmp))
            continue;
          if (o6p->o6p_prefix_len != 128)
            {
              zlog_warn ("  *** prefix length not 128!!!: %d",
                         o6p->o6p_prefix_len);
              continue;
            }
          ospf6_prefix_in6_addr (o6p, &tmp);
          ospf6_ipv6_decode_ipv4 (&tmp, in4);
          {
            char buf1[64], buf2[64];
            inet_ntop (AF_INET6, &tmp, buf1, sizeof(buf1));
            inet_ntop (AF_INET, in4, buf2, sizeof(buf2));
            zlog_info (" Debug IPv4 : %s %s", buf1, buf2);
          }
        }
    }
}

/* Neighbor section */
/* Allocate new Neighbor data structure */
static struct neighbor *
neighbor_new ()
{
  struct neighbor *new = (struct neighbor *)
      XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct neighbor));
  if (new)
    memset (new, 0, sizeof (struct neighbor));
  else
    zvlog_warn ("Can't malloc neighbor");
  return new;
}



/* Make new neighbor structure */
struct neighbor *
make_neighbor (rtr_id_t rtr_id, struct ospf6_if *ospf6_if)
{
  struct neighbor *nbr = neighbor_new ();

  if (!nbr)
    return (struct neighbor *)NULL;
  nbr->state = NBS_DOWN;
  nbr->ospf6_if = ospf6_if;
  nbr->rtr_id = rtr_id;
  inet_ntop (AF_INET, &rtr_id, nbr->str, sizeof (nbr->str));
  nbr->inactivity_timer = (struct thread *)NULL;
  nbr->dd_retrans = list_init ();
  nbr->summarylist = list_init ();
  nbr->retranslist = list_init ();
  nbr->requestlist = list_init ();
  nbr->direct_ack = list_init ();
  list_add_node (ospf6_if->nbr_list, nbr);

  return nbr;
}

/* delete neighbor from ospf6_if nbr_list */
void
delete_neighbor (struct neighbor *nbr, struct ospf6_if *ospf6_if)
{
  /* xxx not yet */
  return;
}

/* delete all neighbor on ospf6_if nbr_list */
void
delete_all_neighbors (struct ospf6_if *ospf6_if)
{
  /* xxx not yet */
  return;
}


/* Lookup functions. */
/* lookup neighbor from OSPF6 interface.
   because neighbor may appear on two different OSPF interface */
struct neighbor *
nbr_lookup (rtr_id_t rtr_id, struct ospf6_if *o6if)
{
  struct neighbor *nbr;
  listnode k;

  for (k = listhead (o6if->nbr_list); k; nextnode (k))
    {
      nbr = (struct neighbor *)getdata (k);
      if (nbr->rtr_id == rtr_id)
        return nbr;
    }

  return (struct neighbor *)NULL;
}


/* show specified area structure */

/* show neighbor structure */
int
show_nbr (struct vty *vty, struct neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

#if 0
  vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
     "RouterID", "I/F-ID", "State", "DR", "BDR", "I/F", "State", VTY_NEWLINE);
#endif

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]%s",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_if->interface->name,
           ifs_name[nbr->ospf6_if->state],
	   VTY_NEWLINE);
  return 0;
}

void
ospf6_neighbor_vty_summary (struct vty *vty, struct neighbor *nbr)
{
  char rtrid[16], dr[16], bdr[16];

/*
   vty_out (vty, "%-15s %-6s %-8s %-15s %-15s %s[%s]%s",
            "RouterID", "I/F-ID", "State", "DR",
            "BDR", "I/F", "State", VTY_NEWLINE);
*/

  inet_ntop (AF_INET, &nbr->rtr_id, rtrid, sizeof (rtrid));
  inet_ntop (AF_INET, &nbr->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &nbr->bdr, bdr, sizeof (bdr));
  vty_out (vty, "%-15s %6lu %-8s %-15s %-15s %s[%s]%s",
           rtrid, nbr->ifid, nbs_name[nbr->state], dr, bdr,
           nbr->ospf6_if->interface->name,
           ifs_name[nbr->ospf6_if->state],
	   VTY_NEWLINE);
}

void
ospf6_neighbor_vty (struct vty *vty, struct neighbor *o6n)
{
  vty_out (vty, " Neighbor %s, interface address%s",
           o6n->str, VTY_NEWLINE);
  vty_out (vty, "    In the area %s via interface %s%s",
           o6n->ospf6_if->area->str, o6n->ospf6_if->interface->name,
           VTY_NEWLINE);
  vty_out (vty, "    Neighbor priority is %d, State is %s, %d state changes%s",
           o6n->rtr_pri, nbs_name[o6n->state], 0, VTY_NEWLINE);
}

