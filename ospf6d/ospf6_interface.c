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
ifs_change (state_t ifs_next, char *reason, struct ospf6_if *ospf6_if)
{
  state_t ifs_prev;

  ifs_prev = ospf6_if->state;

#ifdef DEBUG_OSPF6
  zvlog_info ("IFSCHANGE: [%s]->[%s](%s) on %s",
              ifs_name[ifs_prev], ifs_name[ifs_next], reason,
              ospf6_if->interface->name);
#endif

  switch (ifs_prev)
    {
    case IFS_DR:
    case IFS_BDR:
      switch (ifs_next)
        {
        case IFS_DR:
        case IFS_BDR:
          break;
        default:
          if (mcast_leave (ospf6_sock, (struct sockaddr *)&alldrouters6,
                           ospf6_if->interface->name,
                           ospf6_if->interface->index) < 0)
            zvlog_warn ("mcast_leave() failed: %s", strerror (errno));
          break;
        }
      break;
    default:
      switch (ifs_next)
        {
        case IFS_DR:
        case IFS_BDR:
          if (mcast_join (ospf6_sock, (struct sockaddr *)&alldrouters6,
                          ospf6_if->interface->name,
                          ospf6_if->interface->index) < 0)
            zvlog_warn ("mcast_join() failed: %s", strerror (errno));
          break;
        default:
          break;
        }
      break;
    }

  ospf6_if->state = ifs_next;

  construct_router_lsa (ospf6_if->area);
  dr_change (ospf6_if);

  return 0;
}

int
dr_change (struct ospf6_if *ospf6_if)
{
  if (ospf6_if->prevdr == ospf6_if->dr
      && ospf6_if->prevbdr == ospf6_if->bdr)
    return 0; /* Nothing has been changed */

#ifdef DEBUG_OSPF6
  {
    char dr[16], bdr[16], prevdr[16], prevbdr[16];
    inet_ntop (AF_INET, &ospf6_if->prevdr, prevdr, sizeof (prevdr));
    inet_ntop (AF_INET, &ospf6_if->prevbdr, prevbdr, sizeof (prevbdr));
    inet_ntop (AF_INET, &ospf6_if->dr, dr, sizeof (dr));
    inet_ntop (AF_INET, &ospf6_if->bdr, bdr, sizeof (bdr));
    zvlog_info ("DRCHANGE: {DR[%s], BDR[%s]}->{DR[%s], BDR[%s]}",
                prevdr, prevbdr, dr, bdr);
  }
#endif

  construct_router_lsa (ospf6_if->area);
  if (ospf6_if->state == IFS_DR)
    {
      construct_network_lsa (ospf6_if);
      construct_intra_prefix_lsa (ospf6_if);
    }

  return 0;
}

#if 0
prefixlen_t
mask2prefix (const char *val, const int size)
{
  int ret = 0, i;
  char c, *p;

  for (i = 0; i < size; i++)
    {
      if ((u_char)val[i] != 0xff)
        break;
      ret += 8;
    }
  c = val[i];
  p = &c;
  while (*p)
    {
      ret += 1;
      *p = *p << 1;
    }
  return ret;
}

int
prefix2mask (const int prefix, char *val, const int size)
{
  int i, j;

  if (!val)
    return -1;
  switch (size)
    {
      case 4:
        if (prefix > 32 || prefix < 0)
          return -1;
        break;
      case 16:
        if (prefix > 128 || prefix < 0)
          return -1;
        break;
      default:
        return -1;
    }
  bzero (val, size);
  for (i = 0; i < prefix / 8; i ++)
    val[i] = 0xff;
  for (j = 8 - prefix % 8; j < 8; j++)
    val[i] |= 1 << j;
  return 0;
}
#endif /* 0 */


/* Interface State Machine */
int
interface_up (struct thread *thread)
{
  u_int on, off;
  struct ospf6_if *ospf6_if;

  on = 1; off = 0;

  ospf6_if = (struct ospf6_if *)THREAD_ARG (thread);
  assert (ospf6_if);

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: InterfaceUp on %s", ospf6_if->interface->name);
#endif

  assert (ospf6_if->interface);
  if (!if_is_up (ospf6_if->interface))
    {
      zvlog_err ("Interface %s is down, can't execute InterfaceUp event",
      ospf6_if->interface->name);
      return -1;
    }

  if (ospf6_if->state > IFS_DOWN)
    {
      zvlog_notice ("Interface %s is already up",
                    ospf6_if->interface->name);
      return 0;
    }

  /* ifid of this interface */
  ospf6_if->ifid = ospf6_if->interface->index;
  zvlog_debug ("interface %s: ifid %lu", ospf6_if->interface->name,
               ospf6_if->ifid);

  if (mcast_join (ospf6_sock, (struct sockaddr *)&allspfrouters6,
                  ospf6_if->interface->name,
                  ospf6_if->interface->index) < 0)
    zvlog_warn ("mcast_join() failed: %s\n", strerror (errno));

#ifdef DEBUG_MY_PACKET
  if (setsockopt (ospf6_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                  &on, sizeof (u_int)) < 0)
    {
      zlog (NULL, LOG_WARNING,"setsockopt() failed: IPV6_MULTICAST_LOOP: %s",
                  strerror (errno));
    }
#else
  if (setsockopt (ospf6_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                  &off, sizeof (u_int)) < 0)
    {
      zlog (NULL, LOG_WARNING,"setsockopt() failed: IPV6_MULTICAST_LOOP: %s",
                  strerror (errno));
    }
#endif

  if (setsockopt (ospf6_sock, IPPROTO_IPV6, IPV6_PKTINFO,
                  &on, sizeof (int)) < 0)
    {
      zlog (NULL, LOG_WARNING,"IPV6_PKTINFO setsockopt failed");
      return -1;
    }

  thread_add_event (master, send_hello, ospf6_if, 0);

  if (if_is_pointopoint (ospf6_if->interface))
    {
      ifs_change (IFS_PTOP, "IF Type PointToPoint", ospf6_if);
    }
  else if (ospf6_if->rtr_pri == 0)
    {
      ifs_change (IFS_DROTHER, "Router Priority = 0", ospf6_if);
    }
  else
    {
      ifs_change (IFS_WAITING, "Priority > 0", ospf6_if);
      thread_add_timer (master, wait_timer, ospf6_if,
                        ospf6_if->rtr_dead_interval);
    }

  construct_link_lsa (ospf6_if);
  return 0;
}

int
wait_timer (struct thread *thread)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = (struct ospf6_if *)THREAD_ARG  (thread);
  assert (ospf6_if);

  if (ospf6_if->state != IFS_WAITING)
    return 0;

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: WaitTimer on %s", ospf6_if->interface->name);
#endif

  ifs_change (dr_election (ospf6_if), "WaitTimer:DR Election", ospf6_if);
  return 0;
}

int backup_seen (struct thread *thread)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = (struct ospf6_if *)THREAD_ARG  (thread);
  assert (ospf6_if);

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: BackupSeen on %s", ospf6_if->interface->name);
#endif

  if (ospf6_if->state == IFS_WAITING)
    ifs_change (dr_election (ospf6_if), "BackupSeen:DR Election", ospf6_if);

  return 0;
}

int neighbor_change (struct thread *thread)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = (struct ospf6_if *)THREAD_ARG  (thread);
  assert (ospf6_if);

  if (ospf6_if->state != IFS_DROTHER &&
      ospf6_if->state != IFS_BDR &&
      ospf6_if->state != IFS_DR)
    return 0;

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: NeighborChange on %s", ospf6_if->interface->name);
#endif

  ifs_change (dr_election (ospf6_if), "NeighborChange:DR Election", ospf6_if);

  return 0;
}

int
loopind (struct thread *thread)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = (struct ospf6_if *)THREAD_ARG (thread);
  assert (ospf6_if);

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: LoopInd on %s", ospf6_if->interface->name);
#endif

  return 0;
}

int
interface_down (struct thread *thread)
{
  struct ospf6_if *ospf6_if;

  ospf6_if = (struct ospf6_if *)THREAD_ARG (thread);
  assert (ospf6_if);

#ifdef DEBUG_OSPF6
  zvlog_info ("IFEVENT: InterfaceDown on %s", ospf6_if->interface->name);
#endif

  if (ospf6_if->state == IFS_NONE)
    return 1;

  ifs_change (IFS_DOWN, "Configured", ospf6_if);

#if 0
  {
    struct neighbor *nbr;
    listnode n;
    while (!list_isempty (ospf6_if->nbr_list))
      {
        n = listhead (ospf6_if->nbr_list);
        nbr = (struct neighbor *) getdata (n);
        neighbor_thread_cancel (nbr);
        XFREE (MTYPE_OSPF_NEIGHBOR, nbr);
        list_delete_by_val (ospf6_if->nbr_list, nbr);
      }
    detach_interface (ospf6_if, ospf6_if->area);
  }
#endif

  return 0;
}

