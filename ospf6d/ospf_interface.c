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

#include "ospfd.h"

int
ifs_change (state_t ifs_next, char *reason, struct ospf_if *iface)
{
  state_t ifs_prev;

  ifs_prev = iface->state;

#ifdef DEBUG_OSPF
  log ("IFSCHANGE: [%s]->[%s](%s) on %s \n",
       ifs_name[ifs_prev], ifs_name[ifs_next], reason, iface->ifname);
#endif

  if (ifs_next == IFS_DR || ifs_next == IFS_BDR)
    {
      if (ifs_prev != IFS_DR && ifs_prev != IFS_BDR)
	{
	  if (mcast_join (inet6.ospf_sock, inet6.alldr, inet6.salen,
			  iface->ifname, 0) < 0)
	    {
	      log ("mcast_join() failed: %s\n", strerror (errno));
	    }
	}
    }
  else
    {
      if (ifs_prev == IFS_DR || ifs_prev == IFS_BDR)
	{
	  if (mcast_leave (inet6.ospf_sock, inet6.alldr, inet6.salen,
			   iface->ifname, 0) < 0)
	    {
	      log ("mcast_leave() failed: %s\n", strerror (errno));
	    }
	}
    }

  iface->state = ifs_next;

  construct_router_lsa (iface->area);
  dr_change (iface);

  return 0;
}

int dr_change (struct ospf_if *iface)
{
  char dr[16], bdr[16], prevdr[16], prevbdr[16];

  if (id_val (iface->prevdr) == id_val (iface->dr)
      && id_val (iface->prevbdr) == id_val (iface->bdr))
    return 0; /* Nothing has been changed */
  
#ifdef DEBUG_OSPF
  strncpy (prevdr, inet_ntoa (*(struct in_addr *)&iface->prevdr), sizeof (prevdr));
  strncpy (prevbdr, inet_ntoa (*(struct in_addr *)&iface->prevbdr), sizeof (prevbdr));
  strncpy (dr, inet_ntoa (*(struct in_addr *)&iface->dr), sizeof (dr));
  strncpy (bdr, inet_ntoa (*(struct in_addr *)&iface->bdr), sizeof (bdr));
  log ("DRCHANGE: {DR[%s], BDR[%s]}->{DR[%s], BDR[%s]}\n", prevdr, prevbdr, dr, bdr);
#endif

  construct_router_lsa (iface->area);
  if (iface->state == IFS_DR)
    {
      construct_network_lsa (iface);
      construct_intra_prefix_lsa (iface);
    }

  return 0;
}

#ifdef OLD
/* collect all interface infomation of this machine */
void
get_interface_all ()
{
  int mib[6];
  size_t needed;
  char *lim, *next, ifname[INTERFACE_NAMSIZ];
  char ifbuf[2048];
  struct if_msghdr *ifm, *nextifm;
  struct ifa_msghdr *ifam;
  struct sockaddr_dl *sdl;
  struct ifinfo *ifinfo_new;
  struct interface *iface;
  struct rt_addrinfo *rinfo;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_UNSPEC; /* address family: all */
  mib[4] = NET_RT_IFLIST;
  mib[5] = 0;

  if (sysctl (mib, 6, NULL, &needed, NULL, 0) < 0)
    log ("iflist-sysctl-estimate\n");
  if ((ifbuf = XMALLOC (MTYPE_OSPF_IF, needed)) == NULL)
    log ("malloc in get_interface_all\n");
  if (sysctl (mib, 6, ifbuf, &needed, NULL, 0) < 0)
    log ("actual retrieval of interface table\n");

  lim = ifbuf + needed;
  next = ifbuf;

  while (next < lim)
    {
      iface = NULL;
      bzero (ifname, sizeof (ifname));
      ifm = (struct if_msghdr *)next;

      if (ifm->ifm_type == RTM_IFINFO)
        {
          ifinfo_new = (struct ifinfo *)
                XMALLOC (MTYPE_OSPF_IF, sizeof (struct ifinfo));
          if (!ifinfo_new)
            {
              log ("can't malloc ifinfo in get_interface_all()\n");
              return;
            }
          ifinfo_new->sdl = (struct sockaddr_dl *)(ifm + 1);
	  ifinfo_new->flags = ifm->ifm_flags;
          ifinfo_new->addr_list = list_init ();
          strncpy (ifname, ifinfo_new->sdl->sdl_data,
                   ifinfo_new->sdl->sdl_nlen);
          ifname[ifinfo_new->sdl->sdl_nlen] = '\0';
          iface = make_interface (ifname);
          iface->ifinfo = ifinfo_new;
          iface->networks = list_init ();
        }
      else
        {
          log ("out of sync parsing NET_RT_IFLIST\n");
          return;
        }

      next += ifm->ifm_msglen;
      ifam = (struct ifa_msghdr *)next;

      while (next < lim)
        {
          nextifm = (struct if_msghdr *)next;

          if (nextifm->ifm_type != RTM_NEWADDR)
            {
              break;
            }

          rinfo = (struct rt_addrinfo *)
                   XMALLOC (MTYPE_OSPF_IF, sizeof (struct rt_addrinfo));
          if (!rinfo)
            {
              log ("can't malloc rinfo in get_interface_all()\n");
              return ;
            }

          rinfo->rti_addrs = ifam->ifam_addrs;
          rt_xaddrs ((char *)(ifam + 1), ifam->ifam_msglen + (char *)ifam,
                     rinfo);

          list_add_node (iface->ifinfo->addr_list, rinfo);

          next += nextifm->ifm_msglen;
          ifam = (struct ifa_msghdr *)((char *)ifam + ifam->ifam_msglen);
        }
      address_prepare (iface);
    }
}

void
address_prepare (struct interface *iface)
{
  listnode node;
  struct network *netp;

#ifdef DEBUG_OSPF
  if (list_isempty (iface->ifinfo->addr_list))
    log ("interface %s: no address\n", iface->ifname);
#endif /* DEBUG_OSPF */

  for (node = listhead (iface->ifinfo->addr_list);
       node;
       nextnode (node))
    {
      netp = get_address ((struct rt_addrinfo *)getdata (node));
      if (netp)
	{
	  list_add_node (iface->networks, netp);
	}
    }

  return;
}


struct network *
get_address (struct rt_addrinfo *rinfo)
{
  int i;
  struct network *netp;
  struct sockaddr_in *ifa4, *netmask4;
  struct sockaddr_in6 *ifa, *netmask;

  if (rinfo->rti_addrs & RTAX_IFA == 0)
    {
      log ("No interface address in get_address()\n");
      return NULL;
    }
  if (rinfo->rti_addrs & RTAX_NETMASK == 0)
    {
      log ("No netmask in get_address()\n");
      return NULL;
    }

  netp = (struct network *) XMALLOC (MTYPE_OSPF_IF, sizeof (struct network));
  if (!netp)
    {
      log ("can't malloc in get_address()\n");
      return NULL;
    }

  switch (((struct sockaddr *)rinfo->rti_info[RTAX_IFA])->sa_family)
    {
    case AF_INET:
      ifa4 = (struct sockaddr_in *)rinfo->rti_info[RTAX_IFA];
      netmask4 = (struct sockaddr_in *)rinfo->rti_info[RTAX_NETMASK];

      netp->address.s6_addr32[0] = 0;
      netp->address.s6_addr32[1] = 0;
      netp->address.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
      netp->address.s6_addr32[3] = ifa4->sin_addr.s_addr;
      netp->prefixlen = 96 + mask2prefix ((char *)&netmask4->sin_addr, sizeof(struct in_addr));
      break;
    case AF_INET6:
      ifa = (struct sockaddr_in6 *)rinfo->rti_info[RTAX_IFA];
      netmask = (struct sockaddr_in6 *)rinfo->rti_info[RTAX_NETMASK];

      netp->address.s6_addr32[0] = ifa->sin6_addr.s6_addr32[0];
      netp->address.s6_addr32[1] = ifa->sin6_addr.s6_addr32[1];
      netp->address.s6_addr32[2] = ifa->sin6_addr.s6_addr32[2];
      netp->address.s6_addr32[3] = ifa->sin6_addr.s6_addr32[3];
      netp->prefixlen = mask2prefix ((char *)&netmask->sin6_addr, sizeof(struct in6_addr));
      break;
    default:
      if (netp)
	{
	  XFREE (MTYPE_OSPF_IF, netp);
	}
      return NULL;
    }

  return netp;
}

void
show_one_address (struct vty *vty, struct network *netp)
{
  char ntop_buf[2][INET6_ADDRSTRLEN];
  struct in6_addr network, netmask;

  prefix2mask (netp->prefixlen, (void *)&netmask, sizeof (netmask));
  network.s6_addr32[0] = netp->address.s6_addr32[0] & netmask.s6_addr32[0];
  network.s6_addr32[1] = netp->address.s6_addr32[1] & netmask.s6_addr32[1];
  network.s6_addr32[2] = netp->address.s6_addr32[2] & netmask.s6_addr32[2];
  network.s6_addr32[3] = netp->address.s6_addr32[3] & netmask.s6_addr32[3];

  if (IN6_IS_ADDR_V4MAPPED (&netp->address))
    {
      vty_out (vty, "\tinet %s",
	       inet_ntoa (*(struct in_addr *)&(netp->address.s6_addr32[3])));
      vty_out (vty, " network %s/%d\r\n",
	       inet_ntoa (*(struct in_addr *)&(network.s6_addr32[3])),
	       netp->prefixlen);
    }
  else
    {
      vty_out (vty, "\tinet6 %s network %s/%d\r\n",
	       inet_ntop (AF_INET6, (void *)&netp->address, ntop_buf[0],
			  sizeof (ntop_buf[0])),
	       inet_ntop (AF_INET6, (void *)&network, ntop_buf[1],
			  sizeof (ntop_buf[1])),
	       netp->prefixlen);
    }
  return;
}

void
show_address (struct vty *vty, struct interface *iface)
{
  listnode i;
  struct network *netp;

  for (i = listhead (iface->networks); i; nextnode (i))
    {
      netp = getdata (i);
      show_one_address (vty, netp);
    }
}

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
#endif

/* Interface State Machine */
int
interface_up (struct thread *thread)
{
  u_int on, off;
  struct ospf_if *iface;

  on = 1; off = 0;

  iface = THREAD_ARG (thread);
  if (!iface)
    {
      log_warn ("Thread argument NULL, can't execute InterfaceUp Event\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("IFEVENT: InterfaceUp on %s\n", iface->ifname);
#endif

  if (!if_is_up (iface->interface))
    {
      log_warn ("Interface %s is down, can't execute InterfaceUp Event\n",
		iface->ifname);
      return -1;
    }

  if (iface->state > IFS_DOWN)
    {
      log_warn ("Interface %s is already up, Nothing to do\n", iface->ifname);
      return 0;
    }

  /* ifid of this interface */
  iface->ifid = iface->interface->index;
  zlog (NULL, LOG_INFO, "%s: ifid %d\n", iface->ifname, iface->ifid);

  if (mcast_join (inet6.ospf_sock, inet6.allspf, inet6.salen,
		  iface->ifname, 0) < 0)
    {
      log ("mcast_join() failed: %s\n", strerror (errno));
    }
#ifdef DEBUG_MY_PACKET
  if (setsockopt (inet6.ospf_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		  &on, sizeof (u_int)) < 0)
#else
    if (setsockopt (inet6.ospf_sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    &off, sizeof (u_int)) < 0)
#endif
      {
	log ("setsockopt() failed: IPV6_MULTICAST_LOOP: %s\n", strerror (errno));
      }
  if (setsockopt (inet6.ospf_sock, IPPROTO_IPV6, IPV6_PKTINFO,
		  &on, sizeof (int)) < 0)
    {
      log ("IPV6_PKTINFO setsockopt failed\n");
      return -1;
    }

  thread_add_event (master, send_hello, iface, 0);

  if (if_is_pointopoint (iface->interface))
    {
      ifs_change (IFS_PTOP, "IF Type PointToPoint", iface);
    }
  else if (iface->rtr_pri == 0)
    {
      ifs_change (IFS_DROTHER, "Priority < 0", iface);
    }
  else
    {
      ifs_change (IFS_WAITING, "Priority > 0", iface);
      thread_add_timer (master, wait_timer, iface, iface->rtr_dead_interval);
    }

  construct_link_lsa (iface);
  return 0;
}

int
wait_timer (struct thread *thread)
{
  struct ospf_if *iface;

  iface = THREAD_ARG  (thread);
  if (!iface)
    {
      log_warn ("!!!thread arg null for wait_timer()\n");
      return -1;
    }

  if (iface->state != IFS_WAITING)
    return 0;

#ifdef DEBUG_OSPF
  log ("IFEVENT: WaitTimer on %s\n", iface->ifname);
#endif

  ifs_change (dr_election (iface), "DR Election", iface);
  return 0;
}

int backup_seen (struct thread *thread)
{
  struct ospf_if *iface;

  iface = THREAD_ARG  (thread);
  if (!iface)
    {
      log_warn ("!!!thread arg null for backup_seen()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("IFEVENT: BackupSeen on %s\n", iface->ifname);
#endif

  if (iface->state == IFS_WAITING)
    ifs_change (dr_election (iface), "DR Election", iface);

  return 0;
}

int neighbor_change (struct thread *thread)
{
  struct ospf_if *iface;

  iface = THREAD_ARG  (thread);
  if (!iface)
    {
      log_warn ("!!!thread arg null for neighbor_change()\n");
      return -1;
    }

  if (iface->state != IFS_DROTHER &&
      iface->state != IFS_BDR &&
      iface->state != IFS_DR)
    return 0;

#ifdef DEBUG_OSPF
  log ("IFEVENT: NeighborChange on %s\n", iface->ifname);
#endif

  ifs_change (dr_election (iface), "DR Election", iface);

  return 0;
}

int
loopind (struct thread *thread)
{
  struct ospf_if *iface;

  iface = THREAD_ARG (thread);
  if (!iface)
    {
      log_warn ("!!!thread arg null for loopind()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("IFEVENT: LoopInd on %s\n", iface->ifname);
#endif

  return 0;
}

int
interface_down (struct thread *thread)
{
  struct ospf_if *iface;
  struct area *area;
  listnode n;

  iface = THREAD_ARG (thread);
  if (!iface)
    {
      log_warn ("!!!thread arg null for interface_down()\n");
      return -1;
    }

#ifdef DEBUG_OSPF
  log ("IFEVENT: InterfaceDown on %s\n", iface->ifname);
#endif

  if (iface->state == IFS_NONE)
    return 1;

  ifs_change (IFS_DOWN, "Configured", iface);

  while (!list_isempty (iface->nb_list))
    {
      n = listhead (iface->nb_list);
      XFREE (MTYPE_OSPF_NEIGHBOR, getdata (n));
      list_delete_by_val (iface->nb_list, getdata (n));
    }

  area = iface->area;
  detach_interface (iface, iface->area);

  return 0;
}
