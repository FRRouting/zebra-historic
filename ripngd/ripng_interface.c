/* Interface related function for RIPng.
   Copyright (C) 1998 Kunihiro Ishiguro

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

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <errno.h>

#include "ripngd.h"
#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "sockunion.h"
#include "if.h"
#include "ifa.h"
#include "zebra.h"
#include "memory.h"

/* Linked list of interface. */
list iflist;

int
if_add_multicast (struct interface *ifp)
{
  int ret;
  struct ipv6_mreq mreq;

  bzero (&mreq, sizeof (mreq));
  inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);
#ifdef HYDRANGEA
  SET_IN6_LINKLOCAL_IFINDEX (mreq.ipv6mr_multiaddr, ifp->index);
#endif /* HYDRANGEA */
#ifdef LINUX_IPV6
  mreq.ipv6mr_ifindex = ifp->index;
#else
  mreq.ipv6mr_interface = ifp->index;
#endif /* LINUX_IPV6 */

  ret = setsockopt (ripng->sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
		    (char *) &mreq, sizeof (mreq));
  if (ret < 0)
    log ("can't setsockopt IPV6_ADD_MEMBERSHIP:%s\n", strerror (errno));
  return ret;
}

/* Request routes at all interfaces. */
int
ripng_request_all (struct thread *t)
{
  listnode node;
  struct interface *ifp;

  /* Send RIPng request packet to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      if (if_is_loopback (ifp) || !if_is_up (ifp) || !if_is_multicast (ifp))
	continue;

      if_add_multicast (ifp);

      ripng_request (ifp);
    }
  return 0;
}

/* Is this address belong to me ? */
if_check_address (struct in_addr addr)
{
  listnode node;
  struct sockaddr_in *sin;
  struct interface *ifp;
  struct if_addr *ifa;
  int ret;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);

      ret = ifa_same_addr (ifp, addr);
      if (ret)
	return ret;
    }
  return 0;
}

ifa_same_addr (struct interface *ifp, struct in_addr addr)
{
  int ret;
  listnode node;
  struct if_addr *ifa;
  struct sockaddr_in *sin;

  for (node = ifp->addr->head; node; nextnode (node))
    {
      ifa = getdata (node);

      sin = &ifa->ifa_addr.sin;

      if (sin->sin_family != AF_INET)
	continue;

      ret = memcmp (&sin->sin_addr, &addr, sizeof (struct in_addr));
      if (ret == 0)
	return 1;
    }

  return 0;
}

/* Allocate new address structure. */
struct if_addr *
ifa_new ()
{
  struct if_addr *new = XMALLOC (MTYPE_IF_ADDR, sizeof (struct if_addr));
  bzero (new, sizeof (struct if_addr));
  return new;
}

/* Print if_addr structure. */
void
ifa_print (unsigned long flags, struct if_addr *ifa)
{
  switch (ifa->ifa_addr.sa.sa_family) {
  case AF_INET:
    log ("  inet ");
    sockunion_log (&ifa->ifa_addr);
    log2 (" ");
    sockunion_log (&ifa->ifa_mask);
    log2 (" ");
    if (flags & IFF_BROADCAST)
      sockunion_log (&ifa->ifa_dest);
    log2 ("\n");
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    log ("  inet6 ");
    sockunion_log (&ifa->ifa_addr);
    log2 ("/%d\n", ip6_masklen (ifa->ifa_mask.sin6.sin6_addr));
    break;
#endif /* HAVE_IPV6 */
  default:
    break;
  }
}

#if 0
byte4
zebra_get_packet_size (int sock)
{
  int nbyte;
  byte4 length;

  nbyte = readn (sock, &length, 4);

  length = ntohl (length) - 4;
  return length;
}
#endif

/* Check max mtu size. */
int
ripng_check_max_mtu ()
{
  listnode node;
  struct interface *ifp;
  int mtu;

  mtu = 0;
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      if (mtu < ifp->mtu)
	mtu = ifp->mtu;
    }
  return mtu;
}

/* Get interface information from zebra daemon. */
zebra_get_interface (int sock, u_int32_t length)
{
  u_char *pnt;
  u_char *start, *lim;
  int nbyte;
  struct interface *ifp;
  struct if_addr *ifa;
  u_int32_t ifa_count;

  /* Allocate read buffer. */
  pnt = start = (u_char *) malloc (length + 1);
  nbyte = readn (sock, pnt, length - 8);

  if (nbyte == 0) 
    {
      fprintf (stderr, "connection closed\n");
      return;
    }

  lim = pnt + length - 8;
  while (pnt < lim) 
    {
      ifp = if_new ();

      /* Get interface's name. */
      strncpy (ifp->name, pnt, INTERFACE_NAMSIZ);
      pnt += INTERFACE_NAMSIZ;

      /* Get interface's index and value. */
      ld_1byte (ifp->index, pnt);
      ld_4byte (ifp->flags, pnt);
      ld_4byte (ifp->metric, pnt);
      ld_4byte (ifp->mtu, pnt);

      /* Get interface's address. */
      ld_4byte (ifa_count, pnt);
      while (ifa_count--) 
	{
	  ifa = ifa_new (ifp);
	  list_add_node (ifp->addr, ifa);

	  memcpy (&ifa->ifa_addr, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (&ifa->ifa_mask, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	  memcpy (&ifa->ifa_dest, pnt, sizeof (union sockunion));
	  pnt += sizeof (union sockunion);
	}
    }

  free (start);
  if_dump_all ();

  /* Add ripng getinterface hook at here. */
  if (ripng)
    {
      ripng->max_mtu = ripng_check_max_mtu ();
      ripng_event (RIPNG_REQUEST_EVENT);
    }
}

/* Configuration write function for ripngd. */
interface_config_write (struct vty *vty, vector v)
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;

  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->if_data;

      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);
      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc, VTY_NEWLINE);
      if (ri->ri_send != RIPNG_SEND_UNSPEC)
	vty_out (vty, " no ripng send%s", VTY_NEWLINE);
      if (ri->ri_receive != RIPNG_RECEIVE_UNSPEC)
	vty_out (vty, " no ripng receive%s", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }
}

struct ripng_interface *
ri_new ()
{
  struct ripng_interface *ri;

  ri = XMALLOC (MTYPE_IF, sizeof (struct ripng_interface));
  bzero (ri, sizeof (struct ripng_interface));

  /* Set default values. */
  ri->ri_send = RIPNG_SEND_UNSPEC;
  ri->ri_receive = RIPNG_RECEIVE_UNSPEC;
  ri->ri_split_horizon = RIPNG_SPLIT_HORIZON_UNSPEC;
  ri->ri_default_send = RIPNG_DEFAULT_ADVERTISE_UNSPEC;
  ri->ri_default_receive = RIPNG_DEFAULT_ACCEPT_UNSPEC;

  return ri;
}

DEFUN (ripng_receive,
       ripng_receive_cmd,
       "ripng receive",
       "")
{
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = (struct interface *) vty->index;
  ri = ifp->if_data;

  ri->ri_receive = RIPNG_RECEIVE_UNSPEC;

  return CMD_SUCCESS;
}


DEFUN (no_ripng_receive,
       no_ripng_receive_cmd,
       "no ripng receive",
       "")
{
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = (struct interface *) vty->index;
  ri = ifp->if_data;

  ri->ri_receive = RIPNG_RECEIVE_OFF;
  return CMD_SUCCESS;
}

DEFUN (ripng_send,
       ripng_send_cmd,
       "ripng send",
       "")
{
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = (struct interface *) vty->index;
  ri = ifp->if_data;

  ri->ri_send = RIPNG_SEND_UNSPEC;
  return CMD_SUCCESS;
}

DEFUN (no_ripng_send,
       no_ripng_send_cmd,
       "no ripng send",
       "")
{
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = (struct interface *) vty->index;
  ri = ifp->if_data;

  ri->ri_send = RIPNG_SEND_OFF;
  return CMD_SUCCESS;
}

ripng_if_new_hook (struct interface *ifp)
{
  ifp->if_data = ri_new ();
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Initialization of interface. */
ripng_if_init ()
{
  iflist = list_init ();
  if_add_hook (IF_NEW_HOOK, ripng_if_new_hook);

  /* Install interface node. */
  install_node (&interface_node, interface_config_write);

  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ripng_receive_cmd);
  install_element (INTERFACE_NODE, &no_ripng_receive_cmd);
  install_element (INTERFACE_NODE, &ripng_send_cmd);
  install_element (INTERFACE_NODE, &no_ripng_send_cmd);
}
