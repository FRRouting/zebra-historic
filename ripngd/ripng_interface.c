/*
 * Interface related function for RIPng.
 * Copyright (C) 1998 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "zebra/zebra.h"
#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "memory.h"
#include "buffer.h"
#include "network.h"
#include "filter.h"
#include "log.h"
#include "stream.h"
#include "zclient.h"

#include "ripngd/ripngd.h"

/* If RFC2133 definition is used. */
#ifndef IPV6_JOIN_GROUP
#define IPV6_JOIN_GROUP IPV6_ADD_MEMBERSHIP 
#endif

/* Static utility function. */
static void ripng_enable_apply_all ();

/* Join to the RIPng multicast group. */
int
if_add_multicast (struct interface *ifp)
{
  int ret;
  struct ipv6_mreq mreq;

  bzero (&mreq, sizeof (mreq));
  inet_pton(AF_INET6, RIPNG_GROUP, &mreq.ipv6mr_multiaddr);

  SET_IN6_LINKLOCAL_IFINDEX (mreq.ipv6mr_multiaddr, ifp->index);

  mreq.ipv6mr_interface = ifp->index;

  ret = setsockopt (ripng->sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (char *) &mreq, sizeof (mreq));

  if (ret < 0)
    zlog (NULL, LOG_ERR, 
	  "can't setsockopt IPV6_JOIN_MEMBERSHIP:%s\n", strerror (errno));

  return ret;
}

/* Request routes at all interfaces. */
int
ripng_request_all (struct thread *t)
{
  listnode node;
  struct interface *ifp;
  struct ripng_interface *ri;
  int ripng_request (struct interface *ifp);

  /* Send RIPng request packet to each interface. */
  for (node = listhead (iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      ri = ifp->if_data;

      if (if_is_loopback (ifp) || !if_is_up (ifp))
	continue;

      if (!ri->enable)
	continue;

      if_add_multicast (ifp);
      ripng_request (ifp);
    }
  return 0;
}

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

/* Get all interface information. */
void
ripng_zebra_get_interface (int command, struct zebra *zebra, u_int16_t length)
{
  struct interface *ifp;
  struct connected *connected;
  u_int32_t connected_count;
  unsigned long endp;
  struct stream *s;

  s = zebra->ibuf;
  endp = stream_get_endp (s);

  while (stream_get_getp(s) < endp)
    {
      u_char tmpnam[INTERFACE_NAMSIZ + 1];

      bzero (tmpnam, sizeof (tmpnam));

      /* Get interface's name */
      stream_strncpy (tmpnam, s, INTERFACE_NAMSIZ);

      /* create interface structure */
      ifp = if_get_by_name (tmpnam);

      /* Get interface's index and values. */
      ifp->index = stream_getc (s);
      ifp->flags = stream_getl (s);
      ifp->metric = stream_getl (s);
      ifp->mtu = stream_getl (s);

      /* Get interface's address. */
      connected_count = stream_getl (s);

      while (connected_count--)
	{
	  struct prefix *p;
	  int plen;

	  connected = connected_new ();

	  p = prefix_new ();
	  p->family = stream_getc (s);

	  plen = prefix_blen (p);
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);
	  p->prefixlen = stream_getc (s);
	  connected->address = p;

	  p = prefix_new ();
	  memcpy (&p->u.prefix, stream_pnt (s), plen);
	  stream_forward (s, plen);

	  connected->destination = p;

	  connected_add (ifp, connected);
	}
    }

  /* RIPng enable interface. */
  ripng_enable_apply_all ();

  /* Apply distribute-list to the all interface. */
  distribute_apply_all ();

  /* Add ripng getinterface hook at here. */
  if (ripng)
    {
      ripng->max_mtu = ripng_check_max_mtu ();
      ripng_event (RIPNG_REQUEST_EVENT, 0);
    }
}

#include "vector.h"
#include "vty.h"
#include "command.h"
#include "table.h"

/* RIPng enable interface vector. */
vector ripng_enable_if;

/* RIPng enable network table. */
struct route_table *ripng_enable_network;

/* Lookup RIPng enable network. */
int
ripng_enable_network_lookup (struct interface *ifp)
{
  listnode listnode;
  struct connected *connected;

  for (listnode = listhead (ifp->connected); listnode; nextnode (listnode))
    if ((connected = getdata (listnode)) != NULL)
      {
	struct prefix *p; 
	struct route_node *node;

	p = connected->address;

	if (p->family == AF_INET6)
	  {
	    node = route_node_match (ripng_enable_network, p);
	    if (node)
	      {
		route_unlock_node (node);
		return 1;
	      }
	  }
      }
  return -1;
}

/* Add RIPng enable network. */
void
ripng_enable_network_add (struct prefix *p)
{
  struct route_node *node;

  node = route_node_get (ripng_enable_network, p);
  if (node->info)
    route_unlock_node (node);
  else
    node->info = "enabled";

  ripng_enable_apply_all ();
}

/* Delete RIPng enable network. */
int
ripng_enable_network_delete (struct prefix *p)
{
  struct route_node *node;

  node = route_node_lookup (ripng_enable_network, p);
  if (node)
    {
      node->info = NULL;

      /* Unlock info lock. */
      route_unlock_node (node);

      /* Unlock lookup lock. */
      route_unlock_node (node);
      
      /* Apply new configuration. */
      ripng_enable_apply_all ();

      return 1;
    }
  return -1;
}

/* Lookup function. */
int
ripng_enable_if_lookup (char *ifname)
{
  int i;
  char *str;

  for (i = 0; i < vector_max (ripng_enable_if); i++)
    if ((str = vector_slot (ripng_enable_if, i)) != NULL)
      if (strcmp (str, ifname) == 0)
	return i;
  return -1;
}

/* Add inteface to ripng_enable_if. */
void
ripng_enable_if_add (char *ifname)
{
  int ret;

  ret = ripng_enable_if_lookup (ifname);
  if (ret >= 0)
    return;

  vector_set (ripng_enable_if, strdup (ifname));

  ripng_enable_apply_all ();
}

/* Delete inteface from ripng_enable_if. */
int
ripng_enable_if_delete (char *ifname)
{
  int index;
  char *str;

  index = ripng_enable_if_lookup (ifname);
  if (index < 0)
    return index;

  str = vector_slot (ripng_enable_if, index);
  free (str);
  vector_unset (ripng_enable_if, index);

  ripng_enable_apply_all ();

  return index;
}

/* Set distribute list to all interfaces. */
static void
ripng_enable_apply_all ()
{
  int ret;
  struct interface *ifp;
  listnode node;

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct ripng_interface *ri;

      ifp = getdata (node);
      ri = ifp->if_data;

      ret = ripng_enable_if_lookup (ifp->name);
      if (ret >= 0)
	ri->enable = 1;
      else
	{
	  ret = ripng_enable_network_lookup (ifp);
	  if (ret >= 0)
	    ri->enable = 1;
	  else
	    ri->enable = 0;
	}
    }
}

/* Write RIPng enable network and interface to the vty. */
int
ripng_network_write (struct vty *vty)
{
  int i;
  char *str;
  struct route_node *node;
  char buf[BUFSIZ];

  /* Write enable network. */
  for (node = route_top (ripng_enable_network); node; node = route_next (node))
    if (node->info)
      {
	struct prefix *p = &node->p;
	vty_out (vty, " network %s/%d%s", 
		 inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		 p->prefixlen, VTY_NEWLINE);

      }
  
  /* Write enable interface. */
  for (i = 0; i < vector_max (ripng_enable_if); i++)
    if ((str = vector_slot (ripng_enable_if, i)) != NULL)
      vty_out (vty, " network %s%s", str, VTY_NEWLINE);

  return 0;
}

/* RIPng enable on specified interface or matched network. */
DEFUN (network,
       network_cmd,
       "network IF_OR_ADDR",
       "RIPng enable on specified interface or network.\n"
       "Interface or address")
{
  int ret;
  struct prefix p;

  ret = str2prefix (argv[0], &p);

  /* Given string is interface name. */
  if (ret)
    ripng_enable_network_add (&p);
  else
    ripng_enable_if_add (argv[0]);

  return CMD_SUCCESS;
}

/* RIPng enable on specified interface or matched network. */
DEFUN (no_network,
       no_network_cmd,
       "no network IF_OR_ADDR",
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "Interface or address")
{
  int ret;
  struct prefix p;

  ret = str2prefix (argv[0], &p);

  /* Given string is interface name. */
  if (ret)
    ret = ripng_enable_network_delete (&p);
  else
    ret = ripng_enable_if_delete (argv[0]);

  if (ret < 0)
    {
      vty_out (vty, "can't find network %s\r\n", argv[0]);
      return CMD_WARNING;
    }
  
  return CMD_SUCCESS;
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
  ri->ri_default_send = RIPNG_DEFAULT_ADVERTISE;
  ri->ri_default_receive = RIPNG_DEFAULT_ACCEPT;

  return ri;
}

DEFUN (ripng_receive,
       ripng_receive_cmd,
       "ripng receive",
       "RIPng configuration\n"
       "\n")
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
       NO_STR
       "RIPng configuration\n"
       "\n")
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
       "RIPng configuration\n"
       "Send\n")
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
       NO_STR
       "RIPng configuration\n"
       "\n")
{
  struct interface *ifp;
  struct ripng_interface *ri;

  ifp = (struct interface *) vty->index;
  ri = ifp->if_data;

  ri->ri_send = RIPNG_SEND_OFF;
  return CMD_SUCCESS;
}

int
ripng_if_new_hook (struct interface *ifp)
{
  ifp->if_data = ri_new ();
  return 0;
}

/* Configuration write function for ripngd. */
int
interface_config_write (struct vty *vty)
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
  return 0;
}

/* ripngd's interface node. */
struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Initialization of interface. */
void
ripng_if_init ()
{
  /* Interface initialize. */
  iflist = list_init ();
  if_add_hook (IF_NEW_HOOK, ripng_if_new_hook);

  /* RIPng enable network init. */
  ripng_enable_network = route_table_init ();

  /* RIPng enable interface init. */
  ripng_enable_if = vector_init (1);

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

  install_element (RIPNG_NODE, &network_cmd);
  install_element (RIPNG_NODE, &no_network_cmd);
}
