/*
 * Interface function.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include "linklist.h"
#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "vector.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"

/* For interface multicast configuration. */
#define IF_ZEBRA_MULTICAST_UNSPEC 0
#define IF_ZEBRA_MULTICAST_ON     1
#define IF_ZEBRA_MULTICAST_OFF    2

/* For interface shutdown configuration. */
#define IF_ZEBRA_SHUTDOWN_UNSPEC 0
#define IF_ZEBRA_SHUTDOWN_ON     1
#define IF_ZEBRA_SHUTDOWN_OFF    2

/* `zebra' daemon local interface structure. */
struct if_zebra
{
  int shutdown;
  int multicast;
};

int
if_zebra_new_hook (struct interface *ifp)
{
  struct if_zebra *if_data;

  if_data = XMALLOC (MTYPE_TMP, sizeof (struct if_zebra));
  bzero (if_data, sizeof (struct if_zebra));

  if_data->multicast = IF_ZEBRA_MULTICAST_UNSPEC;
  if_data->shutdown = IF_ZEBRA_SHUTDOWN_UNSPEC;

  ifp->if_data = if_data;
  return 0;
}

int
if_zebra_delete_hook (struct interface *ifp)
{
  if (ifp->if_data)
    XFREE (MTYPE_TMP, ifp->if_data);
  return 0;
}

/* Printout flag information into vty */
void
if_flag_dump_vty (struct vty *vty, unsigned long flag)
{
  int separator = 0;

#define IFF_OUT_VTY(X, Y) \
  if ((X) && (flag & (X))) \
    { \
      if (separator) \
	vty_out (vty, ","); \
      else \
	separator = 1; \
      vty_out (vty, Y); \
    }

  vty_out (vty, "<");
  IFF_OUT_VTY (IFF_UP, "UP");
  IFF_OUT_VTY (IFF_BROADCAST, "BROADCAST");
  IFF_OUT_VTY (IFF_DEBUG, "DEBUG");
  IFF_OUT_VTY (IFF_LOOPBACK, "LOOPBACK");
  IFF_OUT_VTY (IFF_POINTOPOINT, "POINTOPOINT");
  IFF_OUT_VTY (IFF_NOTRAILERS, "NOTRAILERS");
  IFF_OUT_VTY (IFF_RUNNING, "RUNNING");
  IFF_OUT_VTY (IFF_NOARP, "NOARP");
  IFF_OUT_VTY (IFF_PROMISC, "PROMISC");
  IFF_OUT_VTY (IFF_ALLMULTI, "ALLMULTI");
  IFF_OUT_VTY (IFF_OACTIVE, "OACTIVE");
  IFF_OUT_VTY (IFF_SIMPLEX, "SIMPLEX");
  IFF_OUT_VTY (IFF_LINK0, "LINK0");
  IFF_OUT_VTY (IFF_LINK1, "LINK1");
  IFF_OUT_VTY (IFF_LINK2, "LINK2");
  IFF_OUT_VTY (IFF_MULTICAST, "MULTICAST");
  vty_out (vty, ">");
}

/* Output prefix string to vty. */
int
prefix_vty_out (struct vty *vty, struct prefix *p)
{
  char str[INET6_ADDRSTRLEN];

  inet_ntop (p->family, &p->u.prefix, str, sizeof (str));
  vty_out (vty, "%s", str);
  return strlen (str);
}

/* Dump if address information to vty. */
void
connected_dump_vty (struct vty *vty, struct connected *connected)
{
  struct prefix *p;
  struct interface *ifp;

  /* Set inteface pointer. */
  ifp = connected->ifp;

  /* Print interface address. */
  p = connected->address;
  vty_out (vty, "  %s ", prefix_family_str (p));
  prefix_vty_out (vty, p);
  vty_out (vty, "/%d", p->prefixlen);

  /* If there is destination address, print it. */
  p = connected->destination;
  if (p)
    {
      if (p->family == AF_INET)
	if (ifp->flags & IFF_BROADCAST)
	  {
	    vty_out (vty, " broadcast ");
	    prefix_vty_out (vty, p);
	  }

      if (ifp->flags & IFF_POINTOPOINT)
	{
	  vty_out (vty, " pointopoint ");
	  prefix_vty_out (vty, p);
	}
    }
  vty_out (vty, "\r\n");
}


/* Interface's information print out to vty interface. */
void
if_dump_vty (struct vty *vty, struct interface *ifp)
{
  struct connected *connected;
  listnode node;

  vty_out (vty, "Interface %s\r\n", ifp->name);
  if (ifp->desc)
    vty_out (vty, "  Description: %s\r\n", ifp->desc);
  vty_out (vty, "  index %d metric %d mtu %d ",
	   ifp->index, ifp->metric, ifp->mtu);
  if_flag_dump_vty (vty, ifp->flags);
  vty_out (vty, "\r\n");
  
  for (node = listhead (ifp->connected); node; nextnode (node))
    {
      connected = getdata (node);
      connected_dump_vty (vty, connected);
    }
}

/* Check supported address family. */
int
if_supported_family (int family)
{
  if (family == AF_INET)
    return 1;
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    return 1;
#endif /* HAVE_IPV6 */
  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

/* Show all or specified interface to vty. */
DEFUN (show_interface, show_interface_cmd,
       "show interface [IFNAME]",  
       SHOW_STR
       "Interface status and configuration\n"
       "Inteface name\n")
{
  listnode node;
  struct interface *ifp;
  
  /* Specified interface print. */
  if (argc != 0)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (ifp == NULL) 
	{
	  vty_out (vty, "Can't find interface [%s]\r\n", argv[0]);
	  return CMD_WARNING;
	}
      if_dump_vty (vty, ifp);
      return CMD_SUCCESS;
    }

  /* All interface print. */
  for (node = listhead (iflist); node; nextnode (node))
    if_dump_vty (vty, getdata (node));

  return CMD_SUCCESS;
}

DEFUN (multicast,
       multicast_cmd,
       "multicast",
       "Set multicast flag to interface\n")
{
  int ret;
  struct interface *ifp;
  struct if_zebra *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_set_flags (ifp, IFF_MULTICAST);
  if (ret < 0)
    {
      vty_out (vty, "Can't set multicast flag\r\n");
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->if_data;
  if_data->multicast = IF_ZEBRA_MULTICAST_ON;
  
  return CMD_SUCCESS;
}

DEFUN (no_multicast,
       no_multicast_cmd,
       "no multicast",
       NO_STR
       "Unset multicast flag to interface\n")
{
  int ret;
  struct interface *ifp;
  struct if_zebra *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_unset_flags (ifp, IFF_MULTICAST);
  if (ret < 0)
    {
      vty_out (vty, "Can't unset multicast flag\r\n");
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->if_data;
  if_data->multicast = IF_ZEBRA_MULTICAST_OFF;

  return CMD_SUCCESS;
}

DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
  int ret;
  struct interface *ifp;
  struct if_zebra *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_unset_flags (ifp, IFF_UP);
  if (ret < 0)
    {
      vty_out (vty, "Can't shutdown interface\r\n");
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->if_data;
  if_data->shutdown = IF_ZEBRA_SHUTDOWN_ON;

  return CMD_SUCCESS;
}

DEFUN (no_shutdown_if,
       no_shutdown_if_cmd,
       "no shutdown",
       "Negate a command or set its defaults\n"
       "Shutdown the selected interface\n")
{
  int ret;
  struct interface *ifp;
  struct if_zebra *if_data;

  ifp = (struct interface *) vty->index;
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface\r\n");
      return CMD_WARNING;
    }
  if_get_flags (ifp);
  if_data = ifp->if_data;
  if_data->shutdown = IF_ZEBRA_SHUTDOWN_OFF;

  return CMD_SUCCESS;
}

DEFUN (ip_address, ip_address_cmd,
       "ip address IPV4_ADDRESS",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address\n")
{
  int ret;
  struct interface *ifp;
  struct prefix_ipv4 p;

  ifp = (struct interface *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  /* Set interface's flag. */
  ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
  if (ret < 0)
    {
      vty_out (vty, "Can't up interface\r\n");
      return CMD_WARNING;
    }
  if_get_flags (ifp);

  /* Make sure mask is applied and set type to static route*/
  ret = if_set_prefix (ifp, &p);
  if (ret < 0)
    {
      vty_out (vty, "Can't set interface's address.\r\n");
      return CMD_WARNING;
    }


  return CMD_SUCCESS;
}

DEFUN (no_ip_address, no_ip_address_cmd,
       "no ip address IPV4_ADDRESS IPV4_ADDRESS",
       "Negate a command or set its defaults\n"
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address")
{
  return CMD_SUCCESS;
}

int
if_config_write (struct vty *vty)
{
  listnode node;
  struct interface *ifp;

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct if_zebra *if_data;

      ifp = getdata (node);
      if_data = ifp->if_data;
      
      vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);

      if (ifp->desc)
	vty_out (vty, " description %s%s", ifp->desc, VTY_NEWLINE);

      if (if_data)
	{
	  if (if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)
	    vty_out (vty, " shutdown%s", VTY_NEWLINE);

	  if (if_data->multicast != IF_ZEBRA_MULTICAST_UNSPEC)
	    vty_out (vty, " %smulticast%s",
		     if_data->multicast == IF_ZEBRA_MULTICAST_ON ? "" : "no ",
		     VTY_NEWLINE);
	}

      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

/* Allocate and initialize interface vector. */
void
zebra_if_init ()
{
  /* Initialize interface and new hook. */
  if_init ();
  if_add_hook (IF_NEW_HOOK, if_zebra_new_hook);
  if_add_hook (IF_DELETE_HOOK, if_zebra_delete_hook);
  
  /* Install configuration write function. */
  install_node (&interface_node, if_config_write);

  install_element (VIEW_NODE, &show_interface_cmd);
  install_element (ENABLE_NODE, &show_interface_cmd);
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (INTERFACE_NODE, &config_end_cmd);
  install_element (INTERFACE_NODE, &config_exit_cmd);
  install_element (INTERFACE_NODE, &config_help_cmd);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &multicast_cmd);
  install_element (INTERFACE_NODE, &no_multicast_cmd);
  install_element (INTERFACE_NODE, &shutdown_if_cmd);
  install_element (INTERFACE_NODE, &no_shutdown_if_cmd);
  install_element (INTERFACE_NODE, &ip_address_cmd);
}
