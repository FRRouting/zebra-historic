/* ipforward value get by sysctl function.
   Copyright (C) 1997 Kunihiro Ishiguro

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_IPV6
#include <net/if.h>
#ifdef KAME
#include <netinet/in_var.h>
#else /* KAME */
#include <netinet/in6_var.h>
#endif /* KAME */
#endif /* HAVE_IPV6 */

#include "log.h"

#define MIB_SIZ 4

int
ipforward ()
{
  int mib [MIB_SIZ];
  int ipforwarding = 0;
  int len;

  mib [0] = CTL_NET;
  mib [1] = PF_INET;
  mib [2] = IPPROTO_IP;
  mib [3] = IPCTL_FORWARDING;

  len = sizeof ipforwarding;
  if (sysctl (mib, MIB_SIZ, &ipforwarding, &len, 0, 0) < 0) 
    {
      log_warn ("can't get ipforwarding value\n");
      return -1;
    }
  return ipforwarding;
}

#ifdef HAVE_IPV6
int
ipforward_ipv6 ()
{
  int mib [MIB_SIZ];
  int ip6forwarding = 0;
  int len;

  mib [0] = CTL_NET;
  mib [1] = PF_INET6;
#ifdef KAME
  mib [2] = IPPROTO_IPV6;
  mib [3] = IPV6CTL_FORWARDING;
#else /* NOT KAME */
  mib [2] = IPPROTO_IP;
  mib [3] = IP6CTL_FORWARDING;
#endif /* KAME */

  len = sizeof ip6forwarding;
  if (sysctl (mib, MIB_SIZ, &ip6forwarding, &len, 0, 0) < 0) 
    {
      log_warn ("can't get ip6forwarding value\n");
      return -1;
    }
  return ip6forwarding;
}
#endif /* HAVE_IPV6 */
