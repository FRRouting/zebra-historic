/* MTU value get by reading kvm
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

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#include <kvm.h>
#include <limits.h>
#include <fcntl.h>
#include <nlist.h>

kvm_t *kvmd;

kvm_get_mtu()
{
  struct ifnet ifnet;
  unsigned long ifnetaddr;

  char tname[16];
  char buf[_POSIX2_LINE_MAX];

  struct nlist nl[] = {
    {"_ifnet"},
    {""}
  };

  kvmd = kvm_openfiles (NULL, NULL, NULL, O_RDONLY, buf);
  if(kvmd == NULL) {
    printf("error: %s\n", buf);
    return;
  }
  kvm_nlist(kvmd, nl);

  ifnetaddr = nl[0].n_value;

  if (kread(ifnetaddr, (char *)&ifnetaddr, sizeof ifnetaddr)) {
    return;
  }
  
  if(kread(ifnetaddr, (char *)&ifnet, sizeof ifnet)) {
    return;
  }
  
  if(kread((u_long)ifnet.if_name, tname, 16)) {
    kvm_close (NULL);
    return;
  }

  tname[15] = '\0';
  /* for debug */
  /*  printf("Name: %s\n", tname); */
  /*  printf("MTU: %d\n", ifnet.if_mtu); */
  return(ifnet.if_mtu);

}

kread(addr, buf, size)
     u_long addr;
     char *buf;
     int size;
{
  if (kvm_read(kvmd, addr, buf, size) != size) {
    return (-1);
  }
  return (0);
}


