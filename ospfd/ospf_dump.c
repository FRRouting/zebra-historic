/*
 * OSPFd dump routine.
 * Copyright (C) 1999 Toshiaki Takada
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

#include <zebra.h>

#include "thread.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_dump.h"

/* messages for OSPFv2 status */
message ospf_ism_status_msg[] =
{
  { ISM_NoState, "NoState" },
  { ISM_Down, "Down" },
  { ISM_Loopback, "Loopback" },
  { ISM_Waiting, "Waiting" },
  { ISM_PointToPoint, "Point-To-Point" },
  { ISM_Backup, "Backup" },
  { ISM_DROther, "DROther" },
  { ISM_DR, "DR" },
  { ISM_DependUpon, "DependUpon" },
};
int ospf_ism_status_msg_max = OSPF_ISM_STATUS_MAX;

/* Debug option setting interface. */
unsigned long ospf_debug_option = 0;

void debug_on  (unsigned int option) { ospf_debug_option |= option; }
void debug_off (unsigned int option) { ospf_debug_option &= ~option; }
int  debug     (unsigned int option) { return ospf_debug_option &option; }

/* message lookup function */
char *
mes_lookup (message *meslist, int max, int index)
{
  if (index < 0 || index >= max) {
    zlog (NULL, LOG_INFO, "message index out of bound: %d", max);
    return NULL;
  }
  return meslist[index].str;
}
