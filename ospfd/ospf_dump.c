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

#include "stream.h"
#include "thread.h"
#include "prefix.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"

/* messages for OSPFv2 status */
message ospf_ism_status_msg[] =
{
  { ISM_NoState,      "NoState" },
  { ISM_Down,         "Down" },
  { ISM_Loopback,     "Loopback" },
  { ISM_Waiting,      "Waiting" },
  { ISM_PointToPoint, "Point-To-Point" },
  { ISM_Backup,       "Backup" },
  { ISM_DROther,      "DROther" },
  { ISM_DR,           "DR" },
  { ISM_DependUpon,   "DependUpon" },
};
int ospf_ism_status_msg_max = OSPF_ISM_STATUS_MAX;

message ospf_nsm_status_msg[] =
{
  { NSM_NoState,    "NoState" },
  { NSM_Down,       "Down" },
  { NSM_Attempt,    "Attempt" },
  { NSM_Init,       "Init" },
  { NSM_TwoWay,     "TwoWay" },
  { NSM_ExStart,    "ExStart" },
  { NSM_Exchange,   "Exchange" },
  { NSM_Loading,    "Loading" },
  { NSM_Full,       "Full" },
  { NSM_DependUpon, "DependUpon" },
};
int ospf_nsm_status_msg_max = OSPF_NSM_STATUS_MAX;

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

void
ospf_packet_hello_dump (struct stream *s, u_int16_t length)
{
  struct ospf_hello *hello;
  int i;

  hello = (struct ospf_hello *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "hello network_mask %s",
	inet_ntoa (hello->network_mask));
  zlog (NULL, LOG_INFO, "hello hello_interval %d",
	ntohs (hello->hello_interval));
  zlog (NULL, LOG_INFO, "hello options %d", hello->options);
  zlog (NULL, LOG_INFO, "hello priority %d", hello->priority);
  zlog (NULL, LOG_INFO, "hello dead_interval %d",
	ntohl (hello->dead_interval));
  zlog (NULL, LOG_INFO, "hello d_router %s", inet_ntoa (hello->d_router));
  zlog (NULL, LOG_INFO, "hello bd_router %s", inet_ntoa (hello->bd_router));

  length -= 44;
  for (i = 0; length; i++, length -= 4)
    zlog (NULL, LOG_INFO, "hello neighbor %s", inet_ntoa (hello->neighbor[i]));
}

void
ospf_packet_dump (struct stream *s)
{
  struct ip *iph;
  struct ospf_header *ospfh;
  unsigned long sp;

  /* Preserve pointer. */
  sp = stream_get_getp (s);
  stream_set_getp (s, 0);

  iph = (struct ip *) STREAM_DATA (s);

  /* IP Header dump. */
  zlog (NULL, LOG_INFO, "ip_v %d", iph->ip_v);
  zlog (NULL, LOG_INFO, "ip_hl %d", iph->ip_hl);
  zlog (NULL, LOG_INFO, "ip_tos %d", iph->ip_tos);
  zlog (NULL, LOG_INFO, "ip_len %d", iph->ip_len);
  zlog (NULL, LOG_INFO, "ip_id %u", (u_int32_t) iph->ip_id);
  zlog (NULL, LOG_INFO, "ip_off %u", (u_int32_t) iph->ip_off);
  zlog (NULL, LOG_INFO, "ip_ttl %d", iph->ip_ttl);
  zlog (NULL, LOG_INFO, "ip_p %d", iph->ip_p);
  zlog (NULL, LOG_INFO, "ip_sum 0x%x", (u_int32_t) ntohs (iph->ip_sum));
  zlog (NULL, LOG_INFO, "ip_src %s",  inet_ntoa (iph->ip_src));
  zlog (NULL, LOG_INFO, "ip_dst %s", inet_ntoa (iph->ip_dst));

  stream_forward (s, iph->ip_hl * 4);
  ospfh = (struct ospf_header *) STREAM_PNT (s);

  /* OSPF Header dump. */
  zlog (NULL, LOG_INFO, "OSPF Version %d", ospfh->version);
  zlog (NULL, LOG_INFO, "OSPF Type %d", ospfh->type);
  zlog (NULL, LOG_INFO, "OSPF Packet Len %d", ntohs (ospfh->length));
  zlog (NULL, LOG_INFO, "OSPF Router ID %s", inet_ntoa (ospfh->router_id));
  zlog (NULL, LOG_INFO, "OSPF Area ID %s", inet_ntoa (ospfh->area_id));
  zlog (NULL, LOG_INFO, "OSPF Checksum 0x%x", ntohs (ospfh->checksum));

  stream_forward (s, OSPF_HEADER_SIZE);

  switch (ospfh->type)
    {
    case OSPF_MSG_HELLO:
      ospf_packet_hello_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_DB_DESC:
      break;
    case OSPF_MSG_LS_REQ:
      break;
    case OSPF_MSG_LS_UPD:
      break;
    case OSPF_MSG_LS_ACK:
      break;
    default:
      break;
    }

  stream_set_getp (s, sp);
}
