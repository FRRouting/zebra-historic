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
#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"

/* messages for OSPFv2 status */
message ospf_ism_status_msg[] =
{
  { ISM_DependUpon,   "DependUpon" },
  { ISM_Down,         "Down" },
  { ISM_Loopback,     "Loopback" },
  { ISM_Waiting,      "Waiting" },
  { ISM_PointToPoint, "Point-To-Point" },
  { ISM_DROther,      "DROther" },
  { ISM_Backup,       "Backup" },
  { ISM_DR,           "DR" },
};
int ospf_ism_status_msg_max = OSPF_ISM_STATUS_MAX;

message ospf_nsm_status_msg[] =
{
  { NSM_DependUpon, "DependUpon" },
  { NSM_Down,       "Down" },
  { NSM_Attempt,    "Attempt" },
  { NSM_Init,       "Init" },
  { NSM_TwoWay,     "2-Way" },
  { NSM_ExStart,    "ExStart" },
  { NSM_Exchange,   "Exchange" },
  { NSM_Loading,    "Loading" },
  { NSM_Full,       "Full" },
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
ospf_nbr_state_message (struct ospf_neighbor *nbr, char *buf, size_t size)
{
  int status;

  if (!IPV4_ADDR_CMP (&nbr->d_router, &nbr->router_id))
    status = ISM_DR;
  else if (!IPV4_ADDR_CMP (&nbr->bd_router, &nbr->router_id))
    status = ISM_Backup;
  else
    status = ISM_DROther;

  bzero (buf, size);

  snprintf (buf, size, "%s/%s",
	    LOOKUP (ospf_nsm_status_msg, nbr->status),
	    LOOKUP (ospf_ism_status_msg, status));
}

char *
ospf_timer_dump (struct thread *t, char *buf, size_t size)
{
  struct timeval now;
  time_t h, m, s;

  if (!t)
    return "inactive";

  h = m = s = 0;
  bzero (buf, size);

  gettimeofday (&now, NULL);

  s = t->u.sands.tv_sec - now.tv_sec;
  if (s >= 3600)
    {
      h = s / 3600;
      s -= h * 3600;
    }

  if (s >= 60)
    {
      m = s / 60;
      s -= m * 60;
    }

  snprintf (buf, size, "%02ld:%02ld:%02ld", h, m, s);

  return buf;
}

void
ospf_packet_hello_dump (struct stream *s, u_int16_t length)
{
  struct ospf_hello *hello;
  int i;

  hello = (struct ospf_hello *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "Hello NetworkMask %s",
	inet_ntoa (hello->network_mask));
  zlog (NULL, LOG_INFO, "Hello HelloInterval %d",
	ntohs (hello->hello_interval));
  zlog (NULL, LOG_INFO, "Hello Options %d", hello->options);
  zlog (NULL, LOG_INFO, "Hello RtrPriority %d", hello->priority);
  zlog (NULL, LOG_INFO, "Hello RtrDeadInterval %d",
	ntohl (hello->dead_interval));
  zlog (NULL, LOG_INFO, "Hello DRouter %s", inet_ntoa (hello->d_router));
  zlog (NULL, LOG_INFO, "Hello BDRouter %s", inet_ntoa (hello->bd_router));

  length -= OSPF_HEADER_SIZE + OSPF_HELLO_MIN_SIZE;
  for (i = 0; length > 0; i++, length -= sizeof (struct in_addr))
    zlog (NULL, LOG_INFO, "Hello Neighbor %s", inet_ntoa (hello->neighbors[i]));
}

void
ospf_packet_db_desc_dump (struct stream *s, u_int16_t length)
{
  struct ospf_db_desc *dd;
  struct ospf_lsa *lsa;
  u_int32_t getp;

  dd = (struct ospf_db_desc *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "DD Interface MTU %d", ntohs (dd->mtu));
  zlog (NULL, LOG_INFO, "DD Options %d", dd->options);
  zlog (NULL, LOG_INFO, "DD Flags %d", dd->flags);
  zlog (NULL, LOG_INFO, "DD Sequence Number 0x%08x", ntohl (dd->dd_seqnum));

  length -= OSPF_HEADER_SIZE + OSPF_DB_DESC_MIN_SIZE;

  getp = stream_get_getp (s);
  stream_forward (s, OSPF_DB_DESC_MIN_SIZE);

  /* LSA Headers. */
  for (; length > 0; length -= OSPF_LSA_HEADER_SIZE)
    {
      lsa = (struct ospf_lsa *) STREAM_PNT (s);

      zlog (NULL, LOG_INFO, "LS age %d", ntohs (lsa->ls_age));
      zlog (NULL, LOG_INFO, "Options %d", lsa->options);
      zlog (NULL, LOG_INFO, "LS type %d", lsa->type);
      zlog (NULL, LOG_INFO, "Link State ID %s", inet_ntoa (lsa->id));
      zlog (NULL, LOG_INFO, "Advertising Router %s",
	    inet_ntoa (lsa->adv_router));
      zlog (NULL, LOG_INFO, "LS sequence number %x", ntohl (lsa->ls_seqnum));
      zlog (NULL, LOG_INFO, "LS checksum %x", ntohs (lsa->checksum));
      zlog (NULL, LOG_INFO, "length %d", ntohs (lsa->length));

      stream_forward (s, OSPF_LSA_HEADER_SIZE);
    }

  stream_set_getp (s, getp);
}

void
ospf_packet_ls_req_dump (struct stream *s, u_int16_t length)
{
  u_int32_t getp;
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;

  getp = stream_get_getp (s);

  for (; length > 0; length -= 12)
    {
      ls_type = stream_getl (s);
      ls_id.s_addr = stream_get_ipv4 (s);
      adv_router.s_addr = stream_get_ipv4 (s);

      zlog (NULL, LOG_INFO, "Link State Request LS type %d", ls_type);
      zlog (NULL, LOG_INFO, "Link State Request Link State ID %s",
	    inet_ntoa (ls_id));
      zlog (NULL, LOG_INFO, "Link State Request Advertising Router %s",
	    inet_ntoa (adv_router));
    }

  stream_set_getp (s, getp);
}

void
ospf_packet_ls_upd_dump (struct stream *s, u_int16_t length)
{

}

void
ospf_packet_ls_ack_dump (struct stream *s, u_int16_t length)
{

}

void
ospf_packet_dump (struct stream *s)
{
  struct ip *iph;
  struct ospf_header *ospfh;
  unsigned long sp;
  u_int16_t length;

  /* Preserve pointer. */
  sp = stream_get_getp (s);
  stream_set_getp (s, 0);

  iph = (struct ip *) STREAM_DATA (s);

#ifdef GNU_LINUX
  length = ntohs (iph->ip_len);
#else /* GNU_LINUX */
  length = iph->ip_len;
#endif /* GNU_LINUX */

  /* IP Header dump. */
  zlog (NULL, LOG_INFO, "ip_v %d", iph->ip_v);
  zlog (NULL, LOG_INFO, "ip_hl %d", iph->ip_hl);
  zlog (NULL, LOG_INFO, "ip_tos %d", iph->ip_tos);
  zlog (NULL, LOG_INFO, "ip_len %d", length);
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
      ospf_packet_db_desc_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_REQ:
      ospf_packet_ls_req_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_UPD:
      ospf_packet_ls_upd_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_ACK:
      ospf_packet_ls_ack_dump (s, ntohs (ospfh->length));
      break;
    default:
      break;
    }

  stream_set_getp (s, sp);
}
