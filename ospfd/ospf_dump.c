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

#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "command.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_dump.h"
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

/* Debug option variables. */
unsigned long ospf_debug_packet[5] = {0, 0, 0, 0, 0};
unsigned long ospf_debug_event = 0;
unsigned long ospf_debug_ism = 0;
unsigned long ospf_debug_nsm = 0;

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

  if (IPV4_ADDR_SAME (&nbr->d_router, &nbr->address.u.prefix4))
    status = ISM_DR;
  else if (IPV4_ADDR_SAME (&nbr->bd_router, &nbr->address.u.prefix4))
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

char *
ospf_option_dump (u_char options, char *buf, size_t size)
{
  bzero (buf, size);

  snprintf (buf, size, "*|*|%s|%s|%s|%s|%s|*",
	    (options & OSPF_OPTION_DC) ? "DC" : "-",
	    (options & OSPF_OPTION_EA) ? "EA" : "-",
	    (options & OSPF_OPTION_NP) ? "N/P" : "-",
	    (options & OSPF_OPTION_MC) ? "MC" : "-",
	    (options & OSPF_OPTION_E) ? "E" : "-");

  return buf;
}

void
ospf_packet_hello_dump (struct stream *s, u_int16_t length)
{
  struct ospf_hello *hello;
  char options[24];
  int i;

  hello = (struct ospf_hello *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "Hello NetworkMask %s",
	inet_ntoa (hello->network_mask));
  zlog (NULL, LOG_INFO, "Hello HelloInterval %d",
	ntohs (hello->hello_interval));
  zlog (NULL, LOG_INFO, "Hello Options %d (%s)", hello->options,
	ospf_option_dump (hello->options, options, 24));
  zlog (NULL, LOG_INFO, "Hello RtrPriority %d", hello->priority);
  zlog (NULL, LOG_INFO, "Hello RtrDeadInterval %d",
	ntohl (hello->dead_interval));
  zlog (NULL, LOG_INFO, "Hello DRouter %s", inet_ntoa (hello->d_router));
  zlog (NULL, LOG_INFO, "Hello BDRouter %s", inet_ntoa (hello->bd_router));

  length -= OSPF_HEADER_SIZE + OSPF_HELLO_MIN_SIZE;
  for (i = 0; length > 0; i++, length -= sizeof (struct in_addr))
    zlog (NULL, LOG_INFO, "Hello Neighbor %s", inet_ntoa (hello->neighbors[i]));
}

char *
ospf_dd_flags_dump (u_char flags, char *buf, size_t size)
{
  bzero (buf, size);

  snprintf (buf, size, "%s|%s|%s",
	    (flags & OSPF_DD_FLAG_I) ? "I" : "-",
	    (flags & OSPF_DD_FLAG_M) ? "M" : "-",
	    (flags & OSPF_DD_FLAG_MS) ? "MS" : "-");

  return buf;
}

void
ospf_lsa_header_dump (struct ospf_lsa *lsa)
{
  zlog (NULL, LOG_INFO, "LS age %d", ntohs (lsa->ls_age));
  zlog (NULL, LOG_INFO, "Options %d", lsa->options);
  zlog (NULL, LOG_INFO, "LS type %d (%s)",
	lsa->type, ospf_lsa_type_str[lsa->type]);
  zlog (NULL, LOG_INFO, "Link State ID %s", inet_ntoa (lsa->id));
  zlog (NULL, LOG_INFO, "Advertising Router %s",
	inet_ntoa (lsa->adv_router));
  zlog (NULL, LOG_INFO, "LS sequence number 0x%x", ntohl (lsa->ls_seqnum));
  zlog (NULL, LOG_INFO, "LS checksum 0x%x", ntohs (lsa->checksum));
  zlog (NULL, LOG_INFO, "length %d", ntohs (lsa->length));
}

char *
ospf_router_lsa_flags_dump (u_char flags, char *buf, size_t size)
{
  bzero (buf, size);

  snprintf (buf, size, "%s|%s|%s",
	    (flags & ROUTER_LSA_VIRTUAL) ? "V" : "-",
	    (flags & ROUTER_LSA_EXTERNAL) ? "E" : "-",
	    (flags & ROUTER_LSA_BORDER) ? "B" : "-");

  return buf;
}

void
ospf_router_lsa_dump (struct stream *s, u_int16_t length)
{
  char buf[BUFSIZ];
  struct router_lsa *rl;
  int i, len;

  rl = (struct router_lsa *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "Router-LSA flags %s", 
	ospf_router_lsa_flags_dump (rl->flags, buf, BUFSIZ));
  zlog (NULL, LOG_INFO, "Router-LSA # links %d", ntohs (rl->links));

  len = ntohs (rl->header.length) - OSPF_LSA_HEADER_SIZE - 4;
  for (i = 0; len > 0; i++)
    {
      zlog (NULL, LOG_INFO, "Router-LSA Link ID %s",
	    inet_ntoa (rl->link[i].link_id));
      zlog (NULL, LOG_INFO, "Router-LSA Link Data %s",
	    inet_ntoa (rl->link[i].link_data));
      zlog (NULL, LOG_INFO, "Router-LSA Type %d",
	    (u_char) rl->link[i].type);
      zlog (NULL, LOG_INFO, "Router-LSA TOS %d",
	    (u_char) rl->link[i].tos);
      zlog (NULL, LOG_INFO, "Router-LSA metric %d",
	    ntohs (rl->link[i].metric));
      len -= 12;
    }
}

void
ospf_network_lsa_dump (struct stream *s, u_int16_t length)
{
  struct network_lsa *nl;

  nl = (struct network_lsa *) STREAM_PNT (s);
  
  zlog (NULL, LOG_INFO, "LSA total size %d", ntohs (nl->header.length));
  zlog (NULL, LOG_INFO, "Network-LSA size %d", 
	ntohs (nl->header.length) - OSPF_LSA_HEADER_SIZE);
  zlog (NULL, LOG_INFO, "Network-LSA %s", inet_ntoa (nl->mask));
}

void
ospf_summary_lsa_dump (struct stream *s, u_int16_t length)
{
  struct summary_lsa *sl;
  int size;
  int i;

  sl = (struct summary_lsa *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "Summary-LSA Network Mask %s", inet_ntoa (sl->mask));

  size = ntohs (sl->header.length) - OSPF_LSA_HEADER_SIZE - 4;
  for (i = 0; size > 0; size -= 4, i++)
    zlog (NULL, LOG_INFO, "Summary-LSA TOS=%d metric %d",
	  sl->tos, GET_METRIC (sl->metric));
}

void
ospf_as_external_lsa_dump (struct stream *s, u_int16_t length)
{
  struct as_external_lsa *al;
  int size;
  int i;

  al = (struct as_external_lsa *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "AS-external-LSA Network Mask %s",
	inet_ntoa (al->mask));
  size = ntohs (al->header.length) - OSPF_LSA_HEADER_SIZE -4;
  for (i = 0; size > 0; size -= 12, i++)
    {
      zlog (NULL, LOG_INFO, "AS-external-LSA bit %s TOS=%d metric %d",
	    IS_EXTERNAL_METRIC (al->e[i].tos) ? "E" : "-",
	    al->e[i].tos & 0x7f, GET_METRIC (al->e[i].metric));
      zlog (NULL, LOG_INFO, "AS-external-LSA Forwarding address %s",
	    inet_ntoa (al->e[i].fwd_addr));
      zlog (NULL, LOG_INFO, "AS-external-LSA External Route Tag %s",
	    inet_ntoa (al->e[i].route_tag));
    }
}

void
ospf_lsa_header_list_dump (struct stream *s, u_int16_t length)
{
  struct ospf_lsa *lsa;

  /* LSA Headers. */
  while (length > 0)
    {
      lsa = (struct ospf_lsa *) STREAM_PNT (s);
      ospf_lsa_header_dump (lsa);

      stream_forward (s, OSPF_LSA_HEADER_SIZE);
      length -= OSPF_LSA_HEADER_SIZE;
    }
}

void
ospf_packet_db_desc_dump (struct stream *s, u_int16_t length)
{
  struct ospf_db_desc *dd;
  char dd_flags[8];
  char options[24];

  u_int32_t gp;

  gp = stream_get_getp (s);
  dd = (struct ospf_db_desc *) STREAM_PNT (s);

  zlog (NULL, LOG_INFO, "DD Interface MTU %d", ntohs (dd->mtu));
  zlog (NULL, LOG_INFO, "DD Options %d (%s)", dd->options,
	ospf_option_dump (dd->options, options, 24));
  zlog (NULL, LOG_INFO, "DD Flags %d (%s)", dd->flags,
	ospf_dd_flags_dump (dd->flags, dd_flags, 8));
  zlog (NULL, LOG_INFO, "DD Sequence Number 0x%08x", ntohl (dd->dd_seqnum));

  length -= OSPF_HEADER_SIZE + OSPF_DB_DESC_MIN_SIZE;

  stream_forward (s, OSPF_DB_DESC_MIN_SIZE);

  ospf_lsa_header_list_dump (s, length);

  stream_set_getp (s, gp);
}

void
ospf_packet_ls_req_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;

  sp = stream_get_getp (s);

  for (length -= OSPF_HEADER_SIZE; length > 0; length -= 12)
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

  stream_set_getp (s, sp);
}

void
ospf_packet_ls_upd_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;
  struct ospf_lsa *lsa;
  int lsa_len;
  u_int32_t count;

  length -= OSPF_HEADER_SIZE;

  sp = stream_get_getp (s);

  count = stream_getl (s);
  length -= 4;

  zlog (NULL, LOG_INFO, "# LSAs %d", count);

  while (length > 0 && count > 0)
    {
      lsa = (struct ospf_lsa *) STREAM_PNT (s);
      lsa_len = ntohs (lsa->length);
      ospf_lsa_header_dump (lsa);

      switch (lsa->type)
	{
	case OSPF_ROUTER_LSA:
	  ospf_router_lsa_dump (s, length);
	  break;
	case OSPF_NETWORK_LSA:
	  ospf_network_lsa_dump (s, length);
	  break;
	case OSPF_SUMMARY_LSA:
	case OSPF_SUMMARY_LSA_ASBR:
	  ospf_summary_lsa_dump (s, length);
	  break;
	case OSPF_AS_EXTERNAL_LSA:
	  ospf_as_external_lsa_dump (s, length);
	  break;
	default:
	  break;
	}

      stream_forward (s, lsa_len);
      length -= lsa_len;
      count--;
    }

  stream_set_getp (s, sp);
}

void
ospf_packet_ls_ack_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;

  length -= OSPF_HEADER_SIZE;
  sp = stream_get_getp (s);

  ospf_lsa_header_list_dump (s, length);

  stream_set_getp (s, sp);
}

void
ospf_ip_header_dump (struct stream *s)
{
  u_int16_t length;
  struct ip *iph;

  iph = (struct ip *) STREAM_PNT (s);

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
}

void
ospf_header_dump (struct ospf_header *ospfh)
{
  zlog (NULL, LOG_INFO, "OSPF Version %d", ospfh->version);
  zlog (NULL, LOG_INFO, "OSPF Type %d (%s)",
	ospfh->type, ospf_packet_type_str[ospfh->type]);
  zlog (NULL, LOG_INFO, "OSPF Packet Len %d", ntohs (ospfh->length));
  zlog (NULL, LOG_INFO, "OSPF Router ID %s", inet_ntoa (ospfh->router_id));
  zlog (NULL, LOG_INFO, "OSPF Area ID %s", inet_ntoa (ospfh->area_id));
  zlog (NULL, LOG_INFO, "OSPF Checksum 0x%x", ntohs (ospfh->checksum));
}

void
ospf_packet_dump (struct stream *s)
{
  struct ospf_header *ospfh;
  unsigned long gp;

  /* Preserve pointer. */
  gp = stream_get_getp (s);

  /* OSPF Header dump. */
  ospfh = (struct ospf_header *) STREAM_PNT (s);

  /* Until detail flag is set, return. */
  if (!(ospf_debug_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL))
    return;

  /* Show OSPF header detail. */
  ospf_header_dump (ospfh);
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

  stream_set_getp (s, gp);
}


/*
   [no] debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)
                          [send|recv [detail]]
*/

DEFUN (debug_ospf_packet,
       debug_ospf_packet_all_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  int type = 0;
  int flag = 0;
  int i;

  assert (argc > 0);

#ifdef DEBUG
zlog_info ("argc=%d", argc);
#endif /* DEBUG */

  /* Check packet type. */
  if (strncmp (argv[0], "h", 1) == 0)
    type = OSPF_DEBUG_HELLO;
  else if (strncmp (argv[0], "d", 1) == 0)
    type = OSPF_DEBUG_DB_DESC;
  else if (strncmp (argv[0], "ls-r", 4) == 0)
    type = OSPF_DEBUG_LS_REQ;
  else if (strncmp (argv[0], "ls-u", 4) == 0)
    type = OSPF_DEBUG_LS_UPD;
  else if (strncmp (argv[0], "ls-a", 4) == 0)
    type = OSPF_DEBUG_LS_ACK;
  else if (strncmp (argv[0], "a", 1) == 0)
    type = OSPF_DEBUG_ALL;

  /* Default, both send and recv. */
  if (argc == 1)
    flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV;

  /* send or recv. */
  if (argc >= 2)
    {
      if (strncmp (argv[1], "s", 1) == 0)
	flag = OSPF_DEBUG_SEND;
      else if (strncmp (argv[1], "r", 1) == 0)
	flag = OSPF_DEBUG_RECV;
      else if (strncmp (argv[1], "d", 1) == 0)
	flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
    }

  /* detail. */
  if (argc == 3)
    if (strncmp (argv[2], "d", 1) == 0)
      flag |= OSPF_DEBUG_DETAIL;

  for (i = 0; i < 5; i++)
    if (type & (0x01 << i))
      DEBUG_PACKET_ON (i, flag);

#ifdef DEBUG
  for (i = 0; i < 5; i++)
    zlog_info ("flag[%d] = %d", i, ospf_debug_packet[i]);
#endif /* DEBUG */

  return CMD_SUCCESS;
}

ALIAS (debug_ospf_packet,
       debug_ospf_packet_send_recv_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail information\n")

ALIAS (debug_ospf_packet,
       debug_ospf_packet_send_recv_detail_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")
       

DEFUN (no_debug_ospf_packet,
       no_debug_ospf_packet_all_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  int type = 0;
  int flag = 0;
  int i;

  assert (argc > 0);

#ifdef DEBUG
  zlog_info ("argc=%d", argc);
#endif /* DEBUG */

  /* Check packet type. */
  if (strncmp (argv[0], "h", 1) == 0)
    type = OSPF_DEBUG_HELLO;
  else if (strncmp (argv[0], "d", 1) == 0)
    type = OSPF_DEBUG_DB_DESC;
  else if (strncmp (argv[0], "ls-r", 4) == 0)
    type = OSPF_DEBUG_LS_REQ;
  else if (strncmp (argv[0], "ls-u", 4) == 0)
    type = OSPF_DEBUG_LS_UPD;
  else if (strncmp (argv[0], "ls-a", 4) == 0)
    type = OSPF_DEBUG_LS_ACK;
  else if (strncmp (argv[0], "a", 1) == 0)
    type = OSPF_DEBUG_ALL;

  /* Default, both send and recv. */
  if (argc == 1)
    flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL ;

  /* send or recv. */
  if (argc == 2)
    {
      if (strncmp (argv[1], "s", 1) == 0)
	flag = OSPF_DEBUG_SEND | OSPF_DEBUG_DETAIL;
      else if (strncmp (argv[1], "r", 1) == 0)
	flag = OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
      else if (strncmp (argv[1], "d", 1) == 0)
	flag = OSPF_DEBUG_DETAIL;
    }

  /* detail. */
  if (argc == 3)
    if (strncmp (argv[2], "d", 1) == 0)
      flag = OSPF_DEBUG_DETAIL;

  for (i = 0; i < 5; i++)
    if (type & (0x01 << i))
      DEBUG_PACKET_OFF (i, flag);

#ifdef DEBUG
  for (i = 0; i < 5; i++)
    zlog_info ("flag[%d] = %d", i, ospf_debug_packet[i]);
#endif /* DEBUG */

  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf_packet,
       no_debug_ospf_packet_send_recv_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

ALIAS (no_debug_ospf_packet,
       no_debug_ospf_packet_send_recv_detail_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

DEFUN (debug_ospf_ism,
       debug_ospf_ism_cmd,
       "debug ospf ism",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n")
{
  if (argc == 0)
    DEBUG_ON (ism, ISM);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "s", 1) == 0)
	DEBUG_ON (ism, ISM_STATUS);
      else if (strncmp (argv[0], "e", 1) == 0)
	DEBUG_ON (ism, ISM_EVENTS);
      else if (strncmp (argv[0], "t", 1) == 0)
	DEBUG_ON (ism, ISM_TIMERS);
    }

  return CMD_SUCCESS;
}

ALIAS (debug_ospf_ism,
       debug_ospf_ism_sub_cmd,
       "debug ospf ism (status|events|timers)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")

DEFUN (no_debug_ospf_ism,
       no_debug_ospf_ism_cmd,
       "no debug ospf ism",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine")
{
  if (argc == 0)
    DEBUG_OFF (ism, ISM);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "s", 1) == 0)
	DEBUG_OFF (ism, ISM_STATUS);
      else if (strncmp (argv[0], "e", 1) == 0)
	DEBUG_OFF (ism, ISM_EVENTS);
      else if (strncmp (argv[0], "t", 1) == 0)
	DEBUG_OFF (ism, ISM_TIMERS);
    }

  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf_ism,
       no_debug_ospf_ism_sub_cmd,
       "no debug ospf ism (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM Timer Information\n")

DEFUN (debug_ospf_nsm,
       debug_ospf_nsm_cmd,
       "debug ospf nsm",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Neighbor State Machine\n")
{
  if (argc == 0)
    DEBUG_ON (nsm, NSM);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "s", 1) == 0)
	DEBUG_ON (nsm, NSM_STATUS);
      else if (strncmp (argv[0], "e", 1) == 0)
	DEBUG_ON (nsm, NSM_EVENTS);
      else if (strncmp (argv[0], "t", 1) == 0)
	DEBUG_ON (nsm, NSM_TIMERS);
    }

  return CMD_SUCCESS;
}

ALIAS (debug_ospf_nsm,
       debug_ospf_nsm_sub_cmd,
       "debug ospf nsm (status|events|timers)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFUN (no_debug_ospf_nsm,
       no_debug_ospf_nsm_cmd,
       "no debug ospf nsm",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Neighbor State Machine")
{
  if (argc == 0)
    DEBUG_OFF (nsm, NSM);
  else if (argc == 1)
    {
      if (strncmp (argv[0], "s", 1) == 0)
	DEBUG_OFF (nsm, NSM_STATUS);
      else if (strncmp (argv[0], "e", 1) == 0)
	DEBUG_OFF (nsm, NSM_EVENTS);
      else if (strncmp (argv[0], "t", 1) == 0)
	DEBUG_OFF (nsm, NSM_TIMERS);
    }

  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf_nsm,
       no_debug_ospf_nsm_sub_cmd,
       "no debug ospf nsm (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFUN (show_debugging_ospf,
       show_debugging_ospf_cmd,
       "show debugging ospf",
       SHOW_STR
       "OSPF configuration\n"
       "Debugging information\n")
{
  int i;

  vty_out (vty, "Zebra debugging status:\r\n");

  /* debug ism. */
  if (IS_OSPF_DEBUG (ism, ISM) == OSPF_DEBUG_ISM)
    vty_out (vty, "  OSPF ISM debugging is on\r\n");
  else
    {
      if (IS_OSPF_DEBUG (ism, ISM_STATUS))
	vty_out (vty, "  OSPF ISM status debugging is on\r\n");
      else if (IS_OSPF_DEBUG (ism, ISM_EVENTS))
	vty_out (vty, "  OSPF ISM event debugging is on\r\n");
      else if (IS_OSPF_DEBUG (ism, ISM_TIMERS))
	vty_out (vty, "  OSPF ISM timer debugging is on\r\n");
    }

  /* debug nsm. */
  if (IS_OSPF_DEBUG (nsm, NSM) == OSPF_DEBUG_NSM)
    vty_out (vty, "  OSPF NSM debugging is on\r\n");
  else
    {
      if (IS_OSPF_DEBUG (nsm, NSM_STATUS))
	vty_out (vty, "  OSPF NSM status debugging is on\r\n");
      else if (IS_OSPF_DEBUG (nsm, NSM_EVENTS))
	vty_out (vty, "  OSPF NSM event debugging is on\r\n");
      else if (IS_OSPF_DEBUG (nsm, NSM_TIMERS))
	vty_out (vty, "  OSPF NSM timer debugging is on\r\n");
    }

  /* debug packet. */
  for (i = 0; i < 5; i++)
    {
      if (IS_OSPF_DEBUG_PACKET (i, SEND) && IS_OSPF_DEBUG_PACKET (i, RECV))
	{
	  vty_out (vty, "  OSPF packet %s%s debugging is on\r\n",
		   ospf_packet_type_str[i + 1],
		   IS_OSPF_DEBUG_PACKET (i, DETAIL) ? " detail" : "");
	}
      else
	{
	  if (IS_OSPF_DEBUG_PACKET (i, SEND))
	    vty_out (vty, "  OSPF packet %s send%s debugging is on\r\n",
		     ospf_packet_type_str[i + 1],
		     IS_OSPF_DEBUG_PACKET (i, DETAIL) ? " detail" : "");
	  else if (IS_OSPF_DEBUG_PACKET (i, RECV))
	    vty_out (vty, "  OSPF packet %s receive%s debugging is on\r\n",
		     ospf_packet_type_str[i + 1],
		     IS_OSPF_DEBUG_PACKET (i, DETAIL) ? " detail" : "");
	}
    }

  return CMD_SUCCESS;
}

/* Debug node. */
struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""
};

int
config_write_debug (struct vty *vty)
{
  int write = 0;
  int i, r;

  char *type_str[] = {"hello", "dd", "ls-request", "ls-update", "ls-ack"};
  char *detail_str[] = {"", " send", " recv", "", " detail",
			" send detail", " recv detail"};

  /* debug ospf ism (status|events|timers). */
  if (IS_OSPF_DEBUG (ism, ISM) == OSPF_DEBUG_ISM)
    vty_out (vty, "debug ospf ism%s", VTY_NEWLINE);
  else
    {
      if (IS_OSPF_DEBUG (ism, ISM_STATUS))
	vty_out (vty, "debug ospf ism status%s", VTY_NEWLINE);
      else if (IS_OSPF_DEBUG (ism, ISM_EVENTS))
	vty_out (vty, "debug ospf ism event%s", VTY_NEWLINE);
      else if (IS_OSPF_DEBUG (ism, ISM_TIMERS))
	vty_out (vty, "debug ospf ism timer%s", VTY_NEWLINE);
    }

  /* debug ospf nsm (status|events|timers). */
  if (IS_OSPF_DEBUG (nsm, NSM) == OSPF_DEBUG_NSM)
    vty_out (vty, "debug ospf nsm%s", VTY_NEWLINE);
  else
    {
      if (IS_OSPF_DEBUG (nsm, NSM_STATUS))
	vty_out (vty, "debug ospf ism status%s", VTY_NEWLINE);
      else if (IS_OSPF_DEBUG (nsm, NSM_EVENTS))
	vty_out (vty, "debug ospf nsm event%s", VTY_NEWLINE);
      else if (IS_OSPF_DEBUG (nsm, NSM_TIMERS))
	vty_out (vty, "debug ospf nsm timer%s", VTY_NEWLINE);
    }

  /* debug ospf packet all detail. */
  r = OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL;
  for (i = 0; i < 5; i++)
    r &= ospf_debug_packet[i] & (OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL);
  if (r == (OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL))
    {
      vty_out (vty, "debug ospf packet all detail%s", VTY_NEWLINE);
      return 1;
    }

  /* debug ospf packet all. */
  r = OSPF_DEBUG_SEND_RECV;
  for (i = 0; i < 5; i++)
    r &= ospf_debug_packet[i] & OSPF_DEBUG_SEND_RECV;
  if (r == OSPF_DEBUG_SEND_RECV)
    {
      vty_out (vty, "debug ospf packet all%s", VTY_NEWLINE);
      for (i = 0; i < 5; i++)
	if (ospf_debug_packet[i] & OSPF_DEBUG_DETAIL)
	  vty_out (vty, "debug ospf packet %s detail%s",
		   type_str[i], VTY_NEWLINE);
      return 1;
    }

  /* debug ospf packet (hello|dd|ls-request|ls-update|ls-ack)
     (send|recv) (detail). */
  for (i = 0; i < 5; i++)
    {
      if (ospf_debug_packet[i] == 0)
	continue;
      
      vty_out (vty, "debug ospf packet %s%s%s",
	       type_str[i], detail_str[ospf_debug_packet[i]], VTY_NEWLINE);
      write = 1;
    }

  return write;
}

/* Initialize debug commands. */
void
debug_init ()
{
  install_node (&debug_node, config_write_debug);

  install_element (VIEW_NODE, &show_debugging_ospf_cmd);

  install_element (ENABLE_NODE, &show_debugging_ospf_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_all_cmd);
  install_element (ENABLE_NODE, &debug_ospf_ism_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_ism_cmd);
  install_element (ENABLE_NODE, &debug_ospf_nsm_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_nsm_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_all_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_ism_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_ism_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_nsm_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_nsm_cmd);

  install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &debug_ospf_packet_all_cmd);
  install_element (CONFIG_NODE, &debug_ospf_ism_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_ism_cmd);
  install_element (CONFIG_NODE, &debug_ospf_nsm_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_nsm_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_all_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_ism_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_ism_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_nsm_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_nsm_cmd);
}

