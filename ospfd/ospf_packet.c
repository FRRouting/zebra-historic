/* OSPF Sending and Receiving OSPF Packets
   Copyright (C) 1999 Toshiaki Takada

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

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"

/* forward output pointer. */
void
ospf_output_forward (struct stream *s, int size)
{
  s->putp += size;
}

/* Write packet. */
int
ospf_write (struct ospf_interface *oi, int length)
{
  struct stream *s;
  struct sockaddr_in sa;

  s = oi->obuf;
  sa.sin_family = AF_INET;
  sa.sin_port = htons (0);
  inet_aton (OSPF_ALLSPFROUTERS, &sa.sin_addr);

  sendto (oi->fd, STREAM_DATA (oi->obuf), length, 0,
	  (struct sockaddr *) &sa, sizeof (sa));

  return 0;
}

void
ospf_make_header (struct ospf_interface *oi, struct ospf_header *ospfh)
{
  ospfh->version = (u_char) OSPF_VERSION;
  ospfh->type = (u_char) OSPF_MSG_HELLO;

  ospfh->router_id = ospf_top->router_id;

  ospfh->checksum = 0;
  ospfh->area_id = oi->area_id;
  ospfh->auth_type = oi->auth_type;

  bzero (ospfh->auth_data, sizeof (ospfh->auth_data));
}

/* OSPF Hello message read. */
void
ospf_hello (struct ip *iph, struct ospf_header *ospfh,
	    struct ospf_interface *oi, int size)
{
  struct ospf_hello *hello;
  struct ospf_neighbor *nbr;
  struct route_node *rn;
  struct prefix p, key;

  zlog (NULL, LOG_INFO, "OSPF Hello received from [%s]",
	inet_ntoa (iph->ip_src));

  hello = (struct ospf_hello *) STREAM_PNT (oi->ibuf);

  /* get neighbor prefix. */
  p.family = AF_INET;
  p.prefixlen = ip_masklen (hello->network_mask);
  p.u.prefix4 = iph->ip_src;

  /* compare network mask. */
  /* checking is ignored for Point-to-Point and Virtual link. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    if (oi->address->prefixlen != p.prefixlen)
      {
	zlog (NULL, LOG_WARNING, "neighbor [%s] NetworkMask mismatch.",
	      inet_ntoa (ospfh->router_id));
	return;
      }

  /* compare Hello Interval. */
  if (oi->v_hello != ntohs (hello->hello_interval))
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] HelloInterval mismatch.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare Router Dead Interval. */
  if (oi->v_wait != ntohl (hello->dead_interval))
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] RouterDeadInterval mismatch.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* compare options. */
  if (oi->options != hello->options)
    {
      zlog (NULL, LOG_WARNING, "neighbor [%s] Options mismacth.",
	    inet_ntoa (ospfh->router_id));
      return;
    }

  /* get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = 32;
  key.u.prefix4 = ospfh->router_id;

  rn = route_node_get (oi->nbrs, &key);
  if (rn->info)
    {
      route_unlock_node (rn);
      nbr = rn->info;
    }
  else
    {
      /* Create new OSPF Neighbor structure. */
      nbr = ospf_nbr_new ();
      nbr->oi = oi;
      nbr->status = NSM_Down;
      nbr->host = strdup (inet_ntoa (iph->ip_src));
      nbr->router_id = ospfh->router_id;
      nbr->address = p;

      rn->info = nbr;

      /* if Hello is myself, silently add pseudo neighbor. */
      if (! ADDRESS_SAME (&nbr->router_id, &ospf_top->router_id))
	{
	  zlog (NULL, LOG_INFO, "OSPF NSM[%s] start.",
		inet_ntoa (nbr->router_id));
	}
    }

  /* Latest neighbor information set. */
  nbr->priority = hello->priority;
  nbr->options = hello->options;
  nbr->d_router = hello->d_router;
  nbr->bd_router = hello->bd_router;

  /* This is myself. Do not add event thread. */
  if (ADDRESS_SAME (&nbr->router_id, &ospf_top->router_id))
    {
      nbr->status = NSM_TwoWay;
      return;
    }

  /* Add event to thread. */
  OSPF_NSM_EVENT_ADD (nbr, NSM_HelloReceived);

  /* if neighbor itself is DR or no BDR exists,
     cause event BackupSeen */
  if (ospf_nbr_bidirectional (&ospf_top->router_id, hello->neighbors,
			      size - OSPF_HELLO_MIN_SIZE))
    {
      OSPF_NSM_EVENT_ADD (nbr, NSM_TwoWayReceived);

      if (ADDRESS_SAME (&nbr->router_id, &nbr->d_router) ||
	  nbr->bd_router.s_addr == 0)
	OSPF_ISM_EVENT_ADD (oi, ISM_BackupSeen);
    }
}

void
ospf_hello_send (struct ospf_interface *oi)
{
  struct ospf_header *ospfh;
  struct ospf_hello *hello;
  struct ospf_neighbor *nbr;
  struct route_node *node;
  int length;
  int in_cksum (void *ptr, int nbytes);

  oi->obuf = stream_new (oi->ifp->mtu);
  ospfh = (struct ospf_header *) OSPF_OUTPUT_PNT (oi->obuf);

  /* prepare OSPF header. */
  ospf_make_header (oi, ospfh);
  ospf_output_forward (oi->obuf, OSPF_HEADER_SIZE);

  /* prepare Hello body. */
  hello = (struct ospf_hello *) OSPF_OUTPUT_PNT (oi->obuf);
  
  /* set netmask of interface. */
  if (oi->type != OSPF_IFTYPE_POINTOPOINT &&
      oi->type != OSPF_IFTYPE_VIRTUALLINK)
    masklen2ip (oi->address->prefixlen, &hello->network_mask);

  hello->hello_interval = htons (oi->v_hello);
  hello->options = oi->options;
  hello->priority = oi->priority;
  hello->dead_interval = htonl (oi->v_wait);
  hello->d_router = oi->d_router;
  hello->bd_router = oi->bd_router;

  ospf_output_forward (oi->obuf, OSPF_HELLO_MIN_SIZE);

  for (node = route_top (oi->nbrs); node; node = route_next (node))
    {
      if (node->info == NULL)
	continue;

      nbr = node->info;

      stream_put_ipv4 (oi->obuf, nbr->address.u.prefix4.s_addr);
    }

  length = OSPF_OUTPUT_LENGTH (oi->obuf);

  ospfh->length = htons (length);
  ospfh->checksum = in_cksum (ospfh, length);
  ospf_write (oi, length);

  zlog (NULL, LOG_INFO, "OSPF Hello sent");
  /* OSPF_ISM_WRITE_ON (oi->t_write, ospf_write, oi->fd); */
}

void
ospf_db_desc (struct ospf_interface *oi, u_int16_t size)
{

  zlog (NULL, LOG_INFO, "OSPF Database Description received");
}

void
ospf_db_desc_send ()
{

}

void
ospf_ls_req (struct ospf_interface *oi, u_int16_t size)
{
  zlog (NULL, LOG_INFO, "OSPF Link State Request received");
}

void
ospf_ls_req_send ()
{

}

void
ospf_ls_upd (struct ospf_interface *oi, u_int16_t size)
{
  zlog (NULL, LOG_INFO, "OSPF Link State Update received");
}

void
ospf_ls_upd_send ()
{

}

void
ospf_ls_ack (struct ospf_interface *oi, u_int16_t size)
{
  zlog (NULL, LOG_INFO, "OSPF Link State Acknowledgement received");
}

void
ospf_ls_ack_send ()
{

}

int
ospf_recv_packet (struct ospf_interface *oi)
{
  int ret;

  ret = recvfrom (oi->fd, STREAM_DATA (oi->ibuf), STREAM_SIZE (oi->ibuf),
		  0, NULL, 0);

  return ret;
}

int
ospf_check_auth (u_char type, u_char *auth_data)
{
  return 1;
}

int
ospf_check_sum (struct ospf_interface *oi, u_int16_t check_sum)
{
  return 1;
}

/* Starting point of packet process function. */
int
ospf_read (struct thread *thread)
{
  int ret;
  struct ospf_interface *oi;
  struct ip *iph;
  struct ospf_header *ospfh;
  u_int16_t length;

  /* first of all get interface pointer. */
  oi = THREAD_ARG (thread);
  oi->t_read = NULL;

  /* Clear input buffer. */
  stream_reset (oi->ibuf);
  iph = (struct ip *) STREAM_DATA (oi->ibuf);

  /* read OSPF packet. */
  ret = ospf_recv_packet (oi);
  if (ret < 0)
    return ret;

  /* prepare for next packet. */
  OSPF_ISM_READ_ON (oi->t_read, ospf_read, oi->fd);

  /* #define DEBUG */
#ifdef DEBUG
  /* IP Packet dump */
  ospf_packet_dump (oi->ibuf);
#endif /* DEBUG */

  /* get total ip length. */
#ifdef GNU_LINUX
  length = ntohs (iph->ip_len);
#else /* GNU_LINUX */
  length = iph->ip_len;
#endif /* GNU_LINUX */

  /* Packet size check. */
  if (length > oi->ifp->mtu)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet buffer over flow", oi->ifp->name);
      return 0;
    }

  /* my packet should be discarded silently. */
  /*  if (ADDRESS_SAME (&iph->ip_src, &oi->address->u.prefix4))
      return 0; */

  /* Adjust size to message length. */
  stream_forward (oi->ibuf, iph->ip_hl * 4);

  /* get ospf packet header. */
  ospfh = (struct ospf_header *) STREAM_PNT (oi->ibuf);
  stream_forward (oi->ibuf, OSPF_HEADER_SIZE);

  /* check authentication. */
  if (! ospf_check_auth (ospfh->auth_type, ospfh->auth_data))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read authentication failed", oi->ifp->name);
      return -1;
    }

  /* Adjust size to message length. */
  length -= OSPF_HEADER_SIZE;

  /* if check sum is invalid, packet is discarded. */
  if (! ospf_check_sum (oi, ospfh->checksum))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet checksum error", oi->ifp->name);
      return -1;
    }

  /* Read rest of the packet and call each sort of packet routine. */
  switch (ospfh->type)
    {
    case OSPF_MSG_HELLO:
      ospf_hello (iph, ospfh, oi, length);
      break;
    case OSPF_MSG_DB_DESC:
      ospf_db_desc (oi, length);
      break;
    case OSPF_MSG_LS_REQ:
      ospf_ls_req (oi, length);
      break;
    case OSPF_MSG_LS_UPD:
      ospf_ls_upd (oi, length);
      break;
    case OSPF_MSG_LS_ACK:
      ospf_ls_ack (oi, length);
      break;
    default:
      zlog (NULL, LOG_WARNING,
	    "interface %s: OSPF packet header type %d is illegal",
	    oi->ifp->name, ospfh->type);
      break;
    }

  return 0;
}



