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
#include "if.h"
#include "thread.h"
#include "stream.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_packet.h"

/* OSPF Hello message read. */
void
ospf_hello (struct ospf_interface *oi, u_int16_t size)
{
  /*
    struct in_addr mask;
    u_int16_t hello_interval;
    u_char options;
    u_char router_priority;
    u_int32_t router_dead_interval;
    struct in_addr d_router;
    struct in_addr bd_router;
  */
}

void
ospf_hello_send ()
{

}

void
ospf_db_desc (struct ospf_interface *oi, u_int16_t size)
{

}

void
ospf_db_desc_send ()
{

}

void
ospf_ls_req (struct ospf_interface *oi, u_int16_t size)
{

}

void
ospf_ls_req_send ()
{

}

void
ospf_ls_upd (struct ospf_interface *oi, u_int16_t size)
{

}

void
ospf_ls_upd_send ()
{

}

void
ospf_ls_ack (struct ospf_interface *oi, u_int16_t size)
{

}

void
ospf_ls_ack_send ()
{

}

int
ospf_read_packet (struct ospf_interface *oi, int size)
{
  int nbytes;

  /* If size is zero then return. */
  if (! size)
    return 0;

  /* Read packet from fd. */
  nbytes = stream_read (oi->ibuf, oi->fd, size);

  /* If read byte is smaller than zero then error occured. */
  if (nbytes < 0)
    {
      zlog (NULL, LOG_WARNING, "interface %s: ospf_read_packet error: %m",
	    oi->ifp->name);
      /*       OSPF_ISM_EVENT_ADD (oi, ); */
      return -1;
    }

  /* When read byte is zero, clear ospf interface and return. */
  if (nbytes == 0)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf connection closed at [%d]",
	    oi->ifp->name, oi->fd);
      /* OSPF_ISM_EVENT_ADD (oi, connection_closed); */
      return -1;
    }

  /* If header size is different, print warning and return. */
  if (nbytes != size)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read_packet can't read all of packet %d/%d : %m ",
	    oi->ifp->name, size, nbytes);
      /* OSPF_ISM_EVENT_ADD (oi, fatal_error) */
      return -1;
    }
  return 0;
}

int
ospf_check_auth (u_char type, u_char *auth_data)
{
  return 0;
}

int
ospf_check_sum (struct ospf_interface *oi, u_int16_t check_sum)
{
  return 0;
}

/* Starting point of packet process function. */
int
ospf_read (struct thread *thread)
{
  int ret;
  struct ospf_interface *oi;
  u_char version, type;
  u_int16_t length, check_sum, auth_type; 
  struct in_addr router_id, area_id;
  u_char auth_data [OSPF_AUTH_SIZE];

  /* first of all get interface pointer. */
  oi = THREAD_ARG (thread);
  oi->t_read = NULL;

  /* Clear input buffer. */
  stream_reset (oi->ibuf);

  /* read packet header to determin type of packet. */
  ret = ospf_read_packet (oi, OSPF_HEADER_SIZE);

  if (ret < 0)
    return ret;

  /* get header information. */
  version = stream_getc (oi->ibuf);
  type = stream_getc (oi->ibuf);
  length = stream_getw (oi->ibuf);
  router_id.s_addr = stream_get_ipv4 (oi->ibuf);
  area_id.s_addr = stream_get_ipv4 (oi->ibuf);

  /* get check sum, check later. */
  check_sum = stream_getw (oi->ibuf);

  /* check authentication. */
  auth_type = stream_getw (oi->ibuf);
  bzero (auth_data, sizeof (auth_data));
  stream_strncpy (auth_data, oi->ibuf, OSPF_AUTH_SIZE);
  if (! ospf_check_auth (auth_type, auth_data))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read authentication failed", oi->ifp->name);
      return -1;
    }

  /* Packet size check. */
  if (length > OSPF_MAX_PACKET_SIZE)
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet buffer over flow",
	    oi->ifp->name);
      return 0;
    }

  /* Adjust size to message length. */
  length -= OSPF_HEADER_SIZE;

  ret = ospf_read_packet (oi, length);
  if (ret < 0)
    return ret;

  /* if check sum is invalid, packet is discarded. */
  if (! ospf_check_sum (oi, check_sum))
    {
      zlog (NULL, LOG_WARNING,
	    "interface %s: ospf_read packet checksum error",
	    oi->ifp->name);
      return -1;
    }

  /* ospf_packet_dump (oi->ibuf); */

  /* Read rest of the packet and call each sort of packet routine. */
  switch (type)
    {
    case OSPF_MSG_HELLO:
      ospf_hello (oi, length);
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
	    oi->ifp->name, type);
      break;
    }
  return 0;
}

