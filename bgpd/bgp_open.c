/* BGP open message handling
   Copyright (C) 1998 Kunihiro Ishiguro

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

#include <sys/types.h>

#include "bgpd.h"
#include "bgp_peer.h"

void capability_parse (caddr_t *pnt, u_char length);

/* Parse open option */
bgp_open_option_parse (caddr_t *pnt, u_char length)
{
  caddr_t *lim;
  u_char opt_type;
  u_char opt_length;

  lim = pnt + length;
  while (pnt < lim) {
    ld_1byte (opt_type, pnt);
    ld_1byte (opt_length, pnt);

    switch (opt_type)
      {
      case BGP_OPEN_OPT_AUTH:
	/* auth_parse (pnt, opt_length); */
	break;
      case BGP_OPEN_OPT_CAP:
	capability_parse (pnt, opt_length);
	break;
      default:
	/* Unknown open option parameter */
	break;
      }
    pnt += opt_length;
  }
}

/* BGP open message read. Should be called from finite state machine. */
bgp_open_recv (struct peer *peer)
{
  struct bgp_open open;
  u_char *pnt = peer->read_buf;
  
  peer->open_in++;

  ld_1byte (open.version, pnt);
  ld_2byte (open.asno, pnt);
  ld_2byte (open.holdtime, pnt);
  ld_4octet (open.ident, pnt);
  ld_1byte (open.optlen, pnt);

  peer->ident = open.ident;
  peer->v_holdtime = open.holdtime;

  if (open.optlen != 0) 
    bgp_open_option_parse (pnt, open.optlen);

  if (dump_open)
    bgp_open_dump(&open, peer, 2);

  /* Peer BGP version check. */
  if (open.version != BGP_VERSION_4 && open.version != BGP_VERSION_5)
    {
      /* If BGP version doesn't match... */
      bgp_notify_send (peer, 
		       BGP_NOTIFY_OPEN_ERR, 
		       BGP_NOTIFY_OPEN_UNSUP_VERSION);
      return;
    }
  
  if (open.asno != peer->as)
    {
      bgp_notify_send (peer, BGP_NOTIFY_OPEN_ERR, BGP_NOTIFY_OPEN_BAD_PEER_AS);
      bgp_clear (peer, 1);
      return ;
    }

  event_add (peer, Receive_OPEN_message);
}


/* draft-ietf-idr-bgp4-cap-neg-01.txt

4. Capabilities Optional Parameter (Parameter Type 2):

   This is an Optional Parameter that is used by a BGP speaker to convey
   to its BGP peer the list of capabilities supported by the speaker.

   The parameter contains one or more triples <Capability Code,
   Capability Length, Capability Value>, where each triple is encoded as
   shown below:


      +------------------------------+
      | Capability Code (1 octet)    |
      +------------------------------+
      | Capability Length (1 octet)  |
      +------------------------------+
      | Capability Value (variable)  |
      +------------------------------+
*/

/* BGP open message capability. */
struct capability 
{
  u_char code;
  u_char length;
  u_char *val;
};

/* Parse given capability. */
void
capability_parse (caddr_t *pnt, u_char length) 
{
  struct capability *cap;

  /* Fetch structure to the byte stream. */
  cap = (struct capability *) pnt;

  /* At this point only code that we know is MP Capability Code. */
  switch (cap->code)
    {
    case 0x01:
      /* MP Capability Code. */
      mp_capability_negotiation (pnt, length);
      break;
    default:
      /* Unknown capability. */
      log_warn ("");
      break;
    }
}

/* draft-marques-bgp4-cap-mp-01.txt

3. MP Capability Code

   BGP speakers that wish to negotiate the set of (AFI, SAFI) pairs
   availiable on a particular peering should use the MP_EXT Capability
   Code (Type 0x01, in hexadecimal).

   The Capability Value associated with the code is a 32 bit value, in
   network byte-order, defined as:


                     0       7      15      23      31
                     +-------+-------+-------+-------+
                     |      AFI      | Res.  | SAFI  |
                     +-------+-------+-------+-------+

   The use and meaning of this fields is as follows:


         AFI  - Address Family Identifier (16 bit) as defined in [RFC-
         1700].

         Res. - Reserved (8 bit) field. Should be set to 0 by the sender
         and ignored by the receiver.

         SAFI - Subsequent Address Family Identifier (8 bit) field as
         defined in [BGP-MP]
*/

/* BGP-4 Multiprotocol Extentions lead us to the complex world. We can
   negotiate remote peer supports extentions or not. But if
   remote-peer doesn't supports negotiation process itself.  We would
   like to do manual configuration.

   So there is many configurable point.  First of all we want set each
   peer whether we send capability negotiation to the peer or not.
   Next, if we send capability to the peer we want to set my capabilty
   inforation at each peer. */

/* MP Capability information. */
struct mp_capability
{
  u_int16_t afi;
  u_char reserved;
  u_char safi;
};

/* Check my capability */
mp_capability_negotiation (caddr_t start, u_char length)
{
  caddr_t pnt;
  struct mp_capability *mpc;

  for (pnt = start; pnt < start + length; pnt += 4)
    {
      mpc = (struct mp_capability *) pnt;
      if (mpc->afi)
	;
    }
}

/* For debug purpose. */
mp_capability_print ()
{
  ;
}
