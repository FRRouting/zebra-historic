/* BGP peer structure definitions.
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

/* IBGP/EBGP identifier */
enum 
{
  BGP_PEER_IBGP = 1,
  BGP_PEER_EBGP = 2
};

/* Default max TTL. */
#define TTL_MAX 255

/* BGP neighbor structure. */
struct peer {
  /* Packet read buffer (OLD). This have to replaced by buffer structre. */
  u_char header_buf[BGP_HEADER_SIZE];
  u_char read_buf[BGP_MAX_PACKET_SIZE];

  /* Packet buffer (NEW). */
  struct buffer *ibuf;
  struct buffer *obuf;

  /* Peer information */
  char *host;			/* Printable address of this peer. */
  union sockunion *su;		/* Sockunion address of this peer. */
  struct bgp *bgp;		/* Peer's parent bgp. */
  int fd;			/* File descriptor */
  u_short as;			/* Peer AS number. */
  int version;			/* Peer BGP version. */
  u_long ident;			/* Peer BGP identifier. */
  u_long myident;		/* My BGP identifier. */
  int ttl;			/* TTL of TCP connection to this peer. */

  int status;			/* peer finite state machine status */
  int ostatus;			/* Old peer status. */

  /* Default attribute value for this peer. */
  unsigned int def;		/* Option set flag. */
  long localpref;		/* default local preference. */
  /* unsigned long next_hop;	/* nexthop address */
  unsigned long next_hop;	/* nexthop address */
  time_t uptime;		/* Last Up/Down time */

  /* Timer values. */
  u_int v_start;
  u_int v_connect;
  u_int v_holdtime;
  u_int v_keepalive;
  u_int v_asorig;
  u_int v_routeadv;

  /* Threads. */
  struct thread *t_read;
  struct thread *t_write;
  struct thread *t_start;
  struct thread *t_connect;
  struct thread *t_holdtime;
  struct thread *t_keepalive;
  struct thread *t_asorig;
  struct thread *t_routeadv;

  /* Statistics field */
  unsigned int open_in;		/* Open message input count */
  unsigned int open_out;	/* Open message output count */
  unsigned int update_in;	/* Update with nlri message input count */
  unsigned int update_out;	/* Update with nlri message ouput count */
  unsigned int withdrow_in;	/* Update with withdrow message input count */
  unsigned int withdrow_out;	/* Update with withdrow message output count */
  unsigned int keepalive_in;	/* Keepalive input count */
  unsigned int keepalive_out;	/* Keepalive output count */

  /* Filter and route map. */
  struct filter *dist_in;
  struct filter *dist_out;
  struct filter *filt_in;
  struct filter *filt_out;
  struct route_map *route_map_in;
  struct route_map *route_map_out;

  /* prefix_in/out will be need. */
  unsigned int prefix_count;	/* Prefix count of this peer. */
};

/* Prototype */
struct peer *peer_new (void);
struct peer *peer_lookup_from_bgp (struct bgp *bgp, char *addr);
struct peer *peer_lookup_by_su (union sockunion *su);
struct peer *peer_lookup_by_host (char *host);
