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
enum bgp_peer_sort
{
  BGP_PEER_IBGP,
  BGP_PEER_EBGP
};

/* Default max TTL. */
#define TTL_MAX 255

/* BGP neighbor structure. */
struct peer 
{
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
  int version;			/* Peer BGP version. */
  int ttl;			/* TTL of TCP connection to this peer. */
  u_int16_t as;			/* Peer AS number. */
  u_int32_t ident;			/* Peer BGP identifier. */
  u_int32_t myident;		/* My BGP identifier. */

  /* Status of the peer. */
  int status;			/* peer finite state machine status */
  int ostatus;			/* Old peer status. */

  /* Default attribute value for this peer. */
  unsigned int def;		/* Option set flag. */
  long localpref;		/* default local preference. */
  time_t uptime;		/* Last Up/Down time */
  struct in_addr next_hop;	/* nexthop address */

  /* Timer values. */
  u_int32_t v_start;
  u_int32_t v_connect;
  u_int32_t v_holdtime;
  u_int32_t v_keepalive;
  u_int32_t v_asorig;
  u_int32_t v_routeadv;

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
  u_int32_t open_in;		/* Open message input count */
  u_int32_t open_out;		/* Open message output count */
  u_int32_t update_in;		/* Update with nlri message input count */
  u_int32_t update_out;		/* Update with nlri message ouput count */
  u_int32_t withdrow_in;	/* Update with withdrow message input count */
  u_int32_t withdrow_out;	/* Update with withdrow message output count */
  u_int32_t keepalive_in;	/* Keepalive input count */
  u_int32_t keepalive_out;	/* Keepalive output count */

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
int peer_sort (struct peer *peer);
void event_add (struct peer *peer, int event);
int sockunion_vty_out (struct vty *vty, union sockunion *su);

/* For peer related functions. */
void bgp_notify_send (struct peer *peer, u_char err_code, u_char err_subcode);
void bgp_clear(struct peer *peer, int error);
void peer_delete_all ();
void peer_delete (struct peer *peer);

/* For bgp_route.c */
void nlri_parse (u_char *pnt, int len, struct attr *attr, struct peer *peer);
void nlri_withdraw (unsigned char *pnt, int unfeasible_len, struct peer *peer);
void bgp_dump_attr (struct peer *peer, struct attr *attr);
void bgp_peer_delete (struct peer *peer);

/* For bgpd.c */
int bgp_connect (struct peer *peer);
void bgp_open_send (struct peer *peer);
void bgp_keepalive_send(struct peer *peer);
int bgp_read_packet (struct peer *peer);
void bgp_uptime_reset (struct peer *peer);
void peer_uptime_vty (struct vty *vty, struct peer *peer);
void peer_config_write (struct vty *vty, list bgp_peer);

/* For bgp_open.c */
void bgp_open_recv (struct peer *peer);

/* For bgp_dump.c */
void bgp_notify_print(struct peer *peer, struct bgp_notify *bgp_notify);
