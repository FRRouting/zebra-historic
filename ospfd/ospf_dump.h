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

#ifndef _ZEBRA_OSPF_DUMP_H
#define _ZEBRA_OSPF_DUMP_H

/* Prototypes. */
int debug (unsigned int option);
char *mes_lookup (message *, int, int);
void ospf_nbr_state_message (struct ospf_neighbor *, char *, size_t);
char *ospf_timer_dump (struct thread *, char *, size_t);
void ospf_packet_dump (struct stream *s);

#endif /* _ZEBRA_OSPF_DUMP_H */
