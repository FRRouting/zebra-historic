/*
 * Copyright (C) 1999 Yasuhiro Ohara
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


#ifndef OSPF_TYPES_H
#define OSPF_TYPES_H

typedef u_int8_t	instance_id_t;
typedef struct in_addr	rtr_id_t;
typedef struct in_addr	area_id_t;

#define id_val(X) ((X).s_addr)
#define IS_ROUTER_ID_EQUAL(x,y)	(id_val(x) == id_val(y))
#define IS_AREA_ID_EQUAL(x,y)	(id_val(x) == id_val(y))

typedef u_int8_t state_t;
typedef u_int8_t vers_t;
typedef u_int8_t opt_t;
typedef u_int8_t rtr_pri_t;
typedef u_int8_t prefixlen_t;
typedef u_int8_t ddbits;
typedef u_int16_t hello_int_t;
typedef u_int16_t autype_t;
typedef u_int32_t rtr_dead_int_t;
typedef u_int32_t ifid_t;
typedef u_int32_t cost_t;
typedef u_int32_t rxmt_int_t;

#define ALLSPFROUTERS	"224.0.0.5"
#define ALLDROUTERS	"224.0.0.6"

#ifdef HAVE_IPV6

#define ALLSPFROUTERS6	"ff02::5"
#define ALLDROUTERS6	"ff02::6"

#define GET_IFID(x)     ((x).s6_addr8[3])
#endif /* HAVE_IPV6 */

#endif /* OSPF_TYPES_H */

