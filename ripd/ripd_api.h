/* RIP daemon API
 * Copyright (C) 2000 Nbase Communications <davidl@nbase.co.il>
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _RIPD_API_H_
#define _RIPD_API_H_

#include <zebra.h>
#include "prefix.h"
#include "if.h"
#include "command.h"
#include "routemap.h"

/* 
 * typedefs
 */
typedef struct rip_interface      rip_interface_t;   /* ripd/ripd.h */
typedef struct prefix_ipv4        prefix_ipv4_t;     /* lib/prefix.h */
typedef struct route_node         route_node_t;      /* lib/table.h */
typedef struct interface          interface_t;       /* lib/if.h */
typedef struct connected          connected_t;       /* lib/if.h */
typedef struct route_map_index    route_map_index_t; /* lib/routemap.h */
typedef struct route_map          route_map_t;       /* lib/routemap.h */
typedef struct route_map_rule_cmd route_map_rule_cmd_t;/* lib/routemap.h */
typedef struct rip_peer           rip_peer_t;


typedef struct {
  int	is_empty;	/* 1-(rip==NULL), 0- else */
  int   set_outg_upd_filter;	/* 1 - Outgoing update filter list for all interface */
  int   set_incom_upd_filter;	/* 1 - Incoming update filter list for all interface */
  int	default_rx_version;
  int	default_tx_version;
  
  int	default_metric;

  /* RIP statistics. */
  long rip_global_route_changes;
  long rip_global_queries;

  /* RIP timings */
  unsigned long	update_time;	/* updates every %d seconds */
  unsigned long next_due;	/* next due in %d seconds */
  unsigned long timeout_time;	/* Timeout after %d seconds */
  unsigned long garbage_time;	/* garbage collect after %d seconds */
} rip_globals_t;

/*
 * SECTION 1: ripd.c API
 */

/*************************
 Function:ripd_api_start_stop
 PURPOSE: Start/Stop routing process
 PARAMETERS:
   IN u_char is_started : 0 - for stop, else for start
**************************/
int
ripd_api_start_stop (u_char is_started);

/*************************
 Function:ripd_api_enable_routing
 PURPOSE: Enable/disable RIP routing process
   IN u_char enable_it : 0 - for disable, else for enable
**************************/
int
ripd_api_enable_routing (u_char enable_it);

/*************************
 Function:ripd_api_set_default_metric
 PURPOSE:Set a metric of redistribute routes
 PARAMETERS:
    IN route_id
    INT int default_metric
**************************/
int
ripd_api_set_default_metric (int default_metric);

/*************************
 Function:ripd_api_set_default_version
 Enable/Disable RIP routing process
 PARAMETERS:
    IN version
**************************/
int
ripd_api_set_default_version (int version);

/*************************
 Function:ripd_api_set_static_route
 PURPOSE:Enable/Disable RIP routing process
 PARAMETERS:
    IN route_id
    INT create_it : 0 - delete static route, else - creaate a new one
**************************/ 
int
ripd_api_set_static_route (prefix_ipv4_t* route_id, u_char create_it);

#define RIP_SET_TIME_UPDATE    ((u_char) (1 << 0))
#define RIP_SET_TIME_TIMEOUT   ((u_char) (1 << 1))
#define RIP_SET_TIME_GARBAGE   ((u_char) (1 << 2))
#define RIP_SET_TIME_ALL       (RIP_SET_TIME_UPDATE | RIP_SET_TIME_TIMEOUT | RIP_SET_TIME_GARBAGE)

/*************************
 Function:ripd_api_set_timers
 PURPOSE: RIP timers setup
 PARAMETERS:
    IN   unsigned long update;
    IN   unsigned long timeout;
    IN   unsigned long garbage;
    IN   u_char what_mask - bits (RIP_SET_TIME_UPDATE,
                                  RIP_SET_TIME_TIMEOUT,
                                  RIP_SET_TIME_GARBAGE)
**************************/
int
ripd_api_set_timers (unsigned long update,
                     unsigned long timeout,
                     unsigned long garbage,
                     u_char what_mask);

typedef enum {
  RIP_RT_INFO,     /* rip->table    : RIP routing information base */
  RIP_NEIB_INFO,   /* rip->neighbor : RIP neighbor */
  RIP_STATIC_INFO, /* rip->route    : RIP only static routing information. */
} RT_START_ITERATOR_T;

/*************************
 Function:ripd_api_get_next_route_node
 PURPOSE: Get the route node after the current one.
          If the current is NULL, get the fist node.
          If "End of table" is a case, return CMD_ERR_NOTHING_TODO
          If the parameter 'avoid_empties' not equal 0, 
          all empty entries are skipped
 PARAMETERS:
    IN    RT_START_ITERATOR_T table_type
    IN    avoid_empties
    INOUT node
**************************/
int
ripd_api_get_next_route_node (RT_START_ITERATOR_T table_type,
                              u_char avoid_empties,
                              route_node_t **node);

/*************************
 Function:ripd_api_get_globals
 PURPOSE: Get global RIP information
 PARAMETERS:
    OUT rip_globals_t* info
**************************/
int 
ripd_api_get_globals (rip_globals_t *info);

/*
 * SECTION 2: rip_zebra.c API
 */

/*************************
 Function:ripd_api_set_redist_mode
 PURPOSE: Set/Unset the RIP route Redistribute control
 PARAMETERS:
   IN newMode : 1- set. 0- unset
**************************/
int
ripd_api_set_redist_mode (u_char newMode);

/*************************
 Function:ripd_api_get_redist_mode
 PURPOSE: Get the RIP route Redistribute control mode
 PARAMETERS:
   OUT *currentMode : pointer for the result
**************************/
int
ripd_api_get_redist_mode (u_char *currentMode);

/*************************
 Function:ripd_api_set_redist_type_mode
 PURPOSE: Set/Unset the type RIP route Redistribute control
 PARAMETERS:
   IN type (from {ZEBRA_ROUTE_KERNEL,ZEBRA_ROUTE_CONNECT,
                  ZEBRA_ROUTE_STATIC, ZEBRA_ROUTE_OSPF,
                  ZEBRA_ROUTE_BGP}
   IN newMode : 1- set. 0- unset
   IN char* route_map_name
**************************/
int
ripd_api_set_redist_type_mode (int type,
                               u_char newMode,
                               char *route_map_name);

/*************************
 Function:ripd_api_set_redist_type_metric
 PURPOSE: Set/Unset redistribute information from another routing protocol
 PARAMETERS:
   IN type (from {ZEBRA_ROUTE_KERNEL,ZEBRA_ROUTE_CONNECT,
                  ZEBRA_ROUTE_STATIC, ZEBRA_ROUTE_OSPF,
                  ZEBRA_ROUTE_BGP}
   IN newMode : 1- set. 0- unset
   IN metric
**************************/
int
ripd_api_set_redist_type_metric (int type,
                                 u_char newMode,
                                 int metric);

/*************************
 Function:ripd_api_set_default_information_originate
 PURPOSE: Set/Unset Control distribution of default route
 PARAMETERS:
   IN newMode : 1- set. 0- unset
**************************/
int
ripd_api_set_default_information_originate (u_char newMode);

/*
 * SECTION 3: rip_interface.c API
 */

/*************************
 Function:ripd_api_enable_ip_if
 PURPOSE: Enable RIP network
 PARAMETERS:
    IN    struct prefix* prefx : IP prefix
    IN    u_char enable_it : 0 - disable, else - enable
**************************/
int
ripd_api_enable_ip_if (struct prefix *prefx, u_char enable_it);

/*************************
 Function:ripd_api_enable_network
 PURPOSE: Enable RIP network
 PARAMETERS:
    IN    char* if_name : IP prefix or interface name
    IN    u_char enable_it : 0 - disable, else - enable
**************************/
int
ripd_api_enable_network (char *if_name, u_char enable_it);

/*************************
 Function:ripd_api_enable_neighbor
 PURPOSE: Enable/Disable RIP neighbor router
 PARAMETERS:
    IN    struct prefix* prefx : IP prefix
    IN    u_char enable_it : 0 - disable, else - enable
**************************/
int
ripd_api_enable_neighbor (prefix_ipv4_t *prefx, u_char enable_it);

/*************************
 Function:ripd_api_get_if_running
 PURPOSE: Return the flag : is RIP running on this interface.
 PARAMETERS:
    IN    interface_t* ifp - inteface to be checked
    OUT   int *running - pointer to result
**************************/
int
ripd_api_get_if_running (interface_t *ifp, int *running);

/*************************
 Function:ripd_api_set_if_rx_version
 PURPOSE: Set interface's receive RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int ri_version - RIP accepet/announce method
**************************/
int
ripd_api_set_if_rx_version (interface_t *ifp, int ri_version);

/*************************
 Function:ripd_api_get_if_rx_version
 PURPOSE: Get interface's receive RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    OUT   int* ri_version - pointer for result
**************************/
int
ripd_api_get_if_rx_version (interface_t *ifp, int *ri_version);

/*************************
 Function:ripd_api_set_if_tx_version
 PURPOSE: Set interface's send RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int ri_version - RIP accepet/announce method
**************************/
int
ripd_api_set_if_tx_version (interface_t *ifp, int ri_version);

/*************************
 Function:ripd_api_get_if_tx_version
 PURPOSE: Get interface's send RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    OUT   int* ri_version - pointer for result
**************************/
int
ripd_api_get_if_tx_version (interface_t *ifp, int *ri_version);

/*************************
 Function:ripd_api_set_if_authentication_type
 PURPOSE: Set RIP authentication type
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int  auth_type - RIPv2 authentication type
                            (from {RIP_NO_AUTH,
                                   RIP_AUTH_SIMPLE_PASSWORD,
                                   RIP_AUTH_MD5})
**************************/
int
ripd_api_set_if_authentication_type (interface_t *ifp, int auth_type);

/*************************
 Function:ripd_api_set_if_authentication_string
 PURPOSE: RIP authentication string setting
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    char* auth_str - RIP authentication string;
                           if auth_str==NULL, authentication string is disabled
**************************/
int
ripd_api_set_if_authentication_string (interface_t *ifp, char *auth_str);

/*************************
 Function:ripd_api_get_if_authentication_string
 PURPOSE: GET RIP authentication string
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int buffer_size - size of the buffer for the result
    OUT   char* auth_str - pointer to buffer for result (actual length
                           may be counted as its 'strlen')
    OUT   int*  auth_type - RIPv2 authentication type
                            (from {RIP_NO_AUTH,
                                   RIP_AUTH_SIMPLE_PASSWORD,
                                   RIP_AUTH_MD5})
**************************/
int
ripd_api_get_if_authentication_string (interface_t *ifp,
                                       int buffer_size,
                                       char *auth_str,
                                       int *auth_type);

/*************************
 Function:ripd_api_set_if_split_horizon
 PURPOSE: Set interface's send RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int new_split_mode_value
**************************/
int
ripd_api_set_if_split_horizon (interface_t *ifp, int new_split_mode_value);

/*************************
 Function:ripd_api_get_if_split_horizon
 PURPOSE: Set interface's send RIP version control
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    OUT   int* current_split_mode_value
**************************/
int
ripd_api_get_if_split_horizon (interface_t *ifp, int* current_split_mode_value);

/*************************
 Function:ripd_api_set_if_description
 PURPOSE: Set/Delete interface description
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    char *description (if NULL => delete)
**************************/
int 
ripd_api_set_if_description (interface_t *ifp, char *description);

/*************************
 Function:ripd_api_get_if_description
 PURPOSE: Get interface description
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    IN    int max_buffsize
    OUT   char *description
**************************/
int
ripd_api_get_if_description (interface_t *ifp, int max_buffsize, char *description);

/*************************
 Function:ipd_api_get_if_statistics
 PURPOSE: Get RIPD interface statistics
 PARAMETERS:
    IN    interface_t* ifp - inteface to be configured
    OUT   u_long *recv_badpackets
    OUT   u_long *recv_badroutes
    OUT   u_long *sent_updates
**************************/
int 
ripd_api_get_if_statistics (interface_t *ifp,
                            u_long *recv_badpackets,
                            u_long *recv_badroutes,
                            u_long *sent_updates);

/*
 * These functions are an addition to lib/if.c and may be used as API
 */
/*************************
 Function:if_get_next_node
 PURPOSE: Get the node after the current one ('prev_node') in the
          'iflist' linked list.
          If the 'prev_node' is NULL, get the fist node.
          If "End of table" is a case, returns NULL
 PARAMETERS:
    IN    prev_node
**************************/
listnode
if_get_next_node (listnode prev_node);

/*************************
 Function:if_lookup_next (was rip_if_lookup_next in rip_snmp.c)
 PURPOSE: Lookup next interface by IPv4 address.
 PARAMETERS:
    INOUT    in_addr *src
    OUT	     in_addr *dst
    RETURNS: interface *ifp (of NULL in "End of table" case)
 NOTE: it was moved from rip_snmp.c, old name was rip_if_lookup_next
**************************/
interface_t *
if_lookup_next (struct in_addr *src, struct in_addr *dst);

/*************************
 Function:if_get_next_connected
 PURPOSE: Lookup next interface/connected 
 PARAMETERS:
    IN    listnode prev_connected_node
    IN    listnode prev_ifp_node
    OUT   listnode* next_ifp_node
    RETURNS: listnode 'next_connected_node' (of NULL in "End of table" case)
**************************/
listnode
if_get_next_connected (listnode prev_connected_node,
                       listnode prev_ifp_node,
                       listnode* next_ifp_node);

/*
 * Functions from /lib/if.c, usable as API, take prototypes from lib/if.h
 */
#include "lib/if.h"

/*
 * Functions from lib/routemap.c, usable as API
 */
#include "lib/routemap.h"

#endif /* _RIPD_API_H_ */
