#include <zebra.h>
#include "command.h"
#include "vtysh.h"

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_seq_ge_cmd_vtysh, 
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_OSPF6D, no_debug_ospf6_cmd_vtysh, 
       "no debug ospf6 " OSPF6_DUMP_TYPE_LIST, 
       NO_STR
       "Debugging information\n"
       OSPF6_STR
       )

DEFSH (VTYSH_BGPD, no_neighbor_router_id_cmd_vtysh, 
       NO_NEIGHBOR_CMD "router-id A.B.C.D", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set neighbor's special router-id value\n"
       "IP address\n")

DEFSH (VTYSH_ZEBRA, show_ipv6_forwarding_cmd_vtysh, 
       "show ipv6 forwarding", 
       SHOW_STR
       "IPv6 information\n"
       "Forwarding status\n")

DEFSH (VTYSH_RIPD, rip_neighbor_cmd_vtysh, 
       "neighbor A.B.C.D", 
       "Specify a neighbor router\n"
       "Neighbor address\n")

DEFSH (VTYSH_BGPD, neighbor_interface_cmd_vtysh, 
       NEIGHBOR_CMD "interface WORD", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_bgp_network_cmd_vtysh, 
       "no network A.B.C.D/M", 
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_OSPFD, ospf_distance_source_access_list_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M WORD", 
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_cmd_vtysh, 
       "ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")

DEFSH (VTYSH_OSPF6D, redistribute_ospf6_cmd_vtysh, 
       "redistribute ospf6", 
       "Redistribute control\n"
       "OSPF6 route\n")

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_connected_cmd_vtysh, 
       "no redistribute connected", 
       NO_STR
       "Redistribute control\n"
       "Connected route\n")

DEFSH (VTYSH_OSPFD, no_area_vlink_decimal_cmd_vtysh, 
       "no area <0-4294967295> virtual-link A.B.C.D", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFSH (VTYSH_ZEBRA, ip_route_cmd_vtysh, 
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE)", 
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_access_list_remark_cmd_vtysh, 
       "no access-list WORD remark", 
       NO_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n")

DEFSH (VTYSH_RIPNGD, show_debugging_ripng_cmd_vtysh, 
       "show debugging ripng", 
       SHOW_STR
       "RIPng configuration\n"
       "Debugging information\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_type_metric_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214> route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, ipv6_mbgp_neighbor_advertised_route_cmd_vtysh, 
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) advertised-routes", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_events_cmd_vtysh, 
       "no debug bgp events", 
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP events\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, ipv6_access_list_remark_cmd_vtysh, 
       "ipv6 access-list WORD remark .LINE", 
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

DEFSH (VTYSH_OSPFD, area_range_decimal_cmd_vtysh, 
       "area <0-4294967295> range A.B.C.D/M", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFSH (VTYSH_RIPD, ip_rip_authentication_string_cmd_vtysh, 
       "ip rip authentication string LINE", 
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")

DEFSH (VTYSH_OSPF6D, show_debugging_ospf6_cmd_vtysh, 
       "show debugging ospf6", 
       SHOW_STR
       "Debugging infomation\n"
       OSPF6_STR)

DEFSH (VTYSH_BGPD, neighbor_nexthop_self_cmd_vtysh, 
       NEIGHBOR_CMD "next-hop-self", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Disable the next hop calculation for this neighbor\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community_list_exact_cmd_vtysh, 
       "show ipv6 mbgp community-list WORD exact-match", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_shutdown_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) shutdown", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Administratively shut down this neighbor\n")

DEFSH (VTYSH_RIPD, no_rip_distance_source_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M", 
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_rip_routemap_cmd_vtysh, 
       "redistribute rip route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_neighbor_timers_connect_cmd_vtysh, 
       NO_NEIGHBOR_CMD "timers connect [TIMER]", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

DEFSH (VTYSH_BGPD, dump_bgp_all_cmd_vtysh, 
       "dump bgp all PATH", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n"
       "Output filename\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ip_prefix_list_cmd_vtysh, 
       "clear ip prefix-list", 
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR)

DEFSH (VTYSH_RIPD, no_key_chain_cmd_vtysh, 
       "no key chain WORD", 
       NO_STR
       "Authentication key management\n"
       "Key-chain management\n"
       "Key-chain name\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_default_originate_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) default-originate", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Originate default route to this neighbor\n")

DEFSH (VTYSH_OSPFD, ospf_hello_interval_cmd_vtysh, 
       "ospf hello-interval <1-65535>", 
       "OSPF interface commands\n"
       "Time between HELLO packets\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, no_bgp_enforce_first_as_cmd_vtysh, 
       "no bgp enforce-first-as", 
       NO_STR
       "BGP specific commands\n"
       "Enforce the first AS for EBGP routes\n")

DEFSH (VTYSH_ZEBRA, show_interface_cmd_vtysh, 
       "show interface [IFNAME]",   
       SHOW_STR
       "Interface status and configuration\n"
       "Inteface name\n")

DEFSH (VTYSH_BGPD, no_bgp_network_multicast_cmd_vtysh, 
       "no network A.B.C.D/M nlri multicast", 
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_OSPFD, auto_cost_reference_bandwidth_cmd_vtysh, 
       "auto-cost reference-bandwidth <1-4294967>", 
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")

DEFSH (VTYSH_RIPD, rip_network_cmd_vtysh, 
       "network (A.B.C.D/M|WORD)", 
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Interface name\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, rmap_onmatch_next_cmd_vtysh, 
       "on-match next", 
       "Exit policy on matches\n"
       "Next clause\n")

DEFSH (VTYSH_BGPD, no_set_nlri_val_cmd_vtysh, 
       "no set nlri (multicast|unicast)", 
       NO_STR
       SET_STR
       "Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_transparent_nexthop_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-nexthop", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not change nexthop even peer is EBGP peer\n")

DEFSH (VTYSH_BGPD, no_bgp_bestpath_med_cmd_vtysh, 
       "no bgp bestpath med (confed|missing-as-worst)", 
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")

DEFSH (VTYSH_BGPD, debug_bgp_filter_cmd_vtysh, 
       "debug bgp filters", 
       DEBUG_STR
       BGP_STR
       "BGP filters\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_ospf_cmd_vtysh, 
       "redistribute ospf", 
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_description_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) description", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor specific description\n")

DEFSH (VTYSH_BGPD, no_ip_community_list_all_cmd_vtysh, 
       "no ip community-list WORD", 
       NO_STR
       IP_STR
       "Add a community list entry\n"
       "Community list name\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_out_cmd_vtysh, 
       "clear ipv6 bgp <1-65535> out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, neighbor_cmd_vtysh, 
       "neighbor A.B.C.D", 
       NEIGHBOR_STR
       "Neighbor IP address\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_detail_cmd_vtysh, 
       "show ip ospf neighbor detail", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "detail of all neighbors\n")

DEFSH (VTYSH_OSPF6D, no_ospf6_redistribute_connected_cmd_vtysh, 
       "no redistribute connected", 
       NO_STR
       "Redistribute\n"
       "Connected route\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_vpnv4_all_route_cmd_vtysh, 
       "show ip bgp vpnv4 all A.B.C.D", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_static_cmd_vtysh, 
       "redistribute static", 
       "Redistribute information from another routing protocol\n"
       "Static routes\n")

DEFSH (VTYSH_RIPD, rip_distance_cmd_vtysh, 
       "distance <1-255>", 
       "Administrative distance\n"
       "Distance value\n")

DEFSH (VTYSH_BGPD, neighbor_router_id_cmd_vtysh, 
       NEIGHBOR_CMD "router-id A.B.C.D", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set neighbor's special router-id value\n"
       "IP address\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_route_pref_cmd_vtysh, 
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_neighbors_peer_cmd_vtysh, 
       "show ip bgp neighbors (A.B.C.D|X:X::X:X)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFSH (VTYSH_ZEBRA, config_table_cmd_vtysh, 
       "table TABLENO", 
       "Configure target kernel routing table\n"
       "TABLE integer\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_routemap_cmd_vtysh, 
       "default-information originate always route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_sequence_number_cmd_vtysh, 
       "ip prefix-list sequence-number", 
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")

DEFSH (VTYSH_RIPD, debug_rip_packet_direct_cmd_vtysh, 
       "debug rip packet (recv|send)", 
       DEBUG_STR
       RIP_STR
       "RIP packet\n"
       "RIP receive packet\n"
       "RIP send packet\n")

DEFSH (VTYSH_OSPFD, area_default_cost_decimal_cmd_vtysh, 
       "area <0-4294967295> default-cost NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

DEFSH (VTYSH_BGPD, bgp_router_id_cmd_vtysh, 
       "bgp router-id A.B.C.D", 
       "BGP specific commands\n"
       "Override configured router identifier\n"
       "Manually configured router identifier\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_ipv6_access_list_remark_arg_cmd_vtysh, 
       "no ipv6 access-list WORD remark .LINE", 
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_access_list_cmd_vtysh, 
       "no access-list WORD (deny|permit) (A.B.C.D/M|any)", 
       NO_STR 
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Any prefix to match\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_filter_list_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) filter-list WORD (in|out)", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")

DEFSH (VTYSH_OSPFD, area_vlink_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFSH (VTYSH_BGPD, neighbor_capability_route_refresh_cmd_vtysh, 
       NEIGHBOR_CMD "capability route-refresh", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Outbound capability configuration\n"
       "Advertise route-refresh capability to this neighbor\n")

DEFSH (VTYSH_OSPFD, no_refresh_timer_cmd_vtysh, 
       "no refresh timer", 
       "Adjust refresh parameters\n"
       "Unset refresh timer\n")

DEFSH (VTYSH_OSPFD, area_vlink_auth_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D authentication-key AUTH_KEY", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_RIPD, no_ip_rip_send_version_cmd_vtysh, 
       "no ip rip send version", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, access_list_remark_cmd_vtysh, 
       "access-list WORD remark .LINE", 
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

DEFSH (VTYSH_OSPFD, area_import_list_cmd_vtysh, 
       "area A.B.C.D import-list NAME", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")

DEFSH (VTYSH_BGPD, no_router_bgp_view_cmd_vtysh, 
       "no router bgp <1-65535> view WORD", 
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_seq_ge_le_cmd_vtysh, 
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_connected_routemap_cmd_vtysh, 
       "ipv6 bgp redistribute connected route-map WORD", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_weight_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) weight <0-65535>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

DEFSH (VTYSH_ZEBRA, ipv6_nd_send_ra_cmd_vtysh, 
       "ipv6 nd send-ra", 
       IP_STR
       "Neighbor discovery\n"
       "Send router advertisement\n")

DEFSH (VTYSH_BGPD, no_neighbor_prefix_list_cmd_vtysh, 
       NO_NEIGHBOR_CMD "prefix-list WORD (in|out)", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_neighbors_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) neighbors", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_soft_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_match_address_prefixlist_cmd_vtysh, 
       "match ipv6 address prefix-list WORD", 
       "Match values\n"
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IPv6 prefix-list name\n")

DEFSH (VTYSH_BGPD, bgp_confederation_peers_cmd_vtysh, 
       "bgp confederation peers .<1-65535>", 
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_type_advrtr_cmd_vtysh, 
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external) advrtr A.B.C.D", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       "Specify Advertising Router\n"
       "Advertising Router ID\n"
       )

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_le_ge_cmd_vtysh, 
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_soft_cmd_vtysh, 
       "clear ip bgp A.B.C.D soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n")

DEFSH (VTYSH_OSPFD, no_area_default_cost_decimal_cmd_vtysh, 
       "no area <0-4294967295> default-cost NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

DEFSH (VTYSH_OSPFD, debug_ospf_event_cmd_vtysh, 
       "debug ospf event", 
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")

DEFSH (VTYSH_OSPFD, no_ospf_retransmit_interval_cmd_vtysh, 
       "no ospf retransmit-interval", 
       NO_STR
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_vpnv4_soft_cmd_vtysh, 
       "clear ip bgp <1-65535> vpnv4 unicast soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_vpnv4_all_cmd_vtysh, 
       "show ip bgp vpnv4 all", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n")

DEFSH (VTYSH_OSPFD, area_stub_nosum_cmd_vtysh, 
       "area A.B.C.D stub no-summary", 
       "OSPF stub parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_neighbors_peer_cmd_vtysh, 
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X)", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFSH (VTYSH_OSPFD, neighbor_pollinterval_cmd_vtysh, 
       "neighbor A.B.C.D poll-interval <1-65535>", 
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

DEFSH (VTYSH_RIPD, rip_redistribute_rip_cmd_vtysh, 
       "redistribute rip", 
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa no-summary", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

DEFSH (VTYSH_BGPD, no_set_origin_cmd_vtysh, 
       "no set origin", 
       NO_STR
       SET_STR
       "BGP origin code\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_list_cmd_vtysh, 
       "show ip bgp community-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, rmap_onmatch_goto_cmd_vtysh, 
       "on-match goto <1-65535>", 
       "Exit policy on matches\n"
       "Goto Clause number\n"
       "Number\n")

DEFSH (VTYSH_OSPFD, ip_ospf_priority_cmd_vtysh, 
       "ip ospf priority <0-255>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Router priority\n"
       "Priority\n")

DEFSH (VTYSH_OSPFD, debug_ospf_nssa_cmd_vtysh, 
       "debug ospf nssa", 
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")

DEFSH (VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD, router_zebra_cmd_vtysh, 
       "router zebra", 
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community3_exact_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_summary_cmd_vtysh, 
       "show ipv6 mbgp summary", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Summary of BGP neighbor status\n")

DEFSH (VTYSH_OSPFD, ospf_transmit_delay_cmd_vtysh, 
       "ospf transmit-delay <1-65535>", 
       "OSPF interface commands\n"
       "Link state transmit delay\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_kernel_routemap_cmd_vtysh, 
       "redistribute kernel route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, no_ospf_distance_source_access_list_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M WORD", 
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_OSPFD, ip_ospf_message_digest_key_cmd_vtysh, 
       "ip ospf message-digest-key <1-255> md5 KEY", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, area_nssa_t_always_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa translate-always", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR to always translate\n")

DEFSH (VTYSH_OSPFD, no_area_export_list_decimal_cmd_vtysh, 
       "no area <0-4294967295> export-list NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_OSPFD, no_ospf_distribute_list_out_cmd_vtysh, 
       "no distribute-list WORD out (kernel|connected|static|rip|bgp)", 
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_ZEBRA, no_ip_forwarding_cmd_vtysh, 
       "no ip forwarding", 
       NO_STR
       IP_STR
       "Turn off IP forwarding")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_description_val_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) description .LINE", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

DEFSH (VTYSH_BGPD, no_set_vpnv4_nexthop_val_cmd_vtysh, 
       "no set vpnv4 next-hop A.B.C.D", 
       NO_STR
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n"
       "IP address of next hop\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_soft_out_cmd_vtysh, 
       "clear ipv6 bgp * soft out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_kernel_cmd_vtysh, 
       "redistribute kernel", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd_vtysh, 
       "show ipv6 ospf6 neighbor IFNAME NBR_ID detail", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       "A.B.C.D OSPF6 neighbor Router ID in IP address format\n"
       "detailed infomation\n"
       )

DEFSH (VTYSH_OSPFD, network_area_decimal_cmd_vtysh, 
       "network A.B.C.D/M area <0-4294967295>", 
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")

DEFSH (VTYSH_BGPD, no_bgp_default_ipv4_unicast_cmd_vtysh, 
       "no bgp default ipv4-unicast", 
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")

DEFSH (VTYSH_BGPD, ipv4_neighbor_routes_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFSH (VTYSH_BGPD, neighbor_transparent_as_cmd_vtysh, 
       NEIGHBOR_CMD "transparent-as", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not append my AS number even peer is EBGP peer\n")

DEFSH (VTYSH_OSPFD, ospf_distance_source_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M", 
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")

DEFSH (VTYSH_ZEBRA, ipv6_route_cmd_vtysh, 
       "ipv6 route X:X::X:X/M X:X::X:X", 
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "Destination IP Address\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_ebgp_multihop_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_inter_intra_cmd_vtysh, 
       "distance ospf inter-area <1-255> intra-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community_list_cmd_vtysh, 
       "show ipv6 bgp community-list WORD", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")

DEFSH (VTYSH_OSPFD, area_vlink_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFSH (VTYSH_BGPD, neighbor_peer_group_remote_as_cmd_vtysh, 
       "neighbor WORD remote-as <1-65535>", 
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Specify a BGP neighbor\n"
       "AS of remote neighbor\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_le_ge_cmd_vtysh, 
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, undebug_bgp_update_cmd_vtysh, 
       "undebug bgp updates", 
       UNDEBUG_STR
       BGP_STR
       "BGP updates\n")

DEFSH (VTYSH_BGPD, bgp_damp_set_cmd_vtysh, 
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>", 
       "Define dampening parameters\n"
       "BGP Specific commands\n"
       "Half-life time in minutes\n"
       "Reuse value\n"
       "Suppress value\n"
	   "Maximum suppress time in minutes\n")

DEFSH (VTYSH_BGPD, dump_bgp_updates_interval_cmd_vtysh, 
       "dump bgp updates PATH INTERVAL", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n"
       "Output filename\n"
       "Interval of output\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_set_ip_nexthop_val_cmd_vtysh, 
       "no set ip next-hop A.B.C.D", 
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")

DEFSH (VTYSH_OSPFD, no_ospf_abr_type_cmd_vtysh, 
       "no ospf abr-type (cisco|ibm|shortcut)", 
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR,  cisco implementation\n"
       "Alternative ABR,  IBM implementation\n"
       "Shortcut ABR\n")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_hellointerval_cmd_vtysh, 
       "ipv6 ospf6 hello-interval HELLO_INTERVAL", 
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR
       )

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, match_ip_address_cmd_vtysh, 
       "match ip address WORD", 
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_ospf6_routemap_cmd_vtysh, 
       "ipv6 bgp redistribute ospf6 route-map WORD", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Open Shortest Path First (OSPFv3)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_neighbor_route_server_client_cmd_vtysh, 
       NO_NEIGHBOR_CMD "route-server-client", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Server client\n")

DEFSH (VTYSH_RIPD, no_rip_version_val_cmd_vtysh, 
       "no version <1-2>", 
       NO_STR
       "Set routing protocol version\n"
       "version\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_lsid_cmd_vtysh, 
       "show ipv6 ospf6 database lsid <0-4294967295>", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Specify Link State ID\n"
       "Link State ID\n"
       )

DEFSH (VTYSH_RIPD, rip_distance_source_access_list_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M WORD", 
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_vpnv4_all_summary_cmd_vtysh, 
       "show ip bgp vpnv4 all summary", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Summary of BGP neighbor status\n")

DEFSH (VTYSH_RIPNGD, ripng_timers_cmd_vtysh, 
       "timers basic <update> <timeout> <garbage>", 
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_regexp_cmd_vtysh, 
       "show ipv6 mbgp regexp .LINE", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")

DEFSH (VTYSH_OSPF6D, debug_ospf6_cmd_vtysh, 
       "debug ospf6 " OSPF6_DUMP_TYPE_LIST, 
       "Debugging information\n"
       OSPF6_STR
       )

DEFSH (VTYSH_BGPD, bgp_bestpath_aspath_ignore_cmd_vtysh, 
       "bgp bestpath as-path ignore", 
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_send_community_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_neighbor_route_reflector_client_cmd_vtysh, 
       NO_NEIGHBOR_CMD "route-reflector-client", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Reflector client\n")

DEFSH (VTYSH_OSPFD, area_authentication_message_digest_cmd_vtysh, 
       "area A.B.C.D authentication message-digest", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_timers_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers <0-65535> <0-65535>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

DEFSH (VTYSH_BGPD, no_set_aggregator_as_val_cmd_vtysh, 
       "no set aggregator as <1-65535> A.B.C.D", 
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_filter_cmd_vtysh, 
       "no debug bgp filters", 
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP filters\n")

DEFSH (VTYSH_BGPD, bgp_network_cmd_vtysh, 
       "network A.B.C.D/M", 
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community_list_exact_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community-list WORD exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")

DEFSH (VTYSH_BGPD, no_vpnv4_activate_cmd_vtysh, 
       "no neighbor A.B.C.D activate", 
       NO_STR
       NEIGHBOR_STR
       "Neighbor address\n"
       "Enable the Address Family for this Neighbor\n")

DEFSH (VTYSH_BGPD, no_set_community_cmd_vtysh, 
       "no set community", 
       NO_STR
       SET_STR
       "BGP community attribute\n")

DEFSH (VTYSH_ZEBRA, ip_tunnel_cmd_vtysh, 
       "ip tunnel IP_address IP_address", 
       "KAME ip tunneling configuration commands\n"
       "Set FROM IP address and TO IP address\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_always_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa no-summary translate-always", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  always translate\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_no_set_forwarding_cmd_vtysh, 
       "no set forwarding-address X:X::X:X", 
       NO_STR
       "Set value\n"
       "Forwarding Address\n"
       "IPv6 Address\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_ge_cmd_vtysh, 
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, no_set_community_additive_cmd_vtysh, 
       "no set community-additive", 
       NO_STR
       SET_STR
       "BGP community attribute (Add to the existing community)\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_attr_info_cmd_vtysh, 
       "show ip bgp attribute-info", 
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_seq_le_cmd_vtysh, 
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_le_cmd_vtysh, 
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_ripng_routemap_cmd_vtysh, 
       "ipv6 bgp redistribute ripng route-map WORD", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Routing Information Protocol (RIPng)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, no_ospf_default_information_originate_cmd_vtysh, 
       "no default-information originate", 
       NO_STR
       "Control distribution of default information\n"
       "Distribute a default route\n")

DEFSH (VTYSH_BGPD, no_bgp_bestpath_compare_router_id_cmd_vtysh, 
       "no bgp bestpath compare-routerid", 
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_ospf_cmd_vtysh, 
       "redistribute ospf", 
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_network_cmd_vtysh, 
       "ipv6 bgp network X:X::X:X/M", 
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop <1-255>", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_route_server_client_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-server-client", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Server client\n")

DEFSH (VTYSH_OSPFD, no_area_import_list_cmd_vtysh, 
       "no area A.B.C.D import-list NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_ZEBRA, no_ip_tunnel_cmd_vtysh, 
       "no ip tunnel", 
       NO_STR
       "Set FROM IP address and TO IP address\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_route_cmd_vtysh, 
       "show ipv6 bgp X:X::X:X", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")

DEFSH (VTYSH_ZEBRA, no_ip_route_mask_cmd_vtysh, 
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_transmitdelay_cmd_vtysh, 
       "ipv6 ospf6 transmit-delay TRANSMITDELAY", 
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR
       )

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_type_cmd_vtysh, 
       "default-information originate always metric-type (1|2)", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_static_cmd_vtysh, 
       "no ipv6 bgp redistribute static", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_type_metric_cmd_vtysh, 
       "default-information originate always metric-type (1|2) metric <0-16777214>", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "OSPF default metric\n"
       "OSPF metric\n")

DEFSH (VTYSH_OSPFD, area_vlink_auth_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D authentication-key AUTH_KEY", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, no_debug_ospf_event_cmd_vtysh, 
       "no debug ospf event", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")

DEFSH (VTYSH_BGPD, no_vpnv4_network_cmd_vtysh, 
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD", 
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_seq_le_cmd_vtysh, 
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_regexp_cmd_vtysh, 
       "show ipv6 bgp regexp .LINE", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFSH (VTYSH_BGPD, bgp_damp_unset_cmd_vtysh, 
       "no bgp dampening", 
       "Turn off dampening\n"
       "BGP Specific commands\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_spf_tree_cmd_vtysh, 
       "show ipv6 ospf6 spf tree", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Displays spf tree\n")

DEFSH (VTYSH_ZEBRA, no_debug_zebra_packet_cmd_vtysh, 
       "no debug zebra packet", 
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_priority_cmd_vtysh, 
       "no ip ospf priority", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Router priority\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_ipv6_access_list_remark_cmd_vtysh, 
       "no ipv6 access-list WORD remark", 
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n")

DEFSH (VTYSH_BGPD, neighbor_weight_cmd_vtysh, 
       NEIGHBOR_CMD "weight <0-65535>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_kernel_routemap_cmd_vtysh, 
       "no redistribute kernel route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_prefix_cmd_vtysh, 
       "show ipv6 mbgp X:X::X:X/M", 
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_BGPD, bgp_confederation_identifier_cmd_vtysh, 
       "bgp confederation identifier <1-65535>", 
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")

DEFSH (VTYSH_OSPFD, no_ospf_default_metric_cmd_vtysh, 
       "no default-metric", 
       NO_STR
       "Set metric of redistributed routes\n")

DEFSH (VTYSH_ZEBRA, ipv6_nd_prefix_advertisement_cmd_vtysh, 
       "ipv6 nd prefix-advertisement IPV6PREFIX", 
       IP_STR
       "Neighbor discovery\n"
       "Router advertisement\n"
       "IPv6 prefix\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_route_map_all_cmd_vtysh, 
       "no route-map WORD", 
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_cmd_vtysh, 
       "show ip prefix-list", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR)

DEFSH (VTYSH_RIPD, no_ip_rip_receive_version_cmd_vtysh, 
       "no ip rip receive version", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_type_cmd_vtysh, 
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external)", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       )

DEFSH (VTYSH_ZEBRA, show_ip_route_cmd_vtysh, 
       "show ip route", 
       SHOW_STR
       IP_STR
       "IP routing table\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_ge_le_cmd_vtysh, 
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, access_list_cmd_vtysh, 
       "access-list WORD (deny|permit) (A.B.C.D/M|any)", 
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Any prefix to match\n")

DEFSH (VTYSH_BGPD, no_match_community_cmd_vtysh, 
       "no match community WORD", 
       NO_STR
       MATCH_STR
       "Match BGP community list\n"
       "Community-list name (not community value itself)\n")

DEFSH (VTYSH_BGPD, neighbor_override_capability_cmd_vtysh, 
       NEIGHBOR_CMD "override-capability", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Override capability negotiation result\n")

DEFSH (VTYSH_OSPFD, set_metric_type_cmd_vtysh, 
       "set metric-type (1|2)", 
       SET_STR
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_authentication_key_cmd_vtysh, 
       "no ip ospf authentication-key", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Authentication password (key)\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_kernel_routemap_cmd_vtysh, 
       "no ipv6 bgp redistribute kernel route-map WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_vpnv4_soft_out_cmd_vtysh, 
       "clear ip bgp * vpnv4 unicast soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_never_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa no-summary translate-never", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  nor translation\n")

DEFSH (VTYSH_BGPD, no_bgp_distance_cmd_vtysh, 
       "no distance bgp <1-255> <1-255> <1-255>", 
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")

DEFSH (VTYSH_BGPD, neighbor_update_source_cmd_vtysh, 
       NEIGHBOR_CMD "update-source WORD", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Source of routing updates\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_set_local_pref_val_cmd_vtysh, 
       "no set local-preference <0-4294967295>", 
       NO_STR
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_cmd_vtysh, 
       "default-information originate", 
       "Control distribution of default information\n"
       "Distribute a default route\n")

DEFSH (VTYSH_ZEBRA, debug_zebra_packet_detail_cmd_vtysh, 
       "debug zebra packet (recv|send) detail", 
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n"
       "Debug option set detaied information\n")

DEFSH (VTYSH_BGPD, bgp_always_compare_med_cmd_vtysh, 
       "bgp always-compare-med", 
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_out_cmd_vtysh, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor address to clear\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, bgp_cluster_id_cmd_vtysh, 
       "bgp cluster-id A.B.C.D", 
       "BGP specific commands\n"
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_match_ip_address_cmd_vtysh, 
       "no match ip address WORD", 
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list name\n")

DEFSH (VTYSH_RIPD, no_rip_redistribute_type_routemap_cmd_vtysh, 
       "no redistribute (kernel|connected|static|ospf|bgp) route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, dump_bgp_all_interval_cmd_vtysh, 
       "dump bgp all PATH INTERVAL", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n"
       "Output filename\n"
       "Interval of output\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_prefix_first_match_cmd_vtysh, 
       "show ipv6 prefix-list WORD X:X::X:X/M first-match", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "First matched prefix\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_kernel_cmd_vtysh, 
       "no ipv6 bgp redistribute kernel", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_BGPD, dump_bgp_routes_cmd_vtysh, 
       "dump bgp routes-mrt PATH", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n"
       "Output filename\n")

DEFSH (VTYSH_OSPFD, ospf_cost_cmd_vtysh, 
       "ospf cost <1-65535>", 
       "OSPF interface commands\n"
       "Interface cost\n"
       "Cost")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_seq_cmd_vtysh, 
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, ipv6_access_list_cmd_vtysh, 
       "ipv6 access-list WORD (deny|permit) (X:X::X:X/M|any)", 
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Any prefixi to match\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_static_cmd_vtysh, 
       "no redistribute static", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n")

DEFSH (VTYSH_BGPD, no_match_ipv6_next_hop_cmd_vtysh, 
       "no match ipv6 next-hop X:X::X:X", 
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_type_metric_routemap_cmd_vtysh, 
       "default-information originate metric-type (1|2) metric <0-16777214> route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_send_community_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_vpnv4_all_tags_cmd_vtysh, 
       "show ip bgp vpnv4 all tags", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Display BGP tags for prefixes\n")

DEFSH (VTYSH_BGPD, debug_bgp_keepalive_cmd_vtysh, 
       "debug bgp keepalives", 
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_network_cmd_vtysh, 
       "no ip ospf network", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Network type\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_static_routemap_cmd_vtysh, 
       "redistribute static route-map WORD", 
       "Redistribute\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD, show_debugging_rip_cmd_vtysh, 
       "show debugging rip", 
       SHOW_STR
       DEBUG_STR
       RIP_STR)

DEFSH (VTYSH_BGPD, show_ip_bgp_community3_exact_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, no_ospf_network_cmd_vtysh, 
       "no ospf network", 
       NO_STR
       "OSPF interface commands\n"
       "Network type\n")

DEFSH (VTYSH_RIPD, no_debug_rip_packet_direct_cmd_vtysh, 
       "no debug rip packet (recv|send)", 
       NO_STR
       DEBUG_STR
       RIP_STR
       "RIP packet\n"
       "RIP option set for receive packet\n"
       "RIP option set for send packet\n")

DEFSH (VTYSH_ZEBRA, show_debugging_zebra_cmd_vtysh, 
       "show debugging zebra", 
       SHOW_STR
       "Zebra configuration\n"
       "Debugging information\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_border_routers_cmd_vtysh, 
       "show ip ospf border-routers", 
       SHOW_STR
       IP_STR
       "show all the ABR's and ASBR's\n"
       "for this area\n")

DEFSH (VTYSH_ZEBRA, no_zebra_interface_cmd_vtysh, 
       "no interface IFNAME", 
       "Delete a pseudo interface's configuration\n"
       "Interface's name\n")

DEFSH (VTYSH_OSPF6D, set_proctitle_cmd_vtysh, 
       "set proctitle (version|normal|none)", 
       "Set command\n"
       "Process title\n"
       "Version information\n"
       "Normal command-line options\n"
       "Just program name\n"
       )

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_advertised_route_cmd_vtysh, 
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_type_advrtr_lsid_cmd_vtysh, 
       "show ipv6 ospf6 database (router|network|intra-prefix|link|as-external) advrtr A.B.C.D lsid <0-4294967295>", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Router-LSAs\n"
       "Network-LSAs\n"
       "Intra-Area-Prefix-LSAs\n"
       "Link-LSAs\n"
       "AS-External-LSAs\n"
       "Specify Advertising Router\n"
       "Advertising Router ID\n"
       "Specify Link State ID\n"
       "Link State ID\n"
       )

DEFSH (VTYSH_BGPD, show_ipv6_bgp_prefix_cmd_vtysh, 
       "show ipv6 bgp X:X::X:X/M", 
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_OSPFD, no_ospf_cost_cmd_vtysh, 
       "no ospf cost", 
       NO_STR
       "OSPF interface commands\n"
       "Interface cost\n")

DEFSH (VTYSH_BGPD, redistribute_bgp_cmd_vtysh, 
       "redistribute bgp", 
       "Redistribute control\n"
       "BGP route\n")

DEFSH (VTYSH_OSPFD, no_area_shortcut_cmd_vtysh, 
       "no area A.B.C.D shortcut (enable|disable)", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Deconfigure the area's shortcutting mode\n"
       "Deconfigure enabled shortcutting through the area\n"
       "Deconfigure disabled shortcutting through the area\n")

DEFSH (VTYSH_ZEBRA, debug_zebra_packet_cmd_vtysh, 
       "debug zebra packet", 
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n")

DEFSH (VTYSH_BGPD, no_bgp_confederation_peers_cmd_vtysh, 
       "no bgp confederation peers .<1-65535>", 
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)

DEFSH (VTYSH_BGPD, bgp_enforce_first_as_cmd_vtysh, 
       "bgp enforce-first-as", 
       "BGP specific commands\n"
       "Enforce the first AS for EBGP routes\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_zebra_sub_cmd_vtysh, 
       "no debug ospf zebra (interface|redistribute)", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")

DEFSH (VTYSH_BGPD, no_neighbor_translate_update_cmd_vtysh, 
       NO_NEIGHBOR_CMD "translate-update", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_key_chain2_cmd_vtysh, 
       "no ip rip authentication key-chain LINE", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")

DEFSH (VTYSH_BGPD, no_bgp_distance_source_access_list_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M WORD", 
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_cmd_vtysh, 
       "no ip prefix-list WORD", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_summary_cmd_vtysh, 
       "show ip bgp summary", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n")

DEFSH (VTYSH_BGPD, neighbor_timers_cmd_vtysh, 
       NEIGHBOR_CMD "timers <0-65535> <0-65535>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_network_cmd_vtysh, 
       "no ipv6 bgp network X:X::X:X/M", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_description_cmd_vtysh, 
       "ip prefix-list WORD description .LINE", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_seq_le_ge_cmd_vtysh, 
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_OSPFD, no_area_nssa_nosum_decimal_cmd_vtysh, 
       "no area <0-4294967295> nssa no-summary", 
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_name_seq_cmd_vtysh, 
       "show ip prefix-list WORD seq <1-4294967295>", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_filter_list_cmd_vtysh, 
       "show ipv6 mbgp filter-list WORD", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFSH (VTYSH_BGPD, aggregate_address_cmd_vtysh, 
       "aggregate-address A.B.C.D/M", 
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_match_metric_cmd_vtysh, 
       "no match metric <0-4294967295>", 
       NO_STR
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_cmd_vtysh, 
       "ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_cmd_vtysh, 
       "clear ip bgp *", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n")

DEFSH (VTYSH_BGPD, ip_as_path_cmd_vtysh, 
       "ip as-path access-list WORD (deny|permit) .LINE", 
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A regular-expression to match the BGP AS paths\n")

DEFSH (VTYSH_OSPFD, no_ospf_redistribute_source_cmd_vtysh, 
       "no redistribute (kernel|connected|static|rip|bgp)", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_BGPD, set_nlri_cmd_vtysh, 
       "set nlri (multicast|unicast)", 
       SET_STR
       "Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")

DEFSH (VTYSH_BGPD, debug_bgp_update_cmd_vtysh, 
       "debug bgp updates", 
       DEBUG_STR
       BGP_STR
       "BGP updates\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_distribute_list_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) distribute-list WORD (in|out)", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "IPv6 Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_BGPD, no_set_ipv6_nexthop_global_val_cmd_vtysh, 
       "no set ipv6 next-hop global X:X::X:X", 
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_OSPFD, no_area_range_suppress_cmd_vtysh, 
       "no area A.B.C.D range IPV4_PREFIX not-advertise", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")

DEFSH (VTYSH_OSPFD, no_ospf_redistribute_kernel_cmd_vtysh, 
       "no redistribute kernel", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_soft_cmd_vtysh, 
       "clear ip bgp * soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_kernel_cmd_vtysh, 
       "no redistribute kernel", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_OSPF6D, no_router_ospf6_cmd_vtysh, 
       "no router ospf6", 
       NO_STR
       OSPF6_ROUTER_STR
       )

DEFSH (VTYSH_BGPD, bgp_network_unicast_multicast_cmd_vtysh, 
       "network A.B.C.D/M nlri unicast multicast", 
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_OSPFD, no_refresh_timer_val_cmd_vtysh, 
       "no refresh timer <10-1800>", 
       "Adjust refresh parameters\n"
       "Unset refresh timer\n"
       "Timer value in seconds\n")

DEFSH (VTYSH_BGPD, no_neighbor_transparent_as_cmd_vtysh, 
       NO_NEIGHBOR_CMD "transparent-as", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not append my AS number even peer is EBGP peer\n")

DEFSH (VTYSH_OSPFD, area_vlink_param_md5_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535> message-digest-key <1-255> md5 KEY", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_id_cmd_vtysh, 
       "show ip ospf database (nssa-external|asbr-summary|external|network|router|summary) A.B.C.D", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "Network link states\n"
       "Router link states\n"
       "Network summary link states\n"
       "Link State ID (as an IP address)\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_ripng_cmd_vtysh, 
       "redistribute ripng", 
       "Redistribute control\n"
       "RIPng route\n")

DEFSH (VTYSH_BGPD, set_originator_id_cmd_vtysh, 
       "set originator-id A.B.C.D", 
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")

DEFSH (VTYSH_BGPD, neighbor_prefix_list_cmd_vtysh, 
       NEIGHBOR_CMD "prefix-list WORD (in|out)", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_int_detail_cmd_vtysh, 
       "show ip ospf neighbor INTERFACE detail", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n"
       "detail of all neighbors")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_statistics_cmd_vtysh, 
       "show ipv6 ospf6 statistics", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Statistics\n")

DEFSH (VTYSH_RIPD, no_ip_rip_send_version_num_cmd_vtysh, 
       "no ip rip send version (1|2)", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "Version 1\n"
       "Version 2\n")

DEFSH (VTYSH_BGPD, no_bgp_deterministic_med_cmd_vtysh, 
       "no bgp deterministic-med", 
       NO_STR
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")

DEFSH (VTYSH_BGPD, bgp_client_to_client_reflection_cmd_vtysh, 
       "bgp client-to-client reflection", 
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_ospf6_cmd_vtysh, 
       "redistribute ospf6", 
       "Redistribute control\n"
       "OSPF6 route\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_remote_as_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535>", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP Address\n"
       "IPv6 Address\n"
       "Specify a BGP neighbor\n"
       AS_STR)

DEFSH (VTYSH_OSPFD, ip_ospf_cost_cmd_vtysh, 
       "ip ospf cost <1-65535>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Interface cost\n"
       "Cost")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community4_exact_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_summary_name_cmd_vtysh, 
       "show ip prefix-list summary WORD", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, no_neighbor_translate_update_unimulti_cmd_vtysh, 
       NO_NEIGHBOR_CMD "translate-update nlri unicast multicast", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "unicast information\n"
       "multicast inforamtion\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_interface_ifname_cmd_vtysh, 
       "show ipv6 ospf6 interface IFNAME", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       )

DEFSH (VTYSH_BGPD, no_bgp_bestpath_med2_cmd_vtysh, 
       "no bgp bestpath med confed missing-as-worst", 
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_set_forwarding_cmd_vtysh, 
       "set forwarding-address X:X::X:X", 
       "Set value\n"
       "Forwarding Address\n"
       "IPv6 Address\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_advrtr_cmd_vtysh, 
       "show ipv6 ospf6 database advrtr A.B.C.D", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Specify Advertising Router\n"
       "Router ID\n"
       )

DEFSH (VTYSH_BGPD, no_neighbor_activate_cmd_vtysh, 
       NO_NEIGHBOR_CMD "activate", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Enable the Address Family for this Neighbor\n")

DEFSH (VTYSH_RIPD, no_key_string_cmd_vtysh, 
       "no key-string [LINE]", 
       NO_STR
       "Unset key string\n"
       "The key\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_sequence_number_cmd_vtysh, 
       "no ip prefix-list sequence-number", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_cmd_vtysh, 
       "show ip ospf neighbor", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n")

DEFSH (VTYSH_BGPD, ipv6_aggregate_address_summary_only_cmd_vtysh, 
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only", 
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_soft_out_cmd_vtysh, 
       "clear ip bgp * soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_ZEBRA, show_ip_route_addr_cmd_vtysh, 
       "show ip route A.B.C.D", 
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")

DEFSH (VTYSH_RIPD, ip_rip_send_version_1_cmd_vtysh, 
       "ip rip send version 1 2", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_vpnv4_in_cmd_vtysh, 
       "clear ip bgp * vpnv4 unicast in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_soft_in_cmd_vtysh, 
       "clear ipv6 bgp <1-65535> soft in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_static_cmd_vtysh, 
       "redistribute static", 
       "Redistribute\n"
       "Static route\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_sequence_number_cmd_vtysh, 
       "ipv6 prefix-list sequence-number", 
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_ipv6_access_list_cmd_vtysh, 
       "no ipv6 access-list WORD (deny|permit) (X:X::X:X/M|any)", 
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Any prefixi to match\n")

DEFSH (VTYSH_BGPD, no_ipv6_neighbor_override_capability_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) override-capability", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Override capability negotiation result\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_in_cmd_vtysh, 
       "clear ipv6 bgp * in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_ospf_routemap_cmd_vtysh, 
       "redistribute ospf route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_cmd_vtysh, 
       "clear ipv6 bgp <1-65535>", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n")

DEFSH (VTYSH_OSPFD, area_import_list_decimal_cmd_vtysh, 
       "area <0-4294967295> import-list NAME", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_ipv4_soft_out_cmd_vtysh, 
       "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community4_exact_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_retransmitinterval_cmd_vtysh, 
       "ipv6 ospf6 retransmit-interval RXMTINTERVAL", 
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR
       )

DEFSH (VTYSH_BGPD, no_neighbor_transparent_nexthop_cmd_vtysh, 
       NO_NEIGHBOR_CMD "transparent-nexthop", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not change nexthop even peer is EBGP peer\n")

DEFSH (VTYSH_RIPNGD, show_ipv6_ripng_cmd_vtysh, 
       "show ipv6 ripng", 
       SHOW_STR
       IP_STR
       "Show RIPng routes\n")

DEFSH (VTYSH_OSPFD, ospf_router_id_cmd_vtysh, 
       "ospf router-id A.B.C.D", 
       "OSPF specific commands\n"
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, ipv6_access_list_exact_cmd_vtysh, 
       "ipv6 access-list WORD (deny|permit) X:X::X:X/M (exact-match|)", 
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Exact match of the prefixes\n")

DEFSH (VTYSH_OSPF6D, no_ospf6_redistribute_static_cmd_vtysh, 
       "no redistribute static", 
       NO_STR
       "Redistribute\n"
       "Static route\n")

DEFSH (VTYSH_BGPD, match_ip_next_hop_cmd_vtysh, 
       "match ip next-hop WORD", 
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP access-list name\n")

DEFSH (VTYSH_BGPD, no_redistribute_bgp_cmd_vtysh, 
       "no redistribute bgp", 
       NO_STR
       "Redistribute control\n"
       "BGP route\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_description_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) description .LINE", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

DEFSH (VTYSH_OSPFD, debug_ospf_packet_all_cmd_vtysh, 
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)", 
       DEBUG_STR
       OSPF_STR
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_cmd_vtysh, 
       "show ipv6 ospf6", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       )

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_soft_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_vpnv4_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D vpnv4 unicast in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPFD, no_ospf_priority_cmd_vtysh, 
       "no ospf priority", 
       NO_STR
       "OSPF interface commands\n"
       "Router priority\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_update_source_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) update-source", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Source of routing updates\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_neighbor_nexthop_self_cmd_vtysh, 
       NO_NEIGHBOR_CMD "next-hop-self", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Disable the next hop calculation for this neighbor\n")

DEFSH (VTYSH_BGPD, bgp_multiple_instance_cmd_vtysh, 
       "bgp multiple-instance", 
       "BGP specific commands\n"
       "Enable bgp multiple instance\n")

DEFSH (VTYSH_RIPNGD, debug_ripng_zebra_cmd_vtysh, 
       "debug ripng zebra", 
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")

DEFSH (VTYSH_RIPNGD, no_debug_ripng_packet_cmd_vtysh, 
       "no debug ripng packet", 
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_summary_cmd_vtysh, 
       "show ipv6 prefix-list summary", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_group_cmd_vtysh,  
       "clear ipv6 bgp peer-group WORD", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear BGP connections of peer-group\n"
       "BGP peer-group name to clear connection\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_multicast_cmd_vtysh,  
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri multicast", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for multicast routes\n")

DEFSH (VTYSH_RIPD, no_debug_rip_zebra_cmd_vtysh, 
       "no debug rip zebra", 
       NO_STR
       DEBUG_STR
       RIP_STR
       "RIP and ZEBRA communication\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_seq_le_cmd_vtysh, 
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_capability_route_refresh_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) capability route-refresh", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Outbound capability configuration\n"
       "Advertise route-refresh capability to this neighbor\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_timers_connect_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers connect <0-65535>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

DEFSH (VTYSH_OSPFD|VTYSH_OSPF6D, no_passive_interface_cmd_vtysh, 
       "no passive-interface IFNAME", 
       NO_STR
       "Suppress routing updates on an interface\n"
       IFNAME_STR
       )

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_cmd_vtysh, 
       "no ipv6 prefix-list WORD", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, no_neighbor_filter_list_cmd_vtysh, 
       NO_NEIGHBOR_CMD "filter-list WORD (in|out)", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")

DEFSH (VTYSH_OSPFD, area_nssa_t_candidate_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa translate-candidate", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR for translate election\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_prefix_cmd_vtysh, 
       "show ip prefix-list WORD A.B.C.D/M", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_RIPD, send_lifetime_infinite_day_month_cmd_vtysh, 
       "send-lifetime HH:MM:SS <1-31> MONTH <1993-2035> infinite", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires")

DEFSH (VTYSH_OSPFD, refresh_timer_cmd_vtysh, 
       "refresh timer <10-1800>", 
       "Adjust refresh parameters\n"
       "Set refresh timer\n"
       "Timer value in seconds\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_seq_le_ge_cmd_vtysh, 
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, no_set_weight_val_cmd_vtysh, 
       "no set weight <0-4294967295>", 
       NO_STR
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_received_routes_cmd_vtysh, 
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) received-routes", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFSH (VTYSH_BGPD, neighbor_translate_update_unimulti_cmd_vtysh, 
       NEIGHBOR_CMD "translate-update nlri unicast multicast", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "unicast information\n"
       "multicast inforamtion\n")

DEFSH (VTYSH_BGPD, no_set_originator_id_val_cmd_vtysh, 
       "no set originator-id A.B.C.D", 
       NO_STR
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_prefix_cmd_vtysh, 
       "no ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, set_ecommunity_rt_cmd_vtysh, 
       "set extcommunity rt .ASN:nn_or_IP-address:nn", 
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extened communityt\n"
       "VPN extended community\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_transparent_nexthop_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-nexthop", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not change nexthop even peer is EBGP peer\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_vpnv4_soft_in_cmd_vtysh, 
       "clear ip bgp * vpnv4 unicast soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_update_cmd_vtysh, 
       "no debug bgp updates", 
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP updates\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_route_cmd_vtysh, 
       "show ip bgp A.B.C.D", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_ospf_cmd_vtysh, 
       "no redistribute ospf", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n")

DEFSH (VTYSH_BGPD, set_aggregator_as_cmd_vtysh, 
       "set aggregator as <1-65535> A.B.C.D", 
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")

DEFSH (VTYSH_OSPFD, clear_ip_ospf_neighbor_cmd_vtysh, 
       "clear ip ospf neighbor A.B.C.D", 
       "Reset functions\n"
       "IP\n"
       "Clear OSPF\n"
       "Neighbor list\n"
       "Neighbor ID\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_kernel_cmd_vtysh, 
       "redistribute kernel", 
       "Redistribute\n"
       "Static route\n")

DEFSH (VTYSH_BGPD, no_neighbor_shutdown_cmd_vtysh, 
       NO_NEIGHBOR_CMD "shutdown", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Administratively shut down this neighbor\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_set_ip_nexthop_cmd_vtysh, 
       "no set ip next-hop", 
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community_all_cmd_vtysh, 
       "show ipv6 mbgp community", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")

DEFSH (VTYSH_RIPD, ip_rip_authentication_mode_cmd_vtysh, 
       "ip rip authentication mode (md5|text)", 
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "Clear text authentication\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_string2_cmd_vtysh, 
       "no ip rip authentication string LINE", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n"
       "Authentication string\n")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_instance_cmd_vtysh, 
       "ipv6 ospf6 instance-id INSTANCE", 
       IP6_STR
       OSPF6_STR
       "Instance ID\n"
       "<0-255> Instance ID\n"
       )

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_cmd_vtysh, 
       "clear ip bgp <1-65535>", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n")

DEFSH (VTYSH_BGPD, no_ipv6_aggregate_address_cmd_vtysh, 
       "no ipv6 bgp aggregate-address X:X::X:X/M", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_vpnv4_soft_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D vpnv4 unicast soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_no_match_address_prefixlist_cmd_vtysh, 
       "no match ipv6 address prefix-list WORD", 
       NO_STR
       "Match values\n"
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IPv6 prefix-list name\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_soft_cmd_vtysh, 
       "clear ipv6 bgp * soft", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, no_bgp_bestpath_med3_cmd_vtysh, 
       "no bgp bestpath med missing-as-worst confed", 
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

DEFSH (VTYSH_RIPNGD, debug_ripng_packet_direct_cmd_vtysh, 
       "debug ripng packet (recv|send)", 
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")

DEFSH (VTYSH_OSPFD, area_authentication_cmd_vtysh, 
       "area A.B.C.D authentication", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_prefix_cmd_vtysh, 
       "show ipv6 prefix-list WORD X:X::X:X/M", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_prefix_list_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the prefix-list\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_neighborlist_cmd_vtysh, 
       "show ipv6 ospf6 (summary-list|request-list|retransmission-list)", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Link State summary list\n"
       "Link State request list\n"
       "Link State retransmission list\n"
       )

DEFSH (VTYSH_OSPF6D, no_ospf6_redistribute_kernel_cmd_vtysh, 
       "no redistribute kernel", 
       NO_STR
       "Redistribute\n"
       "Static route\n")

DEFSH (VTYSH_BGPD, no_bgp_default_local_preference_cmd_vtysh, 
       "no bgp default local-preference", 
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n")

DEFSH (VTYSH_BGPD, match_nlri_cmd_vtysh, 
       "match nlri (multicast|unicast)", 
       MATCH_STR
       "Match Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")

DEFSH (VTYSH_RIPD, rip_redistribute_type_cmd_vtysh, 
       "redistribute (kernel|connected|static|ospf|bgp)", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_ipv4_soft_in_cmd_vtysh, 
       "clear ip bgp * ipv4 (unicast|multicast) soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_RIPD, ip_rip_send_version_2_cmd_vtysh, 
       "ip rip send version 2 1", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 2\n"
       "RIP version 1\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_metric_cmd_vtysh, 
       "default-information originate metric <0-16777214>", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF default metric\n"
       "OSPF metric\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_port_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) port", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP port\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_turnover_cmd_vtysh, 
       "show ipv6 ospf6 database turnover", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Statistics of Database turn over\n"
       )

DEFSH (VTYSH_OSPFD, no_debug_ospf_ism_sub_cmd_vtysh, 
       "no debug ospf ism (status|events|timers)", 
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM Timer Information\n")

DEFSH (VTYSH_OSPFD, debug_ospf_nsm_cmd_vtysh, 
       "debug ospf nsm", 
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_network_unicast_multicast_cmd_vtysh, 
       "no ipv6 bgp network X:X::X:X/M nlri unicast multicast", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_neighbor_ifname_cmd_vtysh, 
       "show ipv6 ospf6 neighbor IFNAME", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       )

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_soft_cmd_vtysh, 
       "clear ipv6 bgp <1-65535> soft", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_nexthoplist_cmd_vtysh, 
       "show ipv6 ospf6 nexthop-list", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "List of nexthop\n")

DEFSH (VTYSH_RIPNGD, no_debug_ripng_packet_direct_cmd_vtysh, 
       "no debug ripng packet (recv|send)", 
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")

DEFSH (VTYSH_RIPD, no_rip_neighbor_cmd_vtysh, 
       "no neighbor A.B.C.D", 
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")

DEFSH (VTYSH_BGPD, bgp_damp_set2_cmd_vtysh, 
       "bgp dampening <1-45>", 
       "Define dampening parameters\n"
       "BGP Specific commands\n"
       "Half-life time in minutes\n")

DEFSH (VTYSH_RIPD, ip_rip_receive_version_1_cmd_vtysh, 
       "ip rip receive version 1 2", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n")

DEFSH (VTYSH_OSPFD, area_nssa_t_candidate_cmd_vtysh, 
       "area A.B.C.D nssa translate-candidate", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR for translate election\n")

DEFSH (VTYSH_RIPNGD, debug_ripng_packet_cmd_vtysh, 
       "debug ripng packet", 
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")

DEFSH (VTYSH_RIPD, rip_timers_cmd_vtysh, 
       "timers basic <0-4294967295> <1-4294967295> <1-4294967295>", 
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_type_routemap_cmd_vtysh, 
       "default-information originate always metric-type (1|2) route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_soft_in_cmd_vtysh, 
       "clear ip bgp * soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_out_cmd_vtysh, 
       "clear ip bgp <1-65535> out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, no_neighbor_pollinterval_cmd_vtysh, 
       "no neighbor A.B.C.D poll-interval <1-65535>", 
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_vpnv4_soft_cmd_vtysh, 
       "clear ip bgp * vpnv4 unicast soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_RIPD, no_rip_offset_list_cmd_vtysh, 
       "no offset-list WORD (in|out) <0-16>", 
       NO_STR
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_sequence_number_cmd_vtysh, 
       "no ipv6 prefix-list sequence-number", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")

DEFSH (VTYSH_OSPFD, ospf_abr_type_cmd_vtysh, 
       "ospf abr-type (cisco|ibm|shortcut|standard)", 
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR,  cisco implementation\n"
       "Alternative ABR,  IBM implementation\n"
       "Shortcut ABR\n"
       "Standard behavior (RFC2328)\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_soft_reconfiguration_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) soft-reconfiguration inbound", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")

DEFSH (VTYSH_OSPFD, area_vlink_md5_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D message-digest-key <1-255> md5 KEY", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_BGPD, no_neighbor_weight_val_cmd_vtysh, 
       NO_NEIGHBOR_CMD "weight <0-65535>", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_string_cmd_vtysh, 
       "no ip rip authentication string", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication string\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_holdtime_cmd_vtysh, 
       "ip irdp holdtime <0-9000>", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set holdtime value\n"
       "Holdtime value in seconds. Default is 1800 seconds\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_route_ifname_cmd_vtysh, 
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS IFNAME", 
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "Interface name\n")

DEFSH (VTYSH_OSPFD, no_ospf_distance_cmd_vtysh, 
       "no distance <1-255>", 
       NO_STR
       "Define an administrative distance\n"
       "OSPF Administrative distance\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_type_metric_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) metric <0-16777214>", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n")

DEFSH (VTYSH_RIPD, accept_lifetime_day_month_day_month_cmd_vtysh, 
       "accept-lifetime HH:MM:SS <1-31> MONTH <1993-2035> HH:MM:SS <1-31> MONTH <1993-2035>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_ipv4_in_cmd_vtysh, 
       "clear ip bgp <1-65535> ipv4 (unicast|multicast) in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, no_dump_bgp_all_cmd_vtysh, 
       "no dump bgp all [PATH] [INTERVAL]", 
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump all BGP packets\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_passive_cmd_vtysh,  
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> passive", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Passive mode\n")

DEFSH (VTYSH_RIPD, rip_redistribute_type_metric_cmd_vtysh, 
       "redistribute (kernel|connected|static|ospf|bgp) metric <0-16>", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric\n"
       "Metric value\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_seq_cmd_vtysh, 
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_static_routemap_cmd_vtysh, 
       "ipv6 bgp redistribute static route-map WORD", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, debug_ospf_ism_cmd_vtysh, 
       "debug ospf ism", 
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_int_cmd_vtysh, 
       "show ip ospf neighbor INTERFACE", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n")

DEFSH (VTYSH_ZEBRA, no_debug_zebra_events_cmd_vtysh, 
       "no debug zebra events", 
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra events\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_routes_cmd_vtysh, 
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) routes", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFSH (VTYSH_BGPD, no_neighbor_port_cmd_vtysh, 
       NO_NEIGHBOR_CMD "port", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")

DEFSH (VTYSH_BGPD, no_set_community_val_cmd_vtysh, 
       "no set community .AA:NN", 
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_BGPD, set_community_cmd_vtysh, 
       "set community .AA:NN", 
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_neighbors_cmd_vtysh, 
       "show ip bgp neighbors", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_seq_cmd_vtysh, 
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")

DEFSH (VTYSH_RIPD, debug_rip_packet_detail_cmd_vtysh, 
       "debug rip packet (recv|send) detail", 
       DEBUG_STR
       RIP_STR
       "RIP packet\n"
       "RIP receive packet\n"
       "RIP send packet\n"
       "Detailed information display\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_scope_cmd_vtysh, 
       "show ipv6 ospf6 database (as-scope|area-scope|linklocal-scope|)", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "AS scoped LSAs\n"
       "Area scoped LSAs\n"
       "Linklocal scoped LSAs\n"
       )

DEFSH (VTYSH_ZEBRA, no_bandwidth_if_val_cmd_vtysh, 
       "no bandwidth <1-10000000>", 
       NO_STR
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_timers_connect_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers connect [TIMER]", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

DEFSH (VTYSH_BGPD, no_bgp_router_id_val_cmd_vtysh, 
       "no bgp router-id A.B.C.D", 
       NO_STR
       "BGP specific commands\n"
       "Override configured router identifier\n"
       "Manually configured router identifier\n")

DEFSH (VTYSH_BGPD, dump_bgp_updates_cmd_vtysh, 
       "dump bgp updates PATH", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n"
       "Output filename\n")

DEFSH (VTYSH_RIPD, no_router_rip_cmd_vtysh, 
       "no router rip", 
       NO_STR
       "Enable a routing process\n"
       "Routing Information Protocol (RIP)\n")

DEFSH (VTYSH_RIPD, debug_rip_packet_cmd_vtysh, 
       "debug rip packet", 
       DEBUG_STR
       RIP_STR
       "RIP packet\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_cmd_vtysh, 
       "show ipv6 prefix-list", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR)

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_le_cmd_vtysh, 
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_OSPFD, debug_ospf_ism_sub_cmd_vtysh, 
       "debug ospf ism (status|events|timers)", 
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_network_unicast_multicast_cmd_vtysh, 
       "ipv6 bgp network X:X::X:X/M nlri unicast multicast", 
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_RIPD, no_rip_distance_cmd_vtysh, 
       "no distance <1-255>", 
       NO_STR
       "Administrative distance\n"
       "Distance value\n")

DEFSH (VTYSH_ZEBRA, ip_route_mask_cmd_vtysh, 
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE)", 
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n")

DEFSH (VTYSH_BGPD, no_neighbor_soft_reconfiguration_cmd_vtysh, 
       NO_NEIGHBOR_CMD "soft-reconfiguration inbound", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")

DEFSH (VTYSH_OSPF6D, no_debug_ospf6_message_cmd_vtysh, 
       "no debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)", 
       NO_STR
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )

DEFSH (VTYSH_RIPD, rip_default_information_originate_cmd_vtysh, 
       "default-information originate", 
       "Control distribution of default route\n"
       "Distribute a default route\n")

DEFSH (VTYSH_OSPFD, no_ospf_distance_ospf_cmd_vtysh, 
       "no distance ospf", 
       NO_STR
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "OSPF Distance\n")

DEFSH (VTYSH_ZEBRA, no_debug_zebra_kernel_cmd_vtysh, 
       "no debug zebra kernel", 
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n")

DEFSH (VTYSH_BGPD, ipv4_neighbor_received_routes_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFSH (VTYSH_RIPD, no_rip_offset_list_ifname_cmd_vtysh, 
       "no offset-list WORD (in|out) <0-16> IFNAME", 
       NO_STR
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")

DEFSH (VTYSH_OSPFD, debug_ospf_zebra_sub_cmd_vtysh, 
       "debug ospf zebra (interface|redistribute)", 
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_route_reflector_client_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-reflector-client", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Reflector client\n")

DEFSH (VTYSH_OSPFD, debug_ospf_lsa_cmd_vtysh, 
       "debug ospf lsa", 
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n")

DEFSH (VTYSH_OSPFD, ip_ospf_dead_interval_cmd_vtysh, 
       "ip ospf dead-interval <1-65535>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n")

DEFSH (VTYSH_OSPFD, no_area_range_cmd_vtysh, 
       "no area A.B.C.D range A.B.C.D/M", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFSH (VTYSH_BGPD, no_bgp_cluster_id_cmd_vtysh, 
       "no bgp cluster-id", 
       NO_STR
       "BGP specific commands\n"
       "Configure Route-Reflector Cluster-id\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_metric_type_routemap_cmd_vtysh, 
       "default-information originate always metric <0-16777214> metric-type (1|2) route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, network_area_cmd_vtysh, 
       "network A.B.C.D/M area (A.B.C.D|<0-4294967295>)", 
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community2_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, vpnv4_network_cmd_vtysh, 
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD", 
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_cmd_vtysh,  
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR)

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_type_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2) route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD, send_lifetime_infinite_month_day_cmd_vtysh, 
       "send-lifetime HH:MM:SS MONTH <1-31> <1993-2035> infinite", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_detail_cmd_vtysh, 
       "show ip prefix-list detail", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_seq_le_cmd_vtysh, 
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_metric_cmd_vtysh, 
       "default-information originate always metric <0-16777214>", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n")

DEFSH (VTYSH_OSPF6D, no_ospf6_redistribute_bgp_cmd_vtysh, 
       "no redistribute bgp", 
       NO_STR
       "Redistribute\n"
       "RIPng route\n")

DEFSH (VTYSH_BGPD, bgp_damp_set3_cmd_vtysh, 
       "bgp dampening", 
       "Define dampening parameters\n"
       "BGP Specific commands\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_intra_inter_external_cmd_vtysh, 
       "distance ospf intra-area <1-255> inter-area <1-255> external <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_summary_name_cmd_vtysh, 
       "show ipv6 prefix-list summary WORD", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")

DEFSH (VTYSH_ZEBRA, no_ip_address_cmd_vtysh, 
       "no ip address A.B.C.D/M", 
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address (e.g. 10.0.0.1/8)")

DEFSH (VTYSH_RIPD, ip_rip_receive_version_2_cmd_vtysh, 
       "ip rip receive version 2 1", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 2\n"
       "RIP version 1\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_access_list_exact_cmd_vtysh, 
       "no access-list WORD (deny|permit) A.B.C.D/M (exact-match|)", 
       NO_STR 
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_ipv4_soft_in_cmd_vtysh, 
       "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPFD, area_shortcut_decimal_cmd_vtysh, 
       "area <0-4294967295> shortcut (default|enable|disable)", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure the area's shortcutting mode\n"
       "Set default shortcutting behavior\n"
       "Enable shortcutting through the area\n"
       "Disable shortcutting through the area\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_ripng_cmd_vtysh, 
       "redistribute ripng", 
       "Redistribute\n"
       "RIPng route\n")

DEFSH (VTYSH_BGPD, no_set_ecommunity_soo_val_cmd_vtysh, 
       "no set extcommunity soo .ASN:nn_or_IP-address:nn", 
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")

DEFSH (VTYSH_OSPFD, no_ospf_dead_interval_cmd_vtysh, 
       "no ospf dead-interval", 
       NO_STR
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead\n")

DEFSH (VTYSH_RIPNGD, no_ripng_network_cmd_vtysh, 
       "no network IF_OR_ADDR", 
       NO_STR
       "RIPng enable on specified interface or network.\n"
       "Interface or address")

DEFSH (VTYSH_BGPD, undebug_bgp_fsm_cmd_vtysh, 
       "undebug bgp fsm", 
       UNDEBUG_STR
       DEBUG_STR
       BGP_STR
       "Finite State Machine\n")

DEFSH (VTYSH_RIPNGD, no_default_information_originate_cmd_vtysh, 
       "no default-information originate", 
       NO_STR
       "Default route information\n"
       "Distribute default route\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_le_ge_cmd_vtysh, 
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_ZEBRA, show_table_cmd_vtysh, 
       "show table", 
       SHOW_STR
       "default routing table to use for all clients\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_seq_cmd_vtysh, 
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_prefix_cmd_vtysh, 
       "no ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")

DEFSH (VTYSH_ZEBRA, ipv6_address_cmd_vtysh, 
       "ipv6 address IPV6PREFIX/M", 
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")

DEFSH (VTYSH_ZEBRA, debug_zebra_events_cmd_vtysh, 
       "debug zebra events", 
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra events\n")

DEFSH (VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD, no_router_zebra_cmd_vtysh, 
       "no router zebra", 
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPFD, area_stub_nosum_decimal_cmd_vtysh, 
       "area <0-4294967295> stub no-summary", 
       "OSPF stub parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n")

DEFSH (VTYSH_BGPD, ip_community_list_cmd_vtysh, 
       "ip community-list WORD (deny|permit) .AA:NN", 
       IP_STR
       "Add a community list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_network_multicast_cmd_vtysh, 
       "ipv6 bgp network X:X::X:X/M nlri multicast", 
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_neighbors_peer_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFSH (VTYSH_BGPD, no_neighbor_dont_capability_negotiate_cmd_vtysh, 
       NO_NEIGHBOR_CMD "dont-capability-negotiate", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not perform capability negotiation\n")

DEFSH (VTYSH_BGPD, ipv6_mbgp_neighbor_received_routes_cmd_vtysh, 
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) received-routes", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_detail_cmd_vtysh, 
       "show ipv6 prefix-list detail", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")

DEFSH (VTYSH_OSPFD, ospf_authentication_key_cmd_vtysh, 
       "ospf authentication-key AUTH_KEY", 
       "OSPF interface commands\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_ZEBRA, ipv6_route_pref_cmd_vtysh, 
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>", 
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_unicast_cmd_vtysh,  
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri unicast", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n")

DEFSH (VTYSH_BGPD, neighbor_peer_group_cmd_vtysh, 
       "neighbor WORD peer-group", 
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_vpnv4_all_neighbors_cmd_vtysh, 
       "show ip bgp vpnv4 all neighbors", 
       SHOW_STR
       IP_STR
       BGP_STR
       "VPNv4\n"
       "All\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFSH (VTYSH_BGPD, ipv6_neighbor_dont_capability_negotiate_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) dont-capability-negotiate", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not perform capability negotiation\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_ipv4_out_cmd_vtysh, 
       "clear ip bgp * ipv4 (unicast|multicast) out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_summary_cmd_vtysh, 
       "show ipv6 bgp summary", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n")

DEFSH (VTYSH_OSPFD, no_ospf_hello_interval_cmd_vtysh, 
       "no ospf hello-interval", 
       NO_STR
       "OSPF interface commands\n"
       "Time between HELLO packets\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community_all_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")

DEFSH (VTYSH_ZEBRA, show_zebra_client_cmd_vtysh, 
       "show zebra client", 
       SHOW_STR
       "Zebra information"
       "Client information")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ipv6_prefix_list_cmd_vtysh, 
       "clear ipv6 prefix-list", 
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR)

DEFSH (VTYSH_BGPD, neighbor_default_originate_cmd_vtysh, 
       NEIGHBOR_CMD "default-originate", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Originate default route to this neighbor\n")

DEFSH (VTYSH_BGPD, router_bgp_view_cmd_vtysh, 
       "router bgp <1-65535> view WORD", 
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")

DEFSH (VTYSH_BGPD, set_weight_cmd_vtysh, 
       "set weight <0-4294967295>", 
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community2_exact_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, area_export_list_cmd_vtysh, 
       "area A.B.C.D export-list NAME", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_OSPFD, area_range_suppress_decimal_cmd_vtysh, 
       "area <0-4294967295> range IPV4_PREFIX not-advertise", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF DECIMAL area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")

DEFSH (VTYSH_OSPFD, no_ospf_rfc1583_flag_cmd_vtysh, 
       "no ospf rfc1583compatibility", 
       NO_STR
       "OSPF specific commands\n"
       "Disable the RFC1583Compatibility flag\n")

DEFSH (VTYSH_BGPD, set_community_additive_cmd_vtysh, 
       "set community-additive .AA:NN", 
       SET_STR
       "BGP community attribute (Add to the existing community)\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_ZEBRA, debug_zebra_kernel_cmd_vtysh, 
       "debug zebra kernel", 
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community2_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_fsm_cmd_vtysh, 
       "no debug bgp fsm", 
       NO_STR
       DEBUG_STR
       BGP_STR
       "Finite State Machine\n")

DEFSH (VTYSH_OSPFD, no_area_stub_decimal_cmd_vtysh, 
       "no area <0-4294967295> stub", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

DEFSH (VTYSH_BGPD, no_bgp_network_backdoor_cmd_vtysh, 
       "no network A.B.C.D/M backdoor", 
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_ipv4_soft_cmd_vtysh, 
       "clear ip bgp <1-65535> ipv4 (unicast|multicast) soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_RIPD, show_ip_protocols_rip_cmd_vtysh, 
       "show ip protocols", 
       SHOW_STR
       IP_STR
       "IP routing protocol process parameters and statistics\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_key_chain_cmd_vtysh, 
       "no ip rip authentication key-chain", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_port_val_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) port <0-65535>", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP port\n"
       "TCP port number\n")

DEFSH (VTYSH_RIPNGD, no_ripng_timers_cmd_vtysh, 
       "no timers basic", 
       NO_STR
       "RIPng timers setup\n"
       "Basic timer\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_paths_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) paths", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Path information\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community_list_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list name\n")

DEFSH (VTYSH_OSPFD, area_shortcut_cmd_vtysh, 
       "area A.B.C.D shortcut (default|enable|disable)", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure the area's shortcutting mode\n"
       "Set default shortcutting behavior\n"
       "Enable shortcutting through the area\n"
       "Disable shortcutting through the area\n")

DEFSH (VTYSH_RIPD, accept_lifetime_infinite_day_month_cmd_vtysh, 
       "accept-lifetime HH:MM:SS <1-31> MONTH <1993-2035> infinite", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires")

DEFSH (VTYSH_ZEBRA, multicast_cmd_vtysh, 
       "multicast", 
       "Set multicast flag to interface\n")

DEFSH (VTYSH_OSPFD, no_area_nssa_decimal_cmd_vtysh, 
       "no area <0-4294967295> nssa", 
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n")

DEFSH (VTYSH_RIPD, rip_route_cmd_vtysh, 
       "route A.B.C.D/M", 
       "RIP static route configuration\n"
       "IP prefix <network>/<length>\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_intra_external_inter_cmd_vtysh, 
       "distance ospf intra-area <1-255> external <1-255> inter-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_ipv4_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, timers_spf_cmd_vtysh, 
       "timers spf <0-4294967295> <0-4294967295>", 
       "Adjust routing timers\n"
       "OSPF SPF timers\n"
       "Delay between receiving a change to SPF calculation\n"
       "Hold time between consecutive SPF calculations\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_ipv4_soft_cmd_vtysh, 
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, no_dump_bgp_updates_cmd_vtysh, 
       "no dump bgp updates [PATH] [INTERVAL]", 
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump BGP updates only\n")

DEFSH (VTYSH_RIPD, accept_lifetime_month_day_day_month_cmd_vtysh, 
       "accept-lifetime HH:MM:SS MONTH <1-31> <1993-2035> HH:MM:SS <1-31> MONTH <1993-2035>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_RIPD, accept_lifetime_day_month_month_day_cmd_vtysh, 
       "accept-lifetime HH:MM:SS <1-31> MONTH <1993-2035> HH:MM:SS MONTH <1-31> <1993-2035>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_RIPD, no_debug_rip_packet_cmd_vtysh, 
       "no debug rip packet", 
       NO_STR
       DEBUG_STR
       RIP_STR
       "RIP packet\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_metric_type_cmd_vtysh, 
       "default-information originate metric <0-16777214> metric-type (1|2)", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community3_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPFD, ospf_dead_interval_cmd_vtysh, 
       "ospf dead-interval <1-65535>", 
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, neighbor_routes_cmd_vtysh, 
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFSH (VTYSH_OSPFD, neighbor_priority_cmd_vtysh, 
       "neighbor A.B.C.D priority <0-255>", 
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Seconds\n")

DEFSH (VTYSH_ZEBRA, no_multicast_cmd_vtysh, 
       "no multicast", 
       NO_STR
       "Unset multicast flag to interface\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_detail_name_cmd_vtysh, 
       "show ip prefix-list detail WORD", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_rip_cmd_vtysh, 
       "no redistribute rip", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n")

DEFSH (VTYSH_RIPD, no_rip_route_cmd_vtysh, 
       "no route A.B.C.D/M", 
       NO_STR
       "RIP static route configuration\n"
       "IP prefix <network>/<length>\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_ebgp_multihop_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n")

DEFSH (VTYSH_ZEBRA, show_ip_route_protocol_cmd_vtysh, 
       "show ip route (bgp|connected|kernel|ospf|rip|static)", 
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Border Gateway Protocol (BGP)\n"
       "Connected\n"
       "Kernel\n"
       "Open Shortest Path First (OSPF)\n"
       "Routing Information Protocol (RIP)\n"
       "Static routes\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_vpnv4_soft_cmd_vtysh, 
       "clear ip bgp A.B.C.D vpnv4 unicast soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_route_cmd_vtysh, 
       "show ip ospf route", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "OSPF routing table\n")

DEFSH (VTYSH_BGPD, neighbor_dont_capability_negotiate_cmd_vtysh, 
       NEIGHBOR_CMD "dont-capability-negotiate", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not perform capability negotiation\n")

DEFSH (VTYSH_BGPD, no_neighbor_distribute_list_cmd_vtysh, 
       NO_NEIGHBOR_CMD "distribute-list WORD (in|out)", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_RIPD, show_ip_rip_cmd_vtysh, 
       "show ip rip", 
       SHOW_STR
       IP_STR
       "Show RIP routes\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_cmd_vtysh, 
       "show ipv6 ospf6 database", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       )

DEFSH (VTYSH_RIPNGD, show_ipv6_protocols_cmd_vtysh, 
       "show ipv6 protocols", 
       SHOW_STR
       IP_STR
       "Routing protocol information")

DEFSH (VTYSH_RIPD, ip_rip_receive_version_cmd_vtysh, 
       "ip rip receive version (1|2)", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n")

DEFSH (VTYSH_RIPNGD, ripng_aggregate_address_cmd_vtysh, 
       "aggregate-address X:X::X:X/M", 
       "Set aggregate RIPng route announcement\n"
       "Aggregate network\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_ge_cmd_vtysh, 
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_name_cmd_vtysh, 
       "show ipv6 prefix-list WORD", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_ospf_routemap_cmd_vtysh, 
       "no redistribute ospf route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, neighbor_filter_list_cmd_vtysh, 
       NEIGHBOR_CMD "filter-list WORD (in|out)", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")

DEFSH (VTYSH_BGPD, set_vpnv4_nexthop_cmd_vtysh, 
       "set vpnv4 next-hop A.B.C.D", 
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n"
       "IP address of next hop\n")

DEFSH (VTYSH_RIPD, no_rip_default_metric_cmd_vtysh, 
       "no default-metric", 
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")

DEFSH (VTYSH_BGPD, bgp_distance_source_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M", 
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")

DEFSH (VTYSH_OSPFD, no_ospf_transmit_delay_cmd_vtysh, 
       "no ospf transmit-delay", 
       NO_STR
       "OSPF interface commands\n"
       "Link state transmit delay\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_intra_external_cmd_vtysh, 
       "distance ospf intra-area <1-255> external <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "External routes\n"
       "Distance for external routes\n")

DEFSH (VTYSH_BGPD, no_set_community_delete_cmd_vtysh, 
       "no set community-delete", 
       NO_STR
       SET_STR
       "BGP community attribute (Delete from existing community)\n")

DEFSH (VTYSH_BGPD, neighbor_route_reflector_client_cmd_vtysh, 
       NEIGHBOR_CMD "route-reflector-client", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Reflector client\n")

DEFSH (VTYSH_OSPFD, no_ospf_router_id_cmd_vtysh, 
       "no ospf router-id", 
       NO_STR
       "OSPF specific commands\n"
       "router-id for the OSPF process\n")

DEFSH (VTYSH_ZEBRA, show_ip_forwarding_cmd_vtysh, 
       "show ip forwarding", 
       SHOW_STR
       IP_STR
       "IP forwarding status\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_soft_in_cmd_vtysh, 
       "clear ipv6 bgp * soft in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_routemap_cmd_vtysh, 
       "default-information originate route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_vpnv4_soft_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D vpnv4 unicast soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, no_area_default_cost_cmd_vtysh, 
       "no area A.B.C.D default-cost <0-16777215>", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ipv6_prefix_list_name_cmd_vtysh, 
       "clear ipv6 prefix-list WORD", 
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_forwarding_cmd_vtysh, 
       "no ipv6 forwarding", 
       NO_STR
       IP_STR
       "Doesn't forward IPv6 protocol packet")

DEFSH (VTYSH_RIPNGD, no_debug_ripng_events_cmd_vtysh, 
       "no debug ripng events", 
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")

DEFSH (VTYSH_BGPD, no_bgp_confederation_identifier_cmd_vtysh, 
       "no bgp confederation identifier <1-65535>", 
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")

DEFSH (VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD, no_match_interface_cmd_vtysh, 
       "no match interface WORD", 
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_set_ipv6_nexthop_local_cmd_vtysh, 
       "no set ipv6 next-hop local", 
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_access_list_all_cmd_vtysh, 
       "no access-list WORD", 
       NO_STR
       "Add an access list entry\n"
       "Access-list name\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community3_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPFD, ospf_retransmit_interval_cmd_vtysh, 
       "ospf retransmit-interval <3-65535>", 
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_database_summary_cmd_vtysh, 
       "show ipv6 ospf6 database database-summary", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database Summary\n"
       "Summary of Database\n")

DEFSH (VTYSH_RIPNGD, ripng_garbage_timer_cmd_vtysh, 
       "garbage-timer SECOND", 
       "Set RIPng garbage timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, no_neighbor_override_capability_cmd_vtysh, 
       NO_NEIGHBOR_CMD "override-capability", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Override capability negotiation result\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_route_ospf6_prefix_cmd_vtysh, 
       "show ipv6 route ospf6 X::X", 
       SHOW_STR
       IP6_STR
       "Routing table\n"
       OSPF6_STR
       "match IPv6 prefix\n"
       )

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_transparent_as_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-as", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not append my AS number even peer is EBGP peer\n")

DEFSH (VTYSH_OSPFD, no_area_export_list_cmd_vtysh, 
       "no area A.B.C.D export-list NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_BGPD, no_set_origin_val_cmd_vtysh, 
       "no set origin (egp|igp|incomplete)", 
       NO_STR
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_cmd_vtysh, 
       "default-information originate always", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n")

DEFSH (VTYSH_RIPD, no_rip_split_horizon_cmd_vtysh, 
       "no ip split-horizon", 
       NO_STR
       IP_STR
       "Perform split horizon\n")

DEFSH (VTYSH_OSPFD, no_area_nssa_nosum_cmd_vtysh, 
       "no area A.B.C.D nssa no-summary", 
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_cmd_vtysh, 
       "show ipv6 bgp", 
       SHOW_STR
       IP_STR
       BGP_STR)

DEFSH (VTYSH_OSPFD, area_export_list_decimal_cmd_vtysh, 
       "area <0-4294967295> export-list NAME", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_prefix_list_cmd_vtysh, 
       "show ipv6 bgp prefix-list WORD", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_bgp_routemap_cmd_vtysh, 
       "redistribute bgp route-map WORD", 
       "Redistribute\n"
       "BGP routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, ospf_distribute_list_out_cmd_vtysh, 
       "distribute-list WORD out (kernel|connected|static|rip|bgp)", 
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community4_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_neighbors_cmd_vtysh, 
       "show ipv6 mbgp neighbors [PEER]", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_seq_ge_le_cmd_vtysh, 
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, no_neighbor_description_cmd_vtysh, 
       NO_NEIGHBOR_CMD "description", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor specific description\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_type_routemap_cmd_vtysh, 
       "default-information originate metric-type (1|2) route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_route_map_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-map WORD (in|out)", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")

DEFSH (VTYSH_RIPD, rip_default_metric_cmd_vtysh, 
       "default-metric <1-16>", 
       "Set a metric of redistribute routes\n"
       "Default metric\n")

DEFSH (VTYSH_OSPFD, no_router_ospf_cmd_vtysh, 
       "no router ospf", 
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n")

DEFSH (VTYSH_BGPD, bgp_default_ipv4_unicast_cmd_vtysh, 
       "bgp default ipv4-unicast", 
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_le_cmd_vtysh, 
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_OSPFD, ospf_priority_cmd_vtysh, 
       "ospf priority <0-255>", 
       "OSPF interface commands\n"
       "Router priority\n"
       "Priority\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_vpnv4_out_cmd_vtysh, 
       "clear ip bgp <1-65535> vpnv4 unicast out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_connected_cmd_vtysh, 
       "redistribute connected", 
       "Redistribute information from another routing protocol\n"
       "Connected\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_static_routemap_cmd_vtysh, 
       "redistribute static route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, show_debugging_bgp_cmd_vtysh, 
       "show debugging bgp", 
       SHOW_STR
       DEBUG_STR
       BGP_STR)

DEFSH (VTYSH_OSPFD, no_debug_ospf_nsm_cmd_vtysh, 
       "no debug ospf nsm", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine")

DEFSH (VTYSH_BGPD, neighbor_strict_capability_cmd_vtysh, 
       NEIGHBOR_CMD "strict-capability-match", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_route_ifname_pref_cmd_vtysh, 
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")

DEFSH (VTYSH_BGPD, bgp_cluster_id32_cmd_vtysh, 
       "bgp cluster-id <1-4294967295>", 
       "BGP specific commands\n"
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")

DEFSH (VTYSH_BGPD, neighbor_ebgp_multihop_ttl_cmd_vtysh, 
       NEIGHBOR_CMD "ebgp-multihop <1-255>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

DEFSH (VTYSH_BGPD, match_community_cmd_vtysh, 
       "match community WORD", 
       MATCH_STR
       "Match BGP community list\n"
       "Community-list name (not community value itself)\n")

DEFSH (VTYSH_RIPD, accept_lifetime_infinite_month_day_cmd_vtysh, 
       "accept-lifetime HH:MM:SS MONTH <1-31> <1993-2035> infinite", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires")

DEFSH (VTYSH_ZEBRA, ip_irdp_minadvertinterval_cmd_vtysh, 
       "ip irdp minadvertinterval <3-1800>", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set minimum time between advertisement\n"
       "Minimum advertisement interval in seconds\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_ipv4_soft_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_vpnv4_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D vpnv4 unicast out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_message_digest_key_cmd_vtysh, 
       "no ip ospf message-digest-key <1-255>", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n")

DEFSH (VTYSH_RIPNGD, debug_ripng_events_cmd_vtysh, 
       "debug ripng events", 
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")

DEFSH (VTYSH_OSPFD, area_vlink_param_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535>", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community2_exact_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_set_community_none_cmd_vtysh, 
       "no set community none", 
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_always_cmd_vtysh, 
       "area A.B.C.D nssa no-summary translate-always", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  always translate\n")

DEFSH (VTYSH_RIPD, accept_lifetime_month_day_month_day_cmd_vtysh, 
       "accept-lifetime HH:MM:SS MONTH <1-31> <1993-2035> HH:MM:SS MONTH <1-31> <1993-2035>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_hello_interval_cmd_vtysh, 
       "no ip ospf hello-interval", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between HELLO packets\n")

DEFSH (VTYSH_BGPD, set_ipv6_nexthop_global_cmd_vtysh, 
       "set ipv6 next-hop global X:X::X:X", 
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_RIPNGD, ripng_timeout_timer_cmd_vtysh, 
       "timeout-timer SECOND", 
       "Set RIPng timeout timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_packet_all_cmd_vtysh, 
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_cmd_vtysh, 
       "show ipv6 mbgp", 
       SHOW_STR
       IP_STR
       MBGP_STR)

DEFSH (VTYSH_BGPD, bgp_redistribute_connected_routemap_cmd_vtysh, 
       "redistribute connected route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Connected\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_candidate_cmd_vtysh, 
       "area A.B.C.D nssa no-summary translate-candidate", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  translation election\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_route_cmd_vtysh, 
       "no ipv6 route IPV6_ADDRESS IPV6_ADDRESS", 
       NO_STR
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "IP Address\n"
       "IP Netmask\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_cmd_vtysh, 
       "show ip ospf", 
       SHOW_STR
       IP_STR
       "OSPF information\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_metric_routemap_cmd_vtysh, 
       "default-information originate metric <0-16777214> route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, no_area_stub_nosum_decimal_cmd_vtysh, 
       "no area <0-4294967295> stub no-summary", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")

DEFSH (VTYSH_BGPD, match_ip_address_prefix_list_cmd_vtysh, 
       "match ip address prefix-list WORD", 
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_rmap_onmatch_next_cmd_vtysh, 
       "no on-match next", 
       NO_STR
       "Exit policy on matches\n"
       "Next clause\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_filter_list_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFSH (VTYSH_BGPD, no_bgp_multiple_instance_cmd_vtysh, 
       "no bgp multiple-instance", 
       NO_STR
       "BGP specific commands\n"
       "BGP multiple instance\n")

DEFSH (VTYSH_OSPFD, no_area_vlink_cmd_vtysh, 
       "no area A.B.C.D virtual-link A.B.C.D", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_nexthop_self_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) next-hop-self", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Disable the next hop calculation for this neighbor\n")

DEFSH (VTYSH_OSPFD, ip_ospf_network_cmd_vtysh, 
       "ip ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Network type\n"
       "Specify OSPF broadcast multi-access network\n"
       "Specify OSPF NBMA network\n"
       "Specify OSPF point-to-multipoint network\n"
       "Specify OSPF point-to-point network\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_external_intra_inter_cmd_vtysh, 
       "distance ospf external <1-255> intra-area <1-255> inter-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_prefix_list_cmd_vtysh, 
       "show ip bgp prefix-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_id_self_cmd_vtysh, 
       "show ip ospf database (nssa-external|asbr-summary|external|network|router|summary) A.B.C.D (self-originate|)", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "Network link states\n"
       "Router link states\n"
       "Network summary link states\n"
       "Link State ID (as an IP address)\n"
       "Self-originated link states\n")

DEFSH (VTYSH_BGPD, aggregate_address_summary_only_cmd_vtysh, 
       "aggregate-address A.B.C.D/M summary-only", 
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

DEFSH (VTYSH_OSPFD, no_ospf_authentication_key_cmd_vtysh, 
       "no ospf authentication-key", 
       NO_STR
       "OSPF interface commands\n"
       "Authentication password (key)\n")

DEFSH (VTYSH_RIPD, send_lifetime_duration_day_month_cmd_vtysh, 
       "send-lifetime HH:MM:SS <1-31> MONTH <1993-2035> duration <1-2147483646>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_seq_ge_le_cmd_vtysh, 
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, exit_address_family_cmd_vtysh, 
       "exit-address-family", 
       "Exit from Address Family configuration mode\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_spf_table_cmd_vtysh, 
       "show ipv6 ospf6 spf table", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "Displays SPF topology table\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_ism_cmd_vtysh, 
       "no debug ospf ism", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community4_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_ipv6_neighbor_dont_capability_negotiate_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) dont-capability-negotiate", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not perform capability negotiation\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_in_cmd_vtysh, 
       "clear ip bgp * in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_out_cmd_vtysh, 
       "clear ip bgp * out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_bgp_bestpath_aspath_ignore_cmd_vtysh, 
       "no bgp bestpath as-path ignore", 
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")

DEFSH (VTYSH_BGPD, neighbor_translate_update_multicast_cmd_vtysh, 
       NEIGHBOR_CMD "translate-update nlri multicast", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "multicast information\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_scan_cmd_vtysh, 
       "show ip bgp scan", 
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP scan status\n")

DEFSH (VTYSH_BGPD, neighbor_remote_as_unicast_multicast_cmd_vtysh, 
       NEIGHBOR_CMD "remote-as <1-65535> nlri unicast multicast", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n"
       "Configure for multicast routes\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_retransmit_interval_cmd_vtysh, 
       "no ip ospf retransmit-interval", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_view_prefix_cmd_vtysh, 
       "show ip bgp view WORD A.B.C.D/M", 
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_ZEBRA, no_ip_route_mask_pref_cmd_vtysh, 
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")

DEFSH (VTYSH_RIPNGD, no_ripng_update_timer_cmd_vtysh, 
       "no update-timer SECOND", 
       NO_STR
       "Unset RIPng update timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_OSPFD, area_nssa_t_never_cmd_vtysh, 
       "area A.B.C.D nssa translate-never", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR to never translate\n")

DEFSH (VTYSH_BGPD, bgp_distance_source_access_list_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M WORD", 
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_cmd_vtysh,  
       "clear ip bgp (A.B.C.D|X:X::X:X)", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP neighbor IPv6 address to clear\n")

DEFSH (VTYSH_OSPFD, show_debugging_ospf_cmd_vtysh, 
       "show debugging ospf", 
       SHOW_STR
       DEBUG_STR
       OSPF_STR)

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_type_cmd_vtysh, 
       "default-information originate metric-type (1|2)", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_cost_cmd_vtysh, 
       "no ip ospf cost", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Interface cost\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_list_exact_cmd_vtysh, 
       "show ip bgp community-list WORD exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")

DEFSH (VTYSH_RIPD, debug_rip_events_cmd_vtysh, 
       "debug rip events", 
       DEBUG_STR
       RIP_STR
       "RIP events\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_shutdown_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) shutdown", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Administratively shut down this neighbor\n")

DEFSH (VTYSH_BGPD, no_neighbor_capability_route_refresh_cmd_vtysh, 
       NO_NEIGHBOR_CMD "capability route-refresh", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Outbound capability configuration\n"
       "Advertise route-refresh capability to this neighbor\n")

DEFSH (VTYSH_OSPF6D, interface_area_cmd_vtysh, 
       "interface IFNAME area A.B.C.D", 
       "Enable routing on an IPv6 interface\n"
       IFNAME_STR
       "Set the OSPF6 area ID\n"
       "OSPF6 area ID in IPv4 address notation\n"
       )

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_transparent_as_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) transparent-as", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Do not append my AS number even peer is EBGP peer\n")

DEFSH (VTYSH_OSPFD, area_vlink_param_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535>", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_summary_cmd_vtysh, 
       "show ip prefix-list summary", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_keepalive_cmd_vtysh, 
       "no debug bgp keepalives", 
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP keepalives\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community_exact_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_external_intra_cmd_vtysh, 
       "distance ospf external <1-255> intra-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_lsa_cmd_vtysh, 
       "no debug ospf lsa", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_inter_external_cmd_vtysh, 
       "distance ospf inter-area <1-255> external <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")

DEFSH (VTYSH_RIPD, no_rip_redistribute_type_cmd_vtysh, 
       "no redistribute (kernel|connected|static|ospf|bgp)", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_BGPD, set_community_none_cmd_vtysh, 
       "set community none", 
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ipv6_prefix_list_name_prefix_cmd_vtysh, 
       "clear ipv6 prefix-list WORD X:X::X:X/M", 
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n")

DEFSH (VTYSH_OSPFD, ospf_distance_cmd_vtysh, 
       "distance <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n")

DEFSH (VTYSH_ZEBRA, no_ip_route_cmd_vtysh, 
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE)", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community3_exact_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_neighbor_remote_as_cmd_vtysh, 
       NO_NEIGHBOR_CMD "remote-as <1-65535>", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)

DEFSH (VTYSH_OSPFD, no_ip_ospf_transmit_delay_cmd_vtysh, 
       "no ip ospf transmit-delay", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Link state transmit delay\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_rmap_onmatch_goto_cmd_vtysh, 
       "no on-match goto", 
       NO_STR
       "Exit policy on matches\n"
       "Next clause\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_all_cmd_vtysh, 
       "show ip bgp community", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")

DEFSH (VTYSH_BGPD, match_aspath_cmd_vtysh, 
       "match as-path WORD", 
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_prefix_list_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) prefix-list WORD (in|out)", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_BGPD, neighbor_port_cmd_vtysh, 
       NEIGHBOR_CMD "port <0-65535>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_priority_cmd_vtysh, 
       "ipv6 ospf6 priority PRIORITY", 
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "<0-255> Priority\n"
       )

DEFSH (VTYSH_BGPD, neighbor_maximum_prefix_cmd_vtysh, 
       NEIGHBOR_CMD "maximum-prefix <1-4294967295>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_vpnv4_soft_out_cmd_vtysh, 
       "clear ip bgp <1-65535> vpnv4 unicast soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_static_routemap_cmd_vtysh, 
       "no redistribute static route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, bgp_network_backdoor_cmd_vtysh, 
       "network A.B.C.D/M backdoor", 
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")

DEFSH (VTYSH_RIPNGD, no_ripng_aggregate_address_cmd_vtysh, 
       "no aggregate-address X:X::X:X/M", 
       NO_STR
       "Delete aggregate RIPng route announcement\n"
       "Aggregate network")

DEFSH (VTYSH_BGPD, undebug_bgp_normal_cmd_vtysh, 
       "undebug bgp", 
       UNDEBUG_STR
       BGP_STR)

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_ripng_cmd_vtysh, 
       "no ipv6 bgp redistribute ripng", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Routing Information Protocol (RIPng)\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_nsm_sub_cmd_vtysh, 
       "no debug ospf nsm (status|events|timers)", 
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFSH (VTYSH_BGPD, ipv6_aggregate_address_cmd_vtysh, 
       "ipv6 bgp aggregate-address X:X::X:X/M", 
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

DEFSH (VTYSH_BGPD, dump_bgp_routes_interval_cmd_vtysh, 
       "dump bgp routes-mrt PATH INTERVAL", 
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n"
       "Output filename\n"
       "Interval of output\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_name_seq_cmd_vtysh, 
       "show ipv6 prefix-list WORD seq <1-4294967295>", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_interface_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) interface WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, neighbor_soft_reconfiguration_cmd_vtysh, 
       NEIGHBOR_CMD "soft-reconfiguration inbound", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_ipv4_in_cmd_vtysh, 
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_ospf6_cmd_vtysh, 
       "no ipv6 bgp redistribute ospf6", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Open Shortest Path First (OSPFv3)\n")

DEFSH (VTYSH_RIPD, send_lifetime_day_month_day_month_cmd_vtysh, 
       "send-lifetime HH:MM:SS <1-31> MONTH <1993-2035> HH:MM:SS <1-31> MONTH <1993-2035>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_ZEBRA, ip_route_mask_pref_cmd_vtysh, 
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) <1-255>", 
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community3_exact_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_connected_cmd_vtysh, 
       "no ipv6 bgp redistribute connected", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_static_routemap_cmd_vtysh, 
       "no ipv6 bgp redistribute static route-map WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPNGD, ripng_update_timer_cmd_vtysh, 
       "update-timer SECOND", 
       "Set RIPng update timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, set_local_pref_cmd_vtysh, 
       "set local-preference <0-4294967295>", 
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")

DEFSH (VTYSH_ZEBRA, bandwidth_if_cmd_vtysh, 
       "bandwidth <1-10000000>", 
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")

DEFSH (VTYSH_BGPD, no_ipv6_neighbor_strict_capability_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) strict-capability-match", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Strict capability negotiation match\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_id_cmd_vtysh, 
       "show ip ospf neighbor A.B.C.D", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Neighbor ID\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community2_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPFD|VTYSH_BGPD, no_neighbor_cmd_vtysh, 
       NO_NEIGHBOR_CMD, 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR)

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_ipv4_soft_cmd_vtysh, 
       "clear ip bgp * ipv4 (unicast|multicast) soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_port_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) port <0-65535>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP port\n"
       "TCP port number\n")

DEFSH (VTYSH_RIPNGD, debug_ripng_packet_detail_cmd_vtysh, 
       "debug ripng packet (recv|send) detail", 
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n"
       "Debug option set detaied information\n")

DEFSH (VTYSH_OSPFD, area_nssa_t_always_cmd_vtysh, 
       "area A.B.C.D nssa translate-always", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR to always translate\n")

DEFSH (VTYSH_BGPD, set_origin_cmd_vtysh, 
       "set origin (egp|igp|incomplete)", 
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_route_map_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-map WORD (in|out)", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")

DEFSH (VTYSH_BGPD, bgp_redistribute_rip_cmd_vtysh, 
       "redistribute rip", 
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_candidate_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa no-summary translate-candidate", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  translation election\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_regexp_cmd_vtysh, 
       "show ip bgp regexp .LINE", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_external_inter_cmd_vtysh, 
       "distance ospf external <1-255> inter-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "External routes\n"
       "Distance for external routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n")

DEFSH (VTYSH_BGPD, match_ipv6_address_prefix_list_cmd_vtysh, 
       "match ipv6 address prefix-list WORD", 
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_spf_node_cmd_vtysh, 
       "show ipv6 ospf6 spf node", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Shortest Path First caculation\n"
       "vertex infomation\n"
       )

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_prefix_longer_cmd_vtysh, 
       "show ipv6 prefix-list WORD X:X::X:X/M longer", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Lookup longer prefix\n")

DEFSH (VTYSH_RIPD, rip_distance_source_cmd_vtysh, 
       "distance <1-255> A.B.C.D/M", 
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")

DEFSH (VTYSH_RIPNGD, ripng_network_cmd_vtysh, 
       "network IF_OR_ADDR", 
       "RIPng enable on specified interface or network.\n"
       "Interface or address")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_cost_cmd_vtysh, 
       "ipv6 ospf6 cost COST", 
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "<1-65535> Cost\n"
       )

DEFSH (VTYSH_RIPNGD, default_information_originate_cmd_vtysh, 
       "default-information originate", 
       "Default route information\n"
       "Distribute default route\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_connected_routemap_cmd_vtysh, 
       "no ipv6 bgp redistribute connected route-map WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, neighbor_remote_as_cmd_vtysh, 
       NEIGHBOR_CMD "remote-as <1-65535>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_metric_type_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> metric-type (1|2) route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_weight_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) weight", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set default weight for routes from this neighbor\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_default_originate_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) default-originate", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Originate default route to this neighbor\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_soft_reconfiguration_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) soft-reconfiguration inbound", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")

DEFSH (VTYSH_RIPD, rip_passive_interface_cmd_vtysh, 
       "passive-interface IFNAME", 
       "Suppress routing updates on an interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, ipv6_mbgp_neighbor_routes_cmd_vtysh, 
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) routes", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFSH (VTYSH_BGPD, no_ipv6_aggregate_address_summary_only_cmd_vtysh, 
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_update_source_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) update-source WORD", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Source of routing updates\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_soft_out_cmd_vtysh, 
       "clear ip bgp <1-65535> soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPFD, no_ip_ospf_dead_interval_cmd_vtysh, 
       "no ip ospf dead-interval", 
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Interval after which a neighbor is declared dead\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp)", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_vpnv4_in_cmd_vtysh, 
       "clear ip bgp <1-65535> vpnv4 unicast in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_type_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric-type (1|2)", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_RIPD, send_lifetime_duration_month_day_cmd_vtysh, 
       "send-lifetime HH:MM:SS MONTH <1-31> <1993-2035> duration <1-2147483646>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")

DEFSH (VTYSH_RIPD, no_debug_rip_events_cmd_vtysh, 
       "no debug rip events", 
       NO_STR
       DEBUG_STR
       RIP_STR
       "RIP events\n")

DEFSH (VTYSH_BGPD, set_community_delete_cmd_vtysh, 
       "set community-delete WORD", 
       SET_STR
       "BGP community attribute (Delete from the existing community)\n"
       "Community list (Permitted communities are deleted)\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_mode_type_cmd_vtysh, 
       "no ip rip authentication mode (md5|text)", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n"
       "Keyed message digest\n"
       "Clear text authentication\n")

DEFSH (VTYSH_RIPD, debug_rip_zebra_cmd_vtysh, 
       "debug rip zebra", 
       DEBUG_STR
       RIP_STR
       "RIP and ZEBRA communication\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_preference_cmd_vtysh, 
       /* "ip irdp preference <-2147483648-2147483647>",  */
       "ip irdp preference <0-2147483647>", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set default preference level for this interface\n"
       "Preference level\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ip_prefix_list_name_cmd_vtysh, 
       "clear ip prefix-list WORD", 
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_kernel_cmd_vtysh, 
       "redistribute kernel", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_ZEBRA, no_ip_route_pref_cmd_vtysh, 
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>", 
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community2_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPFD, debug_ospf_nsm_sub_cmd_vtysh, 
       "debug ospf nsm (status|events|timers)", 
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_neighbors_peer_cmd_vtysh, 
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X)", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_ge_le_cmd_vtysh, 
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, no_set_ipv6_nexthop_local_val_cmd_vtysh, 
       "no set ipv6 next-hop local X:X::X:X", 
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_OSPFD, no_area_shortcut_decimal_cmd_vtysh, 
       "no area <0-4294967295> shortcut (enable|disable)", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure the area's shortcutting mode\n"
       "Deconfigure enabled shortcutting through the area\n"
       "Deconfigure disabled shortcutting through the area\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_description_cmd_vtysh, 
       "no ip prefix-list WORD description", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")

DEFSH (VTYSH_OSPFD, no_area_authentication_decimal_cmd_vtysh, 
       "no area <0-4294967295> authentication", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_access_list_remark_arg_cmd_vtysh, 
       "no access-list WORD remark .LINE", 
       NO_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Access list entry comment\n"
       "Comment up to 100 characters\n")

DEFSH (VTYSH_BGPD, debug_bgp_fsm_cmd_vtysh, 
       "debug bgp fsm", 
       DEBUG_STR
       BGP_STR
       "BGP Finite State Machine\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_packet_send_recv_cmd_vtysh, 
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

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_bgp_cmd_vtysh, 
       "no redistribute bgp", 
       NO_STR
       "Redistribute control\n"
       "BGP route\n")

DEFSH (VTYSH_BGPD, no_bgp_scan_time_val_cmd_vtysh, 
       "no bgp scan-time <5-60>", 
       NO_STR
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n"
       "Scanner interval (seconds)\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_description_cmd_vtysh, 
       "ipv6 prefix-list WORD description .LINE", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFSH (VTYSH_OSPFD, debug_ospf_zebra_cmd_vtysh, 
       "debug ospf zebra", 
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n")

DEFSH (VTYSH_RIPD, ip_rip_send_version_cmd_vtysh, 
       "ip rip send version (1|2)", 
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement transmission\n"
       "Version control\n"
       "RIP version 1\n"
       "RIP version 2\n")

DEFSH (VTYSH_BGPD, no_ip_as_path_cmd_vtysh, 
       "no ip as-path access-list WORD (deny|permit) .LINE", 
       NO_STR
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "A regular-expression to match the BGP AS paths\n")

DEFSH (VTYSH_OSPFD, area_range_subst_cmd_vtysh, 
       "area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "announce area range as another prefix\n"
       "network prefix to be announced instead of range\n")

DEFSH (VTYSH_BGPD, no_set_aspath_prepend_val_cmd_vtysh, 
       "no set as-path prepend .<1-65535>", 
       NO_STR
       SET_STR
       "Prepend string for a BGP AS-path attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")

DEFSH (VTYSH_BGPD, no_set_ecommunity_rt_val_cmd_vtysh, 
       "no set extcommunity rt .ASN:nn_or_IP-address:nn", 
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extened communityt\n"
       "VPN extended community\n")

DEFSH (VTYSH_RIPD, rip_offset_list_ifname_cmd_vtysh, 
       "offset-list WORD (in|out) <0-16> IFNAME", 
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n"
       "Interface to match\n")

DEFSH (VTYSH_OSPFD, ip_ospf_retransmit_interval_cmd_vtysh, 
       "ip ospf retransmit-interval <3-65535>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_prefix_cmd_vtysh, 
       "show ip bgp A.B.C.D/M", 
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_RIPD, no_rip_redistribute_type_metric_cmd_vtysh, 
       "no redistribute (kernel|connected|static|ospf|bgp) metric <0-16>", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric\n"
       "Metric value\n")

DEFSH (VTYSH_BGPD, no_set_ipv6_nexthop_global_cmd_vtysh, 
       "no set ipv6 next-hop global", 
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_connected_cmd_vtysh, 
       "redistribute connected", 
       "Redistribute control\n"
       "Connected route\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community_list_cmd_vtysh, 
       "show ipv6 mbgp community-list WORD", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")

DEFSH (VTYSH_OSPFD, neighbor_priority_pollinterval_cmd_vtysh, 
       "neighbor A.B.C.D priority <0-255> poll-interval <1-65535>", 
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community3_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_set_atomic_aggregate_cmd_vtysh, 
       "no set atomic-aggregate", 
       NO_STR
       SET_STR
       "BGP atomic aggregate attribute\n" )

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_id_adv_router_cmd_vtysh, 
       "show ip ospf database (nssa-external|asbr-summary|external|network|router|summary) A.B.C.D adv-router A.B.C.D", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "Network link states\n"
       "Router link states\n"
       "Network summary link states\n"
       "Link State ID (as an IP address)\n"
       "Advertising Router link states\n"
       "Advertising Router (as an IP address)\n")

DEFSH (VTYSH_BGPD, neighbor_description_cmd_vtysh, 
       NEIGHBOR_CMD "description .LINE", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

DEFSH (VTYSH_BGPD, no_neighbor_ebgp_multihop_cmd_vtysh, 
       NO_NEIGHBOR_CMD "ebgp-multihop", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_description_arg_cmd_vtysh, 
       "no ip prefix-list WORD description .LINE", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_timers_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) timers", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "BGP per neighbor timers\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_bgp_cmd_vtysh, 
       "redistribute bgp", 
       "Redistribute\n"
       "RIPng route\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_connected_routemap_cmd_vtysh, 
       "redistribute connected route-map WORD", 
       "Redistribute\n"
       "Connected routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_in_cmd_vtysh, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor address to clear\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_RIPD, accept_lifetime_duration_day_month_cmd_vtysh, 
       "accept-lifetime HH:MM:SS <1-31> MONTH <1993-2035> duration <1-2147483646>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")

DEFSH (VTYSH_ZEBRA, no_shutdown_if_cmd_vtysh, 
       "no shutdown", 
       NO_STR
       "Shutdown the selected interface\n")

DEFSH (VTYSH_RIPD, no_rip_redistribute_type_metric_routemap_cmd_vtysh, 
       "no redistribute (kernel|connected|static|ospf|bgp) metric <0-16> route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD, rip_offset_list_cmd_vtysh, 
       "offset-list WORD (in|out) <0-16>", 
       "Modify RIP metric\n"
       "Access-list name\n"
       "For incoming updates\n"
       "For outgoing updates\n"
       "Metric value\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_nd_send_ra_cmd_vtysh, 
       "no ipv6 nd send-ra", 
       NO_STR
       IP_STR
       "Neighbor discovery\n"
       "Send router advertisement\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_ripng_routemap_cmd_vtysh, 
       "redistribute ripng route-map WORD", 
       "Redistribute\n"
       "RIPng routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, neighbor_set_peer_group_cmd_vtysh, 
       NEIGHBOR_CMD "peer-group WORD", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group"
       "peer-group name\n")

DEFSH (VTYSH_OSPFD, no_area_authentication_cmd_vtysh, 
       "no area A.B.C.D authentication", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")

DEFSH (VTYSH_BGPD, no_router_bgp_cmd_vtysh, 
       "no router bgp <1-65535>", 
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR)

DEFSH (VTYSH_OSPFD, area_stub_cmd_vtysh, 
       "area A.B.C.D stub", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")

DEFSH (VTYSH_BGPD, undebug_bgp_keepalive_cmd_vtysh, 
       "undebug bgp keepalives", 
       UNDEBUG_STR
       BGP_STR
       "BGP keepalives\n")

DEFSH (VTYSH_BGPD, neighbor_send_community_cmd_vtysh, 
       NEIGHBOR_CMD "send-community", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n")

DEFSH (VTYSH_RIPD, send_lifetime_month_day_day_month_cmd_vtysh, 
       "send-lifetime HH:MM:SS MONTH <1-31> <1993-2035> HH:MM:SS <1-31> MONTH <1993-2035>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_RIPD, send_lifetime_day_month_month_day_cmd_vtysh, 
       "send-lifetime HH:MM:SS <1-31> MONTH <1993-2035> HH:MM:SS MONTH <1-31> <1993-2035>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_OSPFD, no_network_area_cmd_vtysh, 
       "no network A.B.C.D/M area A.B.C.D", 
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n")

DEFSH (VTYSH_OSPFD, no_area_stub_nosum_cmd_vtysh, 
       "no area A.B.C.D stub no-summary", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_vpnv4_out_cmd_vtysh, 
       "clear ip bgp * vpnv4 unicast out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_OSPF6D, ipv6_ospf6_deadinterval_cmd_vtysh, 
       "ipv6 ospf6 dead-interval ROUTER_DEAD_INTERVAL", 
       IP6_STR
       OSPF6_STR
       "Interval after which a neighbor is declared dead\n"
       SECONDS_STR
       )

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_send_community_extended_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community extended", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_route_ospf6_new_cmd_vtysh, 
       "show ipv6 route ospf6", 
       SHOW_STR
       IP6_STR
       "Routing table\n"
       OSPF6_STR
       )

DEFSH (VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD|VTYSH_OSPF6D|VTYSH_BGPD, no_set_metric_cmd_vtysh, 
       "no set metric", 
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_nssa_cmd_vtysh, 
       "no debug ospf nssa", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_t_never_cmd_vtysh, 
       "area A.B.C.D nssa no-summary translate-never", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa,  nor translation\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community_list_exact_cmd_vtysh, 
       "show ipv6 bgp community-list WORD exact-match", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")

DEFSH (VTYSH_BGPD, no_neighbor_port_val_cmd_vtysh, 
       NO_NEIGHBOR_CMD "port <0-65535>", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_ripng_cmd_vtysh, 
       "ipv6 bgp redistribute ripng", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Routing Information Protocol (RIPng)\n")

DEFSH (VTYSH_OSPFD, no_area_stub_cmd_vtysh, 
       "no area A.B.C.D stub", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community3_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_connected_cmd_vtysh, 
       "redistribute connected", 
       "Redistribute\n"
       "Connected route\n")

DEFSH (VTYSH_OSPFD, ip_ospf_authentication_key_cmd_vtysh, 
       "ip ospf authentication-key AUTH_KEY", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_intra_inter_cmd_vtysh, 
       "distance ospf intra-area <1-255> inter-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_interface_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) interface WORD", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_ospf6_cmd_vtysh, 
       "ipv6 bgp redistribute ospf6", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Open Shortest Path First (OSPFv3)\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_send_community_extended_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) send-community extended", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")

DEFSH (VTYSH_ZEBRA, no_ipv6_address_cmd_vtysh, 
       "no ipv6 address IPV6PREFIX/M", 
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")

DEFSH (VTYSH_BGPD, debug_bgp_normal_cmd_vtysh, 
       "debug bgp", 
       DEBUG_STR
       BGP_STR)

DEFSH (VTYSH_BGPD, no_aggregate_address_cmd_vtysh, 
       "no aggregate-address A.B.C.D/M", 
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_seq_ge_cmd_vtysh, 
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, no_neighbor_maximum_prefix_cmd_vtysh, 
       NO_NEIGHBOR_CMD "maximum-prefix [NUMBER]", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community4_exact_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_ge_cmd_vtysh, 
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, bgp_bestpath_med2_cmd_vtysh, 
       "bgp bestpath med confed missing-as-worst", 
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_regexp_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_filter_list_cmd_vtysh, 
       "show ipv6 bgp filter-list WORD", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFSH (VTYSH_BGPD, neighbor_activate_cmd_vtysh, 
       NEIGHBOR_CMD "activate", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Enable the Address Family for this Neighbor\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_distribute_list_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) distribute-list WORD (in|out)", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "IPv6 Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_metric_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214>", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n")

DEFSH (VTYSH_BGPD, no_bgp_scan_time_cmd_vtysh, 
       "no bgp scan-time", 
       NO_STR
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community4_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) ebgp-multihop <1-255>", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_seq_le_ge_cmd_vtysh, 
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_zebra_cmd_vtysh, 
       "no debug ospf zebra", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n")

DEFSH (VTYSH_RIPD, no_rip_distance_source_access_list_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M WORD", 
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")

DEFSH (VTYSH_OSPF6D, ospf6_redistribute_kernel_routemap_cmd_vtysh, 
       "redistribute kernel route-map WORD", 
       "Redistribute\n"
       "Static routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_version_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) version (4|4+|4-)", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP version\n"
       "Border Gateway Protocol 4\n"
       "Multiprotocol Extensions for BGP-4\n"
       "Multiprotocol Extensions for BGP-4(Old Draft)\n")

DEFSH (VTYSH_OSPFD, no_area_range_subst_cmd_vtysh, 
       "no area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "Do not advertise this range\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")

DEFSH (VTYSH_BGPD, no_set_originator_id_cmd_vtysh, 
       "no set originator-id", 
       NO_STR
       SET_STR
       "BGP originator ID attribute\n")

DEFSH (VTYSH_BGPD, ipv6_neighbor_override_capability_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) override-capability", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Override capability negotiation result\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_nexthop_self_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) next-hop-self", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Disable the next hop calculation for this neighbor\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_unicast_multicast_cmd_vtysh,  
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) remote-as <1-65535> nlri unicast multicast", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n"
       "Configure for multicast routes\n")

DEFSH (VTYSH_BGPD, no_aggregate_address_summary_only_cmd_vtysh, 
       "no aggregate-address A.B.C.D/M summary-only", 
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_multicast_cmd_vtysh, 
       "ip irdp multicast", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Send IRDP advertisement to the multicast address\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ipv6_prefix_list_seq_ge_cmd_vtysh, 
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>", 
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_OSPFD, area_vlink_md5_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D message-digest-key <1-255> md5 KEY", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_type_metric_routemap_cmd_vtysh, 
       "default-information originate always metric-type (1|2) metric <0-16777214> route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD, no_ip_rip_authentication_mode_cmd_vtysh, 
       "no ip rip authentication mode", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication mode\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_no_set_metric_type_cmd_vtysh, 
       "no set metric-type (type-1|type-2)", 
       NO_STR
       "Set value\n"
       "Type of metric\n"
       "OSPF6 external type 1 metric\n"
       "OSPF6 external type 2 metric\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community_exact_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_version_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) version", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Neighbor's BGP version\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_metric_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_address_cmd_vtysh, 
       "ip irdp address A.B.C.D", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Specify IRDP address and preference to proxy-advertise\n"
       "Set IRDP address for proxy-advertise\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_metric_type_cmd_vtysh, 
       "default-information originate always metric <0-16777214> metric-type (1|2)", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_BGPD, bgp_network_multicast_cmd_vtysh, 
       "network A.B.C.D/M nlri multicast", 
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_inter_intra_external_cmd_vtysh, 
       "distance ospf inter-area <1-255> intra-area <1-255> external <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "External routes\n"
       "Distance for external routes\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_packet_send_recv_detail_cmd_vtysh, 
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

DEFSH (VTYSH_BGPD, no_match_nlri_cmd_vtysh, 
       "no match nlri (multicast|unicast)", 
       NO_STR
       MATCH_STR
       "Match Network Layer Reachability Information\n"
       "Multicast\n"
       "Unicast\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_neighbor_cmd_vtysh, 
       "show ipv6 ospf6 neighbor", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       )

DEFSH (VTYSH_OSPFD, ospf_default_metric_cmd_vtysh, 
       "default-metric <0-16777214>", 
       "Set metric of redistributed routes\n"
       "Default metric\n")

DEFSH (VTYSH_OSPFD, ospf_message_digest_key_cmd_vtysh, 
       "ospf message-digest-key <1-255> md5 KEY", 
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_ipv4_soft_out_cmd_vtysh, 
       "clear ip bgp * ipv4 (unicast|multicast) soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_description_arg_cmd_vtysh, 
       "no ipv6 prefix-list WORD description .LINE", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFSH (VTYSH_OSPFD, area_authentication_decimal_cmd_vtysh, 
       "area <0-4294967295> authentication", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")

DEFSH (VTYSH_RIPNGD, no_ripng_route_cmd_vtysh, 
       "no route IPV6ADDR", 
       NO_STR
       "Static route setup\n"
       "Delete static RIPng route announcement\n")

DEFSH (VTYSH_OSPFD|VTYSH_OSPF6D, passive_interface_cmd_vtysh, 
       "passive-interface IFNAME", 
       "Suppress routing updates on an interface\n"
       IFNAME_STR
       )

DEFSH (VTYSH_OSPFD, debug_ospf_packet_send_recv_cmd_vtysh, 
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

DEFSH (VTYSH_BGPD, neighbor_route_server_client_cmd_vtysh, 
       NEIGHBOR_CMD "route-server-client", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Configure a neighbor as Route Server client\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_filter_list_cmd_vtysh, 
       "show ip bgp filter-list WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community4_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_ipv4_soft_out_cmd_vtysh, 
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_view_route_cmd_vtysh, 
       "show ip bgp view WORD A.B.C.D", 
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Network in the BGP routing table to display\n")

DEFSH (VTYSH_RIPD, no_rip_timers_cmd_vtysh, 
       "no timers basic", 
       NO_STR
       "Adjust routing timers\n"
       "Basic routing protocol update timers\n")

DEFSH (VTYSH_OSPFD, area_vlink_param_auth_cmd_vtysh, 
       "area A.B.C.D virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535> authentication-key AUTH_KEY", 
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_BGPD, set_ipv6_nexthop_local_cmd_vtysh, 
       "set ipv6 next-hop local X:X::X:X", 
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_seq_le_ge_cmd_vtysh, 
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_prefix_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_rip_routemap_cmd_vtysh, 
       "no redistribute rip route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, no_debug_ospf_lsa_sub_cmd_vtysh, 
       "no debug ospf lsa (generate|flooding|refresh)", 
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Refres\n")

DEFSH (VTYSH_RIPD, accept_lifetime_duration_month_day_cmd_vtysh, 
       "accept-lifetime HH:MM:SS MONTH <1-31> <1993-2035> duration <1-2147483646>", 
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")

DEFSH (VTYSH_BGPD, no_match_ip_next_hop_cmd_vtysh, 
       "no match ip next-hop WORD", 
       NO_STR
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP access-list name\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_route_map_cmd_vtysh, 
       "no route-map WORD (deny|permit) <1-65535>", 
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map denies set operations\n"
       "Route map permits set operations\n"
       "Sequence to insert to/delete from existing route-map entry\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_soft_out_cmd_vtysh, 
       "clear ipv6 bgp <1-65535> soft out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, neighbor_shutdown_cmd_vtysh, 
       NEIGHBOR_CMD "shutdown", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Administratively shut down this neighbor\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD, match_ip_nexthop_cmd_vtysh, 
       "match ip next-hop WORD", 
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP access-list name\n")

DEFSH (VTYSH_RIPD, ip_rip_authentication_key_chain_cmd_vtysh, 
       "ip rip authentication key-chain LINE", 
       IP_STR
       "Routing Information Protocol\n"
       "Authentication control\n"
       "Authentication key-chain\n"
       "name of key-chain\n")

DEFSH (VTYSH_BGPD, no_ip_as_path_all_cmd_vtysh, 
       "no ip as-path access-list WORD", 
       NO_STR
       IP_STR
       "BGP autonomous system path filter\n"
       "Specify an access list name\n"
       "Regular expression access list name\n")

DEFSH (VTYSH_OSPFD, no_auto_cost_reference_bandwidth_cmd_vtysh, 
       "no auto-cost reference-bandwidth", 
       NO_STR
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_cmd_vtysh, 
       "show ip bgp", 
       SHOW_STR
       IP_STR
       BGP_STR)

DEFSH (VTYSH_BGPD, no_neighbor_weight_cmd_vtysh, 
       NO_NEIGHBOR_CMD "weight", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Set default weight for routes from this neighbor\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_prefix_longer_cmd_vtysh, 
       "show ip prefix-list WORD A.B.C.D/M longer", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Lookup longer prefix\n")

DEFSH (VTYSH_RIPNGD, no_debug_ripng_zebra_cmd_vtysh, 
       "no debug ripng zebra", 
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")

DEFSH (VTYSH_BGPD, match_ipv6_next_hop_cmd_vtysh, 
       "match ipv6 next-hop X:X::X:X", 
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_vpnv4_soft_in_cmd_vtysh, 
       "clear ip bgp <1-65535> vpnv4 unicast soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, bgp_bestpath_med3_cmd_vtysh, 
       "bgp bestpath med missing-as-worst confed", 
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_soft_in_cmd_vtysh, 
       "clear ip bgp <1-65535> soft in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_RIPD, send_lifetime_month_day_month_day_cmd_vtysh, 
       "send-lifetime HH:MM:SS MONTH <1-31> <1993-2035> HH:MM:SS MONTH <1-31> <1993-2035>", 
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")

DEFSH (VTYSH_BGPD, no_set_nlri_cmd_vtysh, 
       "no set nlri", 
       NO_STR
       SET_STR
       "Network Layer Reachability Information\n")

DEFSH (VTYSH_RIPD, key_string_cmd_vtysh, 
       "key-string LINE", 
       "Set key string\n"
       "The key\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_soft_out_cmd_vtysh, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) soft out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_normal_cmd_vtysh, 
       "no debug bgp", 
       NO_STR
       DEBUG_STR
       BGP_STR)

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_ipv4_out_cmd_vtysh, 
       "clear ip bgp <1-65535> ipv4 (unicast|multicast) out", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_ZEBRA, shutdown_if_cmd_vtysh, 
       "shutdown", 
       "Shutdown the selected interface\n")

DEFSH (VTYSH_OSPFD, no_set_metric_type_cmd_vtysh, 
       "no set metric-type (1|2)", 
       SET_STR
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_BGPD, no_neighbor_description_val_cmd_vtysh, 
       NO_NEIGHBOR_CMD "description .LINE", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_ripng_cmd_vtysh, 
       "no redistribute ripng", 
       NO_STR
       "Redistribute control\n"
       "RIPng route\n")

DEFSH (VTYSH_BGPD, no_bgp_distance2_cmd_vtysh, 
       "no distance bgp", 
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_metric_type_routemap_cmd_vtysh, 
       "default-information originate metric <0-16777214> metric-type (1|2) route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPF6D, show_zebra_cmd_vtysh, 
       "show zebra", 
       SHOW_STR
       "Zebra information\n")

DEFSH (VTYSH_BGPD, undebug_bgp_events_cmd_vtysh, 
       "undebug bgp events", 
       UNDEBUG_STR
       BGP_STR
       "BGP events\n")

DEFSH (VTYSH_BGPD, no_set_ecommunity_rt_cmd_vtysh, 
       "no set extcommunity rt", 
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extened communityt\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_static_cmd_vtysh, 
       "ipv6 bgp redistribute static", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Static routes\n")

DEFSH (VTYSH_BGPD, undebug_bgp_all_cmd_vtysh, 
       "undebug all bgp", 
       UNDEBUG_STR
       "Enable all debugging\n"
       BGP_STR)

DEFSH (VTYSH_BGPD, no_set_aggregator_as_cmd_vtysh, 
       "no set aggregator as", 
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n")

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_ospf6_cmd_vtysh, 
       "no redistribute ospf6", 
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")

DEFSH (VTYSH_BGPD, no_set_local_pref_cmd_vtysh, 
       "no set local-preference", 
       NO_STR
       SET_STR
       "BGP local preference path attribute\n")

DEFSH (VTYSH_OSPFD, area_vlink_param_md5_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535> message-digest-key <1-255> md5 KEY", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFSH (VTYSH_OSPFD, debug_ospf_packet_send_recv_detail_cmd_vtysh, 
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

DEFSH (VTYSH_OSPFD, show_ip_ospf_interface_cmd_vtysh, 
       "show ip ospf interface [INTERFACE]", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Interface information\n"
       "Interface name\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_name_cmd_vtysh, 
       "show ip prefix-list WORD", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")

DEFSH (VTYSH_BGPD, no_bgp_router_id_cmd_vtysh, 
       "no bgp router-id", 
       NO_STR
       "BGP specific commands\n"
       "Override configured router identifier\n")

DEFSH (VTYSH_OSPFD, ospf_compatible_rfc1583_cmd_vtysh, 
       "compatible rfc1583", 
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_type_metric_cmd_vtysh, 
       "default-information originate metric-type (1|2) metric <0-16777214>", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n"
       "OSPF default metric\n"
       "OSPF metric\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_filter_list_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) filter-list WORD (in|out)", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_cmd_vtysh, 
       "ip irdp", 
       IP_STR
       "ICMP Router discovery on this interface\n")

DEFSH (VTYSH_BGPD, no_dump_bgp_routes_cmd_vtysh, 
       "no dump bgp routes-mrt [PATH] [INTERVAL]", 
       NO_STR
       "Dump packet\n"
       "BGP packet dump\n"
       "Dump whole BGP routing table\n")

DEFSH (VTYSH_ZEBRA, ipv6_route_ifname_pref_cmd_vtysh, 
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>", 
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::1/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_peer_group_cmd_vtysh,  
       "clear ip bgp peer-group WORD", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear BGP connections of peer-group\n"
       "BGP peer-group name to clear connection\n")

DEFSH (VTYSH_RIPD, no_rip_default_metric_val_cmd_vtysh, 
       "no default-metric <1-16>", 
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_prefix_list_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) prefix-list WORD (in|out)", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_BGPD, no_match_ipv6_address_prefix_list_cmd_vtysh, 
       "no match ipv6 address prefix-list WORD", 
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_ge_le_cmd_vtysh, 
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_OSPFD, no_ospf_redistribute_ospf_cmd_vtysh, 
       "no redistribute ospf", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Open Shortest Path First (OSPF)\n")

DEFSH (VTYSH_BGPD, no_set_community_delete_val_cmd_vtysh, 
       "no set community-delete WORD", 
       NO_STR
       SET_STR
       "BGP community attribute (Delete from the existing community)\n"
       "Community list\n")

DEFSH (VTYSH_ZEBRA, ipv6_route_ifname_cmd_vtysh, 
       "ipv6 route X:X::X:X/M X:X::X:X IFNAME", 
       "IP information\n"
       "IP routing set\n"
       "IP Address\n"
       "Destination IP Address\n"
       "Destination interface name\n")

DEFSH (VTYSH_OSPFD, debug_ospf_lsa_sub_cmd_vtysh, 
       "debug ospf lsa (generate|flooding|refresh)", 
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Refresh\n")

DEFSH (VTYSH_OSPFD, ip_ospf_hello_interval_cmd_vtysh, 
       "ip ospf hello-interval <1-65535>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between HELLO packets\n"
       "Seconds\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_capability_route_refresh_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) capability route-refresh", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Outbound capability configuration\n"
       "Advertise route-refresh capability to this neighbor\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_soft_cmd_vtysh, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) soft", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor address to clear\n"
       "Soft reconfig\n")

DEFSH (VTYSH_OSPFD, area_range_suppress_cmd_vtysh, 
       "area A.B.C.D range IPV4_PREFIX suppress", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_view_cmd_vtysh, 
       "show ip bgp view WORD", 
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n")

DEFSH (VTYSH_OSPFD, area_nssa_cmd_vtysh, 
       "area A.B.C.D nssa", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n")

DEFSH (VTYSH_OSPF6D, show_version_ospf6_cmd_vtysh, 
       "show version ospf6", 
       SHOW_STR
       "Displays ospf6d version\n")

DEFSH (VTYSH_BGPD, no_debug_bgp_all_cmd_vtysh, 
       "no debug all bgp", 
       NO_STR
       DEBUG_STR
       "Enable all debugging\n"
       BGP_STR)

DEFSH (VTYSH_BGPD, no_neighbor_send_community_cmd_vtysh, 
       NO_NEIGHBOR_CMD "send-community", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n")

DEFSH (VTYSH_OSPFD, no_area_import_list_decimal_cmd_vtysh, 
       "no area <0-4294967295> import-list NAME", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFSH (VTYSH_RIPD|VTYSH_RIPNGD|VTYSH_OSPFD, match_interface_cmd_vtysh, 
       "match interface WORD", 
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community4_exact_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_neighbor_timers_cmd_vtysh, 
       NO_NEIGHBOR_CMD "timers", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_summary_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) summary", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFSH (VTYSH_BGPD, no_set_ecommunity_soo_cmd_vtysh, 
       "no set extcommunity soo", 
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n")

DEFSH (VTYSH_BGPD, neighbor_remote_as_multicast_cmd_vtysh, 
       NEIGHBOR_CMD "remote-as <1-65535> nlri multicast", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for multicast routes\n")

DEFSH (VTYSH_BGPD, bgp_distance_cmd_vtysh, 
       "distance bgp <1-255> <1-255> <1-255>", 
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")

DEFSH (VTYSH_BGPD, neighbor_remote_as_passive_cmd_vtysh, 
       NEIGHBOR_CMD "remote-as <1-65535> passive", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Passive mode\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_detail_all_cmd_vtysh, 
       "show ip ospf neighbor detail all", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "detail of all neighbors\n"
       "include down status neighbor\n")

DEFSH (VTYSH_OSPFD, no_area_nssa_cmd_vtysh, 
       "no area A.B.C.D nssa", 
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n")

DEFSH (VTYSH_BGPD, set_atomic_aggregate_cmd_vtysh, 
       "set atomic-aggregate", 
       SET_STR
       "BGP atomic aggregate attribute\n" )

DEFSH (VTYSH_BGPD, no_bgp_distance_source_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M", 
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_paths_cmd_vtysh, 
       "show ip bgp paths", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Path information\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_le_cmd_vtysh, 
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_kernel_cmd_vtysh, 
       "ipv6 bgp redistribute kernel", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n")

DEFSH (VTYSH_BGPD, no_neighbor_route_map_cmd_vtysh, 
       NO_NEIGHBOR_CMD "route-map WORD (in|out)", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_database_turnover_summary_cmd_vtysh, 
       "show ipv6 ospf6 database turnover-summary", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Database summary\n"
       "Statistics summary of Database turn over\n"
       )

DEFSH (VTYSH_BGPD, no_ipv6_bgp_network_multicast_cmd_vtysh, 
       "no ipv6 bgp network X:X::X:X/M nlri multicast", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "NLRI configuration\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_cmd_vtysh, 
       "clear ipv6 bgp *", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n")

DEFSH (VTYSH_OSPFD, area_nssa_nosum_cmd_vtysh, 
       "area A.B.C.D nssa no-summary", 
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

DEFSH (VTYSH_OSPFD, ospf_default_information_originate_always_metric_routemap_cmd_vtysh, 
       "default-information originate always metric <0-16777214> route-map WORD", 
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, ospf_network_cmd_vtysh, 
       "ospf network (broadcast|non-broadcast|point-to-multipoint|point-to-point)", 
       "OSPF interface commands\n"
       "Network type\n"
       "Specify OSPF broadcast multi-access network\n"
       "Specify OSPF NBMA network\n"
       "Specify OSPF point-to-multipoint network\n"
       "Specify OSPF point-to-point network\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_interface_cmd_vtysh, 
       "show ipv6 ospf6 interface", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       )

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_community_exact_cmd_vtysh, 
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_bgp_default_local_preference_val_cmd_vtysh, 
       "no bgp default local-preference <0-4294967295>", 
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_ge_le_cmd_vtysh, 
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_ZEBRA, show_ipv6_cmd_vtysh, 
       "show ipv6 route [IPV6_ADDRESS]", 
       SHOW_STR
       "IP information\n"
       "IP routing table\n"
       "IP Address\n"
       "IP Netmask\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD, no_match_ip_nexthop_cmd_vtysh, 
       "no match ip next-hop WORD", 
       NO_STR
       MATCH_STR
       IP_STR
       "Next hop address\n"
       "IP access-list name\n")

DEFSH (VTYSH_BGPD, ipv4_neighbor_advertised_route_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_exact_cmd_vtysh, 
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, area_vlink_param_auth_decimal_cmd_vtysh, 
       "area <0-4294967295> virtual-link A.B.C.D hello-interval <1-65535> retransmit-interval <3-65535> transmit-delay <1-65535> dead-interval <1-65535> authentication-key AUTH_KEY", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"       
       "Link state transmit delay\n"
       "Seconds\n"
       "Interval after which a neighbor is declared dead\n"
       "Seconds\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

DEFSH (VTYSH_ZEBRA, debug_zebra_packet_direct_cmd_vtysh, 
       "debug zebra packet (recv|send)", 
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")

DEFSH (VTYSH_BGPD, neighbor_send_community_extended_cmd_vtysh, 
       NEIGHBOR_CMD "send-community extended", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")

DEFSH (VTYSH_RIPD, no_rip_version_cmd_vtysh, 
       "no version", 
       NO_STR
       "Set routing protocol version\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_neighbor_route_server_client_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-server-client", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Server client\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_self_cmd_vtysh, 
       "show ip ospf database (nssa-external|asbr-summary|external|network|router|summary) (self-originate|)", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "Network link states\n"
       "Router link states\n"
       "Network summary link states\n"
       "Self-originated link states\n")

DEFSH (VTYSH_BGPD, no_match_ip_address_prefix_list_cmd_vtysh, 
       "no match ip address prefix-list WORD", 
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFSH (VTYSH_BGPD, no_set_weight_cmd_vtysh, 
       "no set weight", 
       NO_STR
       SET_STR
       "BGP weight for routing table\n")

DEFSH (VTYSH_BGPD, no_neighbor_default_originate_cmd_vtysh, 
       NO_NEIGHBOR_CMD "default-originate", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Originate default route to this neighbor\n")

DEFSH (VTYSH_BGPD, no_set_aspath_prepend_cmd_vtysh, 
       "no set as-path prepend", 
       NO_STR
       SET_STR
       "Prepend string for a BGP AS-path attribute\n"
       "Prepend to the as-path\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_inter_external_intra_cmd_vtysh, 
       "distance ospf inter-area <1-255> external <1-255> intra-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_external_cmd_vtysh, 
       "distance ospf external <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "External routes\n"
       "Distance for external routes\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_static_cmd_vtysh, 
       "redistribute static", 
       "Redistribute control\n"
       "Static route\n")

DEFSH (VTYSH_BGPD, no_neighbor_update_source_cmd_vtysh, 
       NO_NEIGHBOR_CMD "update-source", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Source of routing updates\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_bgp_client_to_client_reflection_cmd_vtysh, 
       "no bgp client-to-client reflection", 
       NO_STR
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_adv_router_cmd_vtysh, 
       "show ip ospf database (nssa-external|asbr-summary|external|network|router|summary) adv-router A.B.C.D", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "Network link states\n"
       "Router link states\n"
       "Network summary link states\n"
       "Advertising Router link states\n"
       "Advertising Router (as an IP address)\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_community_info_cmd_vtysh, 
       "show ip bgp community-info", 
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")

DEFSH (VTYSH_BGPD, no_bgp_always_compare_med_cmd_vtysh, 
       "no bgp always-compare-med", 
       NO_STR
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, access_list_exact_cmd_vtysh, 
       "access-list WORD (deny|permit) A.B.C.D/M (exact-match|)", 
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 10.0.0.0/8\n"
       "Exact match of the prefixes\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_route_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")

DEFSH (VTYSH_RIPNGD, no_ripng_garbage_timer_cmd_vtysh, 
       "no garbage-timer SECOND", 
       NO_STR
       "Unset RIPng garbage timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_OSPFD, no_neighbor_priority_pollinterval_cmd_vtysh, 
       "no neighbor A.B.C.D priority <0-255> poll-interval <1-65535>", 
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

DEFSH (VTYSH_ZEBRA, no_debug_zebra_packet_direct_cmd_vtysh, 
       "no debug zebra packet (recv|send)", 
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")

DEFSH (VTYSH_BGPD, neighbor_distribute_list_cmd_vtysh, 
       NEIGHBOR_CMD "distribute-list WORD (in|out)", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Filter updates to/from this neighbor\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_all_ipv4_in_cmd_vtysh, 
       "clear ip bgp * ipv4 (unicast|multicast) in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, neighbor_timers_connect_cmd_vtysh, 
       NEIGHBOR_CMD "timers connect <0-65535>", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_set_metric_val_cmd_vtysh, 
       "no set metric <0-4294967295>", 
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")

DEFSH (VTYSH_OSPF6D, no_interface_cmd_vtysh, 
       "no interface IFNAME", 
       NO_STR
       "Disable routing on an IPv6 interface\n"
       IFNAME_STR
       )

DEFSH (VTYSH_RIPNGD, ripng_route_cmd_vtysh, 
       "route IPV6ADDR", 
       "Static route setup\n"
       "Set static RIPng route announcement\n")

DEFSH (VTYSH_OSPFD, ip_ospf_transmit_delay_cmd_vtysh, 
       "ip ospf transmit-delay <1-65535>", 
       "IP Information\n"
       "OSPF interface commands\n"
       "Link state transmit delay\n"
       "Seconds\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, match_metric_cmd_vtysh, 
       "match metric <0-4294967295>", 
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")

DEFSH (VTYSH_RIPD, no_rip_default_information_originate_cmd_vtysh, 
       "no default-information originate", 
       NO_STR
       "Control distribution of default route\n"
       "Distribute a default route\n")

DEFSH (VTYSH_BGPD, no_match_ipv6_address_cmd_vtysh, 
       "no match ipv6 address WORD", 
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")

DEFSH (VTYSH_ZEBRA, ip_route_pref_cmd_vtysh, 
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) <1-255>", 
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Distance value for this route\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_le_ge_cmd_vtysh, 
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_OSPFD, no_timers_spf_cmd_vtysh, 
       "no timers spf", 
       NO_STR
       "Adjust routing timers\n"
       "OSPF SPF timers\n")

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_static_cmd_vtysh, 
       "no redistribute static", 
       NO_STR
       "Redistribute control\n"
       "Static route\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_route_cmd_vtysh, 
       "show ipv6 mbgp X:X::X:X", 
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_seq_ge_cmd_vtysh, 
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>,  e.g.,  3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_soft_in_cmd_vtysh, 
       "clear ipv6 bgp (A.B.C.D|X:X::X:X) soft in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, set_ecommunity_soo_cmd_vtysh, 
       "set extcommunity soo .ASN:nn_or_IP-address:nn", 
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")

DEFSH (VTYSH_RIPD, no_rip_redistribute_rip_cmd_vtysh, 
       "no redistribute rip", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Routing Information Protocol (RIP)\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X)", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP Address\n"
       "IPv6 Address\n")

DEFSH (VTYSH_OSPFD, area_nssa_t_never_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa translate-never", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR to never translate\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_peer_cmd_vtysh,  
       "clear ipv6 bgp (A.B.C.D|X:X::X:X)", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP neighbor IPv6 address to clear\n")

DEFSH (VTYSH_RIPD, no_rip_passive_interface_cmd_vtysh, 
       "no passive-interface IFNAME", 
       "Suppress routing updates on an interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, neighbor_version_cmd_vtysh, 
       NEIGHBOR_CMD "version (4|4+|4-)", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP version\n"
       "Border Gateway Protocol 4\n"
       "Multiprotocol Extensions for BGP-4\n"
       "Multiprotocol Extensions for BGP-4(Old Draft)\n")

DEFSH (VTYSH_RIPD, no_ip_rip_receive_version_num_cmd_vtysh, 
       "no ip rip receive version (1|2)", 
       NO_STR
       IP_STR
       "Routing Information Protocol\n"
       "Advertisement reception\n"
       "Version control\n"
       "Version 1\n"
       "Version 2\n")

DEFSH (VTYSH_BGPD, neighbor_route_map_cmd_vtysh, 
       NEIGHBOR_CMD "route-map WORD (in|out)", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to outbound routes\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_ospf6_neighbor_ifname_nbrid_cmd_vtysh, 
       "show ipv6 ospf6 neighbor IFNAME NBR_ID", 
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       IFNAME_STR
       "A.B.C.D OSPF6 neighbor Router ID in IP address format\n"
       )

DEFSH (VTYSH_OSPFD, ospf_rfc1583_flag_cmd_vtysh, 
       "ospf rfc1583compatibility", 
       "OSPF specific commands\n"
       "Enable the RFC1583Compatibility flag\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_kernel_routemap_cmd_vtysh, 
       "ipv6 bgp redistribute kernel route-map WORD", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ipv6_prefix_list_detail_name_cmd_vtysh, 
       "show ipv6 prefix-list detail WORD", 
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")

DEFSH (VTYSH_OSPFD, no_ospf_message_digest_key_cmd_vtysh, 
       "no ospf message-digest-key <1-255>", 
       NO_STR
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_in_cmd_vtysh, 
       "clear ip bgp <1-65535> in", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, show_ip_prefix_list_prefix_first_match_cmd_vtysh, 
       "show ip prefix-list WORD A.B.C.D/M first-match", 
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "First matched prefix\n")

DEFSH (VTYSH_OSPF6D, show_ipv6_route_ospf6_external_cmd_vtysh, 
       "show ipv6 route ospf6 external", 
       SHOW_STR
       IP6_STR
       ROUTE_STR
       OSPF6_STR
       "redistributing External information\n"
       )

DEFSH (VTYSH_BGPD, neighbor_remote_as_unicast_cmd_vtysh, 
       NEIGHBOR_CMD "remote-as <1-65535> nlri unicast", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR
       "Network Layer Reachable Information\n"
       "Configure for unicast routes\n")

DEFSH (VTYSH_OSPFD, area_stub_decimal_cmd_vtysh, 
       "area <0-4294967295> stub", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

DEFSH (VTYSH_BGPD, neighbor_advertised_route_cmd_vtysh, 
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFSH (VTYSH_BGPD, undebug_bgp_filter_cmd_vtysh, 
       "undebug bgp filters", 
       UNDEBUG_STR
       BGP_STR
       "BGP filters\n")

DEFSH (VTYSH_BGPD, no_match_aspath_cmd_vtysh, 
       "no match as-path WORD", 
       NO_STR
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")

DEFSH (VTYSH_OSPFD, no_network_area_decimal_cmd_vtysh, 
       "no network A.B.C.D/M area <0-4294967295>", 
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")

DEFSH (VTYSH_OSPFD|VTYSH_OSPF6D, router_id_cmd_vtysh, 
       "router-id ROUTER_ID", 
       "Configure ospf Router-ID.\n"
       V4NOTATION_STR)

DEFSH (VTYSH_OSPFD, no_ospf_distance_source_cmd_vtysh, 
       "no distance <1-255> A.B.C.D/M", 
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")

DEFSH (VTYSH_BGPD, vpnv4_activate_cmd_vtysh, 
       "neighbor A.B.C.D activate", 
       NEIGHBOR_STR
       "Neighbor address\n"
       "Enable the Address Family for this Neighbor\n")

DEFSH (VTYSH_RIPD, no_rip_network_cmd_vtysh, 
       "no network (A.B.C.D/M|WORD)", 
       NO_STR
       "Enable routing on an IP network\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, no_ip_community_list_cmd_vtysh, 
       "no ip community-list WORD (deny|permit) .AA:NN", 
       NO_STR
       IP_STR
       "Add a community list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_kernel_cmd_vtysh, 
       "redistribute kernel", 
       "Redistribute control\n"
       "Kernel route\n")

DEFSH (VTYSH_BGPD, no_set_community_additive_val_cmd_vtysh, 
       "no set community-additive .AA:NN", 
       NO_STR
       SET_STR
       "BGP community attribute (Add to the existing community)\n"
       "Community number in aa:nn format or local-AS|no-advertise|no-export\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_external_inter_intra_cmd_vtysh, 
       "distance ospf external <1-255> inter-area <1-255> intra-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "External routes\n"
       "Distance for external routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community_all_cmd_vtysh, 
       "show ipv6 bgp community", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")

DEFSH (VTYSH_BGPD, set_aspath_prepend_cmd_vtysh, 
       "set as-path prepend .<1-65535>", 
       SET_STR
       "Prepend string for a BGP AS-path attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")

DEFSH (VTYSH_OSPFD, area_nssa_decimal_cmd_vtysh, 
       "area <0-4294967295> nssa", 
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n")

DEFSH (VTYSH_RIPNGD, no_ripng_timeout_timer_cmd_vtysh, 
       "no timeout-timer SECOND", 
       NO_STR
       "Unset RIPng timeout timer in seconds\n"
       "Seconds\n")

DEFSH (VTYSH_OSPFD|VTYSH_OSPF6D, area_range_cmd_vtysh, 
       "area A.B.C.D range X:X::X:X/M", 
       "OSPFv3 area parameters\n"
       "OSPFv3 area ID in IPv4 address format\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "IPv6 address range\n")

DEFSH (VTYSH_BGPD, bgp_bestpath_compare_router_id_cmd_vtysh, 
       "bgp bestpath compare-routerid", 
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")

DEFSH (VTYSH_BGPD, clear_ip_bgp_as_soft_cmd_vtysh, 
       "clear ip bgp <1-65535> soft", 
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community2_exact_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_ospf6_routemap_cmd_vtysh, 
       "no ipv6 bgp redistribute ospf6 route-map WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Open Shortest Path First (OSPFv3)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_connected_routemap_cmd_vtysh, 
       "no redistribute connected route-map WORD", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_OSPFD, no_router_id_cmd_vtysh, 
       "no router-id A.B.C.D", 
       NO_STR
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_as_in_cmd_vtysh, 
       "clear ipv6 bgp <1-65535> in", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_weight_val_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) weight <0-65535>", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

DEFSH (VTYSH_RIPNGD, no_ripng_redistribute_kernel_cmd_vtysh, 
       "no redistribute kernel", 
       NO_STR
       "Redistribute control\n"
       "Kernel route\n")

DEFSH (VTYSH_BGPD, debug_bgp_events_cmd_vtysh, 
       "debug bgp events", 
       DEBUG_STR
       BGP_STR
       "BGP events\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, clear_ip_prefix_list_name_prefix_cmd_vtysh, 
       "clear ip prefix-list WORD A.B.C.D/M", 
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_neighbor_all_cmd_vtysh, 
       "show ip ospf neighbor all", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "include down status neighbor\n")

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_intra_cmd_vtysh, 
       "distance ospf intra-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n")

DEFSH (VTYSH_BGPD, match_ipv6_address_cmd_vtysh, 
       "match ipv6 address WORD", 
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_neighbors_cmd_vtysh, 
       "show ipv6 bgp neighbors [PEER]", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")

DEFSH (VTYSH_ZEBRA, ip_address_cmd_vtysh, 
       "ip address A.B.C.D/M", 
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n")

DEFSH (VTYSH_ZEBRA, no_bandwidth_if_cmd_vtysh, 
       "no bandwidth", 
       NO_STR
       "Set bandwidth informational parameter\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_cmd_vtysh, 
       "show ip ospf database", 
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n")

DEFSH (VTYSH_BGPD, neighbor_transparent_nexthop_cmd_vtysh, 
       NEIGHBOR_CMD "transparent-nexthop", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Do not change nexthop even peer is EBGP peer\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_ipv6_access_list_all_cmd_vtysh, 
       "no ipv6 access-list WORD", 
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n")

DEFSH (VTYSH_BGPD, no_neighbor_send_community_extended_cmd_vtysh, 
       NO_NEIGHBOR_CMD "send-community extended", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Send Community attribute to this neighbor (default enable)\n"
       "Extended Community\n")

DEFSH (VTYSH_OSPF6D, ospf6_routemap_set_metric_type_cmd_vtysh, 
       "set metric-type (type-1|type-2)", 
       "Set value\n"
       "Type of metric\n"
       "OSPF6 external type 1 metric\n"
       "OSPF6 external type 2 metric\n")

DEFSH (VTYSH_OSPFD, area_authentication_message_digest_decimal_cmd_vtysh, 
       "area <0-4294967295> authentication message-digest", 
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_address_preference_cmd_vtysh, 
       "ip irdp address A.B.C.D <0-2147483647>", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Specify IRDP address and preference to proxy-advertise\n"
       "Set IRDP address for proxy-advertise\n"
       "Preference level\n")

DEFSH (VTYSH_BGPD, no_neighbor_translate_update_multicast_cmd_vtysh, 
       NO_NEIGHBOR_CMD "translate-update nlri multicast", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Translate bgp updates\n"
       "Network Layer Reachable Information\n"
       "multicast information\n")

DEFSH (VTYSH_BGPD, clear_ipv6_bgp_all_out_cmd_vtysh, 
       "clear ipv6 bgp * out", 
       CLEAR_STR
       IPV6_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

DEFSH (VTYSH_ZEBRA, show_ip_route_prefix_cmd_vtysh, 
       "show ip route A.B.C.D/M", 
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n")

DEFSH (VTYSH_BGPD, neighbor_received_routes_cmd_vtysh, 
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFSH (VTYSH_OSPF6D, reload_cmd_vtysh, 
       "reload", 
       "Reloads\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_neighbor_route_reflector_client_cmd_vtysh, 
       "no ipv6 bgp neighbor (A.B.C.D|X:X::X:X) route-reflector-client", 
       NO_STR
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Configure a neighbor as Route Reflector client\n")

DEFSH (VTYSH_BGPD, no_ipv6_bgp_redistribute_ripng_routemap_cmd_vtysh, 
       "no ipv6 bgp redistribute ripng route-map WORD", 
       NO_STR
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "IPv6 Routing Information Protocol (RIPng)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_neighbor_interface_cmd_vtysh, 
       NO_NEIGHBOR_CMD "interface WORD", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")

DEFSH (VTYSH_BGPD, show_ip_bgp_ipv4_community2_exact_cmd_vtysh, 
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match", 
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFSH (VTYSH_OSPFD, no_ospf_compatible_rfc1583_cmd_vtysh, 
       "no compatible rfc1583", 
       NO_STR
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")

DEFSH (VTYSH_OSPF6D, no_redistribute_ospf6_cmd_vtysh, 
       "no redistribute ospf6", 
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")

DEFSH (VTYSH_BGPD, bgp_bestpath_med_cmd_vtysh, 
       "bgp bestpath med (confed|missing-as-worst)", 
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")

DEFSH (VTYSH_OSPFD, no_neighbor_priority_cmd_vtysh, 
       "no neighbor A.B.C.D priority <0-255>", 
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n")

DEFSH (VTYSH_RIPNGD, ripng_redistribute_bgp_cmd_vtysh, 
       "redistribute bgp", 
       "Redistribute control\n"
       "BGP route\n")

DEFSH (VTYSH_OSPFD, no_area_range_decimal_cmd_vtysh, 
       "no area <0-4294967295> range A.B.C.D/M", 
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFSH (VTYSH_OSPFD, area_default_cost_cmd_vtysh, 
       "area A.B.C.D default-cost <0-16777215>", 
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

DEFSH (VTYSH_ZEBRA, ip_irdp_maxadvertinterval_cmd_vtysh, 
       "ip irdp maxadvertinterval (0|<4-1800>)", 
       IP_STR
       "ICMP Router discovery on this interface\n"
       "Set maximum time between advertisement\n"
       "Maximum advertisement interval in seconds\n")

DEFSH (VTYSH_BGPD, no_bgp_redistribute_connected_cmd_vtysh, 
       "no redistribute connected", 
       NO_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n")

DEFSH (VTYSH_OSPF6D, no_ospf6_redistribute_ripng_cmd_vtysh, 
       "no redistribute ripng", 
       NO_STR
       "Redistribute\n"
       "RIPng route\n")

DEFSH (VTYSH_RIPD|VTYSH_OSPFD|VTYSH_BGPD, no_ipv6_access_list_exact_cmd_vtysh, 
       "no ipv6 access-list WORD (deny|permit) X:X::X:X/M (exact-match|)", 
       NO_STR
       IPV6_STR
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Prefix to match. e.g. 3ffe:506::/32\n"
       "Exact match of the prefixes\n")

DEFSH (VTYSH_OSPFD, ospf_redistribute_source_metric_type_cmd_vtysh, 
       "redistribute (kernel|connected|static|rip|bgp) metric <0-16777214> metric-type (1|2)", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Routing Information Protocol (RIP)\n"
       "Border Gateway Protocol (BGP)\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1 metrics\n"
       "Set OSPF External Type 2 metrics\n")

DEFSH (VTYSH_BGPD, bgp_deterministic_med_cmd_vtysh, 
       "bgp deterministic-med", 
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")

DEFSH (VTYSH_BGPD, no_neighbor_strict_capability_cmd_vtysh, 
       NO_NEIGHBOR_CMD "strict-capability-match", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, ip_prefix_list_seq_ge_le_cmd_vtysh, 
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>", 
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

DEFSH (VTYSH_BGPD, ipv6_bgp_redistribute_connected_cmd_vtysh, 
       "ipv6 bgp redistribute connected", 
       IPV6_STR
       BGP_STR
       "Redistribute information from another routing protocol\n"
       "Connected\n")

DEFSH (VTYSH_RIPD, no_key_cmd_vtysh, 
       "no key <0-2147483647>", 
       NO_STR
       "Delete a key\n"
       "Key identifier number\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ip_prefix_list_ge_cmd_vtysh, 
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>", 
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")

DEFSH (VTYSH_BGPD, no_set_vpnv4_nexthop_cmd_vtysh, 
       "no set vpnv4 next-hop", 
       NO_STR
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n")

DEFSH (VTYSH_BGPD, bgp_scan_time_cmd_vtysh, 
       "bgp scan-time <5-60>", 
       "BGP specific commands\n"
       "Setting BGP route next-hop scanning interval time\n"
       "Scanner interval (seconds)\n")

DEFSH (VTYSH_BGPD, no_neighbor_ebgp_multihop_ttl_cmd_vtysh, 
       NO_NEIGHBOR_CMD "ebgp-multihop <1-255>", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

DEFSH (VTYSH_BGPD, ipv6_neighbor_strict_capability_cmd_vtysh, 
       "ipv6 bgp neighbor (A.B.C.D|X:X::X:X) strict-capability-match", 
       IPV6_STR
       BGP_STR
       NEIGHBOR_STR
       "IP address\n"
       "IPv6 address\n"
       "Strict capability negotiation match\n")

DEFSH (VTYSH_RIPD, rip_redistribute_type_routemap_cmd_vtysh, 
       "redistribute (kernel|connected|static|ospf|bgp) route-map WORD", 
       "Redistribute information from another routing protocol\n"
       "Kernel routes\n"
       "Connected\n"
       "Static routes\n"
       "Open Shortest Path First (OSPF)\n"
       "Border Gateway Protocol (BGP)\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFSH (VTYSH_BGPD, no_neighbor_version_cmd_vtysh, 
       NO_NEIGHBOR_CMD "version", 
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP version\n")

DEFSH (VTYSH_RIPD, rip_version_cmd_vtysh, 
       "version <1-2>", 
       "Set routing protocol version\n"
       "version\n")

DEFSH (VTYSH_BGPD, show_ipv6_mbgp_prefix_list_cmd_vtysh, 
       "show ipv6 mbgp prefix-list WORD", 
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")

DEFSH (VTYSH_OSPF6D, debug_ospf6_message_cmd_vtysh, 
       "debug ospf6 message (hello|dbdesc|lsreq|lsupdate|lsack|all)", 
       "Debugging infomation\n"
       OSPF6_STR
       "OSPF6 messages\n"
       "OSPF6 Hello\n"
       "OSPF6 Database Description\n"
       "OSPF6 Link State Request\n"
       "OSPF6 Link State Update\n"
       "OSPF6 Link State Acknowledgement\n"
       "OSPF6 all messages\n"
       )

DEFSH (VTYSH_OSPFD, ospf_distance_ospf_inter_cmd_vtysh, 
       "distance ospf inter-area <1-255>", 
       "Define an administrative distance\n"
       "OSPF Administrative distance\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n")

DEFSH (VTYSH_BGPD, neighbor_ebgp_multihop_cmd_vtysh, 
       NEIGHBOR_CMD "ebgp-multihop", 
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Allow EBGP neighbors not on directly connected networks\n")

DEFSH (VTYSH_RIPD, rip_split_horizon_cmd_vtysh, 
       "ip split-horizon", 
       IP_STR
       "Perform split horizon\n")

DEFSH (VTYSH_BGPD, show_ipv6_bgp_community_cmd_vtysh, 
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)", 
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFSH (VTYSH_BGPD, no_bgp_cluster_id_val_cmd_vtysh, 
       "no bgp cluster-id A.B.C.D", 
       NO_STR
       "BGP specific commands\n"
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")

DEFSH (VTYSH_OSPFD, show_ip_ospf_database_type_cmd_vtysh, 
	   "show ip ospf database (nssa-external|asbr-summary|external|max-age|network|router|self-originate|summary)", 
	   SHOW_STR
       IP_STR
       "OSPF information\n"
       "Database summary\n"
       "ASBR summary link states\n"
       "External link states\n"
       "LSAs in MaxAge list\n"
       "Network link states\n"
       "Router link states\n"
       "Self-originated link states\n"
       "Network summary link states\n")

DEFSH (VTYSH_BGPD, bgp_default_local_preference_cmd_vtysh, 
       "bgp default local-preference <0-4294967295>", 
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")

DEFSH (VTYSH_BGPD, no_bgp_network_unicast_multicast_cmd_vtysh, 
       "no network A.B.C.D/M nlri unicast multicast", 
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>,  e.g.,  35.0.0.0/8\n"
       "NLRI configuration\n"
       "Unicast NLRI setup\n"
       "Multicast NLRI setup\n")

DEFSH (VTYSH_RIPD|VTYSH_BGPD, no_ipv6_prefix_list_description_cmd_vtysh, 
       "no ipv6 prefix-list WORD description", 
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")

void
vtysh_init_cmd ()
{
install_element (VIEW_NODE, &show_debugging_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &debug_zebra_events_cmd_vtysh);
install_element (ENABLE_NODE, &debug_zebra_packet_cmd_vtysh);
install_element (ENABLE_NODE, &debug_zebra_packet_direct_cmd_vtysh);
install_element (ENABLE_NODE, &debug_zebra_packet_detail_cmd_vtysh);
install_element (ENABLE_NODE, &debug_zebra_kernel_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_zebra_events_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_zebra_packet_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_zebra_kernel_cmd_vtysh);
install_element (CONFIG_NODE, &debug_zebra_events_cmd_vtysh);
install_element (CONFIG_NODE, &debug_zebra_packet_cmd_vtysh);
install_element (CONFIG_NODE, &debug_zebra_packet_direct_cmd_vtysh);
install_element (CONFIG_NODE, &debug_zebra_packet_detail_cmd_vtysh);
install_element (CONFIG_NODE, &debug_zebra_kernel_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_zebra_events_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_zebra_packet_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_zebra_kernel_cmd_vtysh);
install_element (VIEW_NODE, &show_interface_cmd_vtysh);
install_element (ENABLE_NODE, &show_interface_cmd_vtysh);
install_element (CONFIG_NODE, &no_zebra_interface_cmd_vtysh);
install_element (INTERFACE_NODE, &multicast_cmd_vtysh);
install_element (INTERFACE_NODE, &no_multicast_cmd_vtysh);
install_element (INTERFACE_NODE, &shutdown_if_cmd_vtysh);
install_element (INTERFACE_NODE, &no_shutdown_if_cmd_vtysh);
install_element (INTERFACE_NODE, &bandwidth_if_cmd_vtysh);
install_element (INTERFACE_NODE, &no_bandwidth_if_cmd_vtysh);
install_element (INTERFACE_NODE, &no_bandwidth_if_val_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_address_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_address_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_address_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ipv6_address_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_tunnel_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_tunnel_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_multicast_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_holdtime_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_maxadvertinterval_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_minadvertinterval_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_preference_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_irdp_address_preference_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_route_addr_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_route_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_route_protocol_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_route_addr_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_route_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_route_protocol_cmd_vtysh);
install_element (CONFIG_NODE, &ip_route_cmd_vtysh);
install_element (CONFIG_NODE, &ip_route_mask_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_route_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_route_mask_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_route_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_route_ifname_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_route_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_route_pref_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_route_ifname_pref_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_route_pref_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_cmd_vtysh);
install_element (CONFIG_NODE, &ip_route_pref_cmd_vtysh);
install_element (CONFIG_NODE, &ip_route_mask_pref_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_route_pref_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_route_mask_pref_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_nd_send_ra_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ipv6_nd_send_ra_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_nd_prefix_advertisement_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_forwarding_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_forwarding_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_forwarding_cmd_vtysh);
install_element (ENABLE_NODE, &show_zebra_client_cmd_vtysh);
install_element (VIEW_NODE, &show_table_cmd_vtysh);
install_element (ENABLE_NODE, &show_table_cmd_vtysh);
install_element (CONFIG_NODE, &config_table_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_forwarding_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_forwarding_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_forwarding_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_rip_cmd_vtysh);
install_element (ENABLE_NODE, &debug_rip_events_cmd_vtysh);
install_element (ENABLE_NODE, &debug_rip_packet_cmd_vtysh);
install_element (ENABLE_NODE, &debug_rip_packet_direct_cmd_vtysh);
install_element (ENABLE_NODE, &debug_rip_packet_detail_cmd_vtysh);
install_element (ENABLE_NODE, &debug_rip_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_rip_events_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_rip_packet_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_rip_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &debug_rip_events_cmd_vtysh);
install_element (CONFIG_NODE, &debug_rip_packet_cmd_vtysh);
install_element (CONFIG_NODE, &debug_rip_packet_direct_cmd_vtysh);
install_element (CONFIG_NODE, &debug_rip_packet_detail_cmd_vtysh);
install_element (CONFIG_NODE, &debug_rip_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_rip_events_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_rip_packet_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_rip_zebra_cmd_vtysh);
install_element (RIP_NODE, &rip_network_cmd_vtysh);
install_element (RIP_NODE, &no_rip_network_cmd_vtysh);
install_element (RIP_NODE, &rip_neighbor_cmd_vtysh);
install_element (RIP_NODE, &no_rip_neighbor_cmd_vtysh);
install_element (RIP_NODE, &rip_passive_interface_cmd_vtysh);
install_element (RIP_NODE, &no_rip_passive_interface_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_send_version_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_send_version_1_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_send_version_2_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_send_version_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_send_version_num_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_receive_version_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_receive_version_1_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_receive_version_2_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_receive_version_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_receive_version_num_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_authentication_mode_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_mode_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_mode_type_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_authentication_key_chain_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_key_chain_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_key_chain2_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_rip_authentication_string_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_string_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_rip_authentication_string2_cmd_vtysh);
install_element (INTERFACE_NODE, &rip_split_horizon_cmd_vtysh);
install_element (INTERFACE_NODE, &no_rip_split_horizon_cmd_vtysh);
install_element (RIP_NODE, &rip_offset_list_cmd_vtysh);
install_element (RIP_NODE, &rip_offset_list_ifname_cmd_vtysh);
install_element (RIP_NODE, &no_rip_offset_list_cmd_vtysh);
install_element (RIP_NODE, &no_rip_offset_list_ifname_cmd_vtysh);
install_element (RMAP_NODE, &match_metric_cmd_vtysh);
install_element (RMAP_NODE, &no_match_metric_cmd_vtysh);
install_element (RMAP_NODE, &match_interface_cmd_vtysh);
install_element (RMAP_NODE, &no_match_interface_cmd_vtysh);
install_element (RMAP_NODE, &match_ip_nexthop_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ip_nexthop_cmd_vtysh);
install_element (RMAP_NODE, &match_ip_address_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ip_address_cmd_vtysh);
install_element (RMAP_NODE, &no_set_metric_cmd_vtysh);
install_element (RMAP_NODE, &no_set_metric_val_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ip_nexthop_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ip_nexthop_val_cmd_vtysh);
install_element (CONFIG_NODE, &router_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &no_router_zebra_cmd_vtysh);
install_element (ZEBRA_NODE, &rip_redistribute_rip_cmd_vtysh);
install_element (ZEBRA_NODE, &no_rip_redistribute_rip_cmd_vtysh);
install_element (RIP_NODE, &rip_redistribute_type_cmd_vtysh);
install_element (RIP_NODE, &rip_redistribute_type_routemap_cmd_vtysh);
install_element (RIP_NODE, &rip_redistribute_type_metric_cmd_vtysh);
install_element (RIP_NODE, &no_rip_redistribute_type_cmd_vtysh);
install_element (RIP_NODE, &no_rip_redistribute_type_routemap_cmd_vtysh);
install_element (RIP_NODE, &no_rip_redistribute_type_metric_cmd_vtysh);
install_element (RIP_NODE, &no_rip_redistribute_type_metric_routemap_cmd_vtysh);
install_element (RIP_NODE, &rip_default_information_originate_cmd_vtysh);
install_element (RIP_NODE, &no_rip_default_information_originate_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_rip_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_protocols_rip_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_rip_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_protocols_rip_cmd_vtysh);
install_element (CONFIG_NODE, &no_router_rip_cmd_vtysh);
install_element (RIP_NODE, &rip_version_cmd_vtysh);
install_element (RIP_NODE, &no_rip_version_cmd_vtysh);
install_element (RIP_NODE, &no_rip_version_val_cmd_vtysh);
install_element (RIP_NODE, &rip_default_metric_cmd_vtysh);
install_element (RIP_NODE, &no_rip_default_metric_cmd_vtysh);
install_element (RIP_NODE, &no_rip_default_metric_val_cmd_vtysh);
install_element (RIP_NODE, &rip_timers_cmd_vtysh);
install_element (RIP_NODE, &no_rip_timers_cmd_vtysh);
install_element (RIP_NODE, &rip_route_cmd_vtysh);
install_element (RIP_NODE, &no_rip_route_cmd_vtysh);
install_element (RIP_NODE, &rip_distance_cmd_vtysh);
install_element (RIP_NODE, &no_rip_distance_cmd_vtysh);
install_element (RIP_NODE, &rip_distance_source_cmd_vtysh);
install_element (RIP_NODE, &no_rip_distance_source_cmd_vtysh);
install_element (RIP_NODE, &rip_distance_source_access_list_cmd_vtysh);
install_element (RIP_NODE, &no_rip_distance_source_access_list_cmd_vtysh);
install_element (VIEW_NODE, &show_debugging_ripng_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_ripng_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ripng_events_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ripng_packet_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ripng_packet_direct_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ripng_packet_detail_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ripng_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ripng_events_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ripng_packet_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ripng_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ripng_events_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ripng_packet_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ripng_packet_direct_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ripng_packet_detail_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ripng_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ripng_events_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ripng_packet_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ripng_zebra_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_network_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_network_cmd_vtysh);
install_element (ZEBRA_NODE, &ripng_redistribute_ripng_cmd_vtysh);
install_element (ZEBRA_NODE, &no_ripng_redistribute_ripng_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_redistribute_static_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_redistribute_static_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_redistribute_kernel_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_redistribute_kernel_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_redistribute_connected_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_redistribute_connected_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_redistribute_bgp_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_redistribute_bgp_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_redistribute_ospf6_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_redistribute_ospf6_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ripng_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ripng_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_route_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_route_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_aggregate_address_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_aggregate_address_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_timers_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_timers_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_update_timer_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_update_timer_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_timeout_timer_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_timeout_timer_cmd_vtysh);
install_element (RIPNG_NODE, &ripng_garbage_timer_cmd_vtysh);
install_element (RIPNG_NODE, &no_ripng_garbage_timer_cmd_vtysh);
install_element (RIPNG_NODE, &default_information_originate_cmd_vtysh);
install_element (RIPNG_NODE, &no_default_information_originate_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_ospf_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_detail_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_packet_all_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_ism_sub_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_ism_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_nsm_sub_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_nsm_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_lsa_sub_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_lsa_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_zebra_sub_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_event_cmd_vtysh);
install_element (ENABLE_NODE, &debug_ospf_nssa_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_detail_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_packet_all_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_ism_sub_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_ism_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_nsm_sub_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_nsm_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_lsa_sub_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_lsa_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_zebra_sub_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_event_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_ospf_nssa_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_detail_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_packet_all_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_ism_sub_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_ism_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_nsm_sub_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_nsm_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_lsa_sub_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_lsa_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_zebra_sub_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_event_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf_nssa_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_detail_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_packet_all_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_ism_sub_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_ism_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_nsm_sub_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_nsm_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_lsa_sub_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_lsa_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_zebra_sub_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_zebra_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_event_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf_nssa_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_authentication_key_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_authentication_key_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_message_digest_key_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_message_digest_key_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_cost_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_cost_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_dead_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_dead_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_hello_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_hello_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_network_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_network_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_priority_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_priority_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_retransmit_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_retransmit_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ip_ospf_transmit_delay_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ip_ospf_transmit_delay_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_authentication_key_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_authentication_key_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_message_digest_key_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_message_digest_key_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_cost_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_cost_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_dead_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_dead_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_hello_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_hello_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_network_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_network_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_priority_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_priority_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_retransmit_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_retransmit_interval_cmd_vtysh);
install_element (INTERFACE_NODE, &ospf_transmit_delay_cmd_vtysh);
install_element (INTERFACE_NODE, &no_ospf_transmit_delay_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_id_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_id_adv_router_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_adv_router_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_id_self_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_type_self_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_database_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_id_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_id_adv_router_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_adv_router_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_id_self_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_type_self_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_database_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_border_routers_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_border_routers_cmd_vtysh);
install_element (RMAP_NODE, &set_metric_type_cmd_vtysh);
install_element (RMAP_NODE, &no_set_metric_type_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_type_metric_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_metric_type_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_type_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_metric_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_metric_routemap_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_type_routemap_cmd_vtysh);
install_element (OSPF_NODE, &ospf_redistribute_source_routemap_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_redistribute_source_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distribute_list_out_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_distribute_list_out_cmd_vtysh);
install_element (OSPF_NODE, &ospf_default_information_originate_metric_cmd_vtysh);
install_element (OSPF_NODE, &ospf_default_information_originate_type_cmd_vtysh);
install_element (OSPF_NODE, &ospf_default_information_originate_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_default_information_originate_cmd_vtysh);
install_element (OSPF_NODE, &ospf_default_metric_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_default_metric_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_distance_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_distance_ospf_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_intra_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_intra_inter_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_intra_external_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_intra_inter_external_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_intra_external_inter_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_inter_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_inter_intra_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_inter_external_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_inter_intra_external_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_inter_external_intra_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_external_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_external_intra_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_external_inter_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_external_intra_inter_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_ospf_external_inter_intra_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_source_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_distance_source_cmd_vtysh);
install_element (OSPF_NODE, &ospf_distance_source_access_list_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_distance_source_access_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_interface_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_int_detail_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_int_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_id_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_detail_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_detail_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_neighbor_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_interface_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_int_detail_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_int_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_id_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_detail_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_detail_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_neighbor_all_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_ospf_neighbor_cmd_vtysh);
install_element (CONFIG_NODE, &no_router_ospf_cmd_vtysh);
install_element (OSPF_NODE, &ospf_router_id_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_router_id_cmd_vtysh);
install_element (OSPF_NODE, &router_id_cmd_vtysh);
install_element (OSPF_NODE, &no_router_id_cmd_vtysh);
install_element (OSPF_NODE, &passive_interface_cmd_vtysh);
install_element (OSPF_NODE, &no_passive_interface_cmd_vtysh);
install_element (OSPF_NODE, &ospf_abr_type_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_abr_type_cmd_vtysh);
install_element (OSPF_NODE, &ospf_rfc1583_flag_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_rfc1583_flag_cmd_vtysh);
install_element (OSPF_NODE, &ospf_compatible_rfc1583_cmd_vtysh);
install_element (OSPF_NODE, &no_ospf_compatible_rfc1583_cmd_vtysh);
install_element (OSPF_NODE, &network_area_cmd_vtysh);
install_element (OSPF_NODE, &no_network_area_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_network_area_cmd_vtysh);
install_element (OSPF_NODE, &area_authentication_message_digest_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_authentication_message_digest_cmd_vtysh);
install_element (OSPF_NODE, &area_authentication_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_authentication_cmd_vtysh);
install_element (OSPF_NODE, &no_area_authentication_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_authentication_cmd_vtysh);
install_element (OSPF_NODE, &area_range_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_range_cmd_vtysh);
install_element (OSPF_NODE, &no_area_range_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_range_cmd_vtysh);
install_element (OSPF_NODE, &area_range_suppress_cmd_vtysh);
install_element (OSPF_NODE, &area_range_suppress_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_range_suppress_cmd_vtysh);
install_element (OSPF_NODE, &area_range_subst_cmd_vtysh);
install_element (OSPF_NODE, &no_area_range_subst_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_auth_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_auth_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_md5_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_md5_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_md5_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_md5_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_auth_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_auth_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_param_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_vlink_cmd_vtysh);
install_element (OSPF_NODE, &no_area_vlink_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_vlink_cmd_vtysh);
install_element (OSPF_NODE, &area_stub_nosum_cmd_vtysh);
install_element (OSPF_NODE, &area_stub_nosum_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_stub_cmd_vtysh);
install_element (OSPF_NODE, &area_stub_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_stub_nosum_cmd_vtysh);
install_element (OSPF_NODE, &no_area_stub_nosum_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_stub_cmd_vtysh);
install_element (OSPF_NODE, &no_area_stub_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_never_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_never_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_never_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_never_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_candidate_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_candidate_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_candidate_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_candidate_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_always_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_nosum_t_always_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_always_cmd_vtysh);
install_element (OSPF_NODE, &area_nssa_t_always_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_nssa_nosum_cmd_vtysh);
install_element (OSPF_NODE, &no_area_nssa_nosum_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_nssa_cmd_vtysh);
install_element (OSPF_NODE, &no_area_nssa_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_default_cost_cmd_vtysh);
install_element (OSPF_NODE, &area_default_cost_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_default_cost_cmd_vtysh);
install_element (OSPF_NODE, &no_area_default_cost_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_shortcut_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_shortcut_cmd_vtysh);
install_element (OSPF_NODE, &no_area_shortcut_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_shortcut_cmd_vtysh);
install_element (OSPF_NODE, &area_export_list_cmd_vtysh);
install_element (OSPF_NODE, &area_export_list_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_export_list_cmd_vtysh);
install_element (OSPF_NODE, &no_area_export_list_decimal_cmd_vtysh);
install_element (OSPF_NODE, &area_import_list_cmd_vtysh);
install_element (OSPF_NODE, &area_import_list_decimal_cmd_vtysh);
install_element (OSPF_NODE, &no_area_import_list_cmd_vtysh);
install_element (OSPF_NODE, &no_area_import_list_decimal_cmd_vtysh);
install_element (OSPF_NODE, &timers_spf_cmd_vtysh);
install_element (OSPF_NODE, &no_timers_spf_cmd_vtysh);
install_element (OSPF_NODE, &refresh_timer_cmd_vtysh);
install_element (OSPF_NODE, &no_refresh_timer_val_cmd_vtysh);
install_element (OSPF_NODE, &no_refresh_timer_cmd_vtysh);
install_element (OSPF_NODE, &auto_cost_reference_bandwidth_cmd_vtysh);
install_element (OSPF_NODE, &no_auto_cost_reference_bandwidth_cmd_vtysh);
install_element (OSPF_NODE, &neighbor_cmd_vtysh);
install_element (OSPF_NODE, &no_neighbor_cmd_vtysh);
install_element (OSPF_NODE, &neighbor_priority_cmd_vtysh);
install_element (OSPF_NODE, &no_neighbor_priority_cmd_vtysh);
install_element (OSPF_NODE, &neighbor_pollinterval_cmd_vtysh);
install_element (OSPF_NODE, &no_neighbor_pollinterval_cmd_vtysh);
install_element (OSPF_NODE, &neighbor_priority_pollinterval_cmd_vtysh);
install_element (OSPF_NODE, &no_neighbor_priority_pollinterval_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_ospf_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_ospf_cmd_vtysh);
install_element (VIEW_NODE, &show_debugging_ospf6_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_ospf6_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf6_message_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf6_message_cmd_vtysh);
install_element (CONFIG_NODE, &debug_ospf6_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_ospf6_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_cost_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_deadinterval_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_hellointerval_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_priority_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_retransmitinterval_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_transmitdelay_cmd_vtysh);
install_element (INTERFACE_NODE, &ipv6_ospf6_instance_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_scope_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_lsid_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_advrtr_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_advrtr_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_advrtr_lsid_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_database_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_turnover_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_database_turnover_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_scope_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_lsid_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_advrtr_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_advrtr_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_advrtr_lsid_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_database_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_turnover_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_database_turnover_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_route_ospf6_external_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_route_ospf6_external_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_route_ospf6_new_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_route_ospf6_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_route_ospf6_new_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_route_ospf6_prefix_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_match_address_prefixlist_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_no_match_address_prefixlist_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_set_metric_type_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_no_set_metric_type_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_set_forwarding_cmd_vtysh);
install_element (RMAP_NODE, &ospf6_routemap_no_set_forwarding_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_spf_node_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_spf_tree_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_spf_table_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_spf_node_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_spf_tree_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_spf_table_cmd_vtysh);
install_element (VIEW_NODE, &show_zebra_cmd_vtysh);
install_element (ENABLE_NODE, &show_zebra_cmd_vtysh);
install_element (ZEBRA_NODE, &redistribute_ospf6_cmd_vtysh);
install_element (ZEBRA_NODE, &no_redistribute_ospf6_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_cmd_vtysh);
install_element (VIEW_NODE, &show_version_ospf6_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_neighborlist_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_nexthoplist_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_ospf6_statistics_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_cmd_vtysh);
install_element (ENABLE_NODE, &show_version_ospf6_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_neighborlist_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_nexthoplist_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_ifname_nbrid_detail_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_ospf6_statistics_cmd_vtysh);
install_element (ENABLE_NODE, &reload_cmd_vtysh);
install_element (CONFIG_NODE, &set_proctitle_cmd_vtysh);
install_element (CONFIG_NODE, &ip_community_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_community_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_community_list_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_debugging_bgp_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_fsm_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_fsm_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_events_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_events_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_filter_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_filter_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_keepalive_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_keepalive_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_update_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_update_cmd_vtysh);
install_element (ENABLE_NODE, &debug_bgp_normal_cmd_vtysh);
install_element (CONFIG_NODE, &debug_bgp_normal_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_fsm_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_fsm_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_fsm_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_events_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_events_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_events_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_filter_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_filter_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_filter_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_keepalive_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_keepalive_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_keepalive_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_update_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_update_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_update_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_normal_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_normal_cmd_vtysh);
install_element (CONFIG_NODE, &no_debug_bgp_normal_cmd_vtysh);
install_element (ENABLE_NODE, &no_debug_bgp_all_cmd_vtysh);
install_element (ENABLE_NODE, &undebug_bgp_all_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_all_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_all_interval_cmd_vtysh);
install_element (CONFIG_NODE, &no_dump_bgp_all_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_updates_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_updates_interval_cmd_vtysh);
install_element (CONFIG_NODE, &no_dump_bgp_updates_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_routes_cmd_vtysh);
install_element (CONFIG_NODE, &dump_bgp_routes_interval_cmd_vtysh);
install_element (CONFIG_NODE, &no_dump_bgp_routes_cmd_vtysh);
install_element (CONFIG_NODE, &ip_as_path_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_as_path_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_as_path_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_tags_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_tags_cmd_vtysh);
install_element (BGP_NODE, &bgp_scan_time_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_scan_time_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_scan_time_val_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_scan_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_scan_cmd_vtysh);
install_element (BGP_NODE, &bgp_network_cmd_vtysh);
install_element (BGP_NODE, &bgp_network_multicast_cmd_vtysh);
install_element (BGP_NODE, &bgp_network_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &bgp_network_backdoor_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_network_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_network_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_network_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_network_backdoor_cmd_vtysh);
install_element (BGP_NODE, &aggregate_address_cmd_vtysh);
install_element (BGP_NODE, &aggregate_address_summary_only_cmd_vtysh);
install_element (BGP_NODE, &no_aggregate_address_cmd_vtysh);
install_element (BGP_NODE, &no_aggregate_address_summary_only_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_view_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_view_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_view_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_regexp_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_regexp_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_filter_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_filter_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community2_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community3_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community4_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community2_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community3_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community4_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community2_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community3_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community4_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_list_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_view_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_view_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_view_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_regexp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_regexp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_filter_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_filter_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community2_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community3_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community4_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community2_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community3_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community4_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community2_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community3_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community4_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_list_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_community_list_exact_cmd_vtysh);
install_element (VIEW_NODE, &neighbor_advertised_route_cmd_vtysh);
install_element (VIEW_NODE, &ipv4_neighbor_advertised_route_cmd_vtysh);
install_element (ENABLE_NODE, &neighbor_advertised_route_cmd_vtysh);
install_element (ENABLE_NODE, &ipv4_neighbor_advertised_route_cmd_vtysh);
install_element (VIEW_NODE, &neighbor_received_routes_cmd_vtysh);
install_element (VIEW_NODE, &ipv4_neighbor_received_routes_cmd_vtysh);
install_element (ENABLE_NODE, &neighbor_received_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv4_neighbor_received_routes_cmd_vtysh);
install_element (VIEW_NODE, &neighbor_routes_cmd_vtysh);
install_element (VIEW_NODE, &ipv4_neighbor_routes_cmd_vtysh);
install_element (ENABLE_NODE, &neighbor_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv4_neighbor_routes_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_network_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_network_multicast_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_network_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_network_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_network_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_network_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &ipv6_aggregate_address_cmd_vtysh);
install_element (BGP_NODE, &ipv6_aggregate_address_summary_only_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_aggregate_address_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_aggregate_address_summary_only_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_regexp_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_filter_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community2_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community3_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community4_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community2_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community3_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community4_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_community_list_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_route_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_regexp_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_filter_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community_all_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community2_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community3_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community4_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community2_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community3_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community4_exact_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_community_list_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_regexp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_filter_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community2_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community3_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community4_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community2_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community3_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community4_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_community_list_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_route_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_regexp_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_filter_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community_all_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community2_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community3_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community4_exact_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_community_list_exact_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_bgp_neighbor_advertised_route_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_bgp_neighbor_advertised_route_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_advertised_route_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_bgp_neighbor_received_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_bgp_neighbor_received_routes_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_mbgp_neighbor_received_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_received_routes_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_bgp_neighbor_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_bgp_neighbor_routes_cmd_vtysh);
install_element (VIEW_NODE, &ipv6_mbgp_neighbor_routes_cmd_vtysh);
install_element (ENABLE_NODE, &ipv6_mbgp_neighbor_routes_cmd_vtysh);
install_element (BGP_NODE, &bgp_distance_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_distance_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_distance2_cmd_vtysh);
install_element (BGP_NODE, &bgp_distance_source_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_distance_source_cmd_vtysh);
install_element (BGP_NODE, &bgp_distance_source_access_list_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_distance_source_access_list_cmd_vtysh);
install_element (BGP_NODE, &bgp_damp_set_cmd_vtysh);
install_element (BGP_NODE, &bgp_damp_set2_cmd_vtysh);
install_element (BGP_NODE, &bgp_damp_set3_cmd_vtysh);
install_element (BGP_NODE, &bgp_damp_unset_cmd_vtysh);
install_element (RMAP_NODE, &match_ip_next_hop_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ip_next_hop_cmd_vtysh);
install_element (RMAP_NODE, &match_ip_address_prefix_list_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ip_address_prefix_list_cmd_vtysh);
install_element (RMAP_NODE, &match_aspath_cmd_vtysh);
install_element (RMAP_NODE, &no_match_aspath_cmd_vtysh);
install_element (RMAP_NODE, &match_community_cmd_vtysh);
install_element (RMAP_NODE, &no_match_community_cmd_vtysh);
install_element (RMAP_NODE, &match_nlri_cmd_vtysh);
install_element (RMAP_NODE, &no_match_nlri_cmd_vtysh);
install_element (RMAP_NODE, &set_local_pref_cmd_vtysh);
install_element (RMAP_NODE, &no_set_local_pref_cmd_vtysh);
install_element (RMAP_NODE, &no_set_local_pref_val_cmd_vtysh);
install_element (RMAP_NODE, &set_weight_cmd_vtysh);
install_element (RMAP_NODE, &no_set_weight_cmd_vtysh);
install_element (RMAP_NODE, &no_set_weight_val_cmd_vtysh);
install_element (RMAP_NODE, &set_aspath_prepend_cmd_vtysh);
install_element (RMAP_NODE, &no_set_aspath_prepend_cmd_vtysh);
install_element (RMAP_NODE, &no_set_aspath_prepend_val_cmd_vtysh);
install_element (RMAP_NODE, &set_origin_cmd_vtysh);
install_element (RMAP_NODE, &no_set_origin_cmd_vtysh);
install_element (RMAP_NODE, &no_set_origin_val_cmd_vtysh);
install_element (RMAP_NODE, &set_atomic_aggregate_cmd_vtysh);
install_element (RMAP_NODE, &no_set_atomic_aggregate_cmd_vtysh);
install_element (RMAP_NODE, &set_aggregator_as_cmd_vtysh);
install_element (RMAP_NODE, &no_set_aggregator_as_cmd_vtysh);
install_element (RMAP_NODE, &no_set_aggregator_as_val_cmd_vtysh);
install_element (RMAP_NODE, &set_nlri_cmd_vtysh);
install_element (RMAP_NODE, &no_set_nlri_cmd_vtysh);
install_element (RMAP_NODE, &no_set_nlri_val_cmd_vtysh);
install_element (RMAP_NODE, &set_community_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_val_cmd_vtysh);
install_element (RMAP_NODE, &set_community_additive_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_additive_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_additive_val_cmd_vtysh);
install_element (RMAP_NODE, &set_community_delete_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_delete_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_delete_val_cmd_vtysh);
install_element (RMAP_NODE, &set_community_none_cmd_vtysh);
install_element (RMAP_NODE, &no_set_community_none_cmd_vtysh);
install_element (RMAP_NODE, &set_ecommunity_rt_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ecommunity_rt_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ecommunity_rt_val_cmd_vtysh);
install_element (RMAP_NODE, &set_ecommunity_soo_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ecommunity_soo_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ecommunity_soo_val_cmd_vtysh);
install_element (RMAP_NODE, &match_ipv6_address_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ipv6_address_cmd_vtysh);
install_element (RMAP_NODE, &match_ipv6_next_hop_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ipv6_next_hop_cmd_vtysh);
install_element (RMAP_NODE, &match_ipv6_address_prefix_list_cmd_vtysh);
install_element (RMAP_NODE, &no_match_ipv6_address_prefix_list_cmd_vtysh);
install_element (RMAP_NODE, &set_ipv6_nexthop_global_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ipv6_nexthop_global_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ipv6_nexthop_global_val_cmd_vtysh);
install_element (RMAP_NODE, &set_ipv6_nexthop_local_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ipv6_nexthop_local_cmd_vtysh);
install_element (RMAP_NODE, &no_set_ipv6_nexthop_local_val_cmd_vtysh);
install_element (RMAP_NODE, &set_vpnv4_nexthop_cmd_vtysh);
install_element (RMAP_NODE, &no_set_vpnv4_nexthop_cmd_vtysh);
install_element (RMAP_NODE, &no_set_vpnv4_nexthop_val_cmd_vtysh);
install_element (RMAP_NODE, &set_originator_id_cmd_vtysh);
install_element (RMAP_NODE, &no_set_originator_id_cmd_vtysh);
install_element (RMAP_NODE, &no_set_originator_id_val_cmd_vtysh);
install_element (ZEBRA_NODE, &redistribute_bgp_cmd_vtysh);
install_element (ZEBRA_NODE, &no_redistribute_bgp_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_kernel_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_kernel_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_kernel_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_kernel_routemap_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_static_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_static_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_static_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_static_routemap_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_connected_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_connected_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_connected_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_connected_routemap_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_rip_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_rip_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_rip_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_rip_routemap_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_ospf_cmd_vtysh);
install_element (BGP_NODE, &bgp_redistribute_ospf_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_ospf_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_redistribute_ospf_routemap_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_kernel_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_kernel_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_kernel_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_kernel_routemap_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_static_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_static_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_static_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_static_routemap_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_connected_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_connected_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_connected_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_connected_routemap_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_ripng_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_ripng_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ripng_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ripng_routemap_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_ospf6_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_redistribute_ospf6_routemap_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ospf6_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_redistribute_ospf6_routemap_cmd_vtysh);
install_element (CONFIG_NODE, &bgp_multiple_instance_cmd_vtysh);
install_element (CONFIG_NODE, &no_bgp_multiple_instance_cmd_vtysh);
install_element (BGP_NODE, &bgp_router_id_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_router_id_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_router_id_val_cmd_vtysh);
install_element (BGP_NODE, &bgp_cluster_id_cmd_vtysh);
install_element (BGP_NODE, &bgp_cluster_id32_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_cluster_id_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_cluster_id_val_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_client_to_client_reflection_cmd_vtysh);
install_element (BGP_NODE, &bgp_client_to_client_reflection_cmd_vtysh);
install_element (BGP_NODE, &bgp_always_compare_med_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_always_compare_med_cmd_vtysh);
install_element (BGP_NODE, &bgp_deterministic_med_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_deterministic_med_cmd_vtysh);
install_element (BGP_NODE, &bgp_enforce_first_as_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_enforce_first_as_cmd_vtysh);
install_element (BGP_NODE, &bgp_bestpath_compare_router_id_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_bestpath_compare_router_id_cmd_vtysh);
install_element (BGP_NODE, &bgp_bestpath_aspath_ignore_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_bestpath_aspath_ignore_cmd_vtysh);
install_element (BGP_NODE, &bgp_bestpath_med_cmd_vtysh);
install_element (BGP_NODE, &bgp_bestpath_med2_cmd_vtysh);
install_element (BGP_NODE, &bgp_bestpath_med3_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_bestpath_med_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_bestpath_med2_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_bestpath_med3_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_default_ipv4_unicast_cmd_vtysh);
install_element (BGP_NODE, &bgp_default_ipv4_unicast_cmd_vtysh);
install_element (BGP_NODE, &bgp_default_local_preference_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_default_local_preference_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_default_local_preference_val_cmd_vtysh);
install_element (CONFIG_NODE, &router_bgp_view_cmd_vtysh);
install_element (CONFIG_NODE, &no_router_bgp_cmd_vtysh);
install_element (CONFIG_NODE, &no_router_bgp_view_cmd_vtysh);
install_element (BGP_NODE, &neighbor_remote_as_cmd_vtysh);
install_element (BGP_NODE, &neighbor_remote_as_passive_cmd_vtysh);
install_element (BGP_NODE, &neighbor_remote_as_unicast_cmd_vtysh);
install_element (BGP_NODE, &neighbor_remote_as_multicast_cmd_vtysh);
install_element (BGP_NODE, &neighbor_remote_as_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &neighbor_activate_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_activate_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_remote_as_cmd_vtysh);
install_element (BGP_NODE, &neighbor_shutdown_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_shutdown_cmd_vtysh);
install_element (BGP_NODE, &neighbor_ebgp_multihop_cmd_vtysh);
install_element (BGP_NODE, &neighbor_ebgp_multihop_ttl_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_ebgp_multihop_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_ebgp_multihop_ttl_cmd_vtysh);
install_element (BGP_NODE, &neighbor_description_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_description_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_description_val_cmd_vtysh);
install_element (BGP_NODE, &neighbor_version_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_version_cmd_vtysh);
install_element (BGP_NODE, &neighbor_interface_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_interface_cmd_vtysh);
install_element (BGP_NODE, &neighbor_nexthop_self_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_nexthop_self_cmd_vtysh);
install_element (BGP_NODE, &neighbor_update_source_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_update_source_cmd_vtysh);
install_element (BGP_NODE, &neighbor_default_originate_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_default_originate_cmd_vtysh);
install_element (BGP_NODE, &neighbor_port_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_port_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_port_val_cmd_vtysh);
install_element (BGP_NODE, &neighbor_send_community_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_send_community_cmd_vtysh);
install_element (BGP_NODE, &neighbor_send_community_extended_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_send_community_extended_cmd_vtysh);
install_element (BGP_NODE, &neighbor_weight_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_weight_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_weight_val_cmd_vtysh);
install_element (BGP_NODE, &neighbor_soft_reconfiguration_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_soft_reconfiguration_cmd_vtysh);
install_element (BGP_NODE, &neighbor_route_reflector_client_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_route_reflector_client_cmd_vtysh);
install_element (BGP_NODE, &neighbor_route_server_client_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_route_server_client_cmd_vtysh);
install_element (BGP_NODE, &neighbor_capability_route_refresh_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_capability_route_refresh_cmd_vtysh);
install_element (BGP_NODE, &neighbor_translate_update_multicast_cmd_vtysh);
install_element (BGP_NODE, &neighbor_translate_update_unimulti_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_translate_update_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_translate_update_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_translate_update_unimulti_cmd_vtysh);
install_element (BGP_NODE, &neighbor_dont_capability_negotiate_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_dont_capability_negotiate_cmd_vtysh);
install_element (BGP_NODE, &neighbor_override_capability_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_override_capability_cmd_vtysh);
install_element (BGP_NODE, &neighbor_strict_capability_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_strict_capability_cmd_vtysh);
install_element (BGP_NODE, &neighbor_timers_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_timers_cmd_vtysh);
install_element (BGP_NODE, &neighbor_timers_connect_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_timers_connect_cmd_vtysh);
install_element (BGP_NODE, &neighbor_distribute_list_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_distribute_list_cmd_vtysh);
install_element (BGP_NODE, &neighbor_prefix_list_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_prefix_list_cmd_vtysh);
install_element (BGP_NODE, &neighbor_filter_list_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_filter_list_cmd_vtysh);
install_element (BGP_NODE, &neighbor_route_map_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_route_map_cmd_vtysh);
install_element (BGP_NODE, &neighbor_peer_group_cmd_vtysh);
install_element (BGP_NODE, &neighbor_peer_group_remote_as_cmd_vtysh);
install_element (BGP_NODE, &neighbor_maximum_prefix_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_maximum_prefix_cmd_vtysh);
install_element (BGP_NODE, &bgp_confederation_identifier_cmd_vtysh);
install_element (BGP_NODE, &bgp_confederation_peers_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_confederation_identifier_cmd_vtysh);
install_element (BGP_NODE, &no_bgp_confederation_peers_cmd_vtysh);
install_element (BGP_NODE, &neighbor_transparent_as_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_transparent_as_cmd_vtysh);
install_element (BGP_NODE, &neighbor_transparent_nexthop_cmd_vtysh);
install_element (BGP_NODE, &no_neighbor_transparent_nexthop_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_neighbors_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbors_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_neighbors_peer_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_neighbors_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbors_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_neighbors_peer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_neighbors_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_paths_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_ipv4_paths_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_paths_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_ipv4_paths_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_community_info_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_community_info_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_attr_info_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_attr_info_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_group_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_ipv4_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_ipv4_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_ipv4_soft_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_bgp_vpnv4_all_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_bgp_vpnv4_all_summary_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_peer_vpnv4_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_as_vpnv4_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_bgp_all_vpnv4_soft_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_passive_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_unicast_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_multicast_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_unicast_multicast_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_remote_as_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_shutdown_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_shutdown_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_ebgp_multihop_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_ebgp_multihop_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_ebgp_multihop_ttl_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_description_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_description_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_description_val_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_version_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_version_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_interface_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_interface_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_nexthop_self_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_nexthop_self_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_update_source_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_update_source_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_default_originate_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_default_originate_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_port_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_port_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_port_val_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_send_community_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_send_community_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_send_community_extended_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_send_community_extended_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_weight_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_weight_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_weight_val_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_soft_reconfiguration_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_soft_reconfiguration_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_route_reflector_client_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_reflector_client_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_route_server_client_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_server_client_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_capability_route_refresh_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_capability_route_refresh_cmd_vtysh);
install_element (BGP_NODE, &ipv6_neighbor_dont_capability_negotiate_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_neighbor_dont_capability_negotiate_cmd_vtysh);
install_element (BGP_NODE, &ipv6_neighbor_override_capability_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_neighbor_override_capability_cmd_vtysh);
install_element (BGP_NODE, &ipv6_neighbor_strict_capability_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_neighbor_strict_capability_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_timers_connect_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_timers_connect_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_distribute_list_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_distribute_list_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_prefix_list_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_prefix_list_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_filter_list_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_filter_list_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_route_map_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_route_map_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_transparent_as_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_transparent_as_cmd_vtysh);
install_element (BGP_NODE, &ipv6_bgp_neighbor_transparent_nexthop_cmd_vtysh);
install_element (BGP_NODE, &no_ipv6_bgp_neighbor_transparent_nexthop_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_neighbors_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_bgp_neighbors_peer_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_neighbors_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_mbgp_neighbors_peer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_neighbors_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_bgp_neighbors_peer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_neighbors_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_mbgp_neighbors_peer_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_group_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_soft_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_in_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_soft_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_out_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_peer_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_as_soft_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_bgp_all_soft_cmd_vtysh);
install_element (CONFIG_NODE, &no_key_chain_cmd_vtysh);
install_element (KEYCHAIN_NODE, &no_key_cmd_vtysh);
install_element (KEYCHAIN_NODE, &no_key_chain_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &key_string_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &no_key_string_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &no_key_chain_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &no_key_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_day_month_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_day_month_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_month_day_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_month_day_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_infinite_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_infinite_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_duration_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &accept_lifetime_duration_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_day_month_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_day_month_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_month_day_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_month_day_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_infinite_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_infinite_month_day_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_duration_day_month_cmd_vtysh);
install_element (KEYCHAIN_KEY_NODE, &send_lifetime_duration_month_day_cmd_vtysh);
install_element (CONFIG_NODE, &no_route_map_cmd_vtysh);
install_element (CONFIG_NODE, &no_route_map_all_cmd_vtysh);
install_element (RMAP_NODE, &rmap_onmatch_next_cmd_vtysh);
install_element (RMAP_NODE, &no_rmap_onmatch_next_cmd_vtysh);
install_element (RMAP_NODE, &rmap_onmatch_goto_cmd_vtysh);
install_element (RMAP_NODE, &no_rmap_onmatch_goto_cmd_vtysh);
install_element (CONFIG_NODE, &access_list_exact_cmd_vtysh);
install_element (CONFIG_NODE, &access_list_cmd_vtysh);
install_element (CONFIG_NODE, &access_list_remark_cmd_vtysh);
install_element (CONFIG_NODE, &no_access_list_exact_cmd_vtysh);
install_element (CONFIG_NODE, &no_access_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_access_list_all_cmd_vtysh);
install_element (CONFIG_NODE, &no_access_list_remark_cmd_vtysh);
install_element (CONFIG_NODE, &no_access_list_remark_arg_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_access_list_exact_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_access_list_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_access_list_remark_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_access_list_exact_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_access_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_access_list_all_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_access_list_remark_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_access_list_remark_arg_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_le_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_seq_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_seq_le_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_seq_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_prefix_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_seq_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_description_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_description_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_description_arg_cmd_vtysh);
install_element (CONFIG_NODE, &ip_prefix_list_sequence_number_cmd_vtysh);
install_element (CONFIG_NODE, &no_ip_prefix_list_sequence_number_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_name_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_name_seq_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_prefix_longer_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_prefix_first_match_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_summary_name_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_detail_cmd_vtysh);
install_element (VIEW_NODE, &show_ip_prefix_list_detail_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_name_seq_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_longer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_first_match_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_summary_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_detail_cmd_vtysh);
install_element (ENABLE_NODE, &show_ip_prefix_list_detail_name_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_prefix_list_name_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ip_prefix_list_name_prefix_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_le_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_seq_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_prefix_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_ge_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_description_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_arg_cmd_vtysh);
install_element (CONFIG_NODE, &ipv6_prefix_list_sequence_number_cmd_vtysh);
install_element (CONFIG_NODE, &no_ipv6_prefix_list_sequence_number_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_name_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_name_seq_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_longer_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_name_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_cmd_vtysh);
install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_seq_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_longer_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_name_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_cmd_vtysh);
install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_name_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_prefix_list_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_cmd_vtysh);
install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_prefix_cmd_vtysh);
}
