#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "table.h"
#include "zebra.h"
#include "linklist.h"
#include "memory.h"
#include "route.h"
#include "rtable.h"

extern struct route_table *ipv6_rib_table;

#ifdef TEST
ripng_test ()
{
  struct prefix_in6 pin;

  pin.type = ZEBRA_ROUTE_RIPNG;
  inet_pton (AF_INET6, "3ffe::", &pin.prefix);
  pin.mask = 24;
  inet_pton (AF_INET6, "::1", &pin.gate.addr);

  rib_add_in6 (&pin, 0);
}
#endif /* TEST */

struct rentry *
rentry_new ()
{
  struct rentry *new;

  new = malloc (sizeof (struct rentry));
  return new;
}

rentry_free (struct rentry *entry)
{
  free (entry);
}

struct rentry *
rlist_search (list list, int type)
{
  listnode node;

  for (node = listhead (list); node; node = nextnode (node))
    {
      struct rentry *entry;

      entry = getdata (node);
      if (entry->type == type)
	return entry;
    }
  return NULL;
}

#ifdef HAVE_IPV6
/* Add route to the routing table. */
rtable_add_in6 (int type, struct in6_addr *addr, u_char prefixlen, 
		void *info, unsigned int ifindex)
{
  int ret;
  struct route_node *node;
  struct rentry *entry;
  list rlist;

  /* This lock the node. */
  node = route_node_lookup (ipv6_rib_table, addr, prefixlen);

  /* Make empty routing information list. */
  if (node->route == NULL)
    node->route = list_init ();

  /* Get a list of routes. */
  rlist = node->route;

  switch (type)
    {
    case ZEBRA_ROUTE_RIPNG:
      {
	struct in6_addr *nexthop;

	nexthop = info;

	/* If there is previous entry we perform implicit withdraw. */
	entry = rlist_search (rlist, ZEBRA_ROUTE_RIPNG);
	if (entry)
	  {
	    if (entry->fib)
	      ret = kernel_delete_in6 (addr, 
				       prefixlen, 
				       entry->nexthop, 
				       ifindex);
	    entry->fib = 0;
	  }
	else
	  {
	    entry = rentry_new ();
	  }	    
	entry->nexthop = *nexthop;
	entry->fib = 1;
	ret = kernel_add_in6 (addr, prefixlen, nexthop, ifindex);
      }
      break;
    case ZEBRA_ROUTE_CONNECT:
      entry = rlist_search (rlist, ZEBRA_ROUTE_CONNECT);
      break;
    default:
      break;
    }
}
#endif /* HAVE_IPV6 */
