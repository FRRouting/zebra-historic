#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "prefix.h"
#include "radix.h"

/* Go down radix tree by actual prefix pointer. */
struct radix *
radix_search_p (struct radix *rd, caddr_t p)
{
  while (rd->bit > 0) 
    {
      if (p[rd->offset] & rd->mask)
	rd = rd->right;
      else
	rd = rd->left;
    }
  return rd;
}

#define IN6_CMP_ADDR(X,Y)  memcmp(X, Y, sizeof (struct in6_addr))

/* Lookup radix tree by in6_addr and masklen. */
struct prefix_in6 *
radix_lookup_in6 (struct radix_top *top,
		  struct in6_addr *prefix,
		  u_char masklen)
{
  struct radix *rd;
  struct prefix_in6 *pin6;

  rd = radix_search_p (top->top, (caddr_t) prefix);

  for (pin6 = (struct prefix_in6 *) rd->rt; pin6; pin6 = pin6->next)
    if (IN6_CMP_ADDR (&pin6->prefix, prefix) == 0 && pin6->mask == masklen)
      return pin6;

  return NULL;
}
