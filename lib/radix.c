/* This implementation assumes network mask is sequential
   Copyright (C) 1996,97 Kunihiro Ishiguro

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

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */

#include "zebra.h"
#include "route.h"
#include "radix.h"
#include "log.h"
#include "vector.h"
#include "vty.h"
#include "memory.h"

#define isnode(X) ((X)->bit > 0)
#define isleaf(X) ((X)->bit < 0)

/* For memory allocation statistics. */
unsigned long radix_alloc;
unsigned long mask_alloc;

/* Easy to manipulate radix tree.  We prepare table for each offset
   and mask and shift table. */
struct rd_table 
{
  int offset;
  int mask;
  int shift;
} * rd_table;

/* allocate new mask structure */
static struct mask *
mask_new (int masklen)
{
  struct mask *new;

  new = XMALLOC (MTYPE_RADIX_MASK, sizeof (struct mask));
  bzero (new, sizeof (struct mask));
  new->masklen = masklen;
  mask_alloc++;

  return new;
}

/* Free allocated mask structure. */
static void
mask_free (struct mask *mask)
{
  XFREE (MTYPE_RADIX_MASK, mask);
  mask_alloc--;
}

/* allocate new radix structure */
static struct radix *
radix_new()
{
  struct radix *new;

  new = XMALLOC (MTYPE_RADIX_NODE, sizeof (struct radix));
  bzero (new, sizeof (struct radix));

  radix_alloc++;
  return new;
}

/* Free radix strucure. */
static void
radix_free (struct radix *rd)
{
  struct mask *mp;
  struct mask *mpp;

  if (rd->mlist) 
    {
      mp = rd->mlist;
      while (mp) 
	{
	  mpp = mp;
	  mp = mp->next;
	  mask_free (mpp);
	}
    }
  XFREE (MTYPE_RADIX_NODE, rd);
  radix_alloc--;
}

/* Make radix related bit and mask table. */
static struct rd_table *
radix_make_table (int family)
{
  int i;
  int size;
  int index, rest;
  struct rd_table *table;

  /* Determine size of this radix route */
  if (family == AF_INET)
    size = IPV4_MAX_BITLEN;
#ifdef HAVE_IPV6
  if (family == AF_INET6)
    size = IPV6_MAX_BITLEN;
#endif /* HAVE_IPV6 */

  table = malloc (sizeof (struct rd_table) * (size + 1));

  table[0].offset = 0;
  table[0].mask = 0;
  table[0].shift = 8;
  
  for (i = 0; i < size; i++) 
    {
      index = i / 8;
      rest = i % 8;

      table[i + 1].offset = index;
      table[i + 1].mask = 1 << (7 - rest);
      table[i + 1].shift = 7 - rest;
    }

  return table;
}

/* Add mask to node. */
static void
mask_add_node (struct radix *rd, int masklen)
{
  struct mask *new;
  struct mask *mp, *mpp;

  /* If this is first mask then make new mask structre. */
  if (rd->mlist == NULL)
    {
      rd->mlist = mask_new (masklen);
      return;
    }

  /* Check is there same masklen. */
  mp = mpp = rd->mlist;
  while (mp && masklen < mp->masklen) 
    {
      mpp = mp;
      mp = mp->next;
    }

  /* If there is same masklen increment reference count. */
  if (mp && masklen == mp->masklen) 
    {
      mp->refcnt++;
      return;
    }

  /* Add new mask into linked list. */
  new = mask_new (masklen);
  if (mp == mpp)
    rd->mlist = new;
  else
    mpp->next = new;

  new->next = mp;
}

/* lookup offset and mask from bit value */
static void
radix_set_bit (struct radix *rd, int bit)
{
  rd->bit = bit;
  rd->offset = rd_table[rd->bit].offset;
  rd->mask = rd_table[rd->bit].mask;
}

struct radix_top *
radix_make_rib (int family)
{
  struct radix_top *rtop;

  struct radix *top;
  struct radix *left;
  struct radix *right;

  /* Allocate radix_top structure */
  rtop = malloc (sizeof (struct radix_top));

  /* Allocate top, left, right node */
  top = radix_new();
  left = radix_new();
  right = radix_new();

  /* Link node and leaf each other. */
  top->parent = left->parent = right->parent = top;
  top->left = left;
  top->right = right;

  /* Link radix top to radix_top structure. */
  rtop->top = top;

  /* Top node prepare. */
  radix_set_bit (top, 1);
  mask_add_node (top, 0);
  
  right->bit = -1;
  left->bit = -1;

  if (family == AF_INET) 
    {
      left->rt = prefix_in_new ();
      str2prefix_in ("0.0.0.0/0", (struct prefix_in *)left->rt);
      left->rt->type = ZEBRA_ROUTE_SYSTEM;
      right->rt = prefix_in_new ();
      str2prefix_in ("255.255.255.255/32", (struct prefix_in *)right->rt);
      right->rt->type = ZEBRA_ROUTE_SYSTEM;
    }

#ifdef HAVE_IPV6
  if (family == AF_INET6)
    {
      left->rt = str2routev6 ("::/0");
      left->rt->type = ZEBRA_ROUTE_SYSTEM;
      right->rt = str2routev6 ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128");
      right->rt->type = ZEBRA_ROUTE_SYSTEM;
    }
#endif /* HAVE_IPV6 */

  return rtop;
}

/* Go down radix tree and find the most deep leaf. */
struct radix *
radix_search (struct radix *rd, struct prefix *rt)
{
  caddr_t p = PREFIX (rt);

  while (rd->bit > 0) 
    {
      if (p[rd->offset] & rd->mask)
	rd = rd->right;
      else
	rd = rd->left;
    }
  return rd;
}

/* Return matched prefix head. */
struct prefix *
radix_search_prefix (struct radix_top *rtop, struct prefix *rt)
{
  struct radix *rd = radix_search (rtop->top, rt);
  return rd->rt;
}

/**/
struct prefix_in *
radix_lookup_fn (struct radix_top *rtop,
		 struct prefix_in *pin,
		 int (*func)(struct prefix_in *, struct prefix_in *))
{
  int ret;
  struct prefix_in *prefix;

  prefix = (struct prefix_in *) radix_search_prefix (rtop, (struct prefix *) pin);
  
  while (prefix)
    {
      ret = (*(func))((struct prefix_in *)prefix, (struct prefix_in *)pin);
      if (ret)
	return (struct prefix_in *)prefix;
      prefix = prefix->next;
    }

  return NULL;
}

/* This function check prefix and mask and type. */
int
radix_lookup_rt (struct radix_top *rtop, 
		 struct prefix *rt)
{
  int ret;
  struct prefix *prefix;

  prefix = radix_search_prefix (rtop, rt);

  ret = (*(rtop->sameprefix))(prefix, rt);

  if (!ret)
    return 0;

  while (prefix)
    {
      if (prefix->type == rt->type && prefix->mask == rt->mask)
	return 1;
      prefix = prefix->next;
    }

  return 0;
}

struct prefix_in *
radix_lookup_prefix (struct radix_top *rtop, int type, struct prefix_in *pin)
{
  int ret;
  struct prefix *r;
  
  r = radix_search_prefix (rtop, (struct prefix *) pin);

  /* Check prefix */
  ret = (*(rtop->sameprefix)) (r, (struct prefix *) pin);
  if (!ret)
    return NULL;

  /* Check type of route and mask length. */
  while (r)
    {
      if (r->type == type && r->mask == pin->mask)
	return (struct prefix_in *) r;
      r = r->next;
    }
  return NULL;
}

/* calc first difference bit point of two route */
radix_diff_bit (struct prefix *rt1, struct prefix *rt2)
{
  unsigned char diff;
  int bcount = 1;
  unsigned char *p1 = PREFIX (rt1);
  unsigned char *p2 = PREFIX (rt2);

  while (*p1 == *p2) 
    {
      p1++;
      p2++;
      bcount++;
    }
  bcount <<= 3;

  diff = *p1 ^ *p2;

  while (diff) 
    {
      diff >>= 1;
      bcount--;
    }

  return bcount + 1;
}

/**/
struct radix *
radix_new_pair(struct radix *rd, int bit, struct prefix *rt)
{
  struct radix *leaf;
  struct radix *node;
  struct radix *parent;
  caddr_t p = PREFIX (rt);

  /* Set each radix structure. */
  node = radix_new();
  leaf = radix_new();
  parent = rd->parent;

  /* Node preparation. */
  radix_set_bit (node, bit);
  node->parent = rd->parent;

  /* Leaf preparation. */
  leaf->parent = node;
  leaf->rt = rt;
  leaf->bit = -1;
  
  /* Make linkage from parent to node. */
  if (p[parent->offset] & parent->mask)
    parent->right = node;
  else
    parent->left = node;

  /* Make linkage from node to leaf. */
  if (p[node->offset] & node->mask) 
    {
      node->right = leaf;
      node->left = rd;
    }
  else 
    {
      node->left = leaf;
      node->right = rd;
    }
  rd->parent = node;
  
  return node;
}

/* Promote mask from descend node or leaf. */
mask_add_downnode (struct radix *child, struct radix *add, int bit)
{
  if (isnode (child)) 
    {
      /* In case of node. */
      struct mask *mp, *mpp;

      if (child->mlist) 
	{
	  mp = mpp = child->mlist;
	  while (mp && mp->masklen >= bit) 
	    {
	      mpp = mp;
	      mp = mp->next;
	    }

	  /* Find mask and move it to new node. */
	  if (mp == mpp)
	    child->mlist = NULL;
	  else
	    mpp->next = NULL;

	  add->mlist = mp;
	}
    }
  else 
    {
      /* In case of leaf. */
      int obit;
      struct prefix *rt;

      /* parent node's bit */
      obit = add->parent->bit;
      rt = child->rt;

      /* If there is need of mask addition, now add it to current node. */
      while (rt) 
	{
	  if (rt->mask < bit && rt->mask >= obit)
	    mask_add_node (add, rt->mask);
	  
	  rt = rt->next;
	}
    }
}

/* Add mask to the upper node. */
int
mask_add_upnode (struct radix *top, struct radix *rd, int mask)
{
  struct radix *rdp;

  /* In case of no need of mask adding */
  if (mask >= rd->bit)
    return;

  /* Add mask to proper node. */
  rdp = rd;
  while (mask < rd->bit && rdp != top) 
    {
      rdp = rd;
      rd = rd->parent;
    }
  mask_add_node (rdp, mask);
}

/**/
int
radix_add_new (struct radix *top, struct radix *rd, struct prefix *rt)
{
  int bit;
  struct radix *add;
  struct radix *child;
  caddr_t p = PREFIX (rt);

  /* Calc first different bit. */
  bit = radix_diff_bit (rd->rt, rt);

  /* Walk down tree agein */
  rd = top;
  while (rd->bit > 0 && rd->bit < bit) 
    {
      if (p[rd->offset] & rd->mask)
	rd = rd->right;
      else
	rd = rd->left;
    }

  /* Prepare node pair. */
  add = radix_new_pair (rd, bit, rt);

  /* Mask prepare. */
  if (add->left->rt == rt)
    child = add->right;
  else
    child = add->left;

  /* Mask treatment. */
  mask_add_downnode (child, add, bit);
  mask_add_upnode (top, add, rt->mask);

  return RADIX_RT_SUCCESS;
}

/* add same prefix route to a radix node */
radix_add_rlist (struct radix *rd, struct prefix *rt)
{
  struct prefix *rp;
  struct prefix *rpp;
  
  /* deeper mask goes to deeper entry of a list */
  rp = rpp = rd->rt;
  while (rp && rt->mask > rp->mask) 
    {
      rpp = rp;
      rp = rp->next;
    }

  if (rp == rpp) 
    rd->rt = rt;
  else
    rpp->next = rt;

  rt->next = rp;
}

/**/
struct prefix *
radix_add_duproute (struct radix *top,
		    struct radix *rd,
		    struct prefix *rt)
{
  radix_add_rlist (rd, rt);
  mask_add_upnode (top, rd->parent, rt->mask);
  return rt;
}

/* insert route into radix tree */
struct prefix *
radix_add (struct radix_top *rtop, struct prefix *rt)
{
  int ret;
  struct radix *rd;
  
  rd = radix_search (rtop->top, rt);

  /* Check is this route is same prefix route. */
  ret = (*(rtop->sameprefix))(rd->rt, rt);

  /* Add duplicate route. */
  if (ret)
    return radix_add_duproute (rtop->top, rd, rt);

  radix_add_new (rtop->top, rd, rt);
  return NULL;
}

/* Init radix. */
radix_init ()
{
  /* Make radix table and set it to radix top. */
#ifdef HAVE_IPV6
  rd_table = radix_make_table (AF_INET6);
#else
  rd_table = radix_make_table (AF_INET);
#endif /* HAVE_IPV6 */

  /* Init statistics. */
  radix_alloc = 0;
  mask_alloc = 0;
}

/* Apply function to radix tree. */
radix_apply_func (struct radix_top *rtop,
		 int (* func) (struct prefix *, void *),
		 void *arg)
{
  struct radix *rd;
  struct radix *base, *next;
  struct prefix *route;
  struct prefix *nextroute;

  rd = rtop->top;

  /* Walk down to left most node. */
  while (isnode (rd))
    rd = rd->left;

  while (1)
    {
      base = rd;

      /* If at right child, go up tree. */
      while (rd->parent->right == rd && rd != rtop->top)
	rd = rd->parent;

      if (rd == rtop->top)
	return 0;

      for (rd = rd->parent->right; isnode (rd);)
	rd = rd->left;

      next = rd;

      /* Process route. */
      route = base->rt;
      while (route)
	{
	  /* Preserve pointer. */
	  nextroute = route->next;

	  if (route->type != ZEBRA_ROUTE_SYSTEM)
	    (*func) (route, arg);

	  route = nextroute;
	}

      rd = next;
      
    }
  return 0;
}

/* Apply function to radix tree. */
radix_apply_func2 (struct radix_top *rtop,
		   int (* func) (struct prefix *, void *, void *),
		   void *arg1,
		   void *arg2)
{
  struct radix *rd;
  struct radix *base, *next;
  struct prefix *route;
  struct prefix *nextroute;

  rd = rtop->top;

  /* Walk down to left most node. */
  while (isnode (rd))
    rd = rd->left;

  while (1)
    {
      base = rd;

      /* If at right child, go up tree. */
      while (rd->parent->right == rd && rd != rtop->top)
	rd = rd->parent;

      if (rd == rtop->top)
	return 0;

      for (rd = rd->parent->right; isnode (rd);)
	rd = rd->left;

      next = rd;

      /* Process route. */
      route = base->rt;
      while (route)
	{
	  /* Preserve pointer. */
	  nextroute = route->next;

	  if (route->type != ZEBRA_ROUTE_SYSTEM)
	    (*func) (route, arg1, arg2);

	  route = nextroute;
	}

      rd = next;
      
    }
  return 0;
}

/**/
masked_route_in (struct prefix_in *pin)
{
  unsigned char *rp;
  int offset;
  int shift;
  int i;
  struct in_addr *rt = &pin->prefix;
  int masklen = pin->mask;

  rp = (unsigned char *)rt;

  offset = rd_table[masklen].offset;
  shift = rd_table[masklen].shift;

  for (i = 0; i < offset; i++)
    rp++;

  *rp = ((*rp) >> shift) << shift;
  
  rp++;
  for (i = sizeof (struct in_addr) - offset - 1; i > 0; i--)
    *rp++ = 0;
}

#ifdef HAVE_IPV6
masked_route_in6 (struct in6_addr *rt, int masklen)
{
  unsigned char *rp;
  int offset;
  int shift;
  int i;

  rp = (unsigned char *)rt;

  offset = rd_table[masklen].offset;
  shift = rd_table[masklen].shift;

  for (i = 0; i < offset; i++)
    rp++;

  *rp = ((*rp) >> shift) << shift;
  
  rp++;
  for (i = sizeof (struct in6_addr) - offset - 1; i > 0; i--)
    *rp++ = 0;
}
#endif /* HAVE_IPV6 */

/* delete route from list of route */
struct prefix *
radix_delete_duproute (struct radix_top *rtop,
		       struct radix *rd,
		       struct prefix *rt)
{
  struct prefix *rp;
  struct prefix *rpp;
  
  rp = rpp = rd->rt;
  while (rp) 
    {
      /* Don't check prefix, because upper function should check it. */
      if (rp == rt) 
	{
	  /* This will replaced with same_prefix */
	  if (rp == rpp)
	    rd->rt = rp->next;
	  else
	    rpp->next = rp->next;
	  return rp;
	}
      rpp = rp;
      rp = rp->next;
    }

  /* No deletetion of route occured. */
  return NULL;			
}

/* delete route from list of route */
struct prefix *
radix_delete_duproute_peer (struct radix_top *rtop,
			    struct radix *rd,
			    struct prefix *rt)
{
  struct prefix *rp;
  struct prefix *rpp;
  
  rp = rpp = rd->rt;
  while (rp) 
    {
      /* Don't check prefix, because upper function should check it. */
      if (rp == rt) 
	{
	  /* This will replaced with same_prefix */
	  if (rp == rpp)
	    rd->rt = rp->next;
	  else
	    rpp->next = rp->next;
	  return rp;
	}
      rpp = rp;
      rp = rp->next;
    }

  /* No deletetion of route occured. */
  return NULL;			
}

/* delete route from list of route */
struct prefix *
radix_delete_duproute_func (struct radix *rd,
			    struct prefix *rt, 
			    int (* func) (struct prefix *, struct prefix *, void *),
			    void *arg)
{
  struct prefix *rp;
  struct prefix *rpp;
  
  rp = rpp = rd->rt;
  while (rp) 
    {
      if ((*func)(rp, rt, arg))
	{
	  /* This will replaced with same_prefix */
	  if (rp == rpp)
	    rd->rt = rp->next;
	  else
	    rpp->next = rp->next;
	  return rp;
	}
      rpp = rp;
      rp = rp->next;
    }

  /* No deletetion of route occured. */
  return NULL;			
}

/* Delete mask. */
radix_delete_mask (struct radix *top, struct radix *rd, int masklen)
{
  struct radix *rpp;
  struct mask *mp, *mpp;

  /* Check whether it needs deletion of mask. */
  if (masklen >= rd->bit)
    return;

  /* go up tree */
  rpp = rd;
  /* while (masklen < rd->bit && rd != top) */
  while (masklen < rd->bit && rpp != top) 
    {
      rpp = rd;
      rd = rd->parent;
    }
  
  /* delete mask from node */
  mp = mpp = rpp->mlist;
  while (mp && masklen != mp->masklen) 
    {
      mpp = mp;
      mp = mp->next;
    }

  if (!mp)
    {
      /* log ("radix.c : can't find mask %d\n", masklen); */
      return;
    }

  if (mp->refcnt) 
    {
      mp->refcnt--;
      return;
    }

  if (mp == mpp) 
    rpp->mlist = mp->next;
  else
    mpp->next = mp->next;
  
  mask_free (mp);
}

/* Delete route from radix tree. If there is a route to delete: return
   deleted route else return NULL. */
struct prefix *
radix_delete (struct radix_top *rtop, struct prefix *rt)
{
  int ret;
  struct radix *rd;
  struct radix *rp, *rpp;
  struct radix *another;
  struct prefix *delete;

  /* Find same prefix route node. */
  rd = radix_search (rtop->top, rt);

  ret = (*(rtop->sameprefix))(rd->rt, rt);

  if (! ret)
    return NULL;

  /* If there is duplicate route. */
  if (rd->rt->next) 
    {
      delete = radix_delete_duproute (rtop, rd, rt);

      if (delete)
	radix_delete_mask (rtop->top, rd->parent, delete->mask);

      return delete;
    }

  delete = rd->rt;

  /* delete mask from radix tree */
  radix_delete_mask (rtop->top, rd->parent, rt->mask);

  /* store parent and grand parent */
  rp = rd->parent;
  rpp = rd->parent->parent;

  if (rp->left == rd)
    another = rp->right;
  else
    another = rp->left;

  /* if mask can move to another node do it */
  if (isnode (another)) 
    {
      struct mask *mp;
      mp = rp->mlist;
      while (mp) 
	{
	  if (mp->masklen < another->bit)
	    mask_add_node (another, mp->masklen);

	  mp = mp->next;
	}
    }

  /* delete node and leaf */
  if (rpp->left == rp)
    rpp->left = another;
  else
    rpp->right = another;

  another->parent = rpp;

  radix_free (rd);
  radix_free (rp);

  return delete;
}

/* Delete route from radix tree. If there is a route to delete: return
   deleted route else return NULL. */
struct prefix *
radix_delete_peer (struct radix_top *rtop, struct prefix *rt)
{
  int ret;
  struct radix *rd;
  struct radix *rp, *rpp;
  struct radix *another;
  struct prefix *delete;

  /* Find same prefix route node. */
  rd = radix_search (rtop->top, rt);

  ret = (*(rtop->sameprefix))(rd->rt, rt);

  if (! ret)
    return NULL;

  /* If there is duplicate route. */
  if (rd->rt->next) 
    {
      delete = radix_delete_duproute_peer (rtop, rd, rt);

      if (delete)
	radix_delete_mask (rtop->top, rd->parent, delete->mask);

      return delete;
    }

  delete = rd->rt;

  /* delete mask from radix tree */
  radix_delete_mask (rtop->top, rd->parent, rt->mask);

  /* store parent and grand parent */
  rp = rd->parent;
  rpp = rd->parent->parent;

  if (rp->left == rd)
    another = rp->right;
  else
    another = rp->left;

  /* if mask can move to another node do it */
  if (isnode (another)) 
    {
      struct mask *mp;
      mp = rp->mlist;
      while (mp) 
	{
	  if (mp->masklen < another->bit)
	    mask_add_node (another, mp->masklen);

	  mp = mp->next;
	}
    }

  /* delete node and leaf */
  if (rpp->left == rp)
    rpp->left = another;
  else
    rpp->right = another;

  another->parent = rpp;

  radix_free (rd);
  radix_free (rp);

  return delete;
}

/* Delete route from radix tree. If there is a route to delete: return
   deleted route else return NULL. */
struct prefix *
radix_delete_func (struct radix_top *rtop,
		   struct prefix *rt, 
		   int (* func) (struct prefix *, struct prefix *, void *),
		   void *arg)
{
  int ret;
  struct prefix *del;
  struct radix *rd;
  struct radix *rp, *rpp;
  struct radix *another;

  /* Find same prefix route node. */
  rd = radix_search (rtop->top, rt);

  ret = (*(rtop->sameprefix))(rd->rt, rt);

  if (! ret)
    return NULL;

  /* If there is duplicate route. */
  if (rd->rt->next) 
    {
      struct prefix *delete;

      delete = radix_delete_duproute_func (rd, rt, func, arg);

      if (delete)
	radix_delete_mask (rtop->top, rd->parent, delete->mask);

      return delete;
    }

  /* Check route. */
  if (! (*func)(rd->rt, rt, arg))
    return NULL;

  /* delete mask from radix tree */
  radix_delete_mask (rtop->top, rd->parent, rt->mask);

  /* store parent and grand parent */
  rp = rd->parent;
  rpp = rd->parent->parent;

  if (rp->left == rd)
    another = rp->right;
  else
    another = rp->left;

  /* if mask can move to another node do it */
  if (isnode (another)) 
    {
      struct mask *mp;
      mp = rp->mlist;
      while (mp) 
	{
	  if (mp->masklen < another->bit)
	    mask_add_node (another, mp->masklen);

	  mp = mp->next;
	}
    }

  /* delete node and leaf */
  if (rpp->left == rp)
    rpp->left = another;
  else
    rpp->right = another;

  another->parent = rpp;

  del = rd->rt;
  radix_free (rd);
  radix_free (rp);

  return del;
}

/* currently r is implicitly regartd as host address */
radix_mask_match (struct prefix *r, struct prefix *rt)
{
  u_char *dest = PREFIX (r);
  u_char *rule = PREFIX (rt);
  u_char *start;
  int i;
  int offset;
  int shift;
  
  if (rt_ip_sameprefix (r, rt)) {
    log ("radix_mask_match error: same prefix\r\n");
    return 0;
  }

  offset = rd_table[rt->mask].offset;
  shift = rd_table[rt->mask].shift;

  for (i = 0; i < offset; i++) {
    if (*dest++ != *rule++)
      return 0;
  }
      
  if ((*dest >> shift) != (*rule >> shift))
    return 0;

  /* matched */
  return 1;
}

radix_masked_route (struct prefix *r,struct prefix *m, int mask)
{
  u_char *pnt = PREFIX(r);
  u_char *mpnt = PREFIX(m);
  int offset;
  int shift;
  int i;

  bzero(m, sizeof(struct prefix));

  offset = rd_table[mask].offset;
  shift = rd_table[mask].shift;

  for (i = 0; i < offset; i++) {
    *mpnt++ = *pnt++;
  }
  *mpnt = ((*pnt) >> shift) << shift;
}

/* Return matched route. */
struct prefix *
radix_match(struct radix_top *rtop, struct prefix *rt)
{
  int ret;
  struct radix *rd;
  struct radix *bt;
  unsigned char *p = PREFIX (rt);
  struct prefix *mrt;

  /* Go down radix tree */
  rd = radix_search (rtop->top, rt);

  /* Dose it exactry match ? */
  ret = (*(rtop->sameprefix))(rd->rt, rt);
  if (ret)
    return rd->rt;

  /* Dose it match to network route ? */
  mrt = rd->rt;

#define HOST_MASK 32
  do 
    {
      if (mrt->mask != HOST_MASK) 
	{
	  if (radix_mask_match (rt, mrt)) 
	    {
	      return mrt;
	    }
	}      
    } while (mrt = mrt->next);

  /* O.K. now we start backtracking */
  bt = rd;

  do {
    struct prefix masked;
    struct mask *m;
    struct radix *x;

    bt = bt->parent;
    if (m = bt->mlist) 
      {
	do 
	  {
	    masked.prefix = rt->prefix;
	    masked.mask = m->masklen;
	    
	    masked_route_in ((struct prefix_in *)&masked);
	    x = radix_search (bt, &masked);
	    if ((*(rtop->sameprefix))(x->rt , &masked)) 
	      return x->rt;
	  } while (m = m->next);
      }
  } while (bt != rtop->top);
  

  /* Dose not match */
  return NULL;
}
