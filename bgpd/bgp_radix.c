/* Radix tree for bgpd.  Almost of this will moved to ../lib/radix.c
   Copyright (C) 1996, 97 Kunihiro Ishiguro

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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <config.h>

#include "bgp_radix.h"
#include "bgp_route.h"
#include "bgp_peer.h"
#include "log.h"

#include "vector.h"
#include "vty.h"

/* top pointer of radix tree */
/* static radix_t radix_top; */

/* mask and shift table */
struct {
  int offset;
  int mask;
  int shift;
} RD_TABLE[] = {
  0, 0x00, 8,
  0, 0x80, 7, 0, 0x40, 6, 0, 0x20, 5, 0, 0x10, 4,
  0, 0x08, 3, 0, 0x04, 2, 0, 0x02, 1, 0, 0x01, 0,
  1, 0x80, 7, 1, 0x40, 6, 1, 0x20, 5, 1, 0x10, 4,
  1, 0x08, 3, 1, 0x04, 2, 1, 0x02, 1, 1, 0x01, 0, 
  2, 0x80, 7, 2, 0x40, 6, 2, 0x20, 5, 2, 0x10, 4,
  2, 0x08, 3, 2, 0x04, 2, 2, 0x02, 1, 2, 0x01, 0,
  3, 0x80, 7, 3, 0x40, 6, 3, 0x20, 5, 3, 0x10, 4,
  3, 0x08, 3, 3, 0x04, 2, 3, 0x02, 1, 3, 0x01, 0,
};

#define isnode(X) ((X)->bit > 0)
#define isleaf(X) ((X)->bit < 0)

#define sameprefix(X,Y)  ((X)->prefix == (Y)->prefix)
#define samemasklen(X,Y) ((X)->masklen == (Y)->masklen)
#define samepeer(X,Y)    ((X)->peer == (Y)->peer)

#define put_attr2route(X,Y) ((Y)->attr = X)
#define put_aspath2route(X,Y) ((Y)->attr->aspath = X)

/* for memory allocation statistics */
unsigned long radix_alloc;
unsigned long mask_alloc;

/* allocate new radix structure */
static radix_t
radix_new()
{
  struct Radix *new;

  new = XCALLOC (struct Radix);
  new->flag = RADIX_NORMAL;
  radix_alloc++;
  return new;
}

radix_free(rd)
     radix_t rd;
{
  mask_t mp;
  mask_t mpp;

  if (rd->mlist) {
    mp = rd->mlist;
    while (mp) {
      mpp = mp;
      mp = mp->next;
      mask_free (mpp);
    }
  }
  /*
  if (rd->r) {
    free (rd->r);
  }
  */
  free (rd);
  radix_alloc--;
}

/* allocate new mask structure */
static mask_t
mask_new(masklen)
     int masklen;
{
  mask_t new = XCALLOC (struct mask);
  new->masklen = masklen;
  mask_alloc++;
  return new;
}

/* free allocated mask structure */
mask_free(mask)
     mask_t mask;
{
  free (mask);
  mask_alloc--;
}

/* lookup offset and mask from bit value */
static void
radix_set_bit (rd, bit)
     radix_t rd;
     int bit;
{
  rd->bit = bit;
  rd->offset = RD_TABLE[rd->bit].offset;
  rd->mask = RD_TABLE[rd->bit].mask;
}


/* convert route/mask strint route and add to node */
static void
radix_set_route (rd, addr)
     radix_t rd;
     char *addr;
{
  rd->r = (route_t) str2route(addr);
}

radix_print_all (radix_top, fp)
     radix_t radix_top;
     FILE *fp;
{
  radix_print (radix_top, 0, fp);
}

radix_announce (rd, peer)
     radix_t rd;
     peer_t peer;
{
  route_t rt;

  /* left first */
  if (rd->left->bit < 0) {
    if (rd->left->flag != RADIX_ROOT) {
      rt = rd->left->r;
      do {
	radix_output (peer, rt);
      } while (rt = rt->next);
    }
  } else {
    radix_announce (rd->left, peer);
  }

  /* right left */
  if (rd->right->bit < 0) {
    if (rd->right->flag != RADIX_ROOT) {
      rt = rd->right->r;
      do {
	radix_output (peer, rt);
      } while (rt = rt->next);
    }
  } else {
    radix_announce (rd->right, peer);
  }
}

radix_print (rd, depth, fp)
     radix_t rd;
     int depth;
     FILE *fp;
{
  mask_t m;
  route_t rt;

  fprintf (fp, "%*sbit[%d]", depth, " ",  rd->bit);
  
  for (m = rd->mlist; m; m = m->next) {
    fprintf (fp, " mask[%d:%d]", m->masklen, m->refcnt);
  }
  fprintf (fp, "\r\n");

  if (rd->left->bit < 0) {
    rt = rd->left->r;
    do {
      fprintf (fp, "%*sleft  is leaf[%d] : ", depth, " ", rd->bit);
      route_print (fp, rt);
    } while (rt = rt->next);
  } else {
    fprintf (fp, "%*sleft  is node : \r\n", depth, " ");
    radix_print (rd->left, depth + 1, fp);
  }

  if (rd->right->bit < 0) {
    rt = rd->right->r;
    do {
      fprintf (fp, "%*sright is leaf[%d] : ", depth, " ", rd->bit);
      route_print (fp, rt);
    } while (rt = rt->next);
  } else {
    fprintf (fp, "%*sright is node : \r\n", depth, " ");
    radix_print (rd->right, depth + 2, fp);
  }
  fflush (fp);
}     

route_print (fp, r)
     FILE *fp;
     route_t r;
{
  struct in_addr addr;
  char network[20];

  addr.s_addr = r->prefix;
  sprintf (network, "%s/%d", inet_ntoa(addr), r->masklen);
  fprintf (fp, "%-20s\r\n", network);
}  

/* print route information out to fp */
radix_vty_dump (struct vty *vty, radix_t rd)
{
  route_t rt;

  /* left first */
  if (isleaf (rd->left)) {
    if (rd->left->flag != RADIX_ROOT) {
      rt = rd->left->r;
      do {
	route_vty_out (vty, rt);
      } while (rt = rt->next);
    }
  } else {
    radix_vty_dump (vty, rd->left);
  }

  /* right left */
  if (isleaf (rd->right)) {
    if (rd->right->flag != RADIX_ROOT) {
      rt = rd->right->r;
      do {
	route_vty_out (vty, rt);
      } while (rt = rt->next);
    }
  } else {
    radix_vty_dump (vty, rd->right);
  }
}     

/* go down radix tree and find the most deep leaf */
static radix_t
radix_search(rd, r)
     radix_t rd;
     route_t r;
{
  byte *p = PREFIX (r);

  while (rd->bit > 0) {
    if (p[rd->offset] & rd->mask)
      rd = rd->right;
    else
      rd = rd->left;
  }
  return rd;
}

/* return matched route */
route_t
radix_match(radix_top, r)
     radix_t radix_top;
     route_t r;
{
  struct route masked;
  struct Radix *rd;
  route_t rt;
  radix_t bt;
  byte *p = PREFIX (r);

  /* Go down radix tree */
  rd = radix_search (radix_top, r);

  /* Dose it exactry match ? (Host route) */
  if (rd->r->prefix == r->prefix) {
    return rd->r;
  }

  /* Dose it match to network route ? */
  rt = rd->r;
#define HOST_MASK 32
  do {
    if (rt->masklen != HOST_MASK) {
      if (radix_mask_match (r, rt)) {
	return rt;
      }
    }      
  } while (rt = rt->next);

  /* O.K. now we start backtracking */
  bt = rd;

  do {
    mask_t m;
    radix_t x;

    bt = bt->parent;
    if (m = bt->mlist) {
      do {
	radix_masked_route(r, &masked, m->masklen);
	x = radix_search (bt, &masked);
	if (x->r->prefix == masked.prefix) {
	  return x->r;
	}
      } while (m = m->next);
    }

  } while (bt != radix_top);
  

  /* Dose not match */
  return NULL;
}

/* like CISCO show ip bgp x.x.x.x y.y.y.y longer-prefix */
radix_t
radix_match_longer (radix_top, r)
     radix_t radix_top;
     route_t r;
{
  radix_t rd = radix_top;
  byte *p = PREFIX (r);

  while (rd->bit > 0 && rd->bit <= r->masklen) {
    if (p[rd->offset] & rd->mask)
      rd = rd->right;
    else
      rd = rd->left;
  }
  return rd;
}

radix_masked_route (r, m, mask)
     route_t r;
     route_t m;
     int mask;
{
  byte *pnt = PREFIX(r);
  byte *mpnt = PREFIX(m);
  int offset;
  int shift;
  int i;

  bzero(m, sizeof(struct route));

  offset = RD_TABLE[mask].offset;
  shift = RD_TABLE[mask].shift;

  for (i = 0; i < offset; i++) {
    *mpnt++ = *pnt++;
  }
  *mpnt = ((*pnt) >> shift) << shift;
}

/* currently r is implicitly regartd as host address */
radix_mask_match (r, rt)
  route_t r;  /* dest */
  route_t rt; /* rule */
{
  byte *dest = PREFIX (r);
  byte *rule = PREFIX (rt);
  byte *start;
  int i;
  int offset;
  int shift;
  
  if (r->prefix == rt->prefix) {
    log ("radix_mask_match error: same prefix\r\n");
    return 0;
  }

  offset = RD_TABLE[rt->masklen].offset;
  shift = RD_TABLE[rt->masklen].shift;
  /* printf ("MASK MATCH offset = %d, shift = %d\n", offset, shift); */

  for (i = 0; i < offset; i++) {
    if (*dest++ != *rule++)
      return 0;
  }
      
  if ((*dest >> shift) != (*rule >> shift))
    return 0;

  /* matched */
  return 1;
}

radix_t
radix_new_pair(r, bit, point)
     route_t r;
     int bit;
     radix_t point;
{
  byte *p = PREFIX (r);
  radix_t node;			/* for node */
  radix_t leaf;			/* for leaf */
  radix_t ppoint = point->parent;

  node = radix_new();
  leaf = radix_new();

  /* node prepare */
  radix_set_bit (node, bit);
  node->parent = point->parent;

  /* leaf prepare */
  leaf->parent = node;
  leaf->r = r;
  leaf->bit = -1;
  
  if (p[ppoint->offset] & ppoint->mask) {
    ppoint->right = node;
  } else {
    ppoint->left = node;
  }

  /* link leaf */
  if (p[node->offset] & node->mask) {
    node->right = leaf;
    node->left = point;
  } else {
    node->left = leaf;
    node->right = point;
  }
  point->parent = node;
  
  return node;
}

/* add same prefix route to a radix node */
radix_add_rlist (rx, r)
     struct Radix *rx;
     route_t r;
{
  route_t rp;
  route_t rpp;
  
  /* deeper mask goes to deeper entry of a list */
  rp = rpp = rx->r;
  while (rp && r->masklen > rp->masklen) {
    rpp = rp;
    rp = rp->next;
  }

  if (rp == rpp) {
    rx->r = r;			/* insert into first point */
  } else {
    rpp->next = r;
  }
  r->next = rp;
}

/* try to replace existing route : this function can be merged with
   radix_add_rlist, but so far it doesn't */
route_t
radix_try_replace (rx, r)
     struct Radix *rx;
     route_t r;
{
  route_t rp;
  route_t rpp;
  
  rp = rpp = rx->r;
  while (rp) {
    if (sameprefix (rp, r) && samemasklen (rp, r) & samepeer (rp, r)) {
      if (rp == rpp) {
	rx->r = r;		/* replace at first point */
      } else {
	rpp->next = r;
      }
      r->next = rp->next;
      return rp;		/* return replaced route */
    }
    rpp = rp;
    rp = rp->next;
  }
  /* no replace route is found */
  return NULL;			
}

/* delete route from list of route */
route_t
radix_delete_duproute (rx, r)
     struct Radix *rx;
     route_t r;
{
  route_t rp;
  route_t rpp;
  
  rp = rpp = rx->r;
  while (rp) {
    if (sameprefix (rp, r) && samemasklen (rp, r) & samepeer (rp, r)) {
      if (rp == rpp) {
	rx->r = rp->next;	/* delete first route */
      } else {
	rpp->next = rp->next;
      }
      return rp;		/* return deleted route */
    }
    rpp = rp;
    rp = rp->next;
  }
  /* no deletetion of route occur */
  return NULL;			
}

/* add mask to node */
static void
mask_add_node (rx, masklen)
     struct Radix *rx;
     int masklen;
{
  mask_t new;
  mask_t mp, mpp;

  if (! rx->mlist) {
    rx->mlist = mask_new (masklen);
    return;
  }

  mp = mpp = rx->mlist;
  while (mp && masklen < mp->masklen) {
    mpp = mp;
    mp = mp->next;
  }

  if (mp && masklen == mp->masklen) {
    mp->refcnt++;
    return;
  }

  /* add new mask into linked list */
  new = mask_new (masklen);
  if (mp == mpp) {
    rx->mlist = new;
  } else {
    mpp->next = new;
  }
  new->next = mp;
}


/* add mask to the upper node */
mask_add_upnode (top, rx, mask)
     struct Radix *top;
     struct Radix *rx;
     int mask;
{
  struct Radix *rxx;

  /* in case of no need of mask adding */
  if (mask >= rx->bit)
    return;

  rxx = rx;
  while (mask < rx->bit && rxx != top) {
    rxx = rx;
    rx = rx->parent;
  }
  mask_add_node (rxx, mask);
}

/* promote mask from descend node or leaf */
mask_add_downnode (child, add, bit)
     struct Radix *child;
     struct Radix *add;
     int bit;
{
  if (isnode (child)) {
    /* in case of node */
    mask_t mp, mpp;

    if (child->mlist) {
      mp = mpp = child->mlist;
      while (mp && mp->masklen >= bit) {
	mpp = mp;
	mp = mp->next;
      }
      /* find it and move mask to adding node */
      if (mp == mpp) {
	child->mlist = NULL;
      } else {
	mpp->next = NULL;
      }
      add->mlist = mp;
    }
  } else {
    /* in case of leaf */
    int obit;
    route_t rt;

    /* parent node's bit */
    obit = add->parent->bit;
    rt = child->r;
    /* if there is need of mask addition, now add it to current node */
    while (rt) {
      if (rt->masklen < bit && rt->masklen >= obit) {
	mask_add_node (add, rt->masklen);
      }
      rt = rt->next;
    }
  }
}

route_t
radix_add_duproute (top, rx, r)
     struct Radix *top;
     struct Radix *rx;
     route_t r;
{
  route_t rt;
  
  /* check is there same route coming from the same peer? */
  rt = radix_try_replace (rx, r);
  if (rt)
    return rt;

  radix_add_rlist (rx, r);
  mask_add_upnode (top, rx->parent, r->masklen);
  return NULL;
}

int
radix_add_new (top, rx, r)
     struct Radix *top;
     struct Radix *rx;
     route_t r;
{
  int bit;
  radix_t add, child;
  byte *p = PREFIX (r);

  /* calc first different bit */
  bit = radix_diff_bit (rx->r, r);

  /* walk down tree agein */
  rx = top;
  while (rx->bit > 0 && rx->bit < bit) {
    if (p[rx->offset] & rx->mask) {
      rx = rx->right;
    } else {
      rx = rx->left;
    }
  }
  /* prepare nodes */
  add = radix_new_pair(r, bit, rx);

  /* mask prepare */
  if (add->left->r == r) {
    child = add->right;
  } else {
    child = add->left;
  }
  mask_add_downnode (child, add, bit);
  mask_add_upnode (top, add, r->masklen);
  return BGP_RT_SUCCESS;
}

/* insert route into radix tree */
route_t
radix_add (top, r)
     struct Radix *top;
     route_t r;
{
  int ret;
  radix_t rd;
  
  rd = radix_search (top, r);

  if (sameprefix (rd->r, r)) {
    return radix_add_duproute (top, rd, r);
  }

  radix_add_new (top, rd, r);
  return NULL;
}

/* calc first difference bit point of two route */
radix_diff_bit (r1, r2)
     route_t r1;
     route_t r2;
{
  byte diff;
  int bcount = 1;
  byte *p1 = PREFIX (r1);
  byte *p2 = PREFIX (r2);

  while (*p1 == *p2) {
    p1++;
    p2++;
    bcount++;
  }
  bcount <<= 3;

  diff = *p1 ^ *p2;
  while (diff) {
    diff >>= 1;
    bcount--;
  }

  return bcount + 1;
}

radix_delete_mask (top, rx, masklen)
     struct Radix *top;
     struct Radix *rx;
     int masklen;
{
  radix_t rpp;
  mask_t mp;
  mask_t mpp;

  /* check whether it needs deletion of mask */
  if (masklen >= rx->bit)
    return;

  /* go up tree */
  rpp = rx;
  while (masklen < rx->bit && rx != top) {
    rpp = rx;
    rx = rx->parent;
  }
  
  /* delete mask from node */
  mp = mpp = rpp->mlist;
  while (mp && masklen != mp->masklen) {
    mpp = mp;
    mp = mp->next;
  }
  if (!mp) {
    fprintf (stderr, "cant't find mask");
  }
  if (mp->refcnt) {
    mp->refcnt--;
    return;
  }
  if (mp == mpp) {
    rpp->mlist = mp->next;
  } else {
    mpp->next = mp->next;
  }
  mask_free (mp);
  return;
}

/* delete route from radix tree: 
   if there is route to delete: return deleted route 
   else : return NULL */
route_t
radix_delete (top, r)
     struct Radix *top;
     route_t r;
{
  radix_t rx;
  radix_t rp, rpp;
  radix_t another;
  route_t ro;

  rx = radix_search (top, r);
  ro = rx->r;

  /* can't find route */
  if (! sameprefix (ro, r))
    return NULL;

  /* delete from route list ? */
  if (ro->next) {
    route_t delete;
    delete = radix_delete_duproute (rx, r);
    if (delete)
      radix_delete_mask (top, rx->parent, delete->masklen);
    return delete;
  }

  /* check is this route should be deleted */
  if (! samemasklen (ro, r) || ! samepeer (ro, r)) {
    return NULL;
  }

  /* delete mask from radix tree */
  radix_delete_mask (top, rx->parent, r->masklen);

  /* store parent and grand parent */
  rp = rx->parent;
  rpp = rp->parent;

  if (rp->left == rx) {
    another = rp->right;
  } else {
    another = rp->left;
  }

  /* if mask can move to another node do it */
  if (isnode (another)) {
    mask_t mp;
    mp = rp->mlist;
    while (mp) {
      if (mp->masklen < another->bit) {
	mask_add_node (another, mp->masklen);
      }
      mp = mp->next;
    }
  }

  /* delete node and leaf */
  if (rpp->left == rp) {
    rpp->left = another;
  } else {
    rpp->right = another;
  }
  another->parent = rpp;

  radix_free(rx);
  radix_free(rp);
  return ro;
}

/* init radix tree */
radix_t
radix_init()
{
  radix_t top, left, right;

  /* allocate top, left, right node */
  top = radix_new();
  left = radix_new();
  right = radix_new();

  top->flag = left->flag = right->flag = RADIX_ROOT;

  /* link node and leaf each other */
  top->parent = left->parent = right->parent = top;
  top->left = left;
  top->right = right;

  /* top node */
  radix_set_bit (top, 1);
  mask_add_node (top, 0);
  
  /* right leaf */
  right->bit = -1;
  radix_set_route (right, "255.255.255.255/32");

  /* left leaf */
  left->bit = -1;
  radix_set_route (left, "0.0.0.0/0");

  return top;
}
