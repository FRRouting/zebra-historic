/* Route object related function for route server.
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX_IPV6
#include <linux/in6.h>
#endif /* LINUX_IPV6 */
#include <arpa/inet.h>
#include <config.h>

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_peer.h"
#include "bgp_dump.h"
#include "bgp_attr.h"
#include "bgp_aspath.h"

#include "log.h"
#include "route.h"
#include "radix.h"
#include "zebra.h"
#include "linklist.h"
#include "memory.h"

struct radix_top *bgp_radix;
#ifdef HAVE_IPV6
struct radix_top *bgp_radix_ipv6;
#endif /* HAVE_IPV6 */

/* Allocate radix_top structure. */
bgp_radix_init ()
{
  /* Make table first. */
  radix_init();

  /* Radix for BGP-4 */
  bgp_radix = radix_make_rib (AF_INET);
  bgp_radix->sameprefix = rt_ip_sameprefix;

#ifdef HAVE_IPV6
  bgp_radix_ipv6 = radix_make_rib (AF_INET6);
  bgp_radix_ipv6->sameprefix = rt_ipv6_sameprefix;
#endif /* HAVE_IPV6 */
}

/* NLRI info to route value (u_long) */
u_long
nlri2route (char *str, int size)
{
  u_long ret;
  char zbuf[] = {'\0','\0','\0','\0'};
  char *pnt = zbuf;
  u_char *bp = (u_char *) & ret;

  if (size > 4) 
    {
      log ("NLRI length exceed size of %d\n", size);
      size = 4;
    }

  bcopy(str, pnt, size);
  bcopy(pnt, bp, 4);

  return (ret);
}

/* route allocation statistics */
unsigned long route_alloc = 0;

/**/
unsigned long bgp_info_alloc = 0;

/**/
struct bgp_info *
bgp_info_new ()
{
  struct bgp_info *new;

  new = (struct bgp_info *) malloc (sizeof (struct bgp_info));
  bzero (new, sizeof (struct bgp_info));
  bgp_info_alloc++;

  return new;
}

/* Allocate new prefix_in and bgp_info. */
static struct bgp_route *
bgp_route_new ()
{
  struct bgp_route *br;

  br = XMALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_route));
  bzero (br, sizeof (struct bgp_route));

  return br;
}

/**/
static void
bgp_info_free (struct bgp_info *binfo)
{
  if (binfo->attr)
    attr_free (binfo->attr);
  free (binfo);
  bgp_info_alloc--;
}

/**/
void
bgp_route_free (struct bgp_route *br)
{
  if (br->attr)
    attr_free (br->attr);

  XFREE (MTYPE_BGP_ROUTE, br);
}

/**/
int
bgp_same_peer (struct prefix_in *pin1, struct prefix_in *pin2)
{
  struct bgp_route *br1, *br2;

  br1 = (struct bgp_route *) pin1;
  br2 = (struct bgp_route *) pin2;
      
  if (br1->prefix.s_addr == br2->prefix.s_addr &&
      br1->mask == br2->mask &&
      br1->peer == br2->peer)
    return 1;
  return 0;
}

/**/
dump_bad_nlri (unsigned char *pnt, int rsize, struct peer *peer)
{
  int i;

  log ("Bad nlri dump start\n");
  for (i = 0; i < rsize; i++)
    log ("[%d] %d\n", i, *(pnt+i));
  log ("Bad nlri dump end\n");
}

/* Parse route and add route into radix tree. */
route_parse (u_char *pnt,
	     int rsize,
	     struct attr *attr,
	     struct peer *peer)
{
  u_char *start;
  u_char *lim;
  int psize;
  struct bgp_route *br;

  /* In case of BGP-4+ there will be no NLRI. */
  if (rsize == 0) 
    return;

  /* Set end of the packet. */
  start = pnt;
  lim = pnt + rsize;

  while (pnt < lim ) 
    {
      int dupflag;
      struct bgp_route *find;

      /* Add bgp info to prefix. */
      br = bgp_route_new ();
      br->mask = *pnt++;
      psize = PSIZE (br->mask);
      br->prefix.s_addr = nlri2route (pnt, psize);
      br->peer = peer;
      br->attr = attr;
      br->type = ZEBRA_ROUTE_BGP;
      attr->refcnt++;

      /* Check masklen of incoming route. */
      if (br->mask > 32)
	{
	  log ("wrong mask length %s/%d rsize %d\n", 
	       inet_ntoa (br->prefix), br->mask, rsize);
	  bgp_route_free (br);
	  dump_bad_nlri (start, rsize, peer);
	  return -1;
	}

      dupflag = 0;

      /* Have this route come from same peer ? */
      find = (struct bgp_route *) radix_lookup_fn (bgp_radix,
						   (struct prefix_in *) br, 
						   bgp_same_peer);
      if (find)
	{
	  struct bgp_route *del;

	  del = (struct bgp_route *) radix_delete_peer (bgp_radix, find);
	  if (del != find)
	    {
	      log ("duplicate delete error\n");
	      return -1;
	    }

	  bgp_route_free (del);
	  dupflag = 1;
	}

      bgp_log_route(peer, br, dupflag);

      if (!dupflag)
	peer->prefix_count++;

      radix_add (bgp_radix, (struct prefix *) br);

      pnt += psize;
    }
}

bgp_delete_peer (struct prefix_in *pin1,
		 struct prefix_in *pin2,
		 struct peer *peer)
{
  if (pin1->mask == pin2->mask)
    {
      struct bgp_route *br;

      br = (struct bgp_route *)pin1;

      if (br->peer == peer)
	return 1;
      else
	return 0;
    }
  return 0;
}

/* withdraw handling routine */
withdraw_route(unsigned char *pnt, int unfeasible_len, struct peer *peer)
{
  struct bgp_route new;
  struct bgp_route *del;
  int psize;
  unsigned char *cur = pnt;
  extern FILE *logfp;
  
  while (cur - pnt < unfeasible_len) 
    {
      new.mask = *cur++;
      psize = PSIZE (new.mask);
      new.prefix.s_addr = nlri2route (cur, psize);

      del = (struct bgp_route *) radix_delete_func (bgp_radix,
						    (struct prefix_in *)&new,
						    bgp_delete_peer,
						    peer);

      log ("Withdraw:[%s] %s/%d ", 
	   peer->host, inet_ntoa(new.prefix), new.mask);
	 
      if (del == NULL)
	log2 ("(not exist)\r\n");
      else 
	{
	  log2 ("(exist)\r\n");
	  bgp_route_free (del);
	  peer->prefix_count--;
	}
      cur += psize;
    }
  fflush (logfp);
}
  
bgp_peer_route_delete (struct prefix *rt, struct peer *peer)
{
  struct bgp_route *br;

  br = (struct bgp_route *)rt;

  if (br->peer == peer)
    {
      struct bgp_route *del;

      del = (struct bgp_route *) radix_delete (bgp_radix, rt);
      if (del != (struct bgp_route *) rt)
	{
	  log ("radix_delete bug\n");
	}
      bgp_route_free (del);
    }
}

/**/
bgp_peer_delete (struct peer *peer)
{
  radix_apply_func (bgp_radix, bgp_peer_route_delete, peer);
  peer->prefix_count = 0;
}

struct peer *
peer_lookup_by_logformat (char *str)
{
  char *start;
  char *end;
  char peernamebuf[256];
  struct peer *peer;
  extern list peer_list;

  start = strrchr (str, '[');
  end = strrchr (str, ']');

  if (start == NULL || end == NULL)
    return NULL;
  
  memcpy (peernamebuf, start + 1, end - start - 1);
  peernamebuf[end - start - 1] = '\0';

  peer = (struct peer *) peer_lookup_by_host (peernamebuf);
  if (peer == NULL)
    {
      peer = peer_new();
      peer->host = strdup (peernamebuf);
      list_add_node (peer_list, peer);
    }

  return peer;
}

#if 0
bgp_sim (char *sim_file)
{
  FILE *sim;
  char BUF[256];
  char command[256];
  char ip[256];
  char date[256];
  char time[256];
  struct peer *peer;
  struct prefix_in *pin;
  struct prefix_in *ret;
  struct bgp_info *binfo;

  sim = fopen (sim_file, "r");
  if (sim == NULL) 
    {
      perror ("open");
      exit (1);
    }

  while (fgets(BUF, sizeof (BUF), sim)) 
    {
      int count;

      count = sscanf (BUF, "%s %s %s %s", date, time, command, ip);
      if (count != 4)
	continue;

      peer = peer_lookup_by_logformat (command);
      if (peer == NULL)
	continue;

      /* Update. */
      if (strncmp (command, "Update", 6) == 0)
	{
	  int dupflag = 0;
	  struct prefix_in *find;

	  pin = bgp_route_new ();
	  binfo = pin->gate.info;
	  pin->type = ZEBRA_ROUTE_BGP;

	  str2prefix_in (ip, pin);
	  binfo->peer = peer;
	  binfo->attr = NULL;

	  find = radix_lookup_fn (bgp_radix, pin, bgp_same_peer);
	  if (find)
	    {
	      struct prefix_in *tmp;

	      tmp = (struct prefix_in *) radix_delete_peer (bgp_radix, find);
	      if (tmp != find)
		fprintf (stderr, "duplicate delete error\n");

	      bgp_route_free (tmp);
	      dupflag = 1;
	    }
	  bgp_log_route (peer, pin, dupflag);
	  radix_add (bgp_radix, (struct prefix *) pin);
	}
      /* Withdraw. */
      else if (strncmp (command, "Withdraw", 7) == 0)
	{
	  struct prefix_in *del;

	  pin = bgp_route_new ();
	  binfo = pin->gate.info;
	  pin->type = ZEBRA_ROUTE_BGP;

	  str2prefix_in (ip, pin);
	  binfo->peer = peer;
	  binfo->attr = NULL;

	  del = (struct prefix_in *) radix_delete_func (bgp_radix, pin, bgp_delete_peer, peer);

	  log ("Withdraw:[%s] %s/%d ", 
	       peer->host, inet_ntoa(pin->prefix), pin->mask);
	 
	  if (del == NULL)
	    log2 ("(not exist)\r\n");
	  else
	    {
	      log2 ("(exist)\r\n");
	      bgp_route_free (del);
	    }
	}
    }
}
#endif

#ifdef HAVE_IPV6
bgp_in6_add_radix (struct prefix_in6 *pin6)
{
  radix_add (bgp_radix_ipv6, (struct prefix *) pin6);
}
#endif /* HAVE_IPV6 */
