/* Route object related function for route server.
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

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "prefix.h"
#include "table.h"
#include "zebra.h"
#include "linklist.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "command.h"

#include "bgpd.h"
#include "bgp_route.h"
#include "bgp_attr.h"
#include "bgp_peer.h"
#include "bgp_dump.h"
#include "bgp_aspath.h"
#include "bgp_community.h"

/* BGP Routing Information Base. */
struct route_table *bgp_table_ipv4;
#ifdef HAVE_IPV6
struct route_table *bgp_table_ipv6;
#endif /* HAVE_IPV6 */

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

/* Allocate new bgp route information. */
struct bgp_route *
bgp_route_new ()
{
  struct bgp_route *new;

  new = XMALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_route));
  bzero (new, sizeof (struct bgp_route));

  return new;
}

/* Free bgp route information. */
void
bgp_route_free (struct bgp_route *br)
{
  if (br->attr)
    bgp_attr_free (br->attr);

  XFREE (MTYPE_BGP_ROUTE, br);
}

/* Add bgp route infomation to routing table node. */
void
bgp_route_add (struct bgp_route **rp, struct bgp_route *rib)
{
  struct bgp_route *cp;
  struct bgp_route *pp;

  cp = pp = *rp;

  /* Only this match until I code preference match function. */
  if (cp == pp)
    {
      *rp = rib;

      if (cp)
	cp->prev = rib;
      rib->next = cp;
    }
  else
    {
      if (pp)
	pp->next = rib;
      rib->prev = pp;

      if (cp)
	cp->prev = rib;
      rib->next = cp;
    }
}

/* Delete rib from rib list. */
void
bgp_route_delete (struct bgp_route **rp, struct bgp_route *rib)
{
  if (rib->next)
    rib->next->prev = rib->prev;
  if (rib->prev)
    rib->prev->next = rib->next;
  else
    *rp = rib->next;
}

/* called from BGP Update packet */
void
bgp_log_route(struct prefix_ipv4 *p, struct peer *peer,
	      struct bgp_route *br, int dup)
{
  struct attr *attr;

  attr = br->attr;

  log ( "Update%s:", dup ? "[r]" : "");
  log2 ("[%s] %s/%d", peer->host,inet_ntoa(p->prefix), p->prefixlen);

  bgp_dump_attr (peer, attr);

  log2 ("\r\n");
}

/* Update prefix which comes from peer. */
void
nlri_update (struct prefix_ipv4 *p, struct peer *peer, struct attr *attr)
{
  ;
}

/* Parse route and add route into radix tree. */
void
nlri_parse (u_char *pnt, int len, struct attr *attr, struct peer *peer)
{
  u_char *start;
  u_char *lim;

  /* When protocol is BGP-4+ NLRI length may be zero. */
  if (len == 0) 
    return;

  /* OK Start to parse NLRI. */
  start = pnt;
  lim = pnt + len;

  while (pnt < lim) 
    {
      struct bgp_route *br;
      struct prefix_ipv4 p;
      int dupflag;
      struct bgp_route *same;
      struct route_node *np;
      int psize;

      /* Add bgp info to prefix. */
      br = bgp_route_new ();

      /* Fetch one prefix from NLRI. */
      p.family = AF_INET;
      p.prefixlen = *pnt++;
      psize = PSIZE (p.prefixlen);
      p.prefix.s_addr = nlri2route (pnt, psize);

      /* Check masklen of incoming route. */
      if (p.prefixlen > IPV4_MAX_BITLEN)
	{
	  log ("wrong mask length %s/%d len %d\n", 
	       inet_ntoa (br->prefix), br->mask, len);
	  return;
	}
      br->peer = peer;
      br->attr = attr;
      br->type = ZEBRA_ROUTE_BGP;
      attr->refcnt++;
      dupflag = 0;


      /* Check is this prefix is already announced from same peer. */
      np = route_node_get (bgp_table_ipv4, (struct prefix *) &p);

      for (same = np->info; same; same = same->next)
	if (same->peer == peer)
	  break;

      /* There is a same prefix which comes from the same peer.  This
         means implicit withdraw. */
      if (same)
	{
	  bgp_route_delete ((struct bgp_route **) &np->info, same);
	  bgp_route_free (same);
	  dupflag = 1;
	}

      bgp_log_route (&p, peer, br, dupflag);

      if (!dupflag)
	peer->prefix_count++;

      bgp_route_add ((struct bgp_route **)&np->info, br);

      pnt += psize;
    }
  return;
}

/* withdraw handling routine */
void
nlri_withdraw (unsigned char *pnt, int unfeasible_len, struct peer *peer)
{
  struct bgp_route *del;
  int psize;
  unsigned char *cur = pnt;
  extern FILE *logfp;
  
  while (cur - pnt < unfeasible_len) 
    {
      struct prefix_ipv4 p;
      struct route_node *np;

      p.prefixlen = *cur++;
      psize = PSIZE (p.prefixlen);
      p.prefix.s_addr = nlri2route (cur, psize);

      log ("Withdraw:[%s] %s/%d ", 
	   peer->host, inet_ntoa(p.prefix), p.prefixlen);

      /* First look up routing table node. */
      np = route_node_get (bgp_table_ipv4, (struct prefix *) &p);
      for (del = np->info; del; del = del->next)
	if (del->peer == peer)
	  break;

      /* Withdraw route from route list. */
      if (del == NULL)
	log2 ("(not exist)\r\n");
      else 
	{
	  log2 ("(exist)\r\n");
	  bgp_route_delete ((struct bgp_route **) &np->info, del);
	  bgp_route_free (del);
	  peer->prefix_count--;
	}

      cur += psize;
    }
  fflush (logfp);
}
  
/* Delete peer's all route. */
void
bgp_peer_delete (struct peer *peer)
{
  struct route_node *np;
  struct bgp_route *br;
  struct bgp_route *next;

  for (np = route_top (bgp_table_ipv4); np; np = route_next (np))
    for (br = np->info; br; br = next)
      {
	/* Preserve next pointer. */
	next = br->next;
	if (br->peer == peer)
	  {
	    bgp_route_delete ((struct bgp_route **) &np->info, br);
	    bgp_route_free (br);
	  }
      }
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

	  /* find = radix_lookup_fn (bgp_table, pin, bgp_same_peer); */
	  if (find)
	    {
	      struct prefix_in *tmp;

	      tmp = (struct prefix_in *) radix_delete_peer (bgp_table, find);
	      if (tmp != find)
		fprintf (stderr, "duplicate delete error\n");

	      bgp_route_free (tmp);
	      dupflag = 1;
	    }
	  bgp_log_route (peer, pin, dupflag);
	  radix_add (bgp_table_ipv4, (struct prefix *) pin);
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

	  del = (struct prefix_in *) radix_delete_func (bgp_table_ipv4, pin, bgp_delete_peer, peer);

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

char *bgp_update_origin[] = {"i","e","?"};
char *bgp_update_origin_long[] = {"IGP","EGP","Incomplete"};

/* called from terminal list command */
void
route_vty_out (struct vty *vty, struct prefix *p, struct bgp_route *binfo)
{
  struct attr *attr;

  vty_out (vty, "   ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      vty_out (vty, "%-16s%10lu%10lu%10lu ", 
	       inet_ntoa(attr->next_hop), attr->med, attr->local_pref, attr->weight);
    
    /* Print aspath */
    if (attr->aspath)
      aspath_print_vty (vty, attr->aspath);

    /* Print origin */
    vty_out (vty, " %s", bgp_update_origin[attr->origin]);
  }

  vty_out (vty, "\r\n");
}  

void
route_vty_out_detail (struct vty *vty, struct prefix *p, 
		      struct bgp_route *binfo)
{
  char buf[BUFSIZ];
  struct attr *attr;

  /* Header of detailed BGP route information. */
  vty_out (vty, "BGP routing table entry for %s/%d.\r\n",
	   inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
	   p->prefixlen);

  /* Print attribute */
  attr = binfo->attr;
  if (attr) 
    {
      /* Print aspath */
      if (attr->aspath)
	aspath_print_vty (vty, attr->aspath);

      /* show nex hop */
      if (attr) {
	vty_out (vty, "Nexthop %s\r\n", inet_ntoa(attr->next_hop));
	vty_out (vty, "Origin %s, ", bgp_update_origin_long[attr->origin]);
	vty_out (vty, "metric %lu, ", attr->med);
	vty_out (vty, "weight %lu, ", attr->weight);
	vty_out (vty, "Localpref %lu", attr->local_pref);

	if (attr->community) {
	  vty_out (vty, ", Commuity");
	  community_print_vty (vty, attr->community);
	}
	vty_out (vty, "\r\n");
      }
    }

  vty_out (vty, "\r\n");
}  

/* BGP route print out function. */
DEFUN (show_ip_bgp, show_ip_bgp_cmd,
       "show ip bgp [IPV4_ADDR]",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP address\n")
{
  int ret;
  struct route_node *node;
  struct bgp_route *route;
  struct prefix_ipv4 match;

  route = NULL;

  /* `show ip bgp' command shows all of bgp routes. */
  if (argc == 0)
    {
      int count;

      /* Header print out. */
      vty_out (vty, "Network             Next Hop            Metric    LocPrf Weight Path\r\n");

      /* We try to set counter to ten. */
      count = 10;

      /* Start processing of routes. */
      for (node = route_top (bgp_table_ipv4); node; node = route_next (node)) 
	for (route = node->info; route; route = route->next)
	  {
	    route_vty_out (vty, &node->p, route);

	    /* Decrement counter. */
	    count--;
	    if (count == 0)
	      {
		/* We need to preserve function pointer and process
                   pointer. */
		/* vty->; */
	      }
	  }

      return CMD_SUCCESS;
    }

  /* `show ip bgp IPV4_ADDR command shows specified route's
     information. */
  ret = inet_aton (argv[0], &match.prefix);
  if (! ret)
    {
      vty_out (vty, "address is malformed\r\n");
      return CMD_WARNING;
    }
  match.family = AF_INET;
  match.prefixlen = IPV4_MAX_BITLEN;
  
  /* Lookup route node. */
  node = route_node_match (bgp_table_ipv4, (struct prefix *) &match);

  if (node == NULL) 
    {
      vty_out (vty, "can't find route\r\n");
      return CMD_WARNING;
    }

  /* Node is locked by route_node_lookup. */
  for (route = node->info; route; route = route->next)
    route_vty_out_detail (vty, &node->p, route);

  /* Work is done, so unlock the node. */
  route_unlock_node (node);

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       "Show bgpd's own routing information of IPv6\n")
{
  struct route_node *node;
  struct bgp_route *route;
  
  vty_out (vty, "\r\nNetwork                  Next Hop       Metric    LocPrf Path\r\n");

  /* Start processing of routes. */
  for (node = route_top (bgp_table_ipv6); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      route_vty_out (vty, &node->p, route);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

/* Allocate routing table structure and install commands. */
void
bgp_route_init ()
{
  bgp_table_ipv4 = route_table_init ();
#ifdef HAVE_IPV6
  bgp_table_ipv6 = route_table_init ();
#endif /* HAVE_IPV6 */

  /* Install commands. */
  install_element (VIEW_NODE, &show_ip_bgp_cmd);
  install_element (ENABLE_NODE, &show_ip_bgp_cmd);

#ifdef HAVE_IPV6
  /* IPV6 specific commands. */
  install_element (VIEW_NODE, &show_ipv6_bgp_cmd);
  install_element (ENABLE_NODE, &show_ipv6_bgp_cmd);
#endif /* HAVE_IPV6 */

}
