/*
 * OSPF version 2 daemon program.
 * Copyright (C) 1999, 2000 Toshiaki Takada
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

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
#include "memory.h"
#include "stream.h"
#include "log.h"
#include "sockunion.h"          /* for inet_aton () */
#include "zclient.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"

/* OSPF instance top. */
struct ospf *ospf_top;

extern struct zclient *zclient;

static char *ospf_network_type_str[] =
{
  "Null",
  "POINTOPOINT",
  "BROADCAST",
  "NBMA",
  "POINTOMULTIPOINT",
  "VIRTUALLINK"
};

/* Temporary Area Format Routine AREA-ID and TYPE to ASCII */
char*
ait_ntoa (struct in_addr inaddr, int type)
{

#ifdef HAVE_NSSA

	static char	buf[50];
	static char typ[10];

	typ[0]=0;

	if (type == OSPF_AREA_NSSA) strcpy (typ, "NSSA");
	if (type == OSPF_AREA_STUB) strcpy (typ, "Stub");

	if (typ[0]==0)
	sprintf (buf, "(%s)", inet_ntoa(inaddr));
	else
	sprintf (buf, "(%s [%s])", inet_ntoa(inaddr), typ);

return buf;

#else /* ! HAVE_NSSA */

return (inet_ntoa(inaddr));

#endif /* HAVE_NSSA */

}



/* Get Router ID from ospf interface list. */
struct in_addr
ospf_router_id_get (list if_list)
{
  listnode node;
  struct in_addr router_id;

  bzero (&router_id, sizeof (struct in_addr));

  for (node = listhead (if_list); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      listnode cn;

      if (!if_is_up (ifp) || oi->passive_interface == OSPF_IF_PASSIVE)
	continue;
      
      /* Ignore virtual link interface. */
      if (oi->type != OSPF_IFTYPE_VIRTUALLINK) 
	for (cn = listhead (ifp->connected); cn; nextnode (cn))
	  {
	    struct connected *co = cn->data;

	    if (co->address->family == AF_INET)
	      /* Ignore loopback network. */
	      if (!if_is_loopback (ifp))
		if (IPV4_ADDR_CMP (&router_id, &co->address->u.prefix4) < 0)
		  router_id = co->address->u.prefix4;
	  }
    }

  return router_id;
}

#define OSPF_EXTERNAL_LSA_ORIGINATE_DELAY 1

void
ospf_router_id_update ()
{
  listnode node;
  struct in_addr router_id, router_id_old;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_info ("Router-ID[OLD:%s]: Update",inet_ntoa (ospf_top->router_id));

  router_id_old = ospf_top->router_id;

  if (ospf_top->router_id_static.s_addr != 0)
    router_id = ospf_top->router_id_static;
  else
    router_id = ospf_router_id_get (ospf_top->iflist);

  ospf_top->router_id = router_id;
  
  if (IS_DEBUG_OSPF_EVENT)
    zlog_info ("Router-ID[NEW:%s]: Update", inet_ntoa (ospf_top->router_id));

  if (!IPV4_ADDR_SAME (&router_id_old, &router_id))
    {
      for (node = listhead (ospf_top->iflist); node; nextnode (node))
        {
	  struct interface *ifp = getdata (node);
          struct ospf_interface *oi = ifp->info;
          /* Is interface OSPF enable? */
          /* if (!ospf_if_is_enable (ifp))
             continue; */

          /* Update self-neighbor's router_id. */
          oi->nbr_self->router_id = router_id;
        }

      /* If AS-external-LSA is queued, then flush those LSAs. */
      if (router_id_old.s_addr == 0 && ospf_top->external_origin)
	{
	  int type;
	  /* Originate each redistributed external route. */
	  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
	    if (ospf_top->external_origin & (1 << type))
	      thread_add_event (master, ospf_external_lsa_originate_timer,
				NULL, type);
	  /* Originate Deafult. */
	  if (ospf_top->external_origin & (1 << ZEBRA_ROUTE_MAX))
	    thread_add_event (master, ospf_default_originate_timer,
			      &ospf_top->default_originate, 0);

	  ospf_top->external_origin = 0;
	}

      OSPF_TIMER_ON (ospf_top->t_router_lsa_update,
		     ospf_router_lsa_update_timer, OSPF_LSA_UPDATE_DELAY);
    }
}

int
ospf_router_id_update_timer (struct thread *thread)
{
  if (IS_DEBUG_OSPF_EVENT)
    zlog_info ("Router-ID: Update timer fired!");

  ospf_top->t_router_id_update = NULL;
  ospf_router_id_update ();

  return 0;
}

/* For OSPF area sort by area id. */
int
ospf_area_id_cmp (struct ospf_area *a1, struct ospf_area *a2)
{
  if (ntohl (a1->area_id.s_addr) > ntohl (a2->area_id.s_addr))
    return 1;
  if (ntohl (a1->area_id.s_addr) < ntohl (a2->area_id.s_addr))
    return -1;
  return 0;
}

/* For OSPF neighbor sort by neighbor address. */
int
ospf_nbr_static_cmp (struct ospf_nbr_static *n1, struct ospf_nbr_static *n2)
{
  if (ntohl (n1->addr.s_addr) > ntohl (n2->addr.s_addr))
    return 1;
  if (ntohl (n1->addr.s_addr) < ntohl (n2->addr.s_addr))
    return -1;
  return 0;
}

/* Allocate new ospf structure. */
struct ospf *
ospf_new ()
{
  int i;

  struct ospf *new = XMALLOC (MTYPE_OSPF_TOP, sizeof (struct ospf));
  bzero (new, sizeof (struct ospf));

  new->router_id.s_addr = htonl (0);
  new->router_id_static.s_addr = htonl (0);

  new->abr_type = OSPF_ABR_STAND;
  new->iflist = iflist;
  new->vlinks = list_new ();
  new->areas = list_new ();
  new->areas->cmp = (int (*)(void *, void *)) ospf_area_id_cmp;
  new->networks = (struct route_table *) route_table_init ();
  new->nbr_static = list_new ();
  new->nbr_static->cmp = (int (*)(void *, void *)) ospf_nbr_static_cmp;

  new->lsdb = new_lsdb_new ();

  new->default_originate = DEFAULT_ORIGINATE_NONE;

  new->new_external_route = route_table_init ();
  new->old_external_route = route_table_init ();
  new->external_lsas = route_table_init ();

  /* Distribute parameter init. */
  for (i = 0; i <= ZEBRA_ROUTE_MAX; i++)
    {
      new->dmetric[i].type = -1;
      new->dmetric[i].value = -1;
    }
  new->default_metric = -1;
  new->ref_bandwidth = OSPF_DEFAULT_REF_BANDWIDTH;

  /* SPF timer value init. */
  new->spf_delay = OSPF_SPF_DELAY_DEFAULT;
  new->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;

  /* MaxAge init. */
  new->maxage_lsa = list_new ();
  new->t_maxage_walker =
    thread_add_timer (master, ospf_lsa_maxage_walker,
                      NULL, OSPF_LSA_MAXAGE_CHECK_INTERVAL);

  /* Distance table init. */
  new->distance_table = route_table_init ();

  new->lsa_refresh_queue.index = 0;
  new->lsa_refresh_interval = OSPF_LSA_REFRESH_INTERVAL_DEFAULT;
  new->t_lsa_refresher = thread_add_timer (master, ospf_lsa_refresh_walker,
					   new, new->lsa_refresh_interval);
  new->lsa_refresher_started = time (NULL);
  
  return new;
}


/* allocate new OSPF Area object */
struct ospf_area *
ospf_area_new (struct in_addr area_id)
{
  struct ospf_area *new;

  /* Allocate new config_network. */
  new = XMALLOC (MTYPE_OSPF_AREA, sizeof (struct ospf_area));
  bzero (new, sizeof (struct ospf_area));

  new->top = ospf_top;

  new->area_id = area_id;

  new->external_routing = OSPF_AREA_DEFAULT;
  new->default_cost = 1;
  new->auth_type = OSPF_AUTH_NULL;

  /* New LSDB init. */
  new->lsdb = new_lsdb_new ();

  /* Self-originated LSAs initialize. */
  new->router_lsa_self = NULL;
  /* new->summary_lsa_self = route_table_init(); */
  /* new->summary_lsa_asbr_self = route_table_init(); */

  new->iflist = list_new ();
  new->ranges = route_table_init ();

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    ospf_top->backbone = new;

  return new;
}

void
ospf_area_free (struct ospf_area *area)
{
  /* Free LSDBs. */
  foreach_lsa (ROUTER_LSDB (area), area->lsdb, 0, ospf_lsa_discard_callback);
  foreach_lsa (NETWORK_LSDB (area), area->lsdb, 0, ospf_lsa_discard_callback);
  foreach_lsa (SUMMARY_LSDB (area), area->lsdb, 0, ospf_lsa_discard_callback);
  foreach_lsa (SUMMARY_ASBR_LSDB (area), area->lsdb, 0,
	       ospf_lsa_discard_callback);

#ifdef HAVE_NSSA
  foreach_lsa (NSSA_LSDB (area), area->lsdb, 0, ospf_lsa_discard_callback);
#endif /* HAVE_NSSA */

  new_lsdb_delete_all (area->lsdb);
  new_lsdb_free (area->lsdb);

  ospf_lsa_unlock (area->router_lsa_self);
  
  route_table_finish (area->ranges);
  list_delete (area->iflist);

  if (EXPORT_NAME (area))
    free (EXPORT_NAME (area));

  if (IMPORT_NAME (area))
    free (IMPORT_NAME (area));

  /* Cancel timer. */
  OSPF_TIMER_OFF (area->t_router_lsa_self);

  if (OSPF_IS_AREA_BACKBONE (area))
    ospf_top->backbone = NULL;

  XFREE (MTYPE_OSPF_AREA, area);
}

void
ospf_area_check_free (struct in_addr area_id)
{
  struct ospf_area *area;

  area = ospf_area_lookup_by_area_id (area_id);
  if (area &&
      listcount (area->iflist) == 0 &&
      area->ranges->top == NULL &&
      area->shortcut_configured == OSPF_SHORTCUT_DEFAULT &&
      area->external_routing == OSPF_AREA_DEFAULT &&
      area->no_summary == 0 &&
      area->default_cost == 1 &&
      EXPORT_NAME (area) == NULL &&
      IMPORT_NAME (area) == NULL &&
      area->auth_type == OSPF_AUTH_NULL)
    {
      listnode_delete (ospf_top->areas, area);
      ospf_area_free (area);
    }
}

struct ospf_area *
ospf_area_get (struct in_addr area_id, int format)
{
  struct ospf_area *area;
  
  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      area = ospf_area_new (area_id);
      area->format = format;
      listnode_add_sort (ospf_top->areas, area);
      ospf_check_abr_status ();  
    }

  return area;
}

struct ospf_area *
ospf_area_lookup_by_area_id (struct in_addr area_id)
{
  struct ospf_area *area;
  listnode node;

  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      area = getdata (node);

      if (IPV4_ADDR_SAME (&area->area_id, &area_id))
        return area;
    }

  return NULL;
}

void
ospf_area_add_if (struct ospf_area *area, struct interface *ifp)
{
  listnode_add (area->iflist, ifp);
}

void
ospf_area_del_if (struct ospf_area *area, struct interface *ifp)
{
  listnode_delete (area->iflist, ifp);
}


/* Config network statement related functions. */
struct ospf_network *
ospf_network_new (struct in_addr area_id, int format)
{
  struct ospf_network *new;
  new = XMALLOC (MTYPE_OSPF_NETWORK, sizeof (struct ospf_network));
  bzero (new, sizeof (struct ospf_network));

  new->area_id = area_id;
  new->format = format;
  
  return new;
}

void
ospf_network_free (struct ospf_network *network)
{
  ospf_area_check_free (network->area_id);
  ospf_schedule_abr_task ();
  XFREE (MTYPE_OSPF_NETWORK, network);
}


void
ospf_loopback_run (struct ospf *ospf)
{
  listnode node;
  struct interface *ifp;
  struct ospf_interface *oi;

  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      ifp = getdata (node);
      oi = ifp->info;

      if (if_is_up (ifp))
        {
          /* If interface is loopback, change state. */
          if (if_is_loopback (ifp))
            if (oi->flag == OSPF_IF_DISABLE)
              {       
                oi->flag = OSPF_IF_ENABLE;
		if (IS_DEBUG_OSPF_EVENT)
		  zlog_info ("ISM[%s]: start.", ifp->name);
                OSPF_ISM_EVENT_SCHEDULE (ifp->info, ISM_LoopInd);
              }
        }
    }
}

void
ospf_interface_run (struct ospf *ospf, struct prefix *p,
                    struct ospf_area *area)
{
  struct interface *ifp;
  listnode node;

  /* Get target interface. */
  for (node = listhead (ospf->iflist); node; nextnode (node))
    {
      listnode cn;
      struct ospf_interface *oi;
      u_char flag = OSPF_IF_DISABLE;

      ifp = getdata (node);
      oi = ifp->info;

      if (oi->flag == OSPF_IF_ENABLE)
	continue;

      if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
	continue;

      /* if interface prefix is match specified prefix,
	 then create socket and join multicast group. */
      for (cn = listhead (ifp->connected); cn; nextnode (cn))
	{
	  struct connected *co = cn->data;
	  struct in_addr addr;

	  /* co = getdata (cn); */
	  if (p->family == co->address->family)
	    if (prefix_match (p, co->address))
	      {
		/* get pointer of interface prefix. */
		oi->address = co->address;
		oi->nbr_self->address = *oi->address;

		if (oi->area == NULL && oi->status > ISM_Down)
		  area->act_ints++;

		oi->area = area;

		if (area->external_routing != OSPF_AREA_DEFAULT)
		  UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);

		addr = co->address->u.prefix4;

		/* Remember this interface is running. */
		flag = OSPF_IF_ENABLE;
		oi->flag = flag;

		/* Add pseudo neighbor. */
		ospf_nbr_add_self (oi);

		/* Make sure pseudo neighbor's router_id. */
		oi->nbr_self->router_id = ospf_top->router_id;

		/* Relate ospf interface to ospf instance. */
		oi->ospf = ospf_top;

		/* update network type as interface flag */
		/* If network type is specified previously,
		   skip network type setting. */
		if (oi->type == OSPF_IFTYPE_BROADCAST)
		  {
		    if (ifp->flags & IFF_BROADCAST)
		      oi->type = OSPF_IFTYPE_BROADCAST;
		    else if ((ifp->flags & IFF_POINTOPOINT) &&
			     oi->type == OSPF_IFTYPE_BROADCAST)
		      oi->type = OSPF_IFTYPE_POINTOPOINT;
		  }

		/* Set area flag. */
		switch (area->external_routing)
		  {
		  case OSPF_AREA_DEFAULT:
		    SET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
		    break;
		  case OSPF_AREA_STUB:
		    UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
		    break;
#ifdef HAVE_NSSA
		  case OSPF_AREA_NSSA:
		    UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
		    SET_FLAG (oi->nbr_self->options, OSPF_OPTION_NP);
		    break;
#endif /* HAVE_NSSA */
		  }

		ospf_area_add_if (oi->area, ifp);

		if (if_is_up (ifp)) 
		  ospf_if_up (ifp);

		break;
	      }
	}
      oi->flag = flag;
    }
}

void
ospf_ls_upd_queue_empty (struct ospf_interface *oi)
{
  struct route_node *rn;
  listnode node;
  list lst;
  struct ospf_lsa *lsa;

  /* empty ls update queue */
  for (rn = route_top (oi->ls_upd_queue); rn;
       rn = route_next (rn))
    if ((lst = (list) rn->info))
      {
	for (node = listhead (lst); node; nextnode (node))
	  if ((lsa = getdata (node)))
	    ospf_lsa_unlock (lsa);
	list_free (lst);
	rn->info = NULL;
      }
  
  /* remove update event */
  if (oi->t_ls_upd_event)
    {
      thread_cancel (oi->t_ls_upd_event);
      oi->t_ls_upd_event = NULL;
    }
}

void
ospf_interface_down (struct ospf *ospf, struct prefix *p,
                     struct ospf_area *area)
{
  listnode node, next;

  for (node = listhead (area->iflist); node; node = next)
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      u_char flag = OSPF_IF_ENABLE;
      listnode cn;

      next = node->next;

      if (oi->flag != OSPF_IF_DISABLE && oi->type != OSPF_IFTYPE_VIRTUALLINK)
	{
	  for (cn = listhead (ifp->connected); cn; nextnode (cn))
	    {
	      struct connected *co = cn->data;

	      if (p->family == co->address->family)
		if (prefix_match (p, co->address))
		  {
		    /* Close socket. */
		    close (oi->fd);

		    /* clear input/output buffer stream. */
		    ospf_if_stream_unset (oi);
		    oi->fd = -1;

		    /* Remember this interface is not running. */
		    flag = OSPF_IF_DISABLE;

		    ospf_ls_upd_queue_empty (oi);
		    
		    /* This interface goes down. */
		    OSPF_ISM_EVENT_EXECUTE (oi, ISM_InterfaceDown);

		    ospf_area_del_if (oi->area, ifp);

		    /*		    break; */
		  }
	    }
	  oi->flag = flag;
	}
    }
}

void
ospf_if_update ()
{
  struct route_node *rn;
  struct ospf_network *network;
  struct ospf_area *area;

  if (ospf_top != NULL)
    {
      /* Update Router ID scheduled. */
      if (ospf_top->router_id_static.s_addr == 0)
        if (ospf_top->t_router_id_update == NULL)
          {
            ospf_top->t_router_id_update =
              thread_add_timer (master, ospf_router_id_update_timer, NULL,
                                OSPF_ROUTER_ID_UPDATE_DELAY);
          }

      /* Run loopback. */
      ospf_loopback_run (ospf_top);

      /* Run each interface. */
      for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
	if (rn->info != NULL)
	  {
	    network = (struct ospf_network *) rn->info;
	    area = ospf_area_get (network->area_id, network->format);
	    ospf_interface_run (ospf_top, &rn->p, area);
	  }
    }
}

int
ospf_str2area_id (char *str, struct in_addr *area_id)
{
  int ret;
  int area_id_dec;
  int format;

  if (strchr (str, '.') != NULL)
    {
      ret = inet_aton (str, area_id);
      if (!ret)
        return 0;
      format = OSPF_AREA_ID_FORMAT_ADDRESS;
    }
  else
    {
      area_id_dec = strtol (str, NULL, 10);
      if (area_id_dec < 0)
        return 0;
      area_id->s_addr = htonl (area_id_dec);
      format = OSPF_AREA_ID_FORMAT_DECIMAL;
    }

  return format;
}


/* router ospf command */
DEFUN (router_ospf,
       router_ospf_cmd,
       "router ospf",
       "Enable a routing process\n"
       "Start OSPF configuration\n")
{
#ifdef HAVE_NSSA
  zlog_info ("ROUTER OSPF:   NSSA Enabled by --enable-nssa");
#endif /* HAVE_NSSA */

  /* There is already active ospf instance. */
  if (ospf_top != NULL)
    {
      vty->node = OSPF_NODE;
      vty->index = ospf_top;
      return CMD_SUCCESS;
    }

  /* Make new ospf instance. */
  ospf_top = ospf_new ();
 
 /* Set current ospf point. */
  vty->node = OSPF_NODE;
  vty->index = ospf_top;

  ospf_loopback_run (ospf_top);

  if (ospf_top->router_id_static.s_addr == 0)
    ospf_router_id_update ();

  return CMD_SUCCESS;
}

void ospf_remove_vls_through_area (struct ospf_area *area);

DEFUN (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n")
{
  struct route_node *rn;
  listnode node;
  int i;
  
  if (ospf_top == NULL)
    {
      vty_out (vty, "There isn't active ospf instance.%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Unredister redistribution */
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    ospf_redistribute_unset (i);

  /* Clear static neighbors */
  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      struct ospf_nbr_static *nbr_static = getdata(node);


      OSPF_POLL_TIMER_OFF (nbr_static->t_poll);

      if (nbr_static->neighbor)
	{
	  nbr_static->neighbor->nbr_static = NULL;
	  nbr_static->neighbor = NULL;
	}

      if (nbr_static->oi)
	{
	  listnode_delete (nbr_static->oi->nbr_static, nbr_static);
	  nbr_static->oi = NULL;
	}

      XFREE (MTYPE_OSPF_NEIGHBOR_STATIC, nbr_static);
    }
  list_delete (ospf_top->nbr_static);

  /* Clear networks and Areas. */
  for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
    {
      struct ospf_network *network;
      struct ospf_area *area;

      if ((network = rn->info) != NULL)
	{
	  area = ospf_area_lookup_by_area_id (network->area_id);

	  /* Add InterfaceDown event to appropriate interface. */
	  if (area)
	    ospf_interface_down (ospf_top, &rn->p, area);

	  ospf_network_free (network);
	  rn->info = NULL;
	  route_unlock_node (rn);
	}
    }

  /* Reset interface. */
  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp;
      struct ospf_interface *oi;
      struct route_node *rn;      

      ifp = getdata (node);
      oi = ifp->info;

      /* Clear neighbors. */
      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	if (rn->info)
	  {
	    if (rn->info != oi->nbr_self)
	      {
		ospf_nbr_delete (rn->info);
	      }
	    else
	      {
		rn->info = NULL;
		route_unlock_node (rn);
	      }
	  }

      /* Reset interface variables. */
      ospf_if_reset_variables (oi);
      list_delete_all_node (oi->nbr_static);
    }

  for (node = listhead (ospf_top->areas); node;)
    {
      struct ospf_area *area = getdata (node);
      nextnode (node);
      
      ospf_remove_vls_through_area (area);
    }

  for (node = listhead (ospf_top->vlinks); node; )
    {
      struct ospf_vl_data *vl_data = node->data;
      nextnode (node);

      ospf_vl_delete (vl_data);
    }

  list_delete (ospf_top->vlinks);

  for (node = listhead (ospf_top->areas); node;)
    {
      struct ospf_area *area = getdata (node);
      nextnode (node);
      
      listnode_delete (ospf_top->areas, area);
      ospf_area_free (area);
    }

  /* Cancel all timers. */
  OSPF_TIMER_OFF (ospf_top->t_external_lsa);
  OSPF_TIMER_OFF (ospf_top->t_router_id_update);
  OSPF_TIMER_OFF (ospf_top->t_router_lsa_update);
  OSPF_TIMER_OFF (ospf_top->t_spf_calc);
  OSPF_TIMER_OFF (ospf_top->t_ase_calc);
  OSPF_TIMER_OFF (ospf_top->t_maxage);
  OSPF_TIMER_OFF (ospf_top->t_maxage_walker);
  OSPF_TIMER_OFF (ospf_top->t_abr_task);
  OSPF_TIMER_OFF (ospf_top->t_distribute_update);
  OSPF_TIMER_OFF (ospf_top->t_lsa_refresher);

  foreach_lsa (EXTERNAL_LSDB (ospf_top), ospf_top->lsdb, 0,
	       ospf_lsa_discard_callback);
  new_lsdb_delete_all (ospf_top->lsdb);
  new_lsdb_free (ospf_top->lsdb);

  for (node = listhead (ospf_top->maxage_lsa); node; nextnode (node))
    ospf_lsa_unlock (getdata (node));

  list_delete (ospf_top->maxage_lsa);

  if (ospf_top->old_table)
    ospf_route_table_free (ospf_top->old_table);
  if (ospf_top->new_table)
    {
      ospf_route_delete (ospf_top->new_table);
      ospf_route_table_free (ospf_top->new_table);
    }
  if (ospf_top->old_rtrs)
    ospf_rtrs_free (ospf_top->old_rtrs);
  if (ospf_top->new_rtrs)
    ospf_rtrs_free (ospf_top->new_rtrs);
  if (ospf_top->new_external_route)
    {
      ospf_route_delete (ospf_top->new_external_route);
      ospf_route_table_free (ospf_top->new_external_route);
    }
  if (ospf_top->old_external_route)
    {
      ospf_route_delete (ospf_top->old_external_route);
      ospf_route_table_free (ospf_top->old_external_route);
    }
  if (ospf_top->external_lsas)
    {
      ospf_ase_external_lsas_finish (ospf_top->external_lsas);
    }

  list_delete (ospf_top->areas);
  
  for (i = ZEBRA_ROUTE_SYSTEM; i <= ZEBRA_ROUTE_MAX; i++)
    if (EXTERNAL_INFO (i) != NULL)
      for (rn = route_top (EXTERNAL_INFO (i)); rn; rn = route_next (rn))
	{
	  if (rn->info == NULL)
	    continue;
	  
	  XFREE (MTYPE_OSPF_EXTERNAL_INFO, rn->info);
	  rn->info = NULL;
	  route_unlock_node (rn);
	}

  ospf_distance_reset ();
  route_table_finish (ospf_top->distance_table);

  XFREE (MTYPE_OSPF_TOP, ospf_top);

  ospf_top = NULL;

  return CMD_SUCCESS;
}

DEFUN (ospf_router_id,
       ospf_router_id_cmd,
       "ospf router-id A.B.C.D",
       "OSPF specific commands\n"
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")
{
  int ret;
  struct in_addr router_id;

  ret = inet_aton (argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "Please specify Router ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* ospf_top->router_id = router_id; */
  ospf_top->router_id_static = router_id;

  if (ospf_top->t_router_id_update == NULL)
    ospf_top->t_router_id_update =
      thread_add_timer (master, ospf_router_id_update_timer, NULL,
			OSPF_ROUTER_ID_UPDATE_DELAY);

  return CMD_SUCCESS;
}

ALIAS (ospf_router_id,
       router_id_cmd,
       "router-id A.B.C.D",
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")

DEFUN (no_ospf_router_id,
       no_ospf_router_id_cmd,
       "no ospf router-id",
       NO_STR
       "OSPF specific commands\n"
       "router-id for the OSPF process\n")
{
  ospf_top->router_id_static.s_addr = 0;

  ospf_router_id_update ();

  return CMD_SUCCESS;
}

ALIAS (no_ospf_router_id,
       no_router_id_cmd,
       "no router-id A.B.C.D",
       NO_STR
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")

DEFUN (passive_interface,
       passive_interface_cmd,
       "passive-interface IFNAME",
       "Suppress routing updates on an interface\n"
       "Interface's name\n")
{
  struct ospf_interface *oi;

  oi = ospf_if_lookup_by_name (argv[0]);

  if (oi == NULL)
    {
      vty_out (vty, "Please specify an existing interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->passive_interface = OSPF_IF_PASSIVE;

  return CMD_SUCCESS;
}

DEFUN (no_passive_interface,
       no_passive_interface_cmd,
       "no passive-interface IFNAME",
       NO_STR
       "Allow routing updates on an interface\n"
       "Interface's name\n")
{
  struct ospf_interface *oi;

  oi = ospf_if_lookup_by_name (argv[0]);

  if (oi == NULL)
    {
      vty_out (vty, "Please specify an existing interface%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  oi->passive_interface = OSPF_IF_ACTIVE;

  return CMD_SUCCESS;
}

DEFUN (network_area,
       network_area_cmd,
       "network A.B.C.D/M area (A.B.C.D|<0-4294967295>)",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n")
{
  int ret;
  struct prefix p;
  struct in_addr area_id;
  struct ospf *ospf;
  struct ospf_network *network;
  struct ospf_area *area;
  struct route_node *rn;
  struct external_info *ei;

  ospf = vty->index;

  /* get network prefix. */
  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask (&p);

  /* get Area ID. */
  ret = ospf_str2area_id (argv[1], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = route_node_get (ospf->networks, &p);
  if (rn->info)
    {
      vty_out (vty, "There is already same network statement.%s", VTY_NEWLINE);
      route_unlock_node (rn);
      return CMD_WARNING;
    }

  network = ospf_network_new (area_id, ret);
  
  rn->info = network;

  area = ospf_area_get (area_id, ret);

  /* Run interface config now. */
  ospf_interface_run (ospf, &p, area);

  /* Update connected redistribute. */
  if (ospf_is_type_redistributed (ZEBRA_ROUTE_CONNECT))
    if (EXTERNAL_INFO (ZEBRA_ROUTE_CONNECT))
      for (rn = route_top (EXTERNAL_INFO (ZEBRA_ROUTE_CONNECT));
	   rn; rn = route_next (rn))
	if ((ei = rn->info) != NULL)
	  if (ospf_external_info_find_lsa (&ei->p))
	    if (!ospf_distribute_check_connected (ei))
	      ospf_external_lsa_flush (ei->type, &ei->p,
				       ei->ifindex, ei->nexthop);

  ospf_area_check_free (area_id);
  return CMD_SUCCESS;
}

#if 0
ALIAS (network_area,
       network_area_decimal_cmd,
       "network A.B.C.D/M area <0-4294967295>",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")
#endif

void
ospf_remove_vls_through_area (struct ospf_area *area)
{
  listnode node, next;
  struct ospf_vl_data *vl_data;

  for (node = listhead (ospf_top->vlinks); node; node = next)
    {
      next = node->next;
      if ((vl_data = getdata (node)) != NULL)
	if (IPV4_ADDR_SAME (&vl_data->vl_area_id, &area->area_id))
	  ospf_vl_delete (vl_data);
    }
}


DEFUN (no_network_area,
       no_network_area_cmd,
       "no network A.B.C.D/M area A.B.C.D",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n")
{
  int ret;
  struct ospf *ospf;
  struct prefix_ipv4 p;
  struct in_addr area_id;
  struct route_node *rn;
  struct ospf_network *network;
  struct ospf_area *area;
  struct external_info *ei;

  ospf = (struct ospf *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!ospf_str2area_id (argv[1], &area_id))
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask_ipv4 (&p);

  rn = route_node_get (ospf->networks, (struct prefix *) &p);
  if (!rn->info)
    {
      vty_out (vty, "Can't find specified network area configuration.%s",
               VTY_NEWLINE);
      route_unlock_node (rn);
      return CMD_WARNING;
    }

  network = rn->info;
  if (!IPV4_ADDR_SAME (&area_id, &network->area_id))
    {
      zlog_warn ("Area ID not match, do nothing");
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (network->area_id);
  /* Add InterfaceDown event to appropriate interface. */
  if (area)
    ospf_interface_down (ospf, &rn->p, area);

  ospf_network_free (rn->info);
  rn->info = NULL;
  route_unlock_node (rn);

  /* Update connected redistribute. */
  if (ospf_is_type_redistributed (ZEBRA_ROUTE_CONNECT))
    if (EXTERNAL_INFO (ZEBRA_ROUTE_CONNECT))
      for (rn = route_top (EXTERNAL_INFO (ZEBRA_ROUTE_CONNECT));
	   rn; rn = route_next (rn))
	if ((ei = rn->info) != NULL)
	  if (!ospf_external_info_find_lsa (&ei->p))
	    if (ospf_distribute_check_connected (ei))
	      ospf_external_lsa_originate (ei);

  return CMD_SUCCESS;
}

ALIAS (no_network_area,
       no_network_area_decimal_cmd,
       "no network A.B.C.D/M area <0-4294967295>",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID as a decimal value\n")

struct ospf_area_range *
ospf_new_area_range (struct ospf_area * area,
                     struct prefix_ipv4 *p)
{
  struct ospf_area_range *range;
  struct route_node *node;

  node = route_node_get (area->ranges, (struct prefix *) p);
  if (node->info)
    {
      route_unlock_node (node);
      return node->info;
    }

  range = XMALLOC (MTYPE_OSPF_AREA_RANGE, sizeof (struct ospf_area_range));
  bzero (range, sizeof (struct ospf_area_range));
  range->node = node;
  node->info = range;

  return range;
}


DEFUN (area_range,
       area_range_cmd,
       "area A.B.C.D range A.B.C.D/M",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf_new_area_range (area, &p);
  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}

ALIAS (area_range,
       area_range_decimal_cmd,
       "area <0-4294967295> range A.B.C.D/M",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFUN (no_area_range,
       no_area_range_cmd,
       "no area A.B.C.D range A.B.C.D/M",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area does not exist", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix*) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  XFREE (MTYPE_OSPF_AREA_RANGE, node->info);
  node->info = NULL;

  route_unlock_node (node);
  ospf_area_check_free (area_id);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


ALIAS (no_area_range,
       no_area_range_decimal_cmd,
       "no area <0-4294967295> range A.B.C.D/M",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n")

DEFUN (area_range_suppress,
       area_range_suppress_cmd,
       "area A.B.C.D range IPV4_PREFIX suppress",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = ospf_new_area_range (area, &p);
  SET_FLAG (range->flags, OSPF_RANGE_SUPPRESS);
  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}

#ifdef HAVE_NSSA
ALIAS (area_range_suppress,
       area_range_suppress_decimal_cmd,
       "area <0-4294967295> range IPV4_PREFIX not-advertise",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Configure OSPF DECIMAL area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")
#endif /* HAVE_NSSA */

DEFUN (no_area_range_suppress,
       no_area_range_suppress_cmd,
       "no area A.B.C.D range IPV4_PREFIX not-advertise",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "do not advertise this range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area does not exist", VTY_NEWLINE);
      return CMD_WARNING;
     }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix *) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = (struct ospf_area_range *) node->info;
  UNSET_FLAG (range->flags, OSPF_RANGE_SUPPRESS);

  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}



DEFUN (area_range_subst,
       area_range_subst_cmd,
       "area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "configure OSPF area range for route summarization\n"
       "area range prefix\n"
       "announce area range as another prefix\n"
       "network prefix to be announced instead of range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p, subst;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_ipv4 (argv[2], &subst);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify network prefix as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = ospf_new_area_range (area, &p);

  if (CHECK_FLAG (range->flags, OSPF_RANGE_SUPPRESS))
    {
      vty_out (vty, "The same area range is configured as suppress%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  SET_FLAG (range->flags, OSPF_RANGE_SUBST);
  range->substitute = subst;

  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}


DEFUN (no_area_range_subst,
       no_area_range_subst_cmd,
       "no area A.B.C.D range IPV4_PREFIX substitute IPV4_PREFIX",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Deconfigure OSPF area range for route summarization\n"
       "area range prefix\n"
       "Do not advertise this range\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")
{
  struct ospf_area *area;
  struct ospf_area_range *range;
  struct in_addr area_id;
  struct prefix_ipv4 p, subst;
  struct route_node *node;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area does not exist", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix_ipv4 (argv[1], &p);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify area range as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  node = route_node_lookup (area->ranges, (struct prefix *) &p);
  if (node == NULL)
    {
      vty_out (vty, "Specified area range was not configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  range = (struct ospf_area_range *) node->info;

  ret = str2prefix_ipv4 (argv[2], &subst);
  if (ret <= 0)
    {
      vty_out (vty, "Please specify network prefix as a.b.c.d/mask%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  UNSET_FLAG (range->flags, OSPF_RANGE_SUBST);

  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}

struct ospf_vl_data *
ospf_find_vl_data (struct in_addr area_id, int format,
		   struct in_addr vl_peer, struct vty *vty)
{
  struct ospf_area *area;
  struct ospf_vl_data *vl_data;

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "Configuring VLs over the backbone is not allowed%s",
               VTY_NEWLINE);
      return NULL;
    }
  area = ospf_area_get (area_id, format);

  if (area->external_routing != OSPF_AREA_DEFAULT)
    {
      if (format == OSPF_AREA_ID_FORMAT_ADDRESS)
	vty_out (vty, "Area %s is %s%s",
		 inet_ntoa (area_id),
#ifdef HAVE_NSSA
		 area->external_routing == OSPF_AREA_NSSA?"nssa":"stub",
#else
		 "stub",
#endif /* HAVE_NSSA */		 
		 VTY_NEWLINE);
      else
	vty_out (vty, "Area %d is %s%s",
		 ntohl (area_id.s_addr),
#ifdef HAVE_NSSA
		 area->external_routing == OSPF_AREA_NSSA?"nssa":"stub",
#else
		 "stub",
#endif /* HAVE_NSSA */		 
		 VTY_NEWLINE);	
      return NULL;
    }
  
  if ((vl_data = ospf_vl_lookup (area, vl_peer)) == NULL)
    {
      vl_data = ospf_vl_data_new (area, vl_peer);
      if (vl_data->vl_oi == NULL)
	{
	  vl_data->vl_oi = ospf_vl_new (vl_data);
	  ospf_vl_add (vl_data);
	  ospf_spf_calculate_schedule ();
	}
    }
  return vl_data;
}

int
ospf_vl_set_security (struct in_addr area_id, int format,
		      struct in_addr vl_peer,  char *key, u_char key_id,
		     char *md5_key, struct vty *vty)
{
  struct crypt_key *ck;
  struct ospf_vl_data *vl_data;

  vl_data = ospf_find_vl_data (area_id, format, vl_peer, vty);
  if (!vl_data)
    return CMD_WARNING;
  
  if (key)
    strncpy (vl_data->vl_oi->auth_simple, key, OSPF_AUTH_SIMPLE_SIZE);
  else if (md5_key)
    {
      if (ospf_crypt_key_lookup (vl_data->vl_oi, key_id) != NULL)
	{
	  vty_out (vty, "OSPF: Key %d already exists%s",
		   key_id, VTY_NEWLINE);
	  return CMD_WARNING;
	}
      ck = ospf_crypt_key_new ();
      ck->key_id = key_id;
      strncpy (ck->auth_key, md5_key, OSPF_AUTH_MD5_SIZE);
      
      ospf_crypt_key_add (vl_data->vl_oi->auth_crypt, ck);
    }
  
  return CMD_SUCCESS;
}

int
ospf_vl_set_timers (struct in_addr area_id, int format,
		     struct in_addr vl_peer, u_int16_t hello_interval,
		     u_int16_t retransmit_interval, u_int16_t transmit_delay,
		     u_int16_t dead_interval, struct vty *vty)
{
  struct ospf_vl_data *vl_data;

  vl_data = ospf_find_vl_data (area_id, format, vl_peer, vty);
  if (!vl_data)
    return CMD_WARNING;
  
  vl_data->vl_oi->v_hello = hello_interval;
  vl_data->vl_oi->v_wait = dead_interval;
  vl_data->vl_oi->retransmit_interval = retransmit_interval;
  vl_data->vl_oi->transmit_delay = transmit_delay;
  
  return CMD_SUCCESS;
}

DEFUN (area_vlink,
       area_vlink_cmd,
       "area A.B.C.D virtual-link A.B.C.D",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")
{
  struct in_addr area_id, vl_peer;
  int ret, format;

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  return ospf_vl_set_timers (area_id, format, vl_peer,
			   OSPF_HELLO_INTERVAL_DEFAULT,
			   OSPF_RETRANSMIT_INTERVAL_DEFAULT,
			   OSPF_TRANSMIT_DELAY_DEFAULT,
			   OSPF_ROUTER_DEAD_INTERVAL_DEFAULT, vty);
}

ALIAS (area_vlink,
       area_vlink_decimal_cmd,
       "area <0-4294967295> virtual-link A.B.C.D",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")

DEFUN (area_vlink_param,
       area_vlink_param_cmd,
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
{
  struct in_addr area_id, vl_peer;
  int ret, format;
  int hello, retransmit, transmit, dead;

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  hello = strtol (argv[2], NULL, 10);
  if (hello < 0)
    return CMD_WARNING;
  retransmit = strtol (argv[3], NULL, 10);
  if (retransmit < 0)
    return CMD_WARNING;
  transmit = strtol (argv[4], NULL, 10);
  if (transmit < 0)
    return CMD_WARNING;
  dead = strtol (argv[5], NULL, 10);
  if (dead < 0)
    return CMD_WARNING;

  return ospf_vl_set_timers (area_id, format, vl_peer, hello, retransmit,
			     transmit, dead, vty);
}      

ALIAS (area_vlink_param,
       area_vlink_param_decimal_cmd,
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



DEFUN (area_vlink_param_auth,
       area_vlink_param_auth_cmd,
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
{
  struct in_addr area_id, vl_peer;
  int ret, format;
  int hello, retransmit, transmit, dead;
  char key[OSPF_AUTH_SIMPLE_SIZE+1];

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  hello = strtol (argv[2], NULL, 10);
  if (hello < 0)
    return CMD_WARNING;
  retransmit = strtol (argv[3], NULL, 10);
  if (retransmit < 0)
    return CMD_WARNING;
  transmit = strtol (argv[4], NULL, 10);
  if (transmit < 0)
    return CMD_WARNING;
  dead = strtol (argv[5], NULL, 10);
  if (dead < 0)
    return CMD_WARNING;

  bzero (key, OSPF_AUTH_SIMPLE_SIZE + 1);
  strncpy (key, argv[6], OSPF_AUTH_SIMPLE_SIZE);

  ret = ospf_vl_set_timers (area_id, format, vl_peer, hello, retransmit,
			   transmit, dead, vty);
  if (ret != CMD_SUCCESS)
    return ret;
  return ospf_vl_set_security (area_id, format, vl_peer, key, 0, NULL, vty);
}      

ALIAS (area_vlink_param_auth,
       area_vlink_param_auth_decimal_cmd,
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
     

DEFUN (area_vlink_param_md5,
       area_vlink_param_md5_cmd,
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
{
  struct in_addr area_id, vl_peer;
  int ret, format, key_id;
  int hello, retransmit, transmit, dead;
  char key[OSPF_AUTH_MD5_SIZE+1];

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  hello = strtol (argv[2], NULL, 10);
  if (hello < 0)
    return CMD_WARNING;
  retransmit = strtol (argv[3], NULL, 10);
  if (retransmit < 0)
    return CMD_WARNING;
  transmit = strtol (argv[4], NULL, 10);
  if (transmit < 0)
    return CMD_WARNING;
  dead = strtol (argv[5], NULL, 10);
  if (dead < 0)
    return CMD_WARNING;

  key_id = strtol (argv[6], NULL, 10);
  if (key_id < 0)
    return CMD_WARNING;
  bzero (key, OSPF_AUTH_MD5_SIZE + 1);
  strncpy (key, argv[7], OSPF_AUTH_MD5_SIZE);

  ret = ospf_vl_set_timers (area_id, format, vl_peer, hello, retransmit,
			   transmit, dead, vty);
  if (ret != CMD_SUCCESS)
    return ret;
  return ospf_vl_set_security (area_id, format, vl_peer, NULL,
			       key_id, key, vty);
}      

ALIAS (area_vlink_param_md5,
       area_vlink_param_md5_decimal_cmd,
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


DEFUN (area_vlink_md5,
       area_vlink_md5_cmd,
       "area A.B.C.D virtual-link A.B.C.D message-digest-key <1-255> md5 KEY",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")
{
  struct in_addr area_id, vl_peer;
  int ret, format, key_id;
  char key[OSPF_AUTH_MD5_SIZE+1];

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  key_id = strtol (argv[2], NULL, 10);
  if (key_id < 0)
    return CMD_WARNING;
  bzero (key, OSPF_AUTH_MD5_SIZE + 1);
  strncpy (key, argv[3], OSPF_AUTH_MD5_SIZE);

  return ospf_vl_set_security (area_id, format, vl_peer,
			       NULL, key_id, key, vty);
}

ALIAS (area_vlink_md5,
       area_vlink_md5_decimal_cmd,
       "area <0-4294967295> virtual-link A.B.C.D message-digest-key <1-255> md5 KEY",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)")

DEFUN (area_vlink_auth,
       area_vlink_auth_cmd,
       "area A.B.C.D virtual-link A.B.C.D authentication-key AUTH_KEY",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")
{
  struct in_addr area_id, vl_peer;
  int ret, format;
  char key[OSPF_AUTH_SIMPLE_SIZE+1];

  format = ospf_str2area_id (argv[0], &area_id);
  if (!format)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  bzero (key, OSPF_AUTH_SIMPLE_SIZE + 1);
  strncpy (key, argv[2], OSPF_AUTH_SIMPLE_SIZE);

  return ospf_vl_set_security (area_id, format, vl_peer,
			       key, 0, NULL, vty);
}

ALIAS (area_vlink_auth,
       area_vlink_auth_decimal_cmd,
       "area <0-4294967295> virtual-link A.B.C.D authentication-key AUTH_KEY",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n"
       "Authentication password (key)\n"
       "The OSPF password (key)")

     

DEFUN (no_area_vlink,
       no_area_vlink_cmd,
       "no area A.B.C.D virtual-link A.B.C.D",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")
{
  struct ospf_area *area;
  struct in_addr area_id, vl_peer;
  struct ospf_vl_data *vl_data = NULL;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area does not exist", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = inet_aton (argv[1], &vl_peer);
  if (! ret)
    {
      vty_out (vty, "Please specify valid Router ID as a.b.c.d%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ((vl_data = ospf_vl_lookup (area, vl_peer)))
    ospf_vl_delete (vl_data);

  ospf_area_check_free (area_id);
  
  return CMD_SUCCESS;
}

ALIAS (no_area_vlink,
       no_area_vlink_decimal_cmd,
       "no area <0-4294967295> virtual-link A.B.C.D",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure a virtual link\n"
       "Router ID of the remote ABR\n")


DEFUN (area_shortcut,
       area_shortcut_cmd,
       "area A.B.C.D shortcut (default|enable|disable)",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure the area's shortcutting mode\n"
       "Set default shortcutting behavior\n"
       "Enable shortcutting through the area\n"
       "Disable shortcutting through the area\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int mode;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  if (strncmp (argv[1], "de", 2) == 0)
    mode = OSPF_SHORTCUT_DEFAULT;
  else if (strncmp (argv[1], "di", 2) == 0)
    mode = OSPF_SHORTCUT_DISABLE;
  else if (strncmp (argv[1], "e", 1) == 0)
    mode = OSPF_SHORTCUT_ENABLE;
  else
    return CMD_WARNING;

  if (area->shortcut_configured != mode)
    {
      area->shortcut_configured = mode;
      if (ospf_top->abr_type != OSPF_ABR_SHORTCUT)
        vty_out (vty, "Shortcut area setting will take effect "
                 "only when the router is configured as "
                 "Shortcut ABR%s", VTY_NEWLINE);
      ospf_router_lsa_timer_add (area);
      ospf_schedule_abr_task ();
    }

  ospf_area_check_free (area_id);
  return CMD_SUCCESS;
}

ALIAS (area_shortcut,
       area_shortcut_decimal_cmd,
       "area <0-4294967295> shortcut (default|enable|disable)",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure the area's shortcutting mode\n"
       "Set default shortcutting behavior\n"
       "Enable shortcutting through the area\n"
       "Disable shortcutting through the area\n")

DEFUN (no_area_shortcut,
       no_area_shortcut_cmd,
       "no area A.B.C.D shortcut (enable|disable)",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Deconfigure the area's shortcutting mode\n"
       "Deconfigure enabled shortcutting through the area\n"
       "Deconfigure disabled shortcutting through the area\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int mode;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
     return CMD_SUCCESS;

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area does not exist", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (strncmp (argv[1], "di", 2) == 0)
    mode = OSPF_SHORTCUT_DISABLE;
  else if (strncmp (argv[1], "e", 1) == 0)
    mode = OSPF_SHORTCUT_ENABLE;
  else
    return CMD_WARNING;

  if (area->shortcut_configured == mode)
    {
      ospf_area_check_free (area_id);
      area->shortcut_configured = OSPF_SHORTCUT_DEFAULT;
      ospf_router_lsa_timer_add (area);
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

ALIAS (no_area_shortcut,
       no_area_shortcut_decimal_cmd,
       "no area <0-4294967295> shortcut (enable|disable)",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure the area's shortcutting mode\n"
       "Deconfigure enabled shortcutting through the area\n"
       "Deconfigure disabled shortcutting through the area\n")

struct message ospf_area_type_msg[] =
{
  { OSPF_AREA_DEFAULT,	"Default" },
  { OSPF_AREA_STUB,     "Stub" },
  { OSPF_AREA_NSSA,     "NSSA" },
};
int ospf_area_type_msg_max = OSPF_AREA_TYPE_MAX;

void
ospf_area_type_set (struct ospf_area *area, int type)
{
  listnode node;
  struct ospf_interface *oi;
  struct interface *ifp;

  if (area->external_routing == type)
    {
      if (IS_DEBUG_OSPF_EVENT)
	zlog_info ("Area[%s]: Types are the same, ignored.",
		   inet_ntoa (area->area_id));
      return;
    }

  area->external_routing = type;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_info ("Area[%s]: Configured as %s", inet_ntoa (area->area_id),
	       LOOKUP (ospf_area_type_msg, type));

  switch (area->external_routing)
    {
    case OSPF_AREA_DEFAULT:
      for (node = listhead (area->iflist); node; nextnode (node))
	if ((ifp = getdata (node)) != NULL)
	  if ((oi = ifp->info) != NULL)
	    if (oi->nbr_self != NULL)
	      SET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
      break;
    case OSPF_AREA_STUB:
      for (node = listhead (area->iflist); node; nextnode (node))
	if ((ifp = getdata (node)) != NULL)
	  if ((oi = ifp->info) != NULL)
	    if (oi->nbr_self != NULL)
	      {
		if (IS_DEBUG_OSPF_EVENT)
		  zlog_info ("setting options on %s accordingly", ifp->name);
		UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
		if (IS_DEBUG_OSPF_EVENT)
		  zlog_info ("options set on %s: %x",
			     ifp->name, OPTIONS (oi));
	      }
      break;
    case OSPF_AREA_NSSA:
#ifdef HAVE_NSSA
      if (IS_DEBUG_OSPF_EVENT)
	zlog_info ("Scanning all NSSA interfaces for area %ld, start %ld",
		   area, listhead (area->iflist) );

      for (node = listhead (area->iflist); node; nextnode (node))
	if ((ifp = getdata (node)) != NULL)
	  if ((oi = ifp->info) != NULL)
	    if (oi->nbr_self != NULL)
	      {
		zlog_info ("setting nssa options on %s accordingly", ifp->name);
		UNSET_FLAG (oi->nbr_self->options, OSPF_OPTION_E);
		SET_FLAG (oi->nbr_self->options, OSPF_OPTION_NP);
		zlog_info ("options set on %s: %x",
			   ifp->name, OPTIONS (oi));
	      }
#endif /* HAVE_NSSA */
      break;
    default:
      break;
    }

  ospf_router_lsa_timer_add (area);
  ospf_schedule_abr_task ();
}

int
ospf_area_stub_cmd (struct vty *vty, int argc, char **argv, int no_summary,
		    int xlate)
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

#ifdef HAVE_NSSA
  int nssa = 0;

  zlog_info ("OSPF Area ID set for STUB/NSSA Code = %d", no_summary);

/*  Special translation of no_summary into nssa/no_summary  */
/*  0, 1 = no nssa	    2, 3 = nssa */
/*  0, 2 = no_summary off   1, 3 = no_summary on  */

  if (no_summary >1)
	{
	  nssa = 1;       /* set nssa */
	  no_summary = no_summary - 2; /* translate 2 into 0, 3 into 1 */
	}
#endif /* HAVE_NSSA */



  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as stub%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  if (ospf_vls_in_area (area))
    {
      vty_out (vty, "First deconfigure all VLs through this area%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

#ifdef HAVE_NSSA
  /* Set transllator Role to zero or other. */
  area->NSSATranslatorRole = xlate;
  area->NSSATranslator = xlate;

  if (nssa)
    {
      if (area->external_routing != OSPF_AREA_NSSA)
	ospf_top->anyNSSA++;
      ospf_area_type_set (area, OSPF_AREA_NSSA);
      zlog_info ("OSPF_AREA_NSSA");
    }
  else
    {
      ospf_area_type_set (area, OSPF_AREA_STUB);
      zlog_info ("OSPF_AREA_STUB");
    }
#else /* ! HAVE_NSSA */
  ospf_area_type_set (area, OSPF_AREA_STUB);
  zlog_info ("OSPF_AREA_STUB");
#endif /* HAVE_NSSA */

  area->no_summary = no_summary;

  return CMD_SUCCESS;
}

/*********************************************************************************/

DEFUN (area_stub,
       area_stub_cmd,
       "area A.B.C.D stub",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 0, 0);
}

ALIAS (area_stub,
       area_stub_decimal_cmd,
       "area <0-4294967295> stub",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

#ifdef HAVE_NSSA
DEFUN (area_nssa,
       area_nssa_cmd,
       "area A.B.C.D nssa",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 2, 0);
}

ALIAS (area_nssa,
       area_nssa_decimal_cmd,
       "area <0-4294967295> nssa",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n")
/*****************************************************************************
**/

DEFUN (area_nssa_never,
       area_nssa_t_never_cmd,
       "area A.B.C.D nssa translate-never",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR to never translate\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 2, OSPF_NSSA_ROLE_NEVER);
}

ALIAS (area_nssa_never,
       area_nssa_t_never_decimal_cmd,
       "area <0-4294967295> nssa translate-never",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR to never translate\n")
/*****************************************************************************
**/

DEFUN (area_nssa_candidate,
       area_nssa_t_candidate_cmd,
       "area A.B.C.D nssa translate-candidate",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR for translate election\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 2, OSPF_NSSA_ROLE_CANDIDATE);
}

ALIAS (area_nssa_candidate,
       area_nssa_t_candidate_decimal_cmd,
       "area <0-4294967295> nssa translate-candidate",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR for translate election\n")
/*****************************************************************************
**/

DEFUN (area_nssa_always,
       area_nssa_t_always_cmd,
       "area A.B.C.D nssa translate-always",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure NSSA-ABR to always translate\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 2, OSPF_NSSA_ROLE_ALWAYS);
}

ALIAS (area_nssa_always,
       area_nssa_t_always_decimal_cmd,
       "area <0-4294967295> nssa translate-always",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure NSSA-ABR to always translate\n")

/*************************    NSSA no-summary ********************************
***/

DEFUN (area_nssa_nosum,
       area_nssa_nosum_cmd,
       "area A.B.C.D nssa no-summary",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 3, 0);
}

ALIAS (area_nssa_nosum,
       area_nssa_nosum_decimal_cmd,
       "area <0-4294967295> nssa no-summary",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

/*****************************************************************************
**/

DEFUN (area_nssa_nosum_never,
       area_nssa_nosum_t_never_cmd,
       "area A.B.C.D nssa no-summary translate-never",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, nor translation\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 3, OSPF_NSSA_ROLE_NEVER);
}

ALIAS (area_nssa_nosum_never,
       area_nssa_nosum_t_never_decimal_cmd,
       "area <0-4294967295> nssa no-summary translate-never",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, nor translation\n")

/*****************************************************************************
**/

DEFUN (area_nssa_nosum_candidate,
       area_nssa_nosum_t_candidate_cmd,
       "area A.B.C.D nssa no-summary translate-candidate",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, translation election\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 3, OSPF_NSSA_ROLE_CANDIDATE);
}

ALIAS (area_nssa_nosum_candidate,
       area_nssa_nosum_t_candidate_decimal_cmd,
       "area <0-4294967295> nssa no-summary translate-candidate",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, translation election\n")

/*****************************************************************************
**/

DEFUN (area_nssa_nosum_always,
       area_nssa_nosum_t_always_cmd,
       "area A.B.C.D nssa no-summary translate-always",
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, always translate\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 3, OSPF_NSSA_ROLE_ALWAYS);
}

ALIAS (area_nssa_nosum_always,
       area_nssa_nosum_t_always_decimal_cmd,
       "area <0-4294967295> nssa no-summary translate-always",
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "No inter-area routes into nssa, always translate\n")

#endif /* HAVE_NSSA */
/*********************************************************************************/

DEFUN (area_stub_nosum,
       area_stub_nosum_cmd,
       "area A.B.C.D stub no-summary",
       "OSPF stub parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n")
{
  return ospf_area_stub_cmd (vty, argc, argv, 1, 0);
}

ALIAS (area_stub_nosum,
       area_stub_nosum_decimal_cmd,
       "area <0-4294967295> stub no-summary",
       "OSPF stub parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n")

/*********************************************************************************/

int
ospf_no_area_stub_cmd (struct vty *vty, int argc, char **argv, int no_summary)
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;


#ifdef HAVE_NSSA
  int nssa = 0;

 vty_out (vty, "\nOSPF No-Area ID set for STUB/NSSA Code = %d\n\n", no_summary);


/*  Special translation of no_summary into nssa/no_summary  */
/*  0, 1 = no nssa	    2, 3 = nssa */
/*  0, 2 = no_summary off   1, 3 = no_summary on  */

  if (no_summary >1)
	{
	  nssa = 1;       /* set nssa */
	  no_summary = no_summary - 2; /* translate 2 into 0, 3 into 1 */
	}
#endif /* HAVE_NSSA */



  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
     return CMD_SUCCESS;

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (no_summary)
    {
      area->no_summary = 0;
      ospf_area_check_free (area_id);
      return CMD_SUCCESS;
    }


#ifdef HAVE_NSSA

  if (area->external_routing == OSPF_AREA_NSSA)
  {
    ospf_area_type_set (area, OSPF_AREA_DEFAULT);

    ospf_area_check_free (area_id);

    if (ospf_top->anyNSSA >0)
      ospf_top->anyNSSA--;

    return CMD_SUCCESS;
  }
#endif /* HAVE_NSSA */


  if (area->external_routing == OSPF_AREA_STUB)
    ospf_area_type_set (area, OSPF_AREA_DEFAULT);
  else
    {
      vty_out (vty, "Area is not stub nor nssa%s", VTY_NEWLINE);
      return CMD_WARNING;
    }


  ospf_area_check_free (area_id);
  return CMD_SUCCESS;
}

/*********************************************************************************/

DEFUN (no_area_stub,
       no_area_stub_cmd,
       "no area A.B.C.D stub",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 0);
}

ALIAS (no_area_stub,
       no_area_stub_decimal_cmd,
       "no area <0-4294967295> stub",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")

#ifdef HAVE_NSSA
/*********************************************************************************/

DEFUN (no_area_nssa,
       no_area_nssa_cmd,
       "no area A.B.C.D nssa",
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 2);
}

ALIAS (no_area_nssa,
       no_area_nssa_decimal_cmd,
       "no area <0-4294967295> nssa",
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n")

/*********************************************************************************/
#endif /* HAVE_NSSA */

DEFUN (no_area_stub_nosum,
       no_area_stub_nosum_cmd,
       "no area A.B.C.D stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 1);
}

ALIAS (no_area_stub_nosum,
       no_area_stub_nosum_decimal_cmd,
       "no area <0-4294967295> stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")

#ifdef HAVE_NSSA
/*********************************************************************************/

DEFUN (no_area_nssa_nosum,
       no_area_nssa_nosum_cmd,
       "no area A.B.C.D nssa no-summary",
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID in IP address format\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
  return ospf_no_area_stub_cmd (vty, argc, argv, 3);
}

ALIAS (no_area_nssa_nosum,
       no_area_nssa_nosum_decimal_cmd,
       "no area <0-4294967295> nssa no-summary",
       NO_STR
       "OSPF nssa parameters\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")

/*********************************************************************************/
#endif /* HAVE_NSSA */

DEFUN (area_default_cost,
       area_default_cost_cmd,
       "area A.B.C.D default-cost <0-16777215>",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  u_int32_t cost;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  if (area->external_routing == OSPF_AREA_DEFAULT)
    {
      vty_out (vty, "The area is neither stub, nor NSSA%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  cost = atol (argv[1]);

  if (cost > 16777215)
    {
      vty_out (vty, "Invalid cost value, expected <0-16777215>%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area->default_cost = cost;

  return CMD_SUCCESS;
}

ALIAS (area_default_cost,
       area_default_cost_decimal_cmd,
       "area <0-4294967295> default-cost NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

DEFUN (no_area_default_cost,
       no_area_default_cost_cmd,
       "no area A.B.C.D default-cost <0-16777215>",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  u_int32_t cost;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area_id.s_addr == OSPF_AREA_BACKBONE)
    {
      vty_out (vty, "You cannot configure backbone area as shortcut%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area->external_routing == OSPF_AREA_DEFAULT)
    {
      vty_out (vty, "The area is neither stub, nor NSSA%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  cost = atol (argv[1]);

  if (cost > 16777215)
    {
      vty_out (vty, "Invalid cost value, expected <0-16777215>%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (cost != area->default_cost)
    {
      vty_out (vty, "Specified cost value is not equal to the configured one%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area->default_cost = 1;

  ospf_area_check_free (area_id);
  return CMD_SUCCESS;
}

ALIAS (no_area_default_cost,
       no_area_default_cost_decimal_cmd,
       "no area <0-4294967295> default-cost NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")

int
ospf_set_area_export_list (struct ospf_area * area, char * list_name)
{
  struct access_list *list;
  list = access_list_lookup(AF_INET, list_name);

  EXPORT_LIST (area) = list;

  if (EXPORT_NAME (area))
    free (EXPORT_NAME (area));

  EXPORT_NAME (area) = strdup (list_name);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}

int
ospf_unset_area_export_list (struct ospf_area * area)
{

  EXPORT_LIST (area) = 0;

  if (EXPORT_NAME (area))
    free (EXPORT_NAME (area));

  EXPORT_NAME (area) = NULL;

  ospf_area_check_free (area->area_id);
  
  ospf_schedule_abr_task ();
  return CMD_SUCCESS;
}

DEFUN (area_export_list,
       area_export_list_cmd,
       "area A.B.C.D export-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  return ospf_set_area_export_list (area, argv[1]);
}

ALIAS (area_export_list,
       area_export_list_decimal_cmd,
       "area <0-4294967295> export-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFUN (no_area_export_list,
       no_area_export_list_cmd,
       "no area A.B.C.D export-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return ospf_unset_area_export_list(area);
}

ALIAS (no_area_export_list,
       no_area_export_list_decimal_cmd,
       "no area <0-4294967295> export-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

int
ospf_set_area_import_list (struct ospf_area *area, char *name)
{
  struct access_list *list;
  list = access_list_lookup (AF_INET, name);

  IMPORT_LIST (area) = list;

  if (IMPORT_NAME (area))
    free (IMPORT_NAME (area));

  IMPORT_NAME (area) = strdup (name);
  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}

int
ospf_unset_area_import_list (struct ospf_area * area)
{

  IMPORT_LIST (area) = 0;

  if (IMPORT_NAME (area))
    free (IMPORT_NAME (area));

  IMPORT_NAME (area) = NULL;
  ospf_area_check_free (area->area_id);

  ospf_schedule_abr_task ();

  return CMD_SUCCESS;
}


DEFUN (area_import_list,
       area_import_list_cmd,
       "area A.B.C.D import-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);
  
  return ospf_set_area_import_list (area, argv[1]);
}

ALIAS (area_import_list,
       area_import_list_decimal_cmd,
       "area <0-4294967295> import-list NAME",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")

DEFUN (no_area_import_list,
       no_area_import_list_cmd,
       "no area A.B.C.D import-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF Area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area is not yet configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return ospf_unset_area_import_list (area);
}

ALIAS (no_area_import_list,
       no_area_import_list_decimal_cmd,
       "no area <0-4294967295> import-list NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")

DEFUN (area_authentication_message_digest,
       area_authentication_message_digest_cmd,
       "area A.B.C.D authentication message-digest",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  area->auth_type = OSPF_AUTH_CRYPTOGRAPHIC;

  return CMD_SUCCESS;
}

ALIAS (area_authentication_message_digest,
       area_authentication_message_digest_decimal_cmd,
       "area <0-4294967295> authentication message-digest",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")

DEFUN (area_authentication,
       area_authentication_cmd,
       "area A.B.C.D authentication",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;
  int ret;

  ret = ospf_str2area_id (argv[0], &area_id);
  if (!ret)
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_get (area_id, ret);

  area->auth_type = OSPF_AUTH_SIMPLE;

  return CMD_SUCCESS;
}

ALIAS (area_authentication,
       area_authentication_decimal_cmd,
       "area <0-4294967295> authentication",
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")

DEFUN (no_area_authentication,
       no_area_authentication_cmd,
       "no area A.B.C.D authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "Enable authentication\n")
{
  struct ospf_area *area;
  struct in_addr area_id;

  if (!ospf_str2area_id (argv[0], &area_id))
    {
      vty_out (vty, "OSPF area ID is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  area = ospf_area_lookup_by_area_id (area_id);
  if (!area)
    {
      vty_out (vty, "Area ID %s is not declared%s", inet_ntoa (area_id),
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  area->auth_type = OSPF_AUTH_NULL;

  ospf_area_check_free (area_id);
  
  return CMD_SUCCESS;
}

ALIAS (no_area_authentication,
       no_area_authentication_decimal_cmd,
       "no area <0-4294967295> authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")


DEFUN (ospf_abr_type,
       ospf_abr_type_cmd,
       "ospf abr-type (cisco|ibm|shortcut|standard)",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n"
       "Alternative ABR, IBM implementation\n"
       "Shortcut ABR\n"
       "Standard behavior (RFC2328)\n")
{
  u_char abr_type = OSPF_ABR_UNKNOWN;

  if (strncmp (argv[0], "c", 1) == 0)
    abr_type = OSPF_ABR_CISCO;
  else if (strncmp (argv[0], "i", 1) == 0)
    abr_type = OSPF_ABR_IBM;
  else if (strncmp (argv[0], "sh", 2) == 0)
    abr_type = OSPF_ABR_SHORTCUT;
  else if (strncmp (argv[0], "st", 2) == 0)
    abr_type = OSPF_ABR_STAND;
  else
    return CMD_WARNING;

  /* If ABR type value is changed, schedule ABR task. */
  if (ospf_top->abr_type != abr_type)
    {
      ospf_top->abr_type = abr_type;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type,
       no_ospf_abr_type_cmd,
       "no ospf abr-type (cisco|ibm|shortcut)",
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n"
       "Alternative ABR, IBM implementation\n"
       "Shortcut ABR\n")
{
  u_char abr_type = OSPF_ABR_UNKNOWN;

  if (strncmp (argv[0], "c", 1) == 0)
    abr_type = OSPF_ABR_CISCO;
  else if (strncmp (argv[0], "i", 1) == 0)
    abr_type = OSPF_ABR_IBM;
  else if (strncmp (argv[0], "s", 1) == 0)
    abr_type = OSPF_ABR_SHORTCUT;
  else
    return CMD_WARNING;

  /* If ABR type value is changed, schedule ABR task. */
  if (ospf_top->abr_type == abr_type)
    {
      ospf_top->abr_type = OSPF_ABR_STAND;
      ospf_schedule_abr_task ();
    }

  return CMD_SUCCESS;
}

DEFUN (ospf_compatible_rfc1583,
       ospf_compatible_rfc1583_cmd,
       "compatible rfc1583",
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")
{
  if (ospf_top->RFC1583Compat == 0)
    {
      ospf_top->RFC1583Compat = 1;
      ospf_spf_calculate_schedule ();
    }
  return CMD_SUCCESS;
}

DEFUN (no_ospf_compatible_rfc1583,
       no_ospf_compatible_rfc1583_cmd,
       "no compatible rfc1583",
       NO_STR
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")
{
  if (ospf_top->RFC1583Compat == 1)
    {
      ospf_top->RFC1583Compat = 0;
      ospf_spf_calculate_schedule ();
    }
  return CMD_SUCCESS;
}

ALIAS (ospf_compatible_rfc1583,
       ospf_rfc1583_flag_cmd,
       "ospf rfc1583compatibility",
       "OSPF specific commands\n"
       "Enable the RFC1583Compatibility flag\n")

ALIAS (no_ospf_compatible_rfc1583,
       no_ospf_rfc1583_flag_cmd,
       "no ospf rfc1583compatibility",
       NO_STR
       "OSPF specific commands\n"
       "Disable the RFC1583Compatibility flag\n")

#if 0
DEFUN (ospf_rfc1583_flag,
       ospf_rfc1583_flag_cmd,
       "ospf rfc1583compatibility",
       "OSPF specific commands\n"
       "Enable the RFC1583Compatibility flag\n")
{
  if (ospf_top->RFC1583Compat == 0)
    {
      ospf_top->RFC1583Compat = 1;
      ospf_spf_calculate_schedule ();
    }

  return CMD_SUCCESS;
}

DEFUN (no_ospf_rfc1583_flag,
       no_ospf_rfc1583_flag_cmd,
       "no ospf rfc1583compatibility",
       NO_STR
       "OSPF specific commands\n"
       "Disable the RFC1583Compatibility flag\n")
{
  if (ospf_top->RFC1583Compat == 1)
    {
      ospf_top->RFC1583Compat = 0;
      ospf_spf_calculate_schedule ();
    }

  return CMD_SUCCESS;
}
#endif

char *ospf_abr_type_descr_str[] = 
{
  "Unknown",
  "Standard (RFC2328)",
  "Alternative IBM",
  "Alternative Cisco",
  "Alternative Shortcut"
};

char *ospf_shortcut_mode_descr_str[] = 
{
  "Default",
  "Enabled",
  "Disabled"
};



void
show_ip_ospf_area (struct vty *vty, struct ospf_area *area)
{
  /* Show Area ID. */
  vty_out (vty, " Area ID: %s", inet_ntoa (area->area_id));

  /* Show Area type/mode. */
  if (OSPF_IS_AREA_BACKBONE (area))
    vty_out (vty, " (Backbone)%s", VTY_NEWLINE);
  else
    {
      if (area->external_routing == OSPF_AREA_STUB)
	vty_out (vty, " (Stub%s%s)",
		 area->no_summary ? ", no summary" : "",
		 area->shortcut_configured ? "; " : "");

#ifdef HAVE_NSSA

      else
      if (area->external_routing == OSPF_AREA_NSSA)
	vty_out (vty, " (NSSA%s%s)",
		 area->no_summary ? ", no summary" : "",
		 area->shortcut_configured ? "; " : "");
#endif /* HAVE_NSSA */

      vty_out (vty, "%s", VTY_NEWLINE);
      vty_out (vty, "   Shortcutting mode: %s",
	       ospf_shortcut_mode_descr_str[area->shortcut_configured]);
      vty_out (vty, ", S-bit consensus: %s%s",
	       area->shortcut_capability ? "ok" : "no", VTY_NEWLINE);
    }

  /* Show number of interfaces. */
  vty_out (vty, "   Number of interfaces in this area: Total: %d, "
	   "Active: %d%s", listcount (area->iflist),
	   area->act_ints, VTY_NEWLINE);

#ifdef HAVE_NSSA
  if (area->external_routing == OSPF_AREA_NSSA)
    vty_out (vty, "   It is an NSSA configuration. %s   Elected Translator performs type-7/type-5 LSA translation. %s", VTY_NEWLINE, VTY_NEWLINE);
#endif /* HAVE_NSSA */

  /* Show number of fully adjacent neighbors. */
  vty_out (vty, "   Number of fully adjacent neighbors in this area:"
	   " %d%s", area->full_nbrs, VTY_NEWLINE);

  /* Show authentication type. */
  vty_out (vty, "   Area has ");
  if (area->auth_type == OSPF_AUTH_NULL)
    vty_out (vty, "no authentication%s", VTY_NEWLINE);
  else if (area->auth_type == OSPF_AUTH_SIMPLE)
    vty_out (vty, "simple password authentication%s", VTY_NEWLINE);
  else if (area->auth_type == OSPF_AUTH_CRYPTOGRAPHIC)
    vty_out (vty, "message digest authentication%s", VTY_NEWLINE);

  if (!OSPF_IS_AREA_BACKBONE (area))
    vty_out (vty, "   Number of full virtual adjacencies going through"
	     " this area: %d%s", area->full_vls, VTY_NEWLINE);

  /* Show SPF calculation times. */
  vty_out (vty, "   SPF algorithm executed %d times%s",
	   area->spf_calculation, VTY_NEWLINE);

  /* Show number of LSA. */
  vty_out (vty, "   Number of LSA %d%s", area->lsdb->total, VTY_NEWLINE);

  vty_out (vty, "%s", VTY_NEWLINE);
}

DEFUN (show_ip_ospf,
       show_ip_ospf_cmd,
       "show ip ospf",
       SHOW_STR
       IP_STR
       "OSPF information\n")
{
  listnode node;
  struct ospf_area * area;

  /* Check OSPF is enable. */
  if (ospf_top == NULL)
    {
      vty_out (vty, " OSPF Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  /* Show Router ID. */
  vty_out (vty, " OSPF Routing Process, Router ID: %s%s",
           inet_ntoa (ospf_top->router_id),
           VTY_NEWLINE);

  /* Show capability. */
  vty_out (vty, " Supports only single TOS (TOS0) routes%s", VTY_NEWLINE);
  vty_out (vty, " This implementation conforms to RFC2328%s", VTY_NEWLINE);
  vty_out (vty, " RFC1583Compatibility flag is %s%s",
	   ospf_top->RFC1583Compat ? "enabled" : "disabled", VTY_NEWLINE);

  /* Show SPF timers. */
  vty_out (vty, " SPF schedule delay %d secs, Hold time between two SPFs %d secs%s",
	   ospf_top->spf_delay, ospf_top->spf_holdtime, VTY_NEWLINE);

  /* Show refresh parameters. */
  vty_out (vty, " Refresh timer %d secs%s",
	   ospf_top->lsa_refresh_interval, VTY_NEWLINE);
	   
  /* Show ABR/ASBR flags. */
  if (CHECK_FLAG (ospf_top->flags, OSPF_FLAG_ABR))
    vty_out (vty, " This router is an ABR, ABR type is: %s%s",
             ospf_abr_type_descr_str[ospf_top->abr_type], VTY_NEWLINE);

  if (CHECK_FLAG (ospf_top->flags, OSPF_FLAG_ASBR))
    vty_out (vty, " This router is an ASBR "
             "(injecting external routing information)%s", VTY_NEWLINE);

  /* Show Number of AS-external-LSAs. */
  vty_out (vty, " Number of external LSA %d%s",
	   new_lsdb_count_all (ospf_top->lsdb), VTY_NEWLINE);

  /* Show number of areas attached. */
  vty_out (vty, " Number of areas attached to this router: %d%s%s",
           listcount (ospf_top->areas), VTY_NEWLINE, VTY_NEWLINE);

  /* Show each area status. */
  for (node = listhead (ospf_top->areas); node; nextnode (node))
    if ((area = getdata (node)) != NULL)
      show_ip_ospf_area (vty, area);

  return CMD_SUCCESS;
}

void
show_ip_ospf_interface_sub (struct vty *vty, struct interface *ifp)
{
  struct ospf_interface *oi = ifp->info;
  struct ospf_neighbor *nbr;
  char buf[9];

  /* Is interface up? */
  if (if_is_up (ifp))
    vty_out (vty, "%s is up, line protocol is up%s", ifp->name, VTY_NEWLINE);
  else
    {
      vty_out (vty, "%s is down, line protocol is down%s", ifp->name,
	       VTY_NEWLINE);

      if (oi == NULL || oi->flag == OSPF_IF_DISABLE)
	vty_out (vty, "  OSPF not enabled on this interface%s", VTY_NEWLINE);
      else
	vty_out (vty, "  OSPF is enabled, but not running on this interface%s",
		 VTY_NEWLINE);
      return;
    }

  /* Is interface OSPF enabled? */
  if (oi == NULL || oi->flag == OSPF_IF_DISABLE || oi->address == NULL)
    {
      vty_out (vty, "  OSPF not enabled on this interface%s", VTY_NEWLINE);
      return;
    }
      
  /* Show OSPF interface information. */
  vty_out (vty, "  Internet Address %s/%d,",
           inet_ntoa (oi->address->u.prefix4), oi->address->prefixlen);

  vty_out (vty, " Area %s%s", ait_ntoa (oi->area->area_id, oi->area->external_routing), 
	  VTY_NEWLINE);

  vty_out (vty, "  Router ID %s, Network Type %s, Cost: %d%s",
           inet_ntoa (ospf_top->router_id), ospf_network_type_str[oi->type],
           oi->output_cost, VTY_NEWLINE);

  vty_out (vty, "  Transmit Delay is %d sec, State %s, Priority %d%s",
           oi->transmit_delay, LOOKUP (ospf_ism_status_msg, oi->status),
           PRIORITY (oi), VTY_NEWLINE);

  /* Show DR information. */
  if (DR (oi).s_addr == 0)
    vty_out (vty, "  No designated router on this network%s", VTY_NEWLINE);
  else
    {
      nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &DR (oi));
      if (nbr == NULL)
	vty_out (vty, "  No designated router on this network%s", VTY_NEWLINE);
      else
	{
          vty_out (vty, "  Designated Router (ID) %s,",
		   inet_ntoa (nbr->router_id));
          vty_out (vty, " Interface Address %s%s",
                   inet_ntoa (nbr->address.u.prefix4), VTY_NEWLINE);
        }
    }

  /* Show BDR information. */
  if (BDR (oi).s_addr == 0)
    vty_out (vty, "  No backup designated router on this network%s",
             VTY_NEWLINE);
  else
    {
      nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &BDR (oi));
      if (nbr == NULL)
	vty_out (vty, "  No backup designated router on this network%s",
		 VTY_NEWLINE);
      else
	{
          vty_out (vty, "  Backup Designated Router (ID) %s,",
		   inet_ntoa (nbr->router_id));
          vty_out (vty, " Interface Address %s%s",
                   inet_ntoa (nbr->address.u.prefix4), VTY_NEWLINE);
        }
    }

  vty_out (vty, "  Timer intarvals configured,");
  vty_out (vty, " Hello %d, Dead %d, Wait %d, Retransmit %d%s",
           oi->v_hello, oi->v_wait, oi->v_wait, oi->retransmit_interval,
           VTY_NEWLINE);

  if (oi->passive_interface == OSPF_IF_ACTIVE)
    vty_out (vty, "    Hello due in %s%s",
	     ospf_timer_dump (oi->t_hello, buf, 9), VTY_NEWLINE);
  else /* OSPF_IF_PASSIVE is set */
    vty_out (vty, "    No Hellos (Passive interface)%s", VTY_NEWLINE);

  vty_out (vty, "  Neighbor Count is %d, Adjacent neighbor count is %d%s",
           ospf_nbr_count (oi->nbrs, 0), ospf_nbr_count (oi->nbrs, NSM_Full),
           VTY_NEWLINE);
}

DEFUN (show_ip_ospf_interface,
       show_ip_ospf_interface_cmd,
       "show ip ospf interface [INTERFACE]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Interface information\n"
       "Interface name\n")
{
  struct interface *ifp;
  listnode node;

  /* Show All Interfaces. */
  if (argc == 0)
    for (node = listhead (iflist); node; nextnode (node))
      show_ip_ospf_interface_sub (vty, node->data);
  /* Interface name is specified. */
  else
    {
      if ((ifp = if_lookup_by_name (argv[0])) == NULL)
        vty_out (vty, "No such interface name%s", VTY_NEWLINE);
      else
        show_ip_ospf_interface_sub (vty, ifp);
    }

  return CMD_SUCCESS;
}

void
show_ip_ospf_neighbor_sub (struct vty *vty, struct interface *ifp)
{
  struct route_node *rn;
  struct ospf_interface *oi;
  struct ospf_neighbor *nbr;
  char msgbuf[16];
  char timebuf[9];

  oi = ifp->info;

  for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
    if ((nbr = rn->info))
      /* Do not show myself. */
      if (nbr != oi->nbr_self)
	/* Down state is not shown. */
	if (nbr->status != NSM_Down)
	  {
	    ospf_nbr_state_message (nbr, msgbuf, 16);

	    if (nbr->status == NSM_Attempt && nbr->router_id.s_addr == 0)
	    vty_out (vty, "%-15s %3d   %-15s %8s    ",
		     "-", nbr->priority,
		     msgbuf, ospf_timer_dump (nbr->t_inactivity, timebuf, 9));
	    else
	    vty_out (vty, "%-15s %3d   %-15s %8s    ",
		     inet_ntoa (nbr->router_id), nbr->priority,
		     msgbuf, ospf_timer_dump (nbr->t_inactivity, timebuf, 9));
	    vty_out (vty, "%-15s %-15s %5d %5d %5d%s", inet_ntoa (nbr->src),
		     ifp->name, ospf_ls_retransmit_count (nbr),
		     ospf_ls_request_count (nbr), ospf_db_summary_count (nbr),
		     VTY_NEWLINE);
	  }
}

DEFUN (show_ip_ospf_neighbor,
       show_ip_ospf_neighbor_cmd,
       "show ip ospf neighbor",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n")
{
  listnode node;

  /* Show All neighbors. */
  vty_out (vty, "%sNeighbor ID     Pri   State           Dead "
           "Time   Address         Interface           RXmtL "
           "RqstL DBsmL%s", VTY_NEWLINE, VTY_NEWLINE);

  for (node = listhead (iflist); node; nextnode (node))
    show_ip_ospf_neighbor_sub (vty, node->data);

  return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_all,
       show_ip_ospf_neighbor_all_cmd,
       "show ip ospf neighbor all",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "include down status neighbor\n")
{
  listnode node;

  /* Show All neighbors. */
  vty_out (vty, "%sNeighbor ID     Pri   State           Dead "
           "Time   Address         Interface           RXmtL "
           "RqstL DBsmL%s", VTY_NEWLINE, VTY_NEWLINE);

  for (node = listhead (iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      listnode nbr_node;

      show_ip_ospf_neighbor_sub (vty, ifp);

    /* print Down neighbor status */
    for (nbr_node = listhead (oi->nbr_static); nbr_node; nextnode (nbr_node))
      {
	struct ospf_nbr_static *nbr_static;

	nbr_static = getdata (nbr_node);

	if (nbr_static->neighbor == NULL
	    || nbr_static->neighbor->status == NSM_Down)
	  {
	    vty_out (vty, "%-15s %3d   %-15s %8s    ",
		     "-", nbr_static->priority, "Down", "-");
	    vty_out (vty, "%-15s %-15s %5d %5d %5d%s", 
		     inet_ntoa (nbr_static->addr), ifp->name,
		     0, 0, 0, VTY_NEWLINE);
	  }
      }
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_int,
       show_ip_ospf_neighbor_int_cmd,
       "show ip ospf neighbor INTERFACE",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n")
{
  struct interface *ifp;

  if ((ifp = if_lookup_by_name (argv[0])) == NULL)
    vty_out (vty, "No such interface name%s", VTY_NEWLINE);
  else
    {
      vty_out (vty, "%sNeighbor ID     Pri   State           Dead "
               "Time   Address         Interface           RXmtL "
               "RqstL DBsmL%s", VTY_NEWLINE, VTY_NEWLINE);
      show_ip_ospf_neighbor_sub (vty, ifp);
    }

  return CMD_SUCCESS;
}

void
show_ip_ospf_nbr_static_detail_sub (struct vty *vty, struct interface *ifp,
				  struct ospf_nbr_static *nbr_static)
{
  char timebuf[9];
  struct ospf_interface *oi = ifp->info;

  /* Show neighbor ID. */
  vty_out (vty, " Neighbor %s,", "-");

  /* Show interface address. */
  vty_out (vty, " interface address %s%s",
	   inet_ntoa (nbr_static->addr), VTY_NEWLINE);
  /* Show Area ID. */
  vty_out (vty, "    In the area %s via interface %s%s",
	   ait_ntoa (oi->area->area_id, oi->area->external_routing), ifp->name, VTY_NEWLINE);
  /* Show neighbor priority and state. */
  vty_out (vty, "    Neighbor priority is %d, State is %s,",
	   nbr_static->priority, "Down");
  /* Show state changes. */
  vty_out (vty, " %d state changes%s", nbr_static->state_change, VTY_NEWLINE);

  /* Show PollInterval */
  vty_out (vty, "    Poll interval %d%s", nbr_static->v_poll, VTY_NEWLINE);

  /* Show poll-interval timer. */
  vty_out (vty, "    Poll timer due in %s%s",
	   ospf_timer_dump (nbr_static->t_poll, timebuf, 9), VTY_NEWLINE);

  /* Show poll-interval timer thread. */
  vty_out (vty, "    Thread Poll Timer %s%s", 
	   nbr_static->t_poll != NULL ? "on" : "off", VTY_NEWLINE);
}

void
show_ip_ospf_neighbor_detail_sub (struct vty *vty, struct interface *ifp,
				  struct ospf_neighbor *nbr)
{
  char optbuf[24];
  char timebuf[9];
  struct ospf_interface *oi = ifp->info;

  /* Show neighbor ID. */
  if (nbr->status == NSM_Attempt && nbr->router_id.s_addr == 0)
    vty_out (vty, " Neighbor %s,", "-");
  else
  vty_out (vty, " Neighbor %s,", inet_ntoa (nbr->router_id));

  /* Show interface address. */
  vty_out (vty, " interface address %s%s",
	   inet_ntoa (nbr->address.u.prefix4), VTY_NEWLINE);
  /* Show Area ID. */
  vty_out (vty, "    In the area %s via interface %s%s",
	   ait_ntoa (oi->area->area_id, oi->area->external_routing), ifp->name, VTY_NEWLINE);
  /* Show neighbor priority and state. */
  vty_out (vty, "    Neighbor priority is %d, State is %s,",
	   nbr->priority, LOOKUP (ospf_nsm_status_msg, nbr->status));
  /* Show state changes. */
  vty_out (vty, " %d state changes%s", nbr->state_change, VTY_NEWLINE);

  /* Show Designated Rotuer ID. */
  vty_out (vty, "    DR is %s,", inet_ntoa (nbr->d_router));
  /* Show Backup Designated Rotuer ID. */
  vty_out (vty, " BDR is %s%s", inet_ntoa (nbr->bd_router), VTY_NEWLINE);
  /* Show options. */
  vty_out (vty, "    Options %d %s%s", nbr->options,
	   ospf_option_dump (nbr->options, optbuf, 24), VTY_NEWLINE);
  /* Show Router Dead interval timer. */
  vty_out (vty, "    Dead timer due in %s%s",
	   ospf_timer_dump (nbr->t_inactivity, timebuf, 9), VTY_NEWLINE);
  /* Show Database Summary list. */
  vty_out (vty, "    Database Summary List %d%s",
	   ospf_db_summary_count (nbr), VTY_NEWLINE);
  /* Show Link State Request list. */
  vty_out (vty, "    Link State Request List %d%s",
	   ospf_ls_request_count (nbr), VTY_NEWLINE);
  /* Show Link State Retransmission list. */
  vty_out (vty, "    Link State Retransmission List %d%s",
	   ospf_ls_retransmit_count (nbr), VTY_NEWLINE);
  /* Show inactivity timer thread. */
  vty_out (vty, "    Thread Inactivity Timer %s%s", 
	   nbr->t_inactivity != NULL ? "on" : "off", VTY_NEWLINE);
  /* Show Database Description retransmission thread. */
  vty_out (vty, "    Thread Database Description Retransmision %s%s",
	   nbr->t_db_desc != NULL ? "on" : "off", VTY_NEWLINE);
  /* Show Link State Request Retransmission thread. */
  vty_out (vty, "    Thread Link State Request Retransmission %s%s",
	   nbr->t_ls_req != NULL ? "on" : "off", VTY_NEWLINE);
  /* Show Link State Update Retransmission thread. */
  vty_out (vty, "    Thread Link State Update Retransmission %s%s%s",
	   nbr->t_ls_upd != NULL ? "on" : "off", VTY_NEWLINE, VTY_NEWLINE);
}

DEFUN (show_ip_ospf_neighbor_id,
       show_ip_ospf_neighbor_id_cmd,
       "show ip ospf neighbor A.B.C.D",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Neighbor ID\n")
{
  listnode node;
  struct ospf_neighbor *nbr;
  struct in_addr router_id;
  int ret;

  ret = inet_aton (argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "Please specify Neighbor ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;

      if ((nbr = ospf_nbr_lookup_by_routerid (oi->nbrs, &router_id)))
	{
	  show_ip_ospf_neighbor_detail_sub (vty, ifp, nbr);
	  return CMD_SUCCESS;
	}
    }

  /* Nothing to show. */
  return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_detail,
       show_ip_ospf_neighbor_detail_cmd,
       "show ip ospf neighbor detail",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "detail of all neighbors\n")
{
  listnode node;

  if (!ospf_top)
    return CMD_SUCCESS;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	if ((nbr = rn->info))
	  if (nbr != oi->nbr_self)
	    if (nbr->status != NSM_Down)
	      show_ip_ospf_neighbor_detail_sub (vty, ifp, nbr);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_detail_all,
       show_ip_ospf_neighbor_detail_all_cmd,
       "show ip ospf neighbor detail all",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "detail of all neighbors\n"
       "include down status neighbor\n")
{
  listnode node;

  if (!ospf_top)
    return CMD_SUCCESS;

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	if ((nbr = rn->info))
	  if (nbr != oi->nbr_self)
	    if (oi->type == OSPF_IFTYPE_NBMA && nbr->status != NSM_Down)
	      show_ip_ospf_neighbor_detail_sub (vty, ifp, rn->info);

      if (oi->type == OSPF_IFTYPE_NBMA)
	{
	  listnode nd;

	  for (nd = listhead (oi->nbr_static); nd; nextnode (nd))
	    {
	      struct ospf_nbr_static *nbr_static = getdata (nd);
	      if (nbr_static->neighbor == NULL
		  || nbr_static->neighbor->status == NSM_Down)
		show_ip_ospf_nbr_static_detail_sub (vty, ifp, nbr_static);
	    }
	}
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_int_detail,
       show_ip_ospf_neighbor_int_detail_cmd,
       "show ip ospf neighbor INTERFACE detail",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n"
       "detail of all neighbors")
{
  struct interface *ifp;

  if ((ifp = if_lookup_by_name (argv[0])) == NULL)
    vty_out (vty, "No such interface name%s", VTY_NEWLINE);
  else
    {
      struct ospf_interface *oi = ifp->info;
      struct route_node *rn;
      struct ospf_neighbor *nbr;

      for (rn = route_top (oi->nbrs); rn; rn = route_next (rn))
	if ((nbr = rn->info))
	  if (nbr != oi->nbr_self)
	    if (nbr->status != NSM_Down)
	      show_ip_ospf_neighbor_detail_sub (vty, ifp, nbr);
    }

  return CMD_SUCCESS;
}

DEFUN (timers_spf,
       timers_spf_cmd,
       "timers spf <0-4294967295> <0-4294967295>",
       "Adjust routing timers\n"
       "OSPF SPF timers\n"
       "Delay between receiving a change to SPF calculation\n"
       "Hold time between consecutive SPF calculations\n")
{
  u_int32_t delay, hold;

  delay = strtoul (argv[0], NULL, 10);
  hold = strtoul (argv[1], NULL, 10);

  if (delay < 0 || delay > 0xFFFFFFFF)
    {
      vty_out (vty, "SPF delay timer value is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (hold < 0 || hold > 0xFFFFFFFF)
    {
      vty_out (vty, "SPF hold timer value is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ospf_top->spf_delay = delay;
  ospf_top->spf_holdtime = hold;

  return CMD_SUCCESS;
}

DEFUN (no_timers_spf,
       no_timers_spf_cmd,
       "no timers spf",
       NO_STR
       "Adjust routing timers\n"
       "OSPF SPF timers\n")
{
  ospf_top->spf_delay = OSPF_SPF_DELAY_DEFAULT;
  ospf_top->spf_holdtime = OSPF_SPF_HOLDTIME_DEFAULT;

  return CMD_SUCCESS;
}


void
ospf_nbr_static_add (struct ospf_nbr_static *nbr_static,
		     struct ospf_interface *oi)
{
  struct ospf_neighbor *nbr;
  struct route_node *rn;
  struct prefix key;

  assert (oi);

  if (oi->type != OSPF_IFTYPE_NBMA)
    return;

  if (nbr_static->neighbor != NULL)
    return;

  if (IPV4_ADDR_SAME(&oi->nbr_self->address.u.prefix4, &nbr_static->addr))
    return;
      
  nbr_static->oi = oi;
  listnode_add (oi->nbr_static, nbr_static);

  /* Get neighbor information from table. */
  key.family = AF_INET;
  key.prefixlen = IPV4_MAX_BITLEN;
  key.u.prefix4.s_addr = nbr_static->addr.s_addr;

  rn = route_node_get (oi->nbrs, &key);

  if (rn->info)
    {
      nbr = rn->info;

      nbr->nbr_static = nbr_static;
      nbr_static->neighbor = nbr;

      route_unlock_node (rn);
    }
  else
    {
      nbr = ospf_nbr_new (oi);
      nbr->status = NSM_Down;
      nbr->src.s_addr = nbr_static->addr.s_addr;
      nbr->nbr_static = nbr_static;
      nbr->priority = nbr_static->priority;
      nbr->address = key;

      rn->info = nbr;

      nbr_static->neighbor = nbr;

      OSPF_NSM_EVENT_EXECUTE (nbr, NSM_Start);
    }
}

void
ospf_nbr_static_if_update (struct ospf_interface *oi)
{
  struct ospf_nbr_static *nbr_static;
  listnode node;

  assert(oi);

  if (oi->flag != OSPF_IF_ENABLE)
    return;

  if (oi->type != OSPF_IFTYPE_NBMA)
    return;

  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      struct prefix p;

      nbr_static = getdata (node);
      assert (nbr_static);

      if (nbr_static->oi != NULL)
	continue;

      if (nbr_static->neighbor != NULL)
	continue;

      p.family = AF_INET;
      p.prefixlen = IPV4_MAX_BITLEN;
      p.u.prefix4 = nbr_static->addr;

      if (prefix_match(oi->address, &p))
	ospf_nbr_static_add (nbr_static, oi);
    }
}

struct ospf_nbr_static *
ospf_nbr_static_lookup_by_addr (struct in_addr addr)
{
  listnode node;
  struct ospf_nbr_static *nbr_static;

  if (! ospf_top)
    return NULL;

  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      nbr_static = getdata (node);

      if (IPV4_ADDR_SAME(&nbr_static->addr, &addr))
	return nbr_static;
    }
  return NULL;
}

struct ospf_nbr_static *
ospf_nbr_static_lookup_next (struct in_addr *addr, int first)
{
  listnode node;
  struct ospf_nbr_static *nbr_static;

  if (! ospf_top)
    return NULL;

  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      nbr_static = getdata (node);

      if (first)
	{
	  *addr = nbr_static->addr;
	  return nbr_static;
	}
      else if (ntohl (nbr_static->addr.s_addr) > ntohl (addr->s_addr))
	{
	  *addr = nbr_static->addr;
	  return nbr_static;
	}
    }
  return NULL;
}

int
ospf_nbr_static_new (char *nbr_addr, int priority, int poll_interval,
		     struct vty *vty)
{
  struct ospf_nbr_static *nbr_static;
  listnode node;
  int ret;
  struct in_addr addr;
  struct prefix p;

  ret = inet_aton (nbr_addr, &addr);
  if (!ret)
    {
      vty_out (vty, "Please specify Neighbor address by A.B.C.D%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      nbr_static = getdata (node);

      /* this neighbor is already registered */
      if (IPV4_ADDR_SAME(&nbr_static->addr, &addr))
	{
	  if (nbr_static->v_poll != poll_interval)
	    {
	      nbr_static->v_poll = poll_interval;

	      if (nbr_static->t_poll)
		{
		  OSPF_POLL_TIMER_OFF (nbr_static->t_poll);
		  OSPF_POLL_TIMER_ON (nbr_static->t_poll, ospf_poll_timer,
				      nbr_static->v_poll);
		}
	    }

	  if (nbr_static->priority != priority)
	    nbr_static->priority = priority;

	  return CMD_SUCCESS;
	}
    }

  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4.s_addr = addr.s_addr;

  /* make new static neighbor object */
  nbr_static = XMALLOC (MTYPE_OSPF_NEIGHBOR_STATIC,
			sizeof (struct ospf_nbr_static));
  bzero (nbr_static, sizeof (struct ospf_nbr_static));

  nbr_static->addr = addr;
  nbr_static->oi = NULL;
  nbr_static->neighbor = NULL;
  nbr_static->priority = priority;
  nbr_static->v_poll = poll_interval;
  nbr_static->t_poll = NULL;

  listnode_add_sort (ospf_top->nbr_static, nbr_static);

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = getdata (node);
      struct ospf_interface *oi = ifp->info;

      assert(oi);

      if (oi->flag != OSPF_IF_ENABLE)
	continue;

      if (oi->type != OSPF_IFTYPE_NBMA)
	continue;

      if (!prefix_match(oi->address, &p))
	continue;

      ospf_nbr_static_add (nbr_static, oi);

      return CMD_SUCCESS;
    }

  return CMD_SUCCESS;
}

DEFUN (neighbor_priority_pollinterval,
       neighbor_priority_pollinterval_cmd,
       "neighbor A.B.C.D priority <0-255> poll-interval <1-65535>",
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")
{
  return ospf_nbr_static_new (argv[0], atoi(argv[1]), atoi(argv[2]), vty);
}

DEFUN (neighbor_priority,
       neighbor_priority_cmd,
       "neighbor A.B.C.D priority <0-255>",
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Seconds\n")
{
  return ospf_nbr_static_new (argv[0], atoi(argv[1]),
			      OSPF_POLL_INTERVAL_DEFAULT, vty);
}

DEFUN (neighbor_pollinterval,
       neighbor_pollinterval_cmd,
       "neighbor A.B.C.D poll-interval <1-65535>",
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")
{
  return ospf_nbr_static_new (argv[0], OSPF_NEIGHBOR_PRIORITY_DEFAULT,
			      atoi(argv[1]), vty);
}

DEFUN (neighbor,
       neighbor_cmd,
       "neighbor A.B.C.D",
       NEIGHBOR_STR
       "Neighbor IP address\n")
{
  return ospf_nbr_static_new (argv[0], OSPF_NEIGHBOR_PRIORITY_DEFAULT,
			      OSPF_POLL_INTERVAL_DEFAULT, vty);
}


DEFUN (no_neighbor,
       no_neighbor_cmd,
       "no neighbor A.B.C.D",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n")
{
  int ret;
  listnode node;
  struct ospf_nbr_static *nbr_static = NULL;
  struct in_addr addr;

  ret = inet_aton(argv[0], &addr);
  if (!ret)
    {
      vty_out (vty, "Please specify Neighbor address by A.B.C.D%s",
	       VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      nbr_static = getdata(node);

      if (IPV4_ADDR_SAME(&nbr_static->addr, &addr))
	break;
    }

  if (node == NULL) 
    {
      vty_out (vty, "There is no such Neighbor address %s%s",
	       inet_ntoa(addr), VTY_NEWLINE);
      return CMD_WARNING;
    }

  list_delete_node (ospf_top->nbr_static, node);

  OSPF_POLL_TIMER_OFF (nbr_static->t_poll);

  if (nbr_static->neighbor)
    {
      nbr_static->neighbor->nbr_static = NULL;
      OSPF_NSM_EVENT_SCHEDULE (nbr_static->neighbor, NSM_KillNbr);

      nbr_static->neighbor = NULL;
    }

  if (nbr_static->oi)
    {
      listnode_delete (nbr_static->oi->nbr_static, nbr_static);
      nbr_static->oi = NULL;
    }

  XFREE (MTYPE_OSPF_NEIGHBOR_STATIC, nbr_static);

  return CMD_SUCCESS;
}

ALIAS (no_neighbor,
       no_neighbor_priority_cmd,
       "no neighbor A.B.C.D priority <0-255>",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n")

ALIAS (no_neighbor,
       no_neighbor_pollinterval_cmd,
       "no neighbor A.B.C.D poll-interval <1-65535>",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

ALIAS (no_neighbor,
       no_neighbor_priority_pollinterval_cmd,
       "no neighbor A.B.C.D priority <0-255> poll-interval <1-65535>",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")

DEFUN (clear_ip_ospf_neighbor,
       clear_ip_ospf_neighbor_cmd,
       "clear ip ospf neighbor A.B.C.D",
       "Reset functions\n"
       "IP\n"
       "Clear OSPF\n"
       "Neighbor list\n"
       "Neighbor ID\n")
{
  listnode node;
  struct ospf_neighbor *nbr;
  struct in_addr router_id;
  int ret;

  ret = inet_aton (argv[0], &router_id);
  if (!ret)
    {
      vty_out (vty, "Please specify Neighbor ID by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (node = listhead (ospf_top->iflist); node; nextnode (node))
    {
      struct interface *ifp = node->data;
      struct ospf_interface *oi = ifp->info;

      nbr = ospf_nbr_lookup_by_routerid (oi->nbrs, &router_id);

      if (nbr)
	{
	  OSPF_NSM_EVENT_SCHEDULE (nbr, NSM_SeqNumberMismatch);
	  vty_out (vty, "clear neighbor %s%s", argv[0], VTY_NEWLINE);
	  break;
	}
    }

  return CMD_SUCCESS;
}

DEFUN (refresh_timer, refresh_timer_cmd,
       "refresh timer <10-1800>",
       "Adjust refresh parameters\n"
       "Set refresh timer\n"
       "Timer value in seconds\n")
{
  int interval = (atoi (argv[0])/10)*10;
  int time_left;
  
  if (ospf_top->lsa_refresh_interval == interval)
    return CMD_SUCCESS;

  time_left = ospf_top->lsa_refresh_interval -
    (time (NULL) - ospf_top->lsa_refresher_started);
  
  if (time_left > interval)
    {
      OSPF_TIMER_OFF (ospf_top->t_lsa_refresher);
      ospf_top->t_lsa_refresher =
	thread_add_timer (master, ospf_lsa_refresh_walker, ospf_top,
			  interval);
    }
  ospf_top->lsa_refresh_interval = interval;  
  return CMD_SUCCESS;
}

DEFUN (no_refresh_timer, no_refresh_timer_val_cmd,
       "no refresh timer <10-1800>",
       "Adjust refresh parameters\n"
       "Unset refresh timer\n"
       "Timer value in seconds\n")
{
  int interval;
  int time_left;

  if (argc == 1)
    {
      interval = (atoi (argv[0])/10)*10;
  
      if (ospf_top->lsa_refresh_interval != interval ||
	  interval == OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
	return CMD_SUCCESS;
    }

  time_left = ospf_top->lsa_refresh_interval -
    (time (NULL) - ospf_top->lsa_refresher_started);

  if (time_left > OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
    {
      OSPF_TIMER_OFF (ospf_top->t_lsa_refresher);
      ospf_top->t_lsa_refresher =
	thread_add_timer (master, ospf_lsa_refresh_walker, ospf_top,
			  OSPF_LSA_REFRESH_INTERVAL_DEFAULT);
    }

  ospf_top->lsa_refresh_interval = OSPF_LSA_REFRESH_INTERVAL_DEFAULT;
  
  return CMD_SUCCESS;
}

ALIAS (no_refresh_timer, no_refresh_timer_cmd,
       "no refresh timer",
       "Adjust refresh parameters\n"
       "Unset refresh timer\n")

DEFUN (auto_cost_reference_bandwidth,
       auto_cost_reference_bandwidth_cmd,
       "auto-cost reference-bandwidth <1-4294967>",
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
  u_int32_t refbw;
  listnode node;
  list skip;

  refbw = strtol (argv[0], NULL, 10);
  if (refbw < 1 || refbw > 4294967)
    {
      vty_out (vty, "reference-bandwidth value is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* If reference bandwidth is changed. */
  if ((refbw * 1000) != ospf_top->ref_bandwidth)
    {
      ospf_top->ref_bandwidth = refbw * 1000;
      vty_out (vty, "%% OSPF: Reference bandwidth is changed.%s", VTY_NEWLINE);
      vty_out (vty, "        Please ensure reference bandwidth is consistent across all routers%s", VTY_NEWLINE);

      skip = list_new ();
      for (node = listhead (iflist); node; nextnode (node))
	{
	  struct interface *ifp = getdata (node);
	  struct ospf_interface *oi = ifp->info;
	  int newcost;

	  if (oi->area)
	    {
	      newcost = ospf_if_get_output_cost (oi);

	      if (oi->output_cost != newcost)
		{
		  oi->output_cost = newcost;

		  if (! listnode_lookup (skip, oi->area))
		    {
		      ospf_router_lsa_timer_add (oi->area);
		      listnode_add (skip, oi->area);
		    }
		}
	    }
	}
      list_delete (skip);
    }

  return CMD_SUCCESS;
}

DEFUN (no_auto_cost_reference_bandwidth,
       no_auto_cost_reference_bandwidth_cmd,
       "no auto-cost reference-bandwidth",
       NO_STR
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n")
{
  listnode node;
  list skip;

  if (ospf_top->ref_bandwidth != OSPF_DEFAULT_REF_BANDWIDTH)
    {
      ospf_top->ref_bandwidth = OSPF_DEFAULT_REF_BANDWIDTH;
      vty_out (vty, "%% OSPF: Reference bandwidth is changed.%s", VTY_NEWLINE);
      vty_out (vty, "        Please ensure reference bandwidth is consistent across all routers%s", VTY_NEWLINE);

      skip = list_new ();
      for (node = listhead (iflist); node; nextnode (node))
	{
	  struct interface *ifp = getdata (node);
	  struct ospf_interface *oi = ifp->info;
	  int newcost;

	  if (oi->area)
	    {
	      newcost = ospf_if_get_output_cost (oi);
	      if (oi->output_cost != newcost)
		{
		  oi->output_cost = newcost;
		  if (!listnode_lookup (skip, oi->area))
		    {
		      ospf_router_lsa_timer_add (oi->area);
		      listnode_add (skip, oi->area);
		    }
		}
	    }
	}
      list_delete (skip);
    }
  return CMD_SUCCESS;
}


char *ospf_abr_type_str[] = 
{
  "unknown",
  "standard",
  "ibm",
  "cisco",
  "shortcut"
};

char *ospf_shortcut_mode_str[] = 
{
  "default",
  "enable",
  "disable"
};


void
area_id2str (char *buf, int length, struct ospf_area *area)
{
  bzero (buf, length);

  if (area->format == OSPF_AREA_ID_FORMAT_ADDRESS)
    strncpy (buf, inet_ntoa (area->area_id), length);
  else
    sprintf (buf, "%lu", (unsigned long) ntohl (area->area_id.s_addr));
}

int
config_write_network_area (struct vty *vty)
{
  struct route_node *rn;
  u_char buf[INET_ADDRSTRLEN];

  /* `network area' print. */
  for (rn = route_top (ospf_top->networks); rn; rn = route_next (rn))
    if (rn->info)
      {
	struct ospf_network *n = rn->info;

	bzero (buf, INET_ADDRSTRLEN);

	/* Create Area ID string by specified Area ID format. */
	if (n->format == OSPF_AREA_ID_FORMAT_ADDRESS)
	  strncpy (buf, inet_ntoa (n->area_id), INET_ADDRSTRLEN);
	else
	  sprintf (buf, "%lu", 
		   (unsigned long int) ntohl (n->area_id.s_addr));

	/* Network print. */
	vty_out (vty, " network %s/%d area %s%s",
		 inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
		 buf, VTY_NEWLINE);
      }

  return 0;
}

int
config_write_ospf_area (struct vty *vty)
{
  listnode node;
  u_char buf[INET_ADDRSTRLEN];

  /* Area configuration print. */
  for (node = listhead (ospf_top->areas); node; nextnode (node))
    {
      struct ospf_area *area = getdata (node);
      struct route_node *rn1;

      area_id2str (buf, INET_ADDRSTRLEN, area);

      if (area->auth_type != OSPF_AUTH_NULL)
	{
	  if (area->auth_type == OSPF_AUTH_SIMPLE)
	    vty_out (vty, " area %s authentication%s", buf, VTY_NEWLINE);
	  else
	    vty_out (vty, " area %s authentication message-digest%s",
		     buf, VTY_NEWLINE);
	}

      if (area->shortcut_configured != OSPF_SHORTCUT_DEFAULT)
	vty_out (vty, " area %s shortcut %s%s", buf,
		 ospf_shortcut_mode_str[area->shortcut_configured],
		 VTY_NEWLINE);

      if (
	     (area->external_routing == OSPF_AREA_STUB)
#ifdef HAVE_NSSA
		|| (area->external_routing == OSPF_AREA_NSSA)
#endif /* HAVE_NSSA */
	 )
		{

#ifdef HAVE_NSSA
      if (area->external_routing == OSPF_AREA_NSSA)
	  vty_out (vty, " area %s nssa", buf);
      else
#endif /* HAVE_NSSA */
	  vty_out (vty, " area %s stub", buf);

	  if (area->no_summary)
	    vty_out (vty, " no-summary");

	  vty_out (vty, "%s", VTY_NEWLINE);

	  if (area->default_cost != 1)
	    vty_out (vty, " area %s default-cost %lu%s", buf, 
		     area->default_cost, VTY_NEWLINE);
		}

      for (rn1 = route_top (area->ranges); rn1; rn1 = route_next (rn1))
	if (rn1->info)
	  {
	    struct ospf_area_range *range = rn1->info;

	    vty_out (vty, " area %s range %s/%d", buf,
		     inet_ntoa (rn1->p.u.prefix4), rn1->p.prefixlen);

	    if (CHECK_FLAG (range->flags, OSPF_RANGE_SUPPRESS))
	      vty_out (vty, " not-advertise");

	    if (CHECK_FLAG (range->flags, OSPF_RANGE_SUBST))
	      vty_out (vty, " substitute %s/%d",
		       inet_ntoa (range->substitute.prefix), 
		       range->substitute.prefixlen);

	    vty_out (vty, "%s", VTY_NEWLINE);
	  }

      if (EXPORT_NAME (area))
	vty_out (vty, " area %s export-list %s%s", buf,
		 EXPORT_NAME (area), VTY_NEWLINE);

      if (IMPORT_NAME (area))
	vty_out (vty, " area %s import-list %s%s", buf,
		 IMPORT_NAME (area), VTY_NEWLINE);
    }

  return 0;
}

int
config_write_ospf_nbr_static (struct vty *vty)
{
  listnode node;
  struct ospf_nbr_static *nbr;

  /* Static Neighbor configuration print. */
  for (node = listhead (ospf_top->nbr_static); node; nextnode (node))
    {
      nbr = getdata(node);

      vty_out (vty, " neighbor %s", inet_ntoa(nbr->addr));

      if (nbr->priority != OSPF_NEIGHBOR_PRIORITY_DEFAULT)
	vty_out (vty, " priority %d", nbr->priority);

      if (nbr->v_poll != OSPF_POLL_INTERVAL_DEFAULT)
	vty_out (vty, " poll-interval %d", nbr->v_poll);

      vty_out (vty, "%s", VTY_NEWLINE);
    }

  return 0;
}

int
config_write_virtual_link (struct vty *vty)
{
  listnode node;
  u_char buf[INET_ADDRSTRLEN];

  /* Virtual-Link print */
  for (node = listhead (ospf_top->vlinks); node; nextnode (node))
    {
      listnode n2;
      struct crypt_key *ck;
      struct ospf_vl_data *vl_data = getdata (node);
      struct ospf_interface *oi;

      if (vl_data != NULL)
	{
	  bzero (buf, INET_ADDRSTRLEN);
	  
	  if (vl_data->format == OSPF_AREA_ID_FORMAT_ADDRESS)
	    strncpy (buf, inet_ntoa (vl_data->vl_area_id), INET_ADDRSTRLEN);
	  else
	    sprintf (buf, "%lu", 
		     (unsigned long int) ntohl (vl_data->vl_area_id.s_addr));
	  oi = vl_data->vl_oi;

	  /* timers */
	  if (oi->v_hello != OSPF_HELLO_INTERVAL_DEFAULT ||
	      oi->v_wait != OSPF_ROUTER_DEAD_INTERVAL_DEFAULT ||
	      oi->retransmit_interval != OSPF_RETRANSMIT_INTERVAL_DEFAULT ||
	      oi->transmit_delay != OSPF_TRANSMIT_DELAY_DEFAULT)
	    vty_out (vty, " area %s virtual-link %s hello-interval %d retransmit-interval %d transmit-delay %d dead-interval %d%s",
		     buf,
		     inet_ntoa (vl_data->vl_peer), 
		     oi->v_hello, oi->retransmit_interval,
		     oi->transmit_delay, oi->v_wait,
		     VTY_NEWLINE);
	  else
	    vty_out (vty, " area %s virtual-link %s%s", buf,
		     inet_ntoa (vl_data->vl_peer), VTY_NEWLINE);
	  /* Auth key */
	  if (vl_data->vl_oi->auth_simple[0] != '\0')
	    vty_out (vty, " area %s virtual-link %s authentication-key %s%s",
		     buf,
		     inet_ntoa (vl_data->vl_peer),
		     vl_data->vl_oi->auth_simple,
		     VTY_NEWLINE);
	  /* md5 keys */
	  for (n2 = listhead (vl_data->vl_oi->auth_crypt); n2; nextnode (n2))
	    {
	      ck = getdata (n2);
	      vty_out (vty, " area %s virtual-link %s message-digest-key %d md5 %s%s",
		       buf,
		       inet_ntoa (vl_data->vl_peer),
		       ck->key_id, ck->auth_key, VTY_NEWLINE);
	    }
	 
	}
    }

  return 0;
}

/* OSPF configuration write function. */
int
ospf_config_write (struct vty *vty)
{
  listnode node;
  int write = 0;

  if (ospf_top != NULL)
    {
      /* `router ospf' print. */
      vty_out (vty, "router ospf%s", VTY_NEWLINE);

      write++;

      if (!ospf_top->networks)
        return write;

      /* Router ID print. */
      if (ospf_top->router_id_static.s_addr != 0)
        vty_out (vty, " ospf router-id %s%s",
                 inet_ntoa (ospf_top->router_id_static), VTY_NEWLINE);

      /* ABR type print. */
      if (ospf_top->abr_type != OSPF_ABR_STAND)
        vty_out (vty, " ospf abr-type %s%s", 
                 ospf_abr_type_str[ospf_top->abr_type], VTY_NEWLINE);

      /* RFC1583 compatibility flag print. */
      /* Compatible with CISCO 12.1. */
      if (ospf_top->RFC1583Compat)
	vty_out (vty, " compatible rfc1583%s", VTY_NEWLINE);
      /*
      if (ospf_top->RFC1583Compat)
	vty_out (vty, " ospf rfc1583compatibility%s", VTY_NEWLINE);
      */

      /* SPF timers print. */
      if (ospf_top->spf_delay != OSPF_SPF_DELAY_DEFAULT ||
	  ospf_top->spf_holdtime != OSPF_SPF_HOLDTIME_DEFAULT)
	vty_out (vty, " timers spf %d %d%s",
		 ospf_top->spf_delay, ospf_top->spf_holdtime, VTY_NEWLINE);

      /* SPF refresh parameters print. */
      if (ospf_top->lsa_refresh_interval != OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
	vty_out (vty, " refresh timer %d%s",
		 ospf_top->lsa_refresh_interval, VTY_NEWLINE);

      /* Redistribute information print. */
      config_write_ospf_redistribute (vty);

      /* passive-interface print. */
      for (node = listhead (ospf_top->iflist); node; nextnode (node))
        {
          struct interface *ifp = node->data;
          struct ospf_interface *oi = ifp->info;

	  if (ifp != NULL && oi != NULL)
	    if (oi->passive_interface == OSPF_IF_PASSIVE)
	      vty_out (vty, " passive-interface %s%s", ifp->name, VTY_NEWLINE);
        }

      /* Network area print. */
      config_write_network_area (vty);

      /* Area config print. */
      config_write_ospf_area (vty);

      /* static neighbor print. */
      config_write_ospf_nbr_static (vty);

      /* Virtual-Link print. */
      config_write_virtual_link (vty);

      /* Distribute-list and default-information print. */
      config_write_ospf_distribute (vty);

      /* Distance configuration. */
      config_write_ospf_distance (vty);
    }

  return write;
}

struct cmd_node ospf_node =
{
  OSPF_NODE,
  "%s(config-router)# ",
  1
};

/* Install OSPF related commands. */
void
ospf_init ()
{


  /* Install ospf top node. */
  install_node (&ospf_node, ospf_config_write);

  /* Install ospf commands. */
  install_element (VIEW_NODE, &show_ip_ospf_interface_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_int_detail_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_int_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_id_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_detail_all_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_detail_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_cmd);
  install_element (VIEW_NODE, &show_ip_ospf_neighbor_all_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_interface_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_int_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_int_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_id_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_detail_all_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_neighbor_all_cmd);
#if 0
  install_element (ENABLE_NODE, &clear_ip_ospf_neighbor_cmd);
#endif
  install_element (CONFIG_NODE, &router_ospf_cmd);
  install_element (CONFIG_NODE, &no_router_ospf_cmd);

  install_default (OSPF_NODE);
  install_element (OSPF_NODE, &ospf_router_id_cmd);
  install_element (OSPF_NODE, &no_ospf_router_id_cmd);
  install_element (OSPF_NODE, &router_id_cmd);
  install_element (OSPF_NODE, &no_router_id_cmd);
  install_element (OSPF_NODE, &passive_interface_cmd);
  install_element (OSPF_NODE, &no_passive_interface_cmd);

  install_element (OSPF_NODE, &ospf_abr_type_cmd);
  install_element (OSPF_NODE, &no_ospf_abr_type_cmd);
  install_element (OSPF_NODE, &ospf_rfc1583_flag_cmd);
  install_element (OSPF_NODE, &no_ospf_rfc1583_flag_cmd);
  install_element (OSPF_NODE, &ospf_compatible_rfc1583_cmd);
  install_element (OSPF_NODE, &no_ospf_compatible_rfc1583_cmd);

  /*  install_element (OSPF_NODE, &network_area_decimal_cmd); */
  install_element (OSPF_NODE, &network_area_cmd);
  install_element (OSPF_NODE, &no_network_area_decimal_cmd);
  install_element (OSPF_NODE, &no_network_area_cmd);

  install_element (OSPF_NODE, &area_authentication_message_digest_decimal_cmd);
  install_element (OSPF_NODE, &area_authentication_message_digest_cmd);

  install_element (OSPF_NODE, &area_authentication_decimal_cmd);
  install_element (OSPF_NODE, &area_authentication_cmd);
  install_element (OSPF_NODE, &no_area_authentication_decimal_cmd);
  install_element (OSPF_NODE, &no_area_authentication_cmd);

  install_element (OSPF_NODE, &area_range_decimal_cmd);
  install_element (OSPF_NODE, &area_range_cmd);
  install_element (OSPF_NODE, &no_area_range_decimal_cmd);
  install_element (OSPF_NODE, &no_area_range_cmd);
  install_element (OSPF_NODE, &area_range_suppress_cmd);
#ifdef HAVE_NSSA
  install_element (OSPF_NODE, &area_range_suppress_decimal_cmd);
#endif /* HAVE_NSSA */
  install_element (OSPF_NODE, &no_area_range_suppress_cmd);
  install_element (OSPF_NODE, &area_range_subst_cmd);
  install_element (OSPF_NODE, &no_area_range_subst_cmd);

  install_element (OSPF_NODE, &area_vlink_auth_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_auth_cmd);
  install_element (OSPF_NODE, &area_vlink_md5_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_md5_cmd);
  install_element (OSPF_NODE, &area_vlink_param_md5_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_param_md5_cmd);
  install_element (OSPF_NODE, &area_vlink_param_auth_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_param_auth_cmd);
  install_element (OSPF_NODE, &area_vlink_param_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_param_cmd);
  install_element (OSPF_NODE, &area_vlink_decimal_cmd);
  install_element (OSPF_NODE, &area_vlink_cmd);
  install_element (OSPF_NODE, &no_area_vlink_decimal_cmd);
  install_element (OSPF_NODE, &no_area_vlink_cmd);

  install_element (OSPF_NODE, &area_stub_nosum_cmd);
  install_element (OSPF_NODE, &area_stub_nosum_decimal_cmd);
  install_element (OSPF_NODE, &area_stub_cmd);
  install_element (OSPF_NODE, &area_stub_decimal_cmd);
  install_element (OSPF_NODE, &no_area_stub_nosum_cmd);
  install_element (OSPF_NODE, &no_area_stub_nosum_decimal_cmd);
  install_element (OSPF_NODE, &no_area_stub_cmd);
  install_element (OSPF_NODE, &no_area_stub_decimal_cmd);

#ifdef HAVE_NSSA
  install_element (OSPF_NODE, &area_nssa_nosum_cmd);
  install_element (OSPF_NODE, &area_nssa_nosum_decimal_cmd);
  install_element (OSPF_NODE, &area_nssa_cmd);
  install_element (OSPF_NODE, &area_nssa_decimal_cmd);

  install_element (OSPF_NODE, &area_nssa_nosum_t_never_cmd);
  install_element (OSPF_NODE, &area_nssa_nosum_t_never_decimal_cmd);
  install_element (OSPF_NODE, &area_nssa_t_never_cmd);
  install_element (OSPF_NODE, &area_nssa_t_never_decimal_cmd);

  install_element (OSPF_NODE, &area_nssa_nosum_t_candidate_cmd);
  install_element (OSPF_NODE, &area_nssa_nosum_t_candidate_decimal_cmd);
  install_element (OSPF_NODE, &area_nssa_t_candidate_cmd);
  install_element (OSPF_NODE, &area_nssa_t_candidate_decimal_cmd);

  install_element (OSPF_NODE, &area_nssa_nosum_t_always_cmd);
  install_element (OSPF_NODE, &area_nssa_nosum_t_always_decimal_cmd);
  install_element (OSPF_NODE, &area_nssa_t_always_cmd);
  install_element (OSPF_NODE, &area_nssa_t_always_decimal_cmd);

  install_element (OSPF_NODE, &no_area_nssa_nosum_cmd);
  install_element (OSPF_NODE, &no_area_nssa_nosum_decimal_cmd);
  install_element (OSPF_NODE, &no_area_nssa_cmd);
  install_element (OSPF_NODE, &no_area_nssa_decimal_cmd);
#endif /* HAVE_NSSA */

  install_element (OSPF_NODE, &area_default_cost_cmd);
  install_element (OSPF_NODE, &area_default_cost_decimal_cmd);
  install_element (OSPF_NODE, &no_area_default_cost_cmd);
  install_element (OSPF_NODE, &no_area_default_cost_decimal_cmd);

  install_element (OSPF_NODE, &area_shortcut_decimal_cmd);
  install_element (OSPF_NODE, &area_shortcut_cmd);
  install_element (OSPF_NODE, &no_area_shortcut_decimal_cmd);
  install_element (OSPF_NODE, &no_area_shortcut_cmd);

  install_element (OSPF_NODE, &area_export_list_cmd);
  install_element (OSPF_NODE, &area_export_list_decimal_cmd);
  install_element (OSPF_NODE, &no_area_export_list_cmd);
  install_element (OSPF_NODE, &no_area_export_list_decimal_cmd);

  install_element (OSPF_NODE, &area_import_list_cmd);
  install_element (OSPF_NODE, &area_import_list_decimal_cmd);
  install_element (OSPF_NODE, &no_area_import_list_cmd);
  install_element (OSPF_NODE, &no_area_import_list_decimal_cmd);

  install_element (OSPF_NODE, &timers_spf_cmd);
  install_element (OSPF_NODE, &no_timers_spf_cmd);

  install_element (OSPF_NODE, &refresh_timer_cmd);
  install_element (OSPF_NODE, &no_refresh_timer_val_cmd);
  install_element (OSPF_NODE, &no_refresh_timer_cmd);
  
  install_element (OSPF_NODE, &auto_cost_reference_bandwidth_cmd);
  install_element (OSPF_NODE, &no_auto_cost_reference_bandwidth_cmd);

  install_element (OSPF_NODE, &neighbor_cmd);
  install_element (OSPF_NODE, &no_neighbor_cmd);

  install_element (OSPF_NODE, &neighbor_priority_cmd);
  install_element (OSPF_NODE, &no_neighbor_priority_cmd);

  install_element (OSPF_NODE, &neighbor_pollinterval_cmd);
  install_element (OSPF_NODE, &no_neighbor_pollinterval_cmd);

  install_element (OSPF_NODE, &neighbor_priority_pollinterval_cmd);
  install_element (OSPF_NODE, &no_neighbor_priority_pollinterval_cmd);

  install_element (VIEW_NODE, &show_ip_ospf_cmd);
  install_element (ENABLE_NODE, &show_ip_ospf_cmd);

  /* Make empty list of ospf list. */
  ospf_top = NULL;

  zebra_init ();
}
