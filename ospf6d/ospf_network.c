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

#include "ospfd.h"

extern int errno;
extern list iflist;
extern struct thread_master *master;

/* Address family switch. */
/* Known address families */

struct afswitch inet;
#ifdef HAVE_IPV6
struct afswitch inet6;
#endif

char *mesg_name[] = 
{
  "NONE",
  "HELLO",
  "DATABASE DESCRIPTION",
  "LINK STATE REQUEST",
  "LINK STATE UPDATE",
  "LINK STATE ACK",
  NULL
};

/* statistics global structure */
struct ospfstat ospfstat;

/* iovec functions */
int
iov_clear (struct iovec *iov, size_t iovlen)
{
  int i;
  for (i = 0; i < iovlen; i++)
    {
      iov[i].iov_base = NULL;
      iov[i].iov_len = 0;
    }
  return 0;
}

int
iov_count (struct iovec *iov)
{
  int i;

  for (i = 0; iov[i].iov_base; i++)
    ;

  return i;
}

int
iov_index (struct iovec *iov, void *base)
{
  int i;
  for (i = 0; iov[i].iov_base; i++)
    {
      if (iov[i].iov_base == base)
	return i;
    }
  log ("illegal iov_index() use!\n");
  return -1;
}

int
iov_totallen (struct iovec *iov)
{
  int i;
  int totallen = 0;

  for (i = 0; iov[i].iov_base; i++)
    {
      totallen += iov[i].iov_len;
    }
  return totallen;
}

void *
iov_prepend (int mtype, struct iovec *iov, size_t len)
{
  int i, iovlen;
  void *base;

  if (len <= 0)
    return NULL;

  base = (void *)XMALLOC (mtype, len);
  if (!base)
    {
      log ("Can't malloc buffer for iovec\n");
      return NULL;
    }
  bzero (base, len);

  iovlen = iov_count (iov);
  for (i = iovlen; i; i--)
    {
      iov[i].iov_base = iov[i - 1].iov_base;
      iov[i].iov_len = iov[i - 1].iov_len;
    }
  iov[0].iov_base = (char *)base;
  iov[0].iov_len = len;

  return base;
}

void *
iov_append (int mtype, struct iovec *iov, size_t len)
{
  int i;
  void *base;

  if (len <= 0)
    return NULL;

  base = (void *)XMALLOC (mtype, len);
  if (!base)
    {
      log ("Can't malloc buffer for iovec\n");
      return NULL;
    }
  bzero (base, len);

  /* proceed to the end */
  i = iov_count (iov);

  iov[i].iov_base = (char *)base;
  iov[i].iov_len = len;

  return base;
}

void *
iov_realloc (int mtype, struct iovec *iov, u_int index, size_t len)
{
  void *base;

  if (len <= 0)
    return NULL;
  if (index >= iov_count (iov))
    return NULL;

  base = XREALLOC (mtype, iov[index].iov_base, len);
  if (!base)
    {
      log ("Can't realloc buffer for iovec\n");
      return NULL;
    }

  iov[index].iov_base = (char *)base;
  iov[index].iov_len = len;

  return base;
}

int
iov_detach (struct iovec *iov, int index)
{
  int i;

  for (i = index; i < MAXIOVLIST; i++)
    {
      iov[i].iov_base = iov[i + 1].iov_base;
      iov[i].iov_len = iov[i + 1].iov_len;
    }
  return;
}

void *
iov_attach_last (struct iovec *iov, void *base, size_t len)
{
  int i;
  i = iov_count (iov);
  iov[i].iov_base = (char *)base;
  iov[i].iov_len = len;
  return base;
}

void *
iov_attach_first (struct iovec *iov, void *base, size_t len)
{
  int i, iovlen;

  iovlen = iov_count (iov);
  for (i = iovlen; i; i--)
    {
      iov[i].iov_base = iov[i - 1].iov_base;
      iov[i].iov_len = iov[i - 1].iov_len;
    }
  iov[0].iov_base = (char *)base;
  iov[0].iov_len = len;

  return base;
}

int
iov_free (int mtype, struct iovec *iov, u_int begin, u_int end)
{
  int i;

  for (i = begin; i < end; i++)
    {
#ifdef DEBUG_LSA_PTR
      log ("LSAPTR: Freeing (%#x) in iov_free()\n", iov[i].iov_base);
#endif
      XFREE (mtype, iov[i].iov_base);
      iov[i].iov_base = NULL;
      iov[i].iov_len = 0;
    }

  return 0;
}

/*
 * Expand the compacted form of addresses as returned via the
 * configuration read via sysctl().
 */

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

void
rt_xaddrs(cp, cplim, rtinfo)
	caddr_t cp, cplim;
	struct rt_addrinfo *rtinfo;
{
  struct sockaddr *sa;
  int i;

  memset(rtinfo->rti_info, 0, sizeof(rtinfo->rti_info));
  for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
    if ((rtinfo->rti_addrs & (1 << i)) == 0)
      continue;
    rtinfo->rti_info[i] = sa = (struct sockaddr *)cp;
    ADVANCE(cp, sa);
  }
}

int
sockunion_ospf_socket (union sockunion *su)
{
  int sock;

  if (su->sa.sa_family == 0)
    su->sa.sa_family = AF_INET_UNION;

  sock = socket (su->sa.sa_family, SOCK_RAW, IPPROTO_OSPFIGP);
  if (sock < 0)
    log_warn ("can't make socket sockunion_ospf_socket: %s\n", strerror(errno));

  return sock;
}

#define MAXSOCKADDRLEN sizeof (struct sockaddr_in6)
int
sockfd_to_family (int sockfd)
{
  union {
    struct sockaddr sa;
    char data[MAXSOCKADDRLEN];
  } un;
  int len = MAXSOCKADDRLEN;

  if (getsockname (sockfd, (struct sockaddr *)un.data, &len) < 0)
    return -1;

  return (un.sa.sa_family);
}

int
ospf_read (struct thread *thread)
{
  int sockfd;
  struct iovec iov[MAXIOVLIST];
  int i, msgend, ret, num;
  struct msghdr rmsghdr;
  struct cmsghdr *rcmsgp;
  u_char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
  struct in6_pktinfo *pktinfo;
  union {
    struct sockaddr sa;
    char data[sizeof (struct sockaddr_in6)];
  } unsa;
  struct sockaddr *src;
  struct ospf_msghdr *ospfhp;
  struct interface *iface;
  char ifnamebuf[16];
  u_short msglen;

  bzero (ifnamebuf, sizeof (ifnamebuf));
  bzero (&rmsghdr, sizeof (struct msghdr));
  src = &unsa.sa;
  num = 0;

  sockfd = THREAD_FD (thread);

  switch (sockfd_to_family (sockfd))
    {
    case AF_INET6:
      rcmsgp = (struct cmsghdr *)&cmsgbuf;
      rcmsgp->cmsg_level = IPPROTO_IPV6;
      rcmsgp->cmsg_type = IPV6_PKTINFO;
      rcmsgp->cmsg_len = CMSG_LEN(sizeof (struct in6_pktinfo));
      pktinfo = (struct in6_pktinfo *)(CMSG_DATA(rcmsgp));
      break;
    case AF_INET:
      break;
    default:
      break;
    }

  iov_clear (iov, MAXIOVLIST);
  iov_append (MTYPE_OSPF_MESSAGE, iov, OSPFV3HDRLEN);
  msgend = 1;

  rmsghdr.msg_name = (caddr_t)src;
  rmsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  rmsghdr.msg_iov = iov;
  rmsghdr.msg_iovlen = iov_count (iov);
  rmsghdr.msg_control = (caddr_t)rcmsgp;
  rmsghdr.msg_controllen = sizeof (cmsgbuf);

  num = recvmsg (sockfd, &rmsghdr, MSG_PEEK);
  if (num < 0)
    {
      log ("recvmsg() failed in ospf_read(): %s\n", strerror (errno));
      recvmsg (sockfd, &rmsghdr, 0);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
      return -1;
    }

  switch (sockfd_to_family (sockfd))
    {
    case AF_INET6:
      if (pktinfo->ipi6_ifindex > 0)
	if_indextoname (pktinfo->ipi6_ifindex, ifnamebuf);
      else 
	{
	  log ("Received Interface not found in ospf_read()\n");
	  num = recvmsg (sockfd, &rmsghdr, 0);
	  thread_add_read (master, ospf_read, NULL, sockfd);
	  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
	  return -1;
	}
      iface = if_lookup_by_ifname (ifnamebuf, iflist);
      break;
    case AF_INET:
      iface = if_lookup_by_addr_in_net (src, iflist);
      break;
    default:
      break;
    }

  if (!iface)
    {
      log ("BUG! Received Interface Structure not found\n");
      num = recvmsg (sockfd, &rmsghdr, 0);
      thread_add_read (master, ospf_read, NULL, sockfd);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
      return -1;
    }
  if (!iface->area)
    {
      log_warn ("Interface %s not atached to AREA\n", iface->ifname);
      thread_add_read (master, ospf_read, NULL, sockfd);
      num = recvmsg (sockfd, &rmsghdr, 0);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
      return -1;
    }

  ospfhp = (struct ospf_msghdr *)iov[0].iov_base;
  msglen = ntohs (ospfhp->len);
  switch (ospfhp->version)
    {
    case OSPF_V2:
      ospfhp = (struct ospf_msghdr *)iov_realloc (MTYPE_OSPF_MESSAGE,
						  iov, 0, OSPFV2HDRLEN);
      if (!ospfhp)
	{
	  log ("iov_realloc() failed in ospf_read()\n");
	  goto rvmsg_bad;
	}
      switch (ospfhp->type)
	{
	case MSGT_HELLO:
	  if (!iov_append (MTYPE_OSPF_MESSAGE, iov, msglen - OSPFV2HDRLEN))
	    {
	      log ("iov_append() failed in ospf_read()\n");
	      goto rvmsg_bad;
	    }
	  msgend++;
	  goto rvmsg_ok;

	case MSGT_DATABASE_DESCRIPTION:
	case MSGT_LINKSTATE_REQUEST:
	case MSGT_LINKSTATE_UPDATE:
	case MSGT_LINKSTATE_ACK:
	  goto rvmsg_nosupport;
	default:
	  goto rvmsg_bad;
	}
    case OSPF_V3:
      ospfhp = (struct ospf_msghdr *)iov_realloc (MTYPE_OSPF_MESSAGE,
						  iov, 0, OSPFV3HDRLEN);
      if (!ospfhp)
	{
	  log ("iov_realloc() failed in ospf_read()\n");
	  goto rvmsg_bad;
	}
      switch (ospfhp->type)
	{
	case MSGT_HELLO:
	  if (!iov_append (MTYPE_OSPF_MESSAGE, iov, msglen - OSPFV3HDRLEN))
	    {
	      log ("iov_append() failed in ospf_read()\n");
	      goto rvmsg_bad;
	    }
	  msgend++;
	  goto rvmsg_ok;

	case MSGT_DATABASE_DESCRIPTION:
	  if (!iov_append (MTYPE_OSPF_MESSAGE, iov, OSPFV3DDLEN))
	    {
	      log ("iov_append() failed in ospf_read()\n");
	      goto rvmsg_bad;
	    }
	  msgend++;
	  for (i = 0;
	       i < (msglen - OSPFV3HDRLEN - OSPFV3DDLEN) / sizeof (struct lsa_hdr);
	       i++)
	    {
	      iov_append (MTYPE_OSPF_LSA, iov, sizeof (struct lsa_hdr ));
	    }
	  goto rvmsg_ok;

	case MSGT_LINKSTATE_REQUEST:
	  for (i = 0; i < ((ntohs(ospfhp->len) - OSPFV3HDRLEN)
		 / sizeof (struct linkstate_request));
	       i++)
	    {
	      if (!iov_append (MTYPE_OSPF_MESSAGE, iov,
			       sizeof (struct linkstate_request)))
		{
		  log ("iov_append() failed in ospf_read()\n");
		  goto rvmsg_bad;
		}
	      msgend ++;
	    }
	  goto rvmsg_ok;

	case MSGT_LINKSTATE_UPDATE:
	  if (!iov_append (MTYPE_OSPF_MESSAGE, iov, sizeof (struct linkstate_update)))
	    {
	      log ("iov_append() failed in ospf_read()\n");
	      goto rvmsg_bad;
	    }
	  msgend++;
	  if (!iov_append (MTYPE_OSPF_MESSAGE, iov,
			   msglen - OSPFV3HDRLEN - sizeof (struct linkstate_update)))
	    {
	      /* this is for 0 malloc(). */
	      msgend--;   /* decrement to delete reflection of later increment */
	    }
	  msgend++;       /* this is the "later increment" */
	  goto rvmsg_ok;

	case MSGT_LINKSTATE_ACK:
	  for (i = 0; i < ((ntohs(ospfhp->len) - OSPFV3HDRLEN)
			   / sizeof (struct lsa_hdr));
	       i++)
	    {
	      if (!iov_append (MTYPE_OSPF_MESSAGE, iov,
			       sizeof (struct lsa_hdr)))
		{
		  log ("iov_append() failed in ospf_read()\n");
		  goto rvmsg_bad;
		}
	    }
	  goto rvmsg_ok;

	default:
	  goto rvmsg_bad;
	}
    default:
      goto rvmsg_nosupport;
    }

  rvmsg_nosupport:

  log ("not supported\n"); /* fall through */

  rvmsg_bad:

  log ("OSPFv%d %s: Can't recv\n", iface->area->ospf->version, mesg_name[ospfhp->type]);
  num = recvmsg (sockfd, &rmsghdr, 0);
  thread_add_read (master, ospf_read, NULL, sockfd);
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
  return -1;

  rvmsg_ok:

  rmsghdr.msg_iovlen = iov_count (iov);
  num = recvmsg (sockfd, &rmsghdr, 0);
  if (num < 0)
    {
      log ("recvmsg() failed: %s\n", strerror (errno));
      thread_add_read (master, ospf_read, NULL, sockfd);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
      return -1;
    }

  if (iface->state < IFS_WAITING)
    {
#ifdef DEBUG_OSPF
      log ("Interface %s Not UP\n");
#endif
      thread_add_read (master, ospf_read, NULL, sockfd);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
      return -1;
    }

#ifdef DEBUG_OSPF
  {
    char *srcname, ntopbuf[32], ifnamebuf[16];
    switch (src->sa_family)
      {
      case AF_INET:
	srcname = (char *)&((struct sockaddr_in *)src)->sin_addr;
	break;
      case AF_INET6:
	srcname = (char *)&((struct sockaddr_in6 *)src)->sin6_addr;
	break;
      default:
	log ("BUG!!! in ospf_read()\n");
	iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
	thread_add_read (master, ospf_read, NULL, sockfd);
	return ;
      }
    log ("Recv %s from %s on %s\n",
	 mesg_name[((struct ospf_msghdr *)iov[0].iov_base)->type],
	 inet_ntop (src->sa_family, srcname, ntopbuf, sizeof (ntopbuf)),
	 iface->ifname);
  }
#endif

  if ((ret = proc_ospf(iov, iface)) < 0)
    goto prmsg_bad;

  switch (ospfhp->version)
    {
    case OSPF_V2:
      ospfstat.ospfs_recvver2++;
      switch (ospfhp->type)
	{
	case MSGT_HELLO:
	  if ((ret = proc_hello2 (src, iov, iface)) < 0)
	    goto prmsg_bad;
	  goto prmsg_ok;

	case MSGT_DATABASE_DESCRIPTION:
	case MSGT_LINKSTATE_REQUEST:
	case MSGT_LINKSTATE_UPDATE:
	case MSGT_LINKSTATE_ACK:
	  goto prmsg_nosupport;
	default:
	  goto prmsg_bad;
	}
    case OSPF_V3:
      ospfstat.ospfs_recvver3++;
      switch (ospfhp->type)
	{
	case MSGT_HELLO:
	  if ((ret = proc_hello3 (src, iov, iface)) < 0)
	    goto prmsg_bad;
	  goto prmsg_ok;

	case MSGT_DATABASE_DESCRIPTION:
	  if ((ret = proc_database_description (src, iov, iface)) < 0)
	    goto prmsg_bad;

	  goto prmsg_ok;

	case MSGT_LINKSTATE_REQUEST:
	  if ((ret = proc_linkstate_request (src, iov, iface)) < 0)
	    goto prmsg_bad;

	  goto prmsg_ok;

	case MSGT_LINKSTATE_UPDATE:
	  if ((ret = proc_linkstate_update (src, iov, iface)) < 0)
	    goto prmsg_bad;
	  goto prmsg_ok;

	case MSGT_LINKSTATE_ACK:
	  if ((ret = proc_linkstate_ack (src, iov, iface)) < 0)
	    goto prmsg_bad;
	  goto prmsg_ok;

	default:
	  goto prmsg_bad;
	}
    default:
      ospfstat.ospfs_verunknown++;
      goto prmsg_bad;
    }

 prmsg_nosupport:

  log ("not support\n"); /* Fall through */

 prmsg_bad:
  
  log ("OSPFv%d %s: Can't proc\n",
       iface->area->ospf->version, mesg_name[ospfhp->type]);
  thread_add_read (master, ospf_read, NULL, sockfd);
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, iov_count (iov));
  return -1;

 prmsg_ok:

  /*
  if (num != off)
    log (" Can't proc all packet %d/%d\n", off, num);
  */

  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
  thread_add_read (master, ospf_read, NULL, sockfd);
  return 0;
}

/* Make ospfd's server socket. */
int
ospf_serv_sock ()
{
  union sockunion su;

  bzero (&su, sizeof (union sockunion));

  su.sa.sa_family = inet.af_af = AF_INET;
  inet.af_name = "inet";
  inet.salen = sizeof (struct sockaddr_in);
  inet.ospf_sock = sockunion_ospf_socket (&su);
  if (inet.ospf_sock > 0)
    {
      sockopt_reuseaddr (inet.ospf_sock);
      thread_add_read (master, ospf_read, NULL, inet.ospf_sock);
    }
  else
    {
      log_warn ("Can't Create OSPF Inet Socket.\n");
    }

#ifdef HAVE_IPV6
  su.sa.sa_family = inet6.af_af = AF_INET6;
  inet6.af_name = "inet6";
  inet.salen = sizeof (struct sockaddr_in6);
  inet6.ospf_sock = sockunion_ospf_socket (&su);
  if (inet6.ospf_sock > 0)
    {
      sockopt_reuseaddr (inet6.ospf_sock);
      thread_add_read (master, ospf_read, NULL, inet6.ospf_sock);
    }
  else
    {
      log_warn ("Can't Create OSPF Inet6 Socket.\n");
    }
#endif

  return;
}

int
mcast_prepare ()
{
  int i;

  inet.salen = sizeof (struct sockaddr_in);

  inet.allspf = (struct sockaddr *)
    XMALLOC (MTYPE_OSPF_ADDR, inet.salen);
  if (!inet.allspf)
    {
      log_warn ("Can't asign buf for mcast address.\n");
      terminate(-1);
    }

  inet_pton (AF_INET, ALLSPFROUTERS,
	     &((struct sockaddr_in *)inet.allspf)->sin_addr);
  inet.allspf->sa_family = AF_INET;
  inet.allspf->sa_len = inet.salen;

  inet.alldr = (struct sockaddr *)
    XMALLOC (MTYPE_OSPF_ADDR, inet.salen);
  if (!inet.alldr)
    {
      log_warn ("Can't asign buf for mcast address.\n");
      terminate(-1);
    }

  inet_pton (AF_INET, ALLDROUTERS,
	     &((struct sockaddr_in *)inet.alldr)->sin_addr);
  inet.alldr->sa_family = AF_INET;
  inet.allspf->sa_len = inet.salen;
  
#ifdef HAVE_IPV6
  inet6.salen = sizeof (struct sockaddr_in6);

  inet6.allspf = (struct sockaddr *)
    XMALLOC (MTYPE_OSPF_ADDR, inet6.salen);
  inet_pton (AF_INET6, ALLSPFROUTERS6,
	     &((struct sockaddr_in6 *)inet6.allspf)->sin6_addr);
  inet6.allspf->sa_family = AF_INET6;
  inet6.allspf->sa_len = inet6.salen;

  inet6.alldr = (struct sockaddr *)
    XMALLOC (MTYPE_OSPF_ADDR, inet6.salen);
  inet_pton (AF_INET6, ALLDROUTERS6,
	     &((struct sockaddr_in6 *)inet6.alldr)->sin6_addr);
  inet6.alldr->sa_family = AF_INET6;
  inet6.alldr->sa_len = inet6.salen;
#endif

  return;
}

int
mcast_join (int sockfd, struct sockaddr *sa, size_t salen,
            char *ifname, u_int ifindex)
{

  switch (sa->sa_family)
    {
      case AF_INET:
        {
          struct ip_mreq mreq;
          struct ifreq ifreq;

          memcpy (&mreq.imr_multiaddr,
                  &((struct sockaddr_in *) sa)->sin_addr,
                  sizeof (struct in_addr));

#ifdef HAVE_IPV6
          if (ifindex > 0)
            {
              if (if_indextoname (ifindex, ifreq.ifr_name) == NULL)
                {
                  errno = ENXIO; /* i/f index not found */
                  return -1;
                }
              goto doioctl;
            }
          else
#endif
          if (ifname != NULL)
            {
              strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
doioctl:
              if (ioctl (sockfd, SIOCGIFADDR, &ifreq) < 0)
		{
		  log_warn ("Can't Get Address for %s, Can't Join Multicast Group\n",
			    ifname);
		  return -1;
		}
              memcpy (&mreq.imr_interface,
                      &((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr,
                      sizeof (struct in_addr));
            }
          else
            mreq.imr_interface.s_addr = htonl (INADDR_ANY);

          return (setsockopt (sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                              &mreq, sizeof (mreq)));
        }

#ifdef HAVE_IPV6
      case AF_INET6:
        {
          struct ipv6_mreq mreq6;

          memcpy (&mreq6.ipv6mr_multiaddr,
                  &((struct sockaddr_in6 *) sa)->sin6_addr,
                  sizeof (struct in6_addr));

          if (ifindex > 0)
            mreq6.ipv6mr_interface = ifindex;
          else if (ifname != NULL)
	    {
	      if ((mreq6.ipv6mr_interface = if_nametoindex (ifname)) == 0)
		{
		  errno = ENXIO;  /* i/f name not found */
		  return -1;
		}
	    }
	  else
	    mreq6.ipv6mr_interface = 0;
          return (setsockopt (sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                              &mreq6, sizeof (mreq6)));
        }
#endif

      default:
        errno = EPROTONOSUPPORT;
        return -1;
  }
}

int
mcast_leave (int sockfd, struct sockaddr *sa, size_t salen,
	     char *ifname, u_int ifindex)
{

  switch (sa->sa_family)
    {
      case AF_INET:
        {
          struct ip_mreq mreq;
          struct ifreq ifreq;

          memcpy (&mreq.imr_multiaddr,
                  &((struct sockaddr_in *) sa)->sin_addr,
                  sizeof (struct in_addr));

#ifdef HAVE_IPV6
          if (ifindex > 0)
            {
              if (if_indextoname (ifindex, ifreq.ifr_name) == NULL)
                {
                  errno = ENXIO; /* i/f index not found */
                  return -1;
                }
              goto doioctl;
            }
          else
#endif
          if (ifname != NULL)
            {
              strncpy (ifreq.ifr_name, ifname, IFNAMSIZ);
doioctl:
              if (ioctl (sockfd, SIOCGIFADDR, &ifreq) < 0)
		{
		  log_warn ("Can't Get Address for %s, Can't Join Multicast Group\n",
			    ifname);
		  return -1;
		}
              memcpy (&mreq.imr_interface,
                      &((struct sockaddr_in *) &ifreq.ifr_addr)->sin_addr,
                      sizeof (struct in_addr));
            }
          else
            mreq.imr_interface.s_addr = htonl (INADDR_ANY);

          return (setsockopt (sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                              &mreq, sizeof (mreq)));
        }

#ifdef HAVE_IPV6
      case AF_INET6:
        {
          struct ipv6_mreq mreq6;

          memcpy (&mreq6.ipv6mr_multiaddr,
                  &((struct sockaddr_in6 *) sa)->sin6_addr,
                  sizeof (struct in6_addr));

          if (ifindex > 0)
            mreq6.ipv6mr_interface = ifindex;
          else if (ifname != NULL)
	    {
	      if ((mreq6.ipv6mr_interface = if_nametoindex (ifname)) == 0)
		{
		  errno = ENXIO;  /* i/f name not found */
		  return -1;
		}
	    }
	  else
	    mreq6.ipv6mr_interface = 0;
          return (setsockopt (sockfd, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                              &mreq6, sizeof (mreq6)));
        }
#endif

      default:
        errno = EPROTONOSUPPORT;
        return -1;
  }
}

proc_done (void *pkt)
{
  XFREE (MTYPE_OSPF_MESSAGE, pkt);
}

drop (void *pkt)
{
  /* log_warn ("Drop Packet.\n"); */
  ospfstat.ospfs_drop++;
  proc_done (pkt);
}

int
proc_ip4 (char *pkt, struct ip *iphp, struct interface **iface)
{
  u_short retoff = 0;

  struct sockaddr sa;

/* IP checksum and Protocol field should have been checked 
   by kernel. All we have to do is check source and
   destination and proceed pointer on message buffer. */

  ((struct sockaddr_in *)&sa)->sin_family = AF_INET;
  ((struct sockaddr_in *)&sa)->sin_addr.s_addr = iphp->ip_src.s_addr;
  if (if_lookup_by_addr(&sa, iflist))
    {
      ospfstat.ospfs_pktloopback++;
      /*
      log ("This is that I send, so drop.\n");
      return -1;
      */
    }

  /* get received interface */
  if ((*iface = (struct interface *)
       if_lookup_by_addr_in_net (&sa, iflist)) == NULL)
    {
      ospfstat.ospfs_norecvif++;
      log ("From virtual link?\n");
    }

  retoff += iphp->ip_hl * 4;

  return retoff;
}

int
proc_ip6 (char *pkt, struct ip6_hdr *ip6hp, struct interface **iface)
{
}

int
proc_ip (int af, char *pkt, struct ip *iphp, struct interface *iface)
{
  int retval = 0;

  switch (af)
    {
      case AF_INET:
        ospfstat.ospfs_recvinet++;
        retval = iphp->ip_hl * 4;
	if (retval < 0)
	  return -1;
        break;
      case AF_INET6:
        ospfstat.ospfs_recvinet6++;
      default:
        retval = 0;
        break;
    }

  return retval;
}

int
proc_pkt (int af, char *pkt, struct sockaddr *from)
{
  u_short retoff = 0;
  struct interface *iface = NULL; /* received interface */
  struct ip *iphp;
  struct ospf_msghdr *ospfhp;
  int retval;
  struct sockaddr_in6 *from6;
  char ifname[16];

  /* stats */
  ospfstat.ospfs_total++;

  /* get received interface */
  switch (from->sa_family)
    {
    case AF_INET6:
      from6 = (struct sockaddr_in6 *)from;
      if (from6->sin6_scope_id && if_indextoname (from6->sin6_scope_id, ifname) != NULL)
	iface = if_lookup_by_ifname (ifname, iflist);
      break;
    case AF_INET:
      break;
    default:
      log ("Unknown Family in proc_pkt\n");
      return -1;
    }
  if (!iface)
    {
      iface = if_lookup_by_addr_in_net (from, iflist);
      if (!iface)
	{
	  log_warn ("Recv Interface not found.\n");
	  return -1;
	}
    }

  iphp = (struct ip *)pkt;
  retval = proc_ip (af, pkt, iphp, iface);
  if (retval < 0)
    return -1;
  retoff += retval;

  if (iface->state < IFS_WAITING)
    {
#ifdef DEBUG_OSPF
      log ("IF %s Down\n", iface->ifname);
#endif
      return -1;
    }

  ospfhp = (struct ospf_msghdr *)((char *)iphp + retoff);
  retval = proc_ospf (pkt, iphp, ospfhp, iface);
  if (retval < 0)
    return -1;
  retoff += retval;

  return retoff;
}

int
ospf_send (u_int8_t msgtype, struct iovec *iov,
	   struct sockaddr *dst, struct interface *iface)
{
  int num;
  struct msghdr smsghdr;
  struct cmsghdr *scmsgp;
  struct in6_pktinfo *pktinfo;
  u_char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];

  scmsgp = (struct cmsghdr *)cmsgbuf;

  if (make_ospfhdr (msgtype, iov, iface) < 0)
    {
      log ("Can't make ospfhdr\n");
    }

  smsghdr.msg_iov = iov;
  smsghdr.msg_iovlen = iov_count (iov);

  smsghdr.msg_name = (caddr_t)dst;
  smsghdr.msg_namelen = dst->sa_len;

  switch (iface->area->ospf->version)
    {
    case OSPF_V2:
      smsghdr.msg_control = (caddr_t)NULL;
      smsghdr.msg_controllen = 0;
      num = sendmsg (inet.ospf_sock, &smsghdr, 0);
      break;

    case OSPF_V3:

      smsghdr.msg_control = (caddr_t)cmsgbuf;
      smsghdr.msg_controllen = sizeof (cmsgbuf);

      /* set outgoing interface using ancillary data */
      scmsgp->cmsg_level = IPPROTO_IPV6;
      scmsgp->cmsg_type = IPV6_PKTINFO;
      scmsgp->cmsg_len = CMSG_LEN(sizeof (struct in6_pktinfo));
      pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
      pktinfo->ipi6_ifindex = if_nametoindex (iface->ifname);
      bzero (&pktinfo->ipi6_addr, sizeof (struct in6_addr));
      scmsgp = CMSG_NXTHDR(&smsghdr, scmsgp);

      num = sendmsg (inet6.ospf_sock, &smsghdr, 0);
      break;

    default:
      return -1;
    }

#ifdef DEBUG_OSPF
    {
      char *dstname, ntopbuf[32], ifnamebuf[16];
      switch (dst->sa_family)
	{
	case AF_INET:
	  dstname = (char *)&((struct sockaddr_in *)dst)->sin_addr;
	  break;
	case AF_INET6:
	  dstname = (char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
	  break;
	default:
	  assert (0);
	  return ;
	}
      log ("Send %s to %s on %s\n",
	   mesg_name[((struct ospf_msghdr *)iov[0].iov_base)->type],
	   inet_ntop (dst->sa_family, dstname, ntopbuf, sizeof (ntopbuf)),
	   if_indextoname (pktinfo->ipi6_ifindex, ifnamebuf));
    }
#endif

  if (num != iov_totallen (iov))
    {
      log_warn ("Can't send whole packet %d/%d: %s\n",
		num, iov_totallen (iov),
		strerror(errno));
    }

  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
  iov_detach (iov, 0);

  return 0;
}

int
send_hello (struct thread *thread)
{
  struct interface *iface;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;

  iface = THREAD_ARG (thread);
  assert (iface);
  iov_clear (iov, MAXIOVLIST);

  make_hello3 (iov, &dst, iface);
  ospf_send (MSGT_HELLO, iov, (struct sockaddr *)&dst, iface);

  iface->send_hello = thread_add_timer
    (master, send_hello, iface, iface->hello_interval);

  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);

  return;
}

int
send_database_description (struct thread *thread)
{
  struct neighbor *nbp;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];

  nbp = THREAD_ARG (thread);
  assert (nbp);
  nbp->send_dd = NULL;

  iov_clear (iov, MAXIOVLIST);

  switch (nbp->state)
    {
    case NBS_DOWN:
    case NBS_ATTEMPT:
    case NBS_INIT:
    case NBS_TWOWAY:
      break;
    case NBS_EXSTART:
    case NBS_EXCHANGE:
    case NBS_LOADING:
    case NBS_FULL:

      /* Master need to set timer for retransmit Database Description packet */
      if (DD_IS_MSBIT_SET (nbp->dd_bits))
	{
	  /* Master */
	  nbp->send_dd = thread_add_timer (master, send_database_description,
					   nbp, nbp->interface->rxmt_interval);
	}

      make_database_description (iov, &dst, nbp);
      ospf_send (MSGT_DATABASE_DESCRIPTION, iov, (struct sockaddr *)&dst, nbp->interface);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
      iov_clear (iov, MAXIOVLIST);
      break;
    default:
      break;
    }

  return;
}

int
send_linkstate_request (struct thread *thread)
{
  struct neighbor *nbp;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;

  nbp = THREAD_ARG (thread);
  assert (nbp);
  nbp->send_lsreq = (struct thread *)NULL;

  switch (nbp->state)
    {
    case NBS_DOWN:
    case NBS_ATTEMPT:
    case NBS_INIT:
    case NBS_TWOWAY:
    case NBS_EXSTART:
      break;
    case NBS_EXCHANGE:
    case NBS_LOADING:
    case NBS_FULL:

      if (listcount (nbp->requestlist) == 0)
	{
	  thread_add_event (master, loading_done, nbp, 0);
	  return 0;
	}

      if (make_linkstate_request (iov, &dst, nbp) < 0)
	return 0;

      ospf_send (MSGT_LINKSTATE_REQUEST, iov, (struct sockaddr *)&dst, nbp->interface);
      iov_clear (iov, MAXIOVLIST);
      
      nbp->send_lsreq = thread_add_timer (master, send_linkstate_request,
					  nbp, nbp->interface->rxmt_interval);
      break;
    default:
      break;
    }

  return;
}

int
send_linkstate_update (struct thread *thread)
{
  struct neighbor *nbp;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];

  nbp = THREAD_ARG (thread);
  assert (nbp);

  nbp->send_update = (struct thread *)NULL;

  iov_clear (iov, MAXIOVLIST);

  if (nbp->interface->state <= IFS_WAITING)
    return;

  if (make_linkstate_update (iov, &dst, nbp) < 0)
    return -1;

#ifdef DEBUG_LINKSTATE_UPDATE
  log ("Retransmitting LSAs\n");
#endif

  ospf_send (MSGT_LINKSTATE_UPDATE, iov, (struct sockaddr *)&dst, nbp->interface);
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
  iov_clear (iov, MAXIOVLIST);

  nbp->send_update = thread_add_timer (master, send_linkstate_update, nbp,
				       nbp->interface->rxmt_interval);
  return;
}

int
send_linkstate_ack (struct thread *thread)
{
  struct interface *iface;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];
  struct lsa_internal **p;

  iface = THREAD_ARG (thread);
  assert (iface);

  iface->send_ack = (struct thread *)NULL;

  if (iface->state <= IFS_WAITING)
    return;

  iov_clear (iov, MAXIOVLIST);

  for (p = iface->delayed_ack; *p; p++)
    {
      attach_lsa_hdr_to_iov (*p, iov);
#ifdef DEBUG_OSPF
      log ("[%s] to DELAYED ACK\n", print_lsahdr ((*p)->lsh));
#endif
    }

  dst.sin6_len = sizeof (struct sockaddr_in6);
  dst.sin6_family = AF_INET6;
  dst.sin6_scope_id = if_nametoindex (iface->ifname);
  switch (iface->state)
    {
    case IFS_DR:
    case IFS_BDR:
      inet_pton (AF_INET6, ALLSPFROUTERS6, &dst.sin6_addr);
      break;
    default:
      inet_pton (AF_INET6, ALLDROUTERS6, &dst.sin6_addr);
      break;
    }

  ospf_send (MSGT_LINKSTATE_ACK, iov, (struct sockaddr *)&dst, iface);
  iov_clear (iov, MAXIOVLIST);
  bzero (iface->delayed_ack, sizeof (iface->delayed_ack));

  return;
}
