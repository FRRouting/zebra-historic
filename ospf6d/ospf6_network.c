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

#include "ospf6d.h"

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
  ospf6_warn ("illegal iov_index() use!\n");
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
      ospf6_warn ("Can't malloc buffer for iovec\n");
      return NULL;
    }
  memset (base, 0, len);

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
      ospf6_warn ("Can't malloc buffer for iovec\n");
      return NULL;
    }
  memset (base, 0, len);

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
      ospf6_warn ("Can't realloc buffer for iovec\n");
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
  return 0;
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
      ospf6_debug ("LSAPTR: Freeing (%#x) in iov_free()\n", iov[i].iov_base);
#endif
      XFREE (mtype, iov[i].iov_base);
      iov[i].iov_base = NULL;
      iov[i].iov_len = 0;
    }

  return 0;
}

int
sockunion_ospf_socket (union sockunion *su)
{
  int sock;

  if (su->sa.sa_family == 0)
    su->sa.sa_family = AF_INET_UNION;

  sock = socket (su->sa.sa_family, SOCK_RAW, IPPROTO_OSPFIGP);
  if (sock < 0)
    ospf6_warn ("can't make socket for ospf6: %s\n", strerror(errno));

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
ospf6_recv (struct thread *thread)
{
  struct iovec iov[MAXIOVLIST];
  int sockfd, i, j, msgend, num;
  struct msghdr rmsghdr;
  struct cmsghdr *rcmsgp = NULL;
  u_char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
  struct in6_pktinfo *pktinfo = NULL;
  union {
    struct sockaddr sa;
    char data[sizeof (struct sockaddr_in6)];
  } unsa;
  struct sockaddr_in6 *src;
  struct ospf6_hdr *ospf6_hdr;
  struct ospf6_if *ospf6_if = NULL;
  char ifnamebuf[16];
  unsigned short msglen;

  memset (ifnamebuf, 0, sizeof (ifnamebuf));
  memset (&rmsghdr, 0, sizeof (struct msghdr));
  src = (struct sockaddr_in6 *)&unsa.sa;
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
    default:
      break;
    }

  iov_clear (iov, MAXIOVLIST);
  iov_append (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_hdr));
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
      ospf6_warn ("recvmsg() failed in ospf6_recv(): %s\n", strerror (errno));
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
          ospf6_warn ("Received Interface not found in ospf6_recv()\n");
          num = recvmsg (sockfd, &rmsghdr, 0);
          thread_add_read (master, ospf6_recv, NULL, sockfd);
          iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
          return -1;
        }
      ospf6_if = ospf6_if_lookup (ifnamebuf);
      break;
    default:
      break;
    }

  if (!ospf6_if)
    {
      ospf6_err ("BUG! Received Interface Structure not found\n");
      num = recvmsg (sockfd, &rmsghdr, 0);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
      return -1;
    }
  if (!ospf6_if->area)
    {
      ospf6_warn ("Interface %s not atached to AREA\n",
                   ospf6_if->interface->name);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      num = recvmsg (sockfd, &rmsghdr, 0);
      iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
      return -1;
    }

  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;
  msglen = ntohs (ospf6_hdr->len);
  switch (ospf6_hdr->type)
    {
    case MSGT_HELLO:
      if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
                       msglen - sizeof (struct ospf6_hdr)))
        {
          ospf6_err ("iov_append() failed in ospf6_recv()\n");
          goto rvmsg_bad;
        }
      msgend++;
      goto rvmsg_ok;

    case MSGT_DATABASE_DESCRIPTION:
      if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
                       sizeof (struct database_description)))
        {
          ospf6_err ("iov_append() failed in ospf6_recv()\n");
          goto rvmsg_bad;
        }
      msgend++;
      j = (msglen - sizeof (struct ospf6_hdr)
           - sizeof (struct database_description))
          / sizeof (struct lsa_hdr);
      for (i = 0; i < j; i++)
        {
          if (!iov_append (MTYPE_OSPF6_LSA, iov, sizeof (struct lsa_hdr )))
            {
              ospf6_err ("iov_append() failed in ospf6_recv()\n");
              goto rvmsg_bad;
            }
        }
      goto rvmsg_ok;

    case MSGT_LINKSTATE_REQUEST:
      j = (msglen - sizeof (struct ospf6_hdr))
          / sizeof (struct linkstate_request);
      for (i = 0; i < j; i++)
        {
          if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
               sizeof (struct linkstate_request)))
            {
               ospf6_err ("iov_append() failed in ospf6_recv()\n");
               goto rvmsg_bad;
            }
          msgend++;
        }
      goto rvmsg_ok;

    case MSGT_LINKSTATE_UPDATE:
      if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
           sizeof (struct linkstate_update)))
        {
          ospf6_err ("iov_append() failed in ospf6_recv()\n");
          goto rvmsg_bad;
        }
      msgend++;
      j = msglen - sizeof (struct ospf6_hdr)
          - sizeof (struct linkstate_update);
      if (!j)
        {
          ospf6_warn ("received lsupdate contains no data.\n");
        }
      else if (!iov_append (MTYPE_OSPF6_LSA, iov, j))
        {
          ospf6_err ("iov_append() failed in ospf6_recv()\n");
          goto rvmsg_bad;
        }
      goto rvmsg_ok;

    case MSGT_LINKSTATE_ACK:
      j = (msglen - sizeof (struct ospf6_hdr)) / sizeof (struct lsa_hdr);
      for (i = 0; i < j; i++)
        {
          if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
               sizeof (struct lsa_hdr)))
            {
              log ("iov_append() failed in ospf6_recv()\n");
              goto rvmsg_bad;
            }
        }
      goto rvmsg_ok;

    default:
      goto rvmsg_nosupport;
    }

rvmsg_nosupport:
  ospf6_warn ("not supported "); /* fall through */
rvmsg_bad:
  ospf6_warn ("OSPFv%d %s: Can't recv\n", ospf6_hdr->version,
              mesg_name[ospf6_hdr->type]);

  num = recvmsg (sockfd, &rmsghdr, 0);
  thread_add_read (master, ospf6_recv, NULL, sockfd);
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
  return -1;

rvmsg_ok:
  rmsghdr.msg_iovlen = iov_count (iov);
  num = recvmsg (sockfd, &rmsghdr, 0);
  if (num < 0)
    {
      ospf6_warn ("recvmsg() failed: %s\n", strerror (errno));
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
      return -1;
    }

  if (ospf6_if->state < IFS_WAITING)
    {
      ospf6_debug ("Interface %s Not UP\n");
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
      return -1;
    }

#ifdef DEBUG_OSPF6
  {
    char *srcname, ntopbuf[32];
    srcname = (char *)&src->sin6_addr;
    ospf6_debug ("Recv %s from %s on %s\n",
                  mesg_name[ospf6_hdr->type],
                  inet_ntop (src->sin6_family, srcname,
                             ntopbuf, sizeof (ntopbuf)),
                  ospf6_if->interface->name);
  }
#endif

  if (proc_ospf6_hdr(iov, ospf6_if) < 0)
    goto prmsg_bad;

  switch (ospf6_hdr->type)
    {
    case MSGT_HELLO:
      if (proc_hello (src, iov, ospf6_if) < 0)
        goto prmsg_bad;
      goto prmsg_ok;

    case MSGT_DATABASE_DESCRIPTION:
      if (proc_database_description (src, iov, ospf6_if) < 0)
        goto prmsg_bad;
      goto prmsg_ok;

    case MSGT_LINKSTATE_REQUEST:
      if (proc_linkstate_request (src, iov, ospf6_if) < 0)
        goto prmsg_bad;
      goto prmsg_ok;

    case MSGT_LINKSTATE_UPDATE:
      if (proc_linkstate_update (src, iov, ospf6_if) < 0)
        goto prmsg_bad;
      goto prmsg_ok;

    case MSGT_LINKSTATE_ACK:
      if (proc_linkstate_ack (src, iov, ospf6_if) < 0)
        goto prmsg_bad;
      goto prmsg_ok;

    default:
      goto prmsg_nosupport;
    }

prmsg_nosupport:
  ospf6_warn ("not support\n"); /* Fall through */
prmsg_bad:
  ospf6_warn ("OSPFv%d %s: Can't proc\n",
               ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
  thread_add_read (master, ospf6_recv, NULL, sockfd);
  iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, msgend);
  return -1;

prmsg_ok:
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, msgend);
  thread_add_read (master, ospf6_recv, NULL, sockfd);
  return 0;
}

/* Make ospf6d's server socket. */
int
ospf6_serv_sock ()
{
  union sockunion su;
  int socket;

  memset (&su, 0, sizeof (union sockunion));

  su.sa.sa_family = AF_INET6;
  socket = sockunion_ospf_socket (&su);
  if (socket > 0)
    {
      sockopt_reuseaddr (socket);
      thread_add_read (master, ospf6_recv, NULL, socket);
    }
  else
    {
      ospf6_warn ("Can't Create OSPF6 Socket.\n");
    }

  ospf6_sock = socket;

  /* setup global sockaddr_in6, allspf6 & alldr6 for later use */
  allspfrouters6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  allspfrouters6.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &allspfrouters6.sin6_addr);
  alldrouters6.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  alldrouters6.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &alldrouters6.sin6_addr);

  return 0;
}

int
mcast_join (int sockfd, struct sockaddr *sa, char *ifname, u_int ifindex)
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
mcast_leave (int sockfd, struct sockaddr *sa, char *ifname, u_int ifindex)
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

int
ospf6_send (u_char msgtype, struct iovec *iov,
            struct sockaddr *dst, struct ospf6_if *ospf6_if)
{
  int num;
  struct msghdr smsghdr;
  struct cmsghdr *scmsgp;
  struct in6_pktinfo *pktinfo;
  u_char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];

  scmsgp = (struct cmsghdr *)cmsgbuf;

  if (make_ospf6_hdr (msgtype, iov, ospf6_if) < 0)
    {
      ospf6_warn ("Can't make ospf6_hdr\n");
      return -1;
    }

  smsghdr.msg_iov = iov;
  smsghdr.msg_iovlen = iov_count (iov);

  smsghdr.msg_name = (caddr_t)dst;
#ifdef SIN6_LEN
  smsghdr.msg_namelen = dst->sa_len;
#else
  smsghdr.msg_namelen = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */

  smsghdr.msg_control = (caddr_t)cmsgbuf;
  smsghdr.msg_controllen = sizeof (cmsgbuf);

  /* set outgoing interface using ancillary data */
  scmsgp->cmsg_level = IPPROTO_IPV6;
  scmsgp->cmsg_type = IPV6_PKTINFO;
  scmsgp->cmsg_len = CMSG_LEN(sizeof (struct in6_pktinfo));
  pktinfo = (struct in6_pktinfo *)(CMSG_DATA(scmsgp));
  pktinfo->ipi6_ifindex = if_nametoindex (ospf6_if->interface->name);
  memset (&pktinfo->ipi6_addr, 0, sizeof (struct in6_addr));
  scmsgp = CMSG_NXTHDR(&smsghdr, scmsgp);

  num = sendmsg (ospf6_sock, &smsghdr, 0);

#ifdef DEBUG_OSPF
  {
    char *dstname, ntopbuf[32], ifnamebuf[16];
    struct ospf6_hdr *ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;
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
    ospf6_debug ("Send %s to %s on %s\n",
                 mesg_name[ospf6_hdr->type],
                 inet_ntop (dst->sa_family, dstname,
                            ntopbuf, sizeof (ntopbuf)),
                 if_indextoname (pktinfo->ipi6_ifindex, ifnamebuf));
  }
#endif

  if (num != iov_totallen (iov))
    {
      ospf6_warn ("Can't send whole packet %d/%d: %s\n",
                   num, iov_totallen (iov), strerror(errno));
    }

  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
  iov_detach (iov, 0);

  return 0;
}

int
send_hello (struct thread *thread)
{
  struct ospf6_if *ospf6_if;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;

  ospf6_if = THREAD_ARG (thread);
  assert (ospf6_if);
  iov_clear (iov, MAXIOVLIST);

  make_hello (iov, &dst, ospf6_if);
  ospf6_send (MSGT_HELLO, iov, (struct sockaddr *)&dst, ospf6_if);

  ospf6_if->send_hello = thread_add_timer
    (master, send_hello, ospf6_if, ospf6_if->hello_interval);

  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, iov_count (iov));

  return 0;
}

int
send_database_description (struct thread *thread)
{
  struct neighbor *nbr;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];

  nbr = THREAD_ARG (thread);
  assert (nbr);
  nbr->send_dd = NULL;
  iov_clear (iov, MAXIOVLIST);

  switch (nbr->state)
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
      if (DD_IS_MSBIT_SET (nbr->dd_bits))
        {
        /* Master */
          nbr->send_dd = thread_add_timer (master, send_database_description,
                                           nbr, nbr->ospf6_if->rxmt_interval);
        }

      make_database_description (iov, &dst, nbr);
      ospf6_send (MSGT_DATABASE_DESCRIPTION, iov,
                  (struct sockaddr *)&dst, nbr->ospf6_if);
      iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
      iov_clear (iov, MAXIOVLIST);
      break;
    default:
      break;
    }

  return 0;
}

int
send_linkstate_request (struct thread *thread)
{
  struct neighbor *nbr;
  struct iovec iov[MAXIOVLIST];
  struct sockaddr_in6 dst;

  nbr = THREAD_ARG (thread);
  assert (nbr);
  nbr->send_lsreq = (struct thread *)NULL;

  switch (nbr->state)
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
      if (listcount (nbr->requestlist) == 0)
        {
          thread_add_event (master, loading_done, nbr, 0);
          return 0;
        }

      if (make_linkstate_request (iov, &dst, nbr) < 0)
        return 0;

      ospf6_send (MSGT_LINKSTATE_REQUEST, iov,
                  (struct sockaddr *)&dst, nbr->ospf6_if);
      iov_clear (iov, MAXIOVLIST);
      
      nbr->send_lsreq = thread_add_timer (master, send_linkstate_request,
                                          nbr, nbr->ospf6_if->rxmt_interval);
      break;
    default:
      break;
    }

  return 0;
}

int
send_linkstate_update (struct thread *thread)
{
  struct neighbor *nbr;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];

  nbr = THREAD_ARG (thread);
  assert (nbr);

  nbr->send_update = (struct thread *)NULL;
  iov_clear (iov, MAXIOVLIST);

  if (nbr->ospf6_if->state <= IFS_WAITING)
    return 0;

  if (make_linkstate_update (iov, &dst, nbr) < 0)
    return -1;

#ifdef DEBUG_LINKSTATE_UPDATE
  log ("Retransmitting LSAs\n");
#endif

  ospf6_send (MSGT_LINKSTATE_UPDATE, iov, (struct sockaddr *)&dst,
              nbr->ospf6_if);
  iov_free (MTYPE_OSPF_MESSAGE, iov, 0, 1);
  iov_clear (iov, MAXIOVLIST);

  nbr->send_update = thread_add_timer (master, send_linkstate_update, nbr,
                                       nbr->ospf6_if->rxmt_interval);
  return 0;
}

int
send_linkstate_ack (struct thread *thread)
{
  struct ospf6_if *ospf6_if;
  struct sockaddr_in6 dst;
  struct iovec iov[MAXIOVLIST];
  listnode i;
  struct lsa_internal *p;

  ospf6_if = THREAD_ARG (thread);
  assert (ospf6_if);

  ospf6_if->send_ack = (struct thread *)NULL;

  if (ospf6_if->state <= IFS_WAITING)
    return 0;

  iov_clear (iov, MAXIOVLIST);

  for (i = listhead (ospf6_if->delayed_ack); i; nextnode (i))
    {
      p = (struct lsa_internal *) getdata (i);
      attach_lsa_hdr_to_iov (p, iov);
#ifdef DEBUG_OSPF6
      ospf6_debug ("[%s] to DELAYED ACK\n", print_lsahdr (p->lsh));
#endif
    }

#ifdef SIN6_LEN
  dst.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
  dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  dst.sin6_scope_id = if_nametoindex (ospf6_if->interface->name);
#endif /* SIN6_LEN */

  switch (ospf6_if->state)
    {
    case IFS_DR:
    case IFS_BDR:
      inet_pton (AF_INET6, ALLSPFROUTERS6, &dst.sin6_addr);
      break;
    default:
      inet_pton (AF_INET6, ALLDROUTERS6, &dst.sin6_addr);
      break;
    }

  ospf6_send (MSGT_LINKSTATE_ACK, iov, (struct sockaddr *)&dst, ospf6_if);
  iov_clear (iov, MAXIOVLIST);

  for (i = listhead (ospf6_if->delayed_ack); i;
       i = listhead (ospf6_if->delayed_ack))
    {
      list_delete_by_val (ospf6_if->delayed_ack, getdata (i));
    }

  return 0;
}

