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
      zlog (NULL, LOG_WARNING,"Can't malloc buffer for iovec");
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
      zlog (NULL, LOG_WARNING,"Can't malloc buffer for iovec");
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
      zlog (NULL, LOG_WARNING,"Can't realloc buffer for iovec");
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

void *
iov_detach_first (struct iovec *iov)
{
  int i, iovlen;
  void *base;
  size_t len;

  base = iov[0].iov_base;
  len = iov[0].iov_len;
  iovlen = iov_count (iov);
  for (i = 0; i < iovlen; i++)
    {
      iov[i].iov_base = iov[i + 1].iov_base;
      iov[i].iov_len = iov[i + 1].iov_len;
    }
  return base;
}

int
iov_free (int mtype, struct iovec *iov, u_int begin, u_int end)
{
  int i;

  for (i = begin; i < end; i++)
    {
      if (mtype == MTYPE_OSPF6_LSA)
        o6log.pointer ("free %#x in iov_free()", iov[i].iov_base);
      XFREE (mtype, iov[i].iov_base);
      iov[i].iov_base = NULL;
      iov[i].iov_len = 0;
    }

  return 0;
}

void
iov_trim_head (int mtype, struct iovec *iov)
{
  void *base;

  base = iov_detach_first (iov);
  XFREE (mtype, base);
  return;
}

void
iov_free_all (int mtype, struct iovec *iov)
{
  int i, end = iov_count (iov);

  for (i = 0; i < end; i++)
    {
      XFREE (mtype, iov[i].iov_base);
      iov[i].iov_base = NULL;
      iov[i].iov_len = 0;
    }
  return;
}

int
sockunion_ospf6_socket (union sockunion *su)
{
  int sock;

  if (su->sa.sa_family == 0)
    su->sa.sa_family = AF_INET_UNION;

  sock = socket (su->sa.sa_family, SOCK_RAW, IPPROTO_OSPFIGP);
  if (sock < 0)
    zlog (NULL, LOG_WARNING,"Can't make socket for ospf6: %s", strerror(errno));

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

/* XXX consider whole construction of this function!
   the mtype statistics is broken */
int
ospf6_recv (struct thread *thread)
{
  struct iovec iov[MAXIOVLIST];
  int sockfd, i, hdrnum, num;
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
  char ifnamebuf[INTERFACE_NAMSIZ];
  unsigned short msglen = 0;

  memset (ifnamebuf, 0, sizeof (ifnamebuf));
  memset (&rmsghdr, 0, sizeof (struct msghdr));
  src = (struct sockaddr_in6 *)&unsa.sa;
  num = 0;

  sockfd = THREAD_FD (thread);

  /* ancillary data set up */
  rcmsgp = (struct cmsghdr *)&cmsgbuf;
  rcmsgp->cmsg_level = IPPROTO_IPV6;
  rcmsgp->cmsg_type = IPV6_PKTINFO;
  rcmsgp->cmsg_len = CMSG_LEN(sizeof (struct in6_pktinfo));
  pktinfo = (struct in6_pktinfo *)(CMSG_DATA(rcmsgp));

  /* clear message field */
  iov_clear (iov, MAXIOVLIST);

  /* prepare ospf6 message header buffer */
  iov_append (MTYPE_OSPF6_MESSAGE, iov, sizeof (struct ospf6_hdr));

  /* set buffer, ancillary data field to msghdr for sendmsg */
  rmsghdr.msg_name = (caddr_t)src;
  rmsghdr.msg_namelen = sizeof (struct sockaddr_in6);
  rmsghdr.msg_iov = iov;
  rmsghdr.msg_iovlen = iov_count (iov);
  rmsghdr.msg_control = (caddr_t)rcmsgp;
  rmsghdr.msg_controllen = sizeof (cmsgbuf);

  /* peek message type */
  num = recvmsg (sockfd, &rmsghdr, MSG_PEEK);
  if (num < 0)
    {
      /* if failed, log and read packet then return */
      zlog (NULL, LOG_WARNING, "recvmsg() failed in ospf6_recv(): %s",
            strerror (errno));
      recvmsg (sockfd, &rmsghdr, 0);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }

  /* get received interface */
  if (pktinfo->ipi6_ifindex > 0)
    if_indextoname (pktinfo->ipi6_ifindex, ifnamebuf);
  else
    {
      /* if failed, log and read packet then return */
      zlog (NULL, LOG_WARNING,
            "Received Interface not found in ospf6_recv()");
      recvmsg (sockfd, &rmsghdr, 0);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }
  ospf6_if = ospf6_if_lookup (ifnamebuf);

  if (!ospf6_if)
    {
      zlog (NULL, LOG_ERR, "BUG! Received Interface Structure not found");
      num = recvmsg (sockfd, &rmsghdr, 0);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }
  if (!ospf6_if->area)
    {
      zlog (NULL, LOG_WARNING, "Interface %s not atached to AREA",
            ospf6_if->interface->name);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      num = recvmsg (sockfd, &rmsghdr, 0);
      iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }

  /* for each message type, set appropriate buffer */
  ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;
  msglen = ntohs (ospf6_hdr->len);
  switch (ospf6_hdr->type)
    {
      case MSGT_HELLO:
        /* one buffer for hello */
        if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
                       msglen - sizeof (struct ospf6_hdr)))
          {
            zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            recvmsg (sockfd, &rmsghdr, 0);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_DATABASE_DESCRIPTION:
        if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
                       sizeof (struct database_description)))
          {
            zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            recvmsg (sockfd, &rmsghdr, 0);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        /* calculate ospf6_lsa_hdr number */
        hdrnum = (msglen - sizeof (struct ospf6_hdr)
                         - sizeof (struct database_description))
                  / sizeof (struct ospf6_lsa_hdr);
        for (i = 0; i < hdrnum; i++)
          {
            /* LSA hdr in DatabaseDescription will treat as LSA
               as attached to request list */
            if (!iov_append (MTYPE_OSPF6_LSA, iov,
                             sizeof (struct ospf6_lsa_hdr )))
              {
                zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
                thread_add_read (master, ospf6_recv, NULL, sockfd);
                recvmsg (sockfd, &rmsghdr, 0);
                iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
                iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
                iov_free_all (MTYPE_OSPF6_LSA, iov);
                return -1;
              }
          }
        break;

      case MSGT_LINKSTATE_REQUEST:
        /* calculate LSRequest header number */
        hdrnum = (msglen - sizeof (struct ospf6_hdr))
                  / sizeof (struct linkstate_request);
        for (i = 0; i < hdrnum; i++)
          {
            if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
                             sizeof (struct linkstate_request)))
              {
                zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
                thread_add_read (master, ospf6_recv, NULL, sockfd);
                recvmsg (sockfd, &rmsghdr, 0);
                iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
                return -1;
              }
          }
        break;

      case MSGT_LINKSTATE_UPDATE:
        if (!iov_append (MTYPE_OSPF6_MESSAGE, iov,
             sizeof (struct linkstate_update)))
          {
            zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            recvmsg (sockfd, &rmsghdr, 0);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        /* count header size */
        hdrnum = msglen - sizeof (struct ospf6_hdr)
                 - sizeof (struct linkstate_update);
        if (!hdrnum)
          {
            zlog (NULL, LOG_WARNING, "received LSUpdate contains no data.");
          }
        else if (!iov_append (MTYPE_OSPF6_MESSAGE, iov, hdrnum))
          {
            /* why mtype is MESSAGE is because this is temporary
               buffer for LSA */
            zlog (NULL, LOG_ERR, "iov_append() failed in ospf6_recv()");
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            recvmsg (sockfd, &rmsghdr, 0);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_ACK:
        /* calculate number of ospf6_lsa_hdr */
        hdrnum = (msglen - sizeof (struct ospf6_hdr))
                  / sizeof (struct ospf6_lsa_hdr);
        for (i = 0; i < hdrnum; i++)
          {
            /* this will treated like LSA on delayed ack list */
            if (!iov_append (MTYPE_OSPF6_LSA, iov,
                             sizeof (struct ospf6_lsa_hdr)))
              {
                zvlog_err ("iov_append() failed in ospf6_recv()");
                thread_add_read (master, ospf6_recv, NULL, sockfd);
                recvmsg (sockfd, &rmsghdr, 0);
                iov_free_all (MTYPE_OSPF6_LSA, iov);
                return -1;
              }
          }
        break;

      default:
        zlog (NULL, LOG_WARNING,"OSPFv%d %#x: Can't recv",
              ospf6_hdr->version, ospf6_hdr->type);
        thread_add_read (master, ospf6_recv, NULL, sockfd);
        recvmsg (sockfd, &rmsghdr, 0);
        iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
        return -1;
    }

  rmsghdr.msg_iovlen = iov_count (iov);
  num = recvmsg (sockfd, &rmsghdr, 0);
  if (num < 0)
    {
      zlog (NULL, LOG_WARNING, "recvmsg() failed: %s", strerror (errno));
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }

  if (ospf6_if->state < IFS_WAITING)
    {
      zvlog_debug ("Interface %s Not UP");
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }

  {
    char ntopbuf[32];
    o6log.network ("receive %s from %s on %s",
                   mesg_name[ospf6_hdr->type],
                   inet_ntop (src->sin6_family, (char *)&src->sin6_addr,
                              ntopbuf, sizeof (ntopbuf)),
                   ospf6_if->interface->name);
  }

  if (proc_ospf6_hdr(iov, ospf6_if) < 0)
    {
      zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
            ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
      thread_add_read (master, ospf6_recv, NULL, sockfd);
      iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
      return -1;
    }

  switch (ospf6_hdr->type)
    {
      case MSGT_HELLO:
        if (proc_hello (src, iov, ospf6_if) < 0)
          {
            zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
                  ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_DATABASE_DESCRIPTION:
        if (proc_database_description (src, iov, ospf6_if) < 0)
          {
            zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
                  ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_REQUEST:
        if (proc_linkstate_request (src, iov, ospf6_if) < 0)
          {
            zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
                  ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_UPDATE:
        if (proc_linkstate_update (src, iov, ospf6_if) < 0)
          {
            zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
                  ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;

      case MSGT_LINKSTATE_ACK:
        if (proc_linkstate_ack (src, iov, ospf6_if) < 0)
          {
            zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
                  ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
            thread_add_read (master, ospf6_recv, NULL, sockfd);
            iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
            return -1;
          }
        break;
    default:
        zlog (NULL, LOG_WARNING,"OSPFv%d %s: Can't proc",
              ospf6_hdr->version, mesg_name[ospf6_hdr->type]);
        thread_add_read (master, ospf6_recv, NULL, sockfd);
        iov_free_all (MTYPE_OSPF6_MESSAGE, iov);
        return -1;
    }

  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);
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
  socket = sockunion_ospf6_socket (&su);
  if (socket < 0)
    {
      zlog (NULL, LOG_WARNING,"Can't Create OSPF6 Socket.");
    }

  sockopt_reuseaddr (socket);

#if 0
  thread_add_read (master, ospf6_recv, NULL, socket);
#else
  thread_add_read (master, ospf6_receive, NULL, socket);
#endif

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
                  log_warn ("Can't Get Address for %s, "
                            "Can't Join Multicast Group\n",
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
      zvlog_warn ("Can't make ospf6_hdr");
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

  {
    char *dstname, ntopbuf[32], ifnamebuf[16];
    struct ospf6_hdr *ospf6_hdr = (struct ospf6_hdr *)iov[0].iov_base;
    dstname = (char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
    o6log.network ("send %s to %s on %s",
                   mesg_name[ospf6_hdr->type],
                   inet_ntop (dst->sa_family, dstname,
                              ntopbuf, sizeof (ntopbuf)),
                   if_indextoname (pktinfo->ipi6_ifindex, ifnamebuf));
  }

  if (num != iov_totallen (iov))
    {
      zvlog_warn ("Can't send whole packet %d/%d: %s",
                  num, iov_totallen (iov), strerror(errno));
    }

  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

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

  iov_trim_head (MTYPE_OSPF6_MESSAGE, iov);

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
      iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);
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
  iov_clear (iov, MAXIOVLIST);

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

  o6log.network ("retransmitting LSAs");

  ospf6_send (MSGT_LINKSTATE_UPDATE, iov, (struct sockaddr *)&dst,
              nbr->ospf6_if);
  iov_free (MTYPE_OSPF6_MESSAGE, iov, 0, 1);
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
  struct ospf6_lsa *p;

  ospf6_if = THREAD_ARG (thread);
  assert (ospf6_if);

  ospf6_if->send_ack = (struct thread *)NULL;

  if (ospf6_if->state <= IFS_WAITING)
    return 0;

  iov_clear (iov, MAXIOVLIST);

  for (i = listhead (ospf6_if->delayed_ack); i; nextnode (i))
    {
      p = (struct ospf6_lsa *) getdata (i);
      attach_lsa_hdr_to_iov (p, iov);

      o6log.network ("LSAck(delayed): %s", print_lsahdr (p->lsa_hdr));
    }

  if (iov_count (iov) == 0)
    return 0;

  dst.sin6_family = AF_INET6;
#ifdef SIN6_LEN
  dst.sin6_len = sizeof (struct sockaddr_in6);
#endif /* SIN6_LEN */
#ifdef HAVE_SIN6_SCOPE_ID
  dst.sin6_scope_id = if_nametoindex (ospf6_if->interface->name);
#endif /* HAVE_SIN6_SCOPE_ID */

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

  while (listcount (ospf6_if->delayed_ack))
    {
      i = listhead (ospf6_if->delayed_ack);
      p = getdata (i);
      ospf6_remove_delayed_ack (p, ospf6_if);
    }

  return 0;
}

void
ospf6_prefix_in6_addr (struct ospf6_prefix *o6p, struct in6_addr *in6)
{
  memset (in6, 0, sizeof (struct in6_addr));
  memcpy (in6, o6p + 1, OSPF6_PREFIX_SPACE (o6p->o6p_prefix_len));
  return;
}

