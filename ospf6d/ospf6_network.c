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

void
iov_copy_all (struct iovec *dst, struct iovec *src, int size)
{
  int i;
  for (i = 0; i < size; i++)
    {
      dst[i].iov_base = src[i].iov_base;
      dst[i].iov_len = src[i].iov_len;
    }
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

  thread_add_read (master, ospf6_receive, NULL, socket);

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

void
ospf6_join_alldr (u_int ifindex)
{
  struct ipv6_mreq mreq6;

  assert (ifindex);

  memcpy (&mreq6.ipv6mr_multiaddr, &alldrouters6.sin6_addr,
          sizeof (struct in6_addr));
  mreq6.ipv6mr_interface = ifindex;

  if (setsockopt (ospf6_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                  &mreq6, sizeof (mreq6)) < 0)
    zlog_warn ("*** can't join AllDRouters6 on ifindex %d", ifindex);
}

void
ospf6_leave_alldr (u_int ifindex)
{
  struct ipv6_mreq mreq6;

  assert (ifindex);

  memcpy (&mreq6.ipv6mr_multiaddr, &alldrouters6.sin6_addr,
          sizeof (struct in6_addr));
  mreq6.ipv6mr_interface = ifindex;

  if (setsockopt (ospf6_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                  &mreq6, sizeof (mreq6)) < 0)
    zlog_warn ("*** can't leave AllDRouters6 on ifindex %d", ifindex);
}

#ifndef s6_addr32
#define s6_addr32 u6_addr.u6_addr32
#define s6_addr16 u6_addr.u6_addr16
#define s6_addr8  u6_addr.u6_addr8
#define s6_addr   u6_addr.u6_addr8
#endif

void
ospf6_ipv4_encode_ipv6 (struct in_addr *in4, struct in6_addr *in6)
{
  /* IPv4 address to IPv4 Mapped Address */
  memset (in6, 0, sizeof (struct in6_addr));
  in6->s6_addr16[5] = 0xffff;
  in6->s6_addr32[3] = in4->s_addr;
}

void
ospf6_ipv6_decode_ipv4 (struct in6_addr *in6, struct in_addr *in4)
{
  if (!IN6_IS_ADDR_V4MAPPED (in6))
    zlog_warn (" *** converting address not IPv4MappedAddress!!");

  /* IPv4 Mapped Address to IPv4 address*/
  memset (in4, 0, sizeof (struct in_addr));
  in4->s_addr = in6->s6_addr32[3];
}

int
mcast_join (int sockfd, struct sockaddr *sa, char *ifname, u_int ifindex)
{
  struct ipv6_mreq mreq6;

  switch (sa->sa_family)
    {
      case AF_INET6:
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
      default:
        errno = EPROTONOSUPPORT;
        return -1;
    }
}

int
mcast_leave (int sockfd, struct sockaddr *sa, char *ifname, u_int ifindex)
{
  struct ipv6_mreq mreq6;

  switch (sa->sa_family)
    {
      case AF_INET6:
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
      default:
        errno = EPROTONOSUPPORT;
        return -1;
    }
}


/* quick declaration for warning */
int make_ospf6_hdr (msgtype_t , struct iovec *, struct ospf6_if *);
int make_hello (struct iovec *, struct sockaddr_in6 *, struct ospf6_if *);
int make_database_description (struct iovec *, struct sockaddr_in6 *,
                               struct neighbor *);
int make_linkstate_request (struct iovec *, struct sockaddr_in6 *,
                            struct neighbor *);
int make_linkstate_update (struct iovec *, struct sockaddr_in6 *,
                           struct neighbor *);

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
    {
      o6log.network ("LSAck(delayed): nothing to acknowledge");
      return 0;
    }

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

