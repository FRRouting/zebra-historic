struct rentry
{
  int type;			/* Type of this route */
  int fib;			/* Is this route goes to fib. */
#ifdef HAVE_IPV6
  struct in6_addr nexthop;
#endif
  struct interface *ifp;
  void *info;			/* Route specific information. */
};
