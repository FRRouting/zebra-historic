/*
GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.
*/

/*
 * network.c -- network library
 *
 * Copyright (c) 1997 Kunihiro Ishiguro
 */
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * Read nbytes from fd and store into ptr.
 */
int
readn (int fd, char *ptr, int nbytes)
{
  int nleft, nread;

  nleft = nbytes;
  while (nleft > 0) {
    nread = read (fd, ptr, nleft);
    if (nread < 0) {
      return (nread);
    } else if (nread == 0) {
      break;
    }
    nleft -= nread;
    ptr += nread;
  }
  return (nbytes - nleft);
}  

/*
 * Write nbytes from ptr to fd.
 */
int
writen(int fd, char *ptr, int nbytes)
{
  int nleft, nwritten;
  nleft = nbytes;

  while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if (nwritten <= 0) {
      return (nwritten);
    }
    nleft -= nwritten;
    ptr += nwritten;
  }
  return (nbytes - nleft);
}
