/*
 * $Id: memory.h,v 1.45 1999/02/23 14:32:06 developer Exp $
 *
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_MEMORY_H
#define _ZEBRA_MEMORY_H

/* #define MEMORY_LOG */

/* For tagging memory, below is the type of the memory. */
enum
{
  MTYPE_TMP = 1,
  MTYPE_COMMAND,
  MTYPE_COMMAND_CONST,
  MTYPE_STRVEC,
  MTYPE_VECTOR,
  MTYPE_VECTOR_INDEX,
  MTYPE_LINK_LIST,
  MTYPE_LINK_NODE,
  MTYPE_THREAD,
  MTYPE_THREAD_MASTER,
  MTYPE_VTY,
  MTYPE_VTY_HIST,
  MTYPE_IF,
  MTYPE_CONNECTED,
  MTYPE_AS_SEG,
  MTYPE_AS_PASN,
  MTYPE_AS_PATH,
  MTYPE_COMMUNITY,
  MTYPE_COMMUNITY_VAL,
  MTYPE_BGP_ROUTE,
  MTYPE_ATTR,
  MTYPE_BUFFER,
  MTYPE_BUFFER_DATA,
  MTYPE_STREAM,
  MTYPE_STREAM_DATA,
  MTYPE_STREAM_FIFO,
  MTYPE_BGP_PEER,
  MTYPE_RADIX_NODE,
  MTYPE_RADIX_MASK,
  MTYPE_PREFIX,
  MTYPE_PREFIX_IPV4,
  MTYPE_PREFIX_IPV6,
  MTYPE_HASH,
  MTYPE_HASH_BACKET,
  MTYPE_RIPNG_ROUTE,
  MTYPE_ROUTE_TABLE,
  MTYPE_ROUTE_NODE,
  MTYPE_RIPNG_SLOT,
  MTYPE_ACCESS_LIST,
  MTYPE_FILTER,
  MTYPE_ROUTE_MAP,
  MTYPE_ROUTE_MAP_NAME,
  MTYPE_ROUTE_MAP_INDEX,
  MTYPE_ROUTE_MAP_RULE,
  MTYPE_ROUTE_MAP_RULE_STR,
  MTYPE_ROUTE_MAP_COMPILED,
  MTYPE_RIP_INFO,
  MTYPE_RIB,
  MTYPE_DESC,
  MTYPE_OSPF_TOP,
  MTYPE_OSPF_AREA,
  MTYPE_OSPF_IF,
  MTYPE_OSPF_NEIGHBOR,
  MTYPE_OSPF_ROUTE,
  MTYPE_OSPF_ADDR,
  MTYPE_OSPF_MESSAGE,
  MTYPE_OSPF_TMP,
  MTYPE_OSPF_LSA,
  MTYPE_DISTRIBUTE,
  MTYPE_ZLOG,
  MTYPE_AS_FILTER,
  MTYPE_AS_LIST,
  MTYPE_MAX
};

#ifdef MEMORY_LOG
#define XMALLOC(mtype, size) \
  mtype_xmalloc (__FILE__, __LINE__, (mtype), (size))
#define XCALLOC(mtype, num, size) \
  mtype_xcalloc (__FILE__, __LINE__, (mtype), (num), (size))
#define XREALLOC(mtype, ptr, size)  \
  mtype_xrealloc (__FILE__, __LINE__, (mtype), (ptr), (size))
#define XFREE(mtype, ptr) \
  mtype_xfree (__FILE__, __LINE__, (mtype), (ptr))
#define XSTRDUP(mtype, str) \
  mtype_xstrdup (__FILE__, __LINE__, (mtype), (str))
#else
#define XMALLOC(mtype, size)       xmalloc ((mtype), (size))
#define XCALLOC(mtype, num, size)  xcalloc ((mtype), (num), (size))
#define XREALLOC(mtype, ptr, size) xrealloc ((mtype), (ptr), (size))
#define XFREE(mtype, ptr)          xfree ((mtype), (ptr))
#define XSTRDUP(mtype, str)        xstrdup ((mtype), (str))
#endif /* MEMORY_LOG */

/* Prototypes of memory function. */
void *xmalloc (int type, size_t size);
void *xcalloc (int type, size_t num, size_t size);
void *xrealloc (int type, void *ptr, size_t size);
void  xfree (int type, void *ptr);
char *xstrdup (int type, char *str);

void *mtype_xmalloc (const char *file,
		     int line,
		     int type,
		     size_t size);

void *mtype_xcalloc (const char *file,
		     int line,
		     int type,
		     size_t num,
		     size_t size);

void *mtype_xrealloc (const char *file,
		     int line,
		     int type, 
		     void *ptr,
		     size_t size);

void mtype_xfree (const char *file,
		  int line,
		  int type,
		  void *ptr);

char *mtype_xstrdup (const char *file,
		     int line,
		     int type,
		     char *str);
void memory_init ();

#endif /* _ZEBRA_MEMORY_H */
