/*
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

#include <zebra.h>

#include "log.h"
#include "memory.h"

void alloc_inc (int);
void alloc_dec (int);

struct messages
{
  int index;
  char *str;
} mstr [] =
{
  { MTYPE_COMMAND, "command" },
  { MTYPE_COMMAND_CONST, "command_const" },
  { MTYPE_THREAD, "thread" },
  { MTYPE_THREAD_MASTER, "thread_master" },
  { MTYPE_VECTOR, "vector" },
  { MTYPE_VECTOR_INDEX, "vector_index" },
  { MTYPE_IF, "interface" },
  { 0, NULL },
};

char *
lookup (struct messages *mes, int index)
{
  struct messages *pnt;
  
  for (pnt = mes; pnt->index != 0; pnt++)
    if (pnt->index == index)
      return pnt->str;
  return "";
}

/* Fatal memory allocation error occured. */
static void
zerror (const char *fname, int type, size_t size)
{
  fprintf (stderr, "%s : can't allocate memory for `%s' size %d\n", 
	   fname, lookup (mstr, type), size);
  exit (1);
}

/* Memory allocation. */
void *
zmalloc (int type, size_t size)
{
  void *memory;

  memory = malloc (size);

  if (memory == NULL)
    zerror ("malloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory allocation with num * size with cleared. */
void *
zcalloc (int type, size_t num, size_t size)
{
  void *memory;

  memory = calloc (num, size);

  if (memory == NULL)
    zerror ("calloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory reallocation. */
void *
zrealloc (int type, void *ptr, size_t size)
{
  void *memory;

  memory = realloc (ptr, size);
  if (memory == NULL)
    zerror ("realloc", type, size);
  return memory;
}

/* Memory free. */
void
zfree (int type, void *ptr)
{
  alloc_dec (type);
  free (ptr);
}

/* String duplication. */
char *
zstrdup (int type, char *str)
{
  void *dup;

  dup = strdup (str);
  if (dup == NULL)
    zerror ("strdup", type, strlen (str));
  alloc_inc (type);
  return dup;
}

#ifdef MEMORY_LOG
void
mtype_log (char *func, void *memory, const char *file, int line, int type)
{
  zlog (NULL, LOG_INFO, "%s: %s %p %s %d",
	  func, lookup (mstr, type), memory, file, line);
}

void *
mtype_zmalloc (const char *file, int line, int type, size_t size)
{
  void *memory;

  mstat[type].c_malloc++;
  mstat[type].t_malloc++;

  memory = zmalloc (type, size);
  mtype_log ("zmalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zcalloc (const char *file, int line, int type, size_t num, size_t size)
{
  void *memory;

  mstat[type].c_calloc++;
  mstat[type].t_calloc++;

  memory = zcalloc (type, num, size);
  mtype_log ("xcalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zrealloc (const char *file, int line, int type, void *ptr, size_t size)
{
  void *memory;

  /* Realloc need before allocated pointer. */
  mstat[type].t_realloc++;

  memory = zrealloc (type, ptr, size);

  mtype_log ("xrealloc", memory, file, line, type);

  return memory;
}

/* Important function. */
void 
mtype_zfree (const char *file, int line, int type, void *ptr)
{
  mstat[type].t_free++;

  mtype_log ("xfree", ptr, file, line, type);

  xfree (type, ptr);
}

char *
mtype_zstrdup (const char *file, int line, int type, char *str)
{
  char *memory;

  mstat[type].c_strdup++;

  memory = zstrdup (type, str);
  
  mtype_log ("xstrdup", memory, file, line, type);

  return memory;
}
#endif /* MEMORY_LOG */

struct 
{
  char *name;
  unsigned long alloc;
} mstat [MTYPE_MAX];

/* Increment allocation counter. */
void
alloc_inc (int type)
{
  mstat[type].alloc++;
}

/* Decrement allocation counter. */
void
alloc_dec (int type)
{
  mstat[type].alloc--;
}

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

/* For pretty printng of memory allocate information. */
struct memory_list
{
  int index;
  char *format;
} memory_list[] =
{
  { MTYPE_ROUTE_TABLE,     "Route table     : %ld\r\n", },
  { MTYPE_ROUTE_NODE,      "Route node      : %ld\r\n", },
  { MTYPE_RIB,             "RIB             : %ld\r\n", },
  { MTYPE_FILTER,          "Filter Entry    : %ld\r\n", },
  { MTYPE_ACCESS_LIST,     "Access List     : %ld\r\n", },
  { MTYPE_ROUTE_MAP,       "Route map       : %ld\r\n", },
  { MTYPE_ROUTE_MAP_NAME,  "Route map name  : %ld\r\n", },
  { MTYPE_ROUTE_MAP_INDEX, "Route map index : %ld\r\n", },
  { MTYPE_ROUTE_MAP_RULE,  "Route map rule  : %ld\r\n", },
  { MTYPE_ROUTE_MAP_RULE_STR, "Route map rule str: %ld\r\n", },
  { 0,                     "---------------------\r\n" },
  { MTYPE_ATTR,            "BGP attribute   : %ld\r\n", },
  { MTYPE_AS_PATH,         "BGP aspath      : %ld\r\n", },
  { MTYPE_AS_SEG,          "BGP aspath seg  : %ld\r\n", },
  { MTYPE_AS_PASN,         "BGP aspath pasn : %ld\r\n", },
  { 0,                     "---------------------\r\n" },
  { MTYPE_AS_LIST,         "BGP as list     : %ld\r\n", },
  { MTYPE_AS_FILTER,       "BGP as filter   : %ld\r\n", },
  { 0,                     "---------------------\r\n" },
  { MTYPE_DESC,            "Command desc    : %ld\r\n", },
  { 0,                     "---------------------\r\n" },
  { MTYPE_BUFFER,          "Buffer          : %ld\r\n", },
  { MTYPE_BUFFER_DATA,     "Buffer data     : %ld\r\n", },
  { MTYPE_STREAM,          "Stream          : %ld\r\n", },
  { -1, NULL },
};

DEFUN (show_memory,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")
{
  struct memory_list *m;

  for (m = memory_list; m->index >= 0; m++)
    if (m->index == 0)
      vty_out (vty, m->format);
    else
      vty_out (vty, m->format, mstat[m->index].alloc);

  return CMD_SUCCESS;
}

void
memory_init ()
{
  install_element (VIEW_NODE, &show_memory_cmd);
  install_element (ENABLE_NODE, &show_memory_cmd);
}
