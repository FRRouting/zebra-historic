/*
 * Community attribute related functions.
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

#include "hash.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "roken.h"
#include "str.h"

#include "bgpd/bgp_community.h"

/* Hash of community attribute. */
struct Hash *comhash;

/* Create new community attribute. */
struct community *
community_parse (char *pnt, u_short length)
{
  struct community comtmp;
  struct community *find;
  struct community *new;

  /* Make temporary community for hash look up. */
  comtmp.size = length / 4;
  comtmp.val = (u_int32_t *) pnt;
  comtmp.refcnt = 0;

  /* Looking up hash of community attribute. */
  find = (struct community *) hash_search (comhash, &comtmp);
  if (find)
    {
      /* find->refcnt++; */
      return find;
    }

  /* Make new community attribute and intern it into hash. */
  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));

  /* new->refcnt = 1; */
  new->refcnt = 0;
  new->size = length / 4;
  new->val = (u_int32_t *) XMALLOC (MTYPE_COMMUNITY_VAL, length);
  memcpy (new->val, pnt, length);

  hash_push (comhash, new);

  return new;
}

/* Free community attribute. */
void
community_free (struct community *com)
{
  if (com->refcnt)
    com->refcnt--;

  if (com->refcnt == 0)
    {
      struct community *ret;
  
      /* Community value com must exist in hash. */
      ret = (struct community *) hash_pull (comhash, com);
      assert (ret != NULL);

      if (com->val)
	XFREE (MTYPE_COMMUNITY_VAL, com->val);
      XFREE (MTYPE_COMMUNITY, com);
    }
}

/* Pretty printing of community.  For debug and logging purpose. */
const char *
community_print (struct community *com)
{
  /* XXX non-re-entrant warning */
  static char buf[BUFSIZ];
  int i;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  bzero(buf, BUFSIZ);

  for (i = 0; i < com->size; i++) {
    comval = ntohl (com_nthval (com, i));
    switch (comval) {
    case COMMUNITY_NO_EXPORT:
      strlcat (buf, " no_export", BUFSIZ);
      break;
    case COMMUNITY_NO_ADVERTIZE:
      strlcat (buf, " no_advertize", BUFSIZ);
      break;
    case COMMUNITY_NO_EXPORT_SUBCONFED:
      strlcat (buf, " no_export_subconfed", BUFSIZ);
      break;
    default:
      as = (comval >> 16) & 0xFFFF ;
      val = comval & 0xFFFF;
      snprintf (buf + strlen (buf), BUFSIZ - strlen (buf), " %d:%d", as, val);
      break;
    }
  }
  return buf;
}

/* Make hash value of community attribute. This function is used by
   hash package.*/
unsigned int
community_hash_make (struct community *com)
{
  int c;
  unsigned int key;
  unsigned char *pnt;

  key = 0;
  pnt = (unsigned char *)com->val;
  
  for(c = 0; c < com->size * 4; c++)
    key += pnt[c];
      
  return key %= HASHTABSIZE;
}

/* If two aspath have same value then return 1 else return 0. This
   function is used by hash package. */
int
community_cmp (struct community *com1, struct community *com2)
{
  if (com1->size == com2->size)
    if (memcmp (com1->val, com2->val, com1->size * 4) == 0)
      return 1;
  return 0;
}

/* Initialize comminity related hash. */
void
community_init ()
{
  comhash = hash_new (HASHTABSIZE);
  comhash->hash_key = community_hash_make;
  comhash->hash_cmp = community_cmp;
}

/* Below functions are not used current point. */

#if 0
/* Get next community token from string. */
u_char *
community_gettoken (u_char *pnt, u_int32_t *val)
{
  u_char *p;
#define COMBUFSIZ 256
  char buf[COMBUFSIZ];
  int i;
  
  p = pnt;
  while (isspace (*p)) {
    p++;
  }
  if (*p == '\0') {
    return NULL;
  }
  /* well known communities */
  if (isalpha (*p)) {
    i = 0;
    buf[i++] = *p++;
    while ((isalpha (*p) || *p == '_') && i < (COMBUFSIZ - 2)) {
      buf[i++] = *p++;
    }
    buf[i] = '\0';
    *val = 0;
    if (strcmp (buf, "no_export") == 0)
      *val = COMMUNITY_NO_EXPORT;
    if (strcmp (buf, "no_advertize") == 0)
      *val = COMMUNITY_NO_ADVERTIZE;
    if (strcmp (buf, "no_export_subconfed") == 0)
      *val = COMMUNITY_NO_EXPORT_SUBCONFED;
    return p;
  }
  /* community val */
  if (isdigit (*p)) {
    int separator = 0;
    u_int32_t asval = 0;

    *val = (*p++ - '0');
    while (isdigit (*p) || *p == ':') {
      if (*p == ':') {
	separator = 1;
	asval = *val;
	*val = 0;
      } else {
	*val *= 10;
	*val += (*p - '0');
      }
      p++;
    }
    if (separator) {
      *val = (asval << 16) + *val;
    }
    return p;
  }
  p++;
  return p;
}

/* Add one community value to the community. */
void
community_add_val (struct community *com, u_int32_t val)
{
  com->size++;
  com->val = (u_int32_t *) xrealloc (com->val, com_length (com));
  com_lastval (com) = htonl (val);
}


/* convert string to community structure */
struct community *
community_str2com (char *str)
{
  struct community *new;
  u_int32_t val;
  u_char *pnt = str;

  new = XMALLOC (MTYPE_COMMUNITY, sizeof (struct community));

  while ((pnt = community_gettoken (pnt, &val))) {
    if (val != 0) {
      community_add_val (new, val);
    }
  }
  return new;
}

/* If community com include value of val return 1 else return 0. */
int
community_contain (struct community *com, u_int32_t val)
{
  int i;
  u_int32_t *pos = com->val;

  for (i = 0; i < com->size; i++) {
    if (pos[i] == val) {
      return 1;
    }
  }
  return 0;
}
#endif /* 0 */

/* Below is vty related function which needs some header include. */

/* Pretty printing of community attribute. */
void
community_print_vty (struct vty *vty, struct community *com)
{
  int i;
  u_int32_t comval;
  u_int16_t as;
  u_int16_t val;

  for (i = 0; i < com->size; i++) 
    {
      comval = ntohl (com_nthval (com, i));
      switch (comval) 
	{
	case COMMUNITY_NO_EXPORT:
	  vty_out (vty, " no_export");
	  break;
	case COMMUNITY_NO_ADVERTIZE:
	  vty_out (vty, " no_advertize");
	  break;
	case COMMUNITY_NO_EXPORT_SUBCONFED:
	  vty_out (vty, " no_export_subconfed");
	  break;
	default:
	  as = (comval >> 16) & 0xFFFF ;
	  val = comval & 0xFFFF;
	  vty_out (vty, " %d:%d", as, val);
	  break;
	}
    }
}

/* For `show ip bgp community' command. */
void
community_print_all_vty (struct vty *vty)
{
  int i;
  HashBacket *mp;

  for (i = 0; i < HASHTABSIZE; i++)
    if ((mp = (HashBacket *) hash_head (comhash, i)) != NULL)
      while (mp) 
	{
	  struct community *com;

	  com = (struct community *) mp->data;

	  vty_out (vty, "[%x:%d] (%d)", mp, i, com->refcnt);
	  community_print_vty (vty, com);
	  vty_out (vty, "\r\n");
	  mp = mp->next;
	}
}
