/*
 * AS path management routines.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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
#include "roken.h"
#include "vector.h"
#include "vty.h"
#include "str.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"

/* for aspath_gettoken() and aspath_str2as() */
#define AS_TOKEN_ASVAL        1
#define AS_TOKEN_SET_START    2
#define AS_TOKEN_SET_END      3
#define AS_TOKEN_CONFED_START 4
#define AS_TOKEN_CONFED_END   5
#define AS_TOKEN_UNKNOWN      6

/* Minimum size of aspath header and as value. */
#define AS_HEADER_SIZE        2
#define AS_VALUE_SIZE         2

/* To fetch and store as segment value. */
struct assegment
{
  u_char type;
  u_char length;
  as_t asval[1];
};

/* Delimiter character of each AS type. */
struct
{
  int type;
  char *start;
  char *end;
} aspath_delimiter [] =
{
  { 0 },
  { AS_SET,             "{", "}" },
  { AS_SEQUENCE,        "",  ""  },
  { AS_CONFED_SET,      "[", "]" },
  { AS_CONFED_SEQUENCE, "(", ")" }
};

/* Hash for aspath.  This is top level structure of AS path. */
struct Hash *ashash;

struct aspath *
aspath_new ()
{
  struct aspath *aspath;

  aspath = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  bzero (aspath, sizeof (struct aspath));
  
  return aspath;
}

/* Free aspath. */
void
aspath_free (struct aspath *aspath)
{
  if (aspath->refcnt)
    aspath->refcnt--;

  if (aspath->refcnt == 0)
    {
      struct aspath *ret;
      
      /* This aspath must exist in aspath hash table. */
      ret = hash_pull (ashash, aspath);
      assert (ret != NULL);

      if (aspath->data)
	XFREE (MTYPE_AS_SEG, aspath->data);

#ifdef RADIX_REGEXP
      if (aspath->pasn)
	XFREE (MTYPE_AS_PASN, aspath->pasn);
#endif /* RADIX_REGEXP */

      XFREE (MTYPE_AS_PATH, aspath);
    }
}

/* Duplicate aspath structure.  Created same aspath structure but
   reference count is cleared. */
struct aspath *
aspath_dup (struct aspath *aspath)
{
  struct aspath *new;

  new = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  bzero (new, sizeof (struct aspath));
  new->length = aspath->length;

  if (new->length)
    {
      new->data = XMALLOC (MTYPE_AS_SEG, aspath->length);
      memcpy (new->data, aspath->data, aspath->length);
    }
  else
    new->data = NULL;

  return new;
}

/* Free uninterned aspath structure. */
void
aspath_undup (struct aspath *aspath)
{
  if (aspath)
    {
      if (aspath->data)
	XFREE (MTYPE_AS_SEG, aspath->data);
#ifdef RADIX_REGEXP
      if (aspath->pasn)
	XFREE (MTYPE_AS_PASN, aspath->pasn);
#endif /* RADIX_REGEXP */
      XFREE (MTYPE_AS_PATH, aspath);
    }
}

/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same aspath in the aspath
   hash then return it else make new aspath structure. */
struct aspath *
aspath_parse (caddr_t pnt, int length)
{
  struct aspath astmp;
  struct aspath *find;
  struct aspath *aspath;

  /* Looking up aspath hash entry. */
  astmp.data = pnt;
  astmp.length = length;

  find = hash_search (ashash, &astmp);

  /* If already same aspath exists is ashash then return it. */
  if (find)
    {
      /* find->refcnt++; */
      return find;
    }

  /* New aspath strucutre is needed. */
  aspath = XMALLOC (MTYPE_AS_PATH, sizeof (struct aspath));
  aspath->length = length;

  /* In case of IBGP connection aspath's length can be zero. */
  if (length)
    {
      aspath->data = XMALLOC (MTYPE_AS_SEG, length);
      memcpy (aspath->data, pnt, length);
    }
  else
    aspath->data = NULL;

  /* aspath->refcnt = 1; */
  aspath->refcnt = 0;
  hash_push (ashash, aspath);

  /* Make variable for aspath regexp. */
#ifdef RADIX_REGEXP
  {
    int i;
    int len;
    u_char *p;
    u_int16_t *pasn;

    len = length;
    p = pnt;
    i = 0;
    while (len > 0) {
      int num;

      /* data is <TYPE(1),LENGTH(1),DATA(variable)> */
      switch (*p) {
      case AS_SET:
      case AS_SEQUENCE:
      case AS_CONFED_SET:
      case AS_CONFED_SEQUENCE:
	break;
      default:
	zlog (NULL, LOG_INFO, "%d : unknown segment type", *p);
	return NULL;
      }

      /* increment the pointer */
      p++, len--;
      
      /* get # of ASs in this segment */
      num = *p; /* path segment length (len < 256) */
      p++, len--;
      
      /* update total # of ASs and calculate remaining length */
      i += num;

      /* check the length */
      if (num * 2 > len) {
	zlog (NULL, LOG_INFO, "num=%d too big", num);
	return NULL;
      }

      /* convert variable length data to a string */
      p += num * 2;
      len -= num * 2;
    }
    if (len)
      {
	zlog (NULL, LOG_INFO, "len = %d remains", len);
	return NULL;
      }
    aspath->hop_count = i;

    /* for simply as-path array */
    pasn = XMALLOC (MTYPE_AS_PASN, sizeof(*pasn) * (i + 1));

    len = length;
    p = pnt;
    i = 0;
    while (len > 0) {
      int seg, num, k;

      /* data is <TYPE(1),LENGTH(1),DATA(variable)> */
      seg = *p; /* path segment type */
      p++, len--;

      /* get # of ASs in this segment */
      num = *p; /* path segment length (len < 256) */
      p++, len--;

      /* check the length */
      assert(num * 2 <= len);

      /* convert variable length data to a string */
      for (k = 0; k < num; k++) {
	u_int16_t asn;

	asn = (*p << 8); /* higher octet of AS# */
	p++, len--;
	asn |= *p; /* lower octet of AS# */
	p++, len--;
	assert(i < aspath->hop_count);
	pasn[i++] = asn;
      }
    }
    aspath->pasn = pasn;
  }
#endif /* RADIX_REGEXP */

  return aspath;
}

/* AS path loop check.  If aspath contains asno then return 1. */
int
aspath_loop_check (struct aspath *aspath, as_t asno)
{
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  if (aspath == NULL)
    return 0;

  pnt = aspath->data;
  end = aspath->data + aspath->length;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;
      
      for (i = 0; i < assegment->length; i++)
	{
	  if (assegment->asval[i] == htons(asno))
	    return 1;
	}
      pnt += (assegment->length * 2) + 2;
    }
  return 0;
}

/* Add specified as to the leftmost of aspath. */
struct aspath *
aspath_add_left (struct aspath *aspath, as_t asno)
{
  struct assegment *assegment;

  assegment = (struct assegment *) aspath->data;

  /* In case of empty aspath. */
  if (assegment->length == 0)
    {
      aspath->length = AS_HEADER_SIZE + AS_VALUE_SIZE;
      aspath->data = XREALLOC (MTYPE_AS_SEG, aspath->data, aspath->length);

      assegment = (struct assegment *) aspath->data;
      assegment->type = AS_SEQUENCE;
      assegment->length = 1;
      assegment->asval[0] = htons (asno);

      return aspath;
    }

  /* First segment is AS_SEQUENCE*/
  if (assegment->type == AS_SEQUENCE)
    {
      caddr_t newdata;
      struct assegment *newsegment;

      newdata = XMALLOC (MTYPE_AS_SEG, aspath->length + AS_VALUE_SIZE);
      newsegment = (struct assegment *) newdata;

      newsegment->type = AS_SEQUENCE;
      newsegment->length = assegment->length + 1;
      newsegment->asval[0] = htons (asno);

      memcpy (newdata + AS_HEADER_SIZE + AS_VALUE_SIZE,
	      aspath->data + AS_HEADER_SIZE, 
	      aspath->length - AS_HEADER_SIZE);

      XFREE (MTYPE_AS_SEG, aspath->data);

      aspath->data = newdata;
      aspath->length += AS_VALUE_SIZE;
    }

  return aspath;
}

/* Add new as value to as path structure. */
void
aspath_as_add (struct aspath *as, as_t asno)
{
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  /* Increase as->data for new as value. */
  as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
  as->length += 2;

  pnt = as->data;
  end = as->data + as->length;
  assegment = (struct assegment *) pnt;

  /* Last segment search procedure. */
  while (pnt + 2 < end)
    {
      assegment = (struct assegment *) pnt;

      /* We add 2 for segment_type and segment_length and segment
         value assegment->length * 2. */
      pnt += (AS_HEADER_SIZE + (assegment->length * AS_VALUE_SIZE));
    }

  assegment->asval[assegment->length] = htons (asno);
  assegment->length++;
}

/* Add new as segment to the as path. */
void
aspath_segment_add (struct aspath *as, int type)
{
  struct assegment *assegment;

  if (as->data == NULL)
    {
      as->data = XMALLOC (MTYPE_AS_SEG, 2);
      assegment = (struct assegment *) as->data;
      as->length = 2;
    }
  else
    {
      as->data = XREALLOC (MTYPE_AS_SEG, as->data, as->length + 2);
      assegment = (struct assegment *) (as->data + as->length);
      as->length += 2;
    }

  assegment->type = type;
  assegment->length = 0;
}

/* Make empty aspath structure. */
struct aspath *
aspath_empty_aspath ()
{
  struct assegment segment;

  return aspath_parse (NULL, 0);

#if 0
  /* This is not acceptable for gated. */
  segment.type = AS_SEQUENCE;
  segment.length = 0;

  return aspath_parse ((caddr_t) &segment, AS_HEADER_SIZE);
#endif /* 0 */  
}

/* Special purpose function. */
struct aspath *
aspath_val2as (as_t asno)
{
  struct assegment segment;

  segment.type = AS_SEQUENCE;
  segment.length = 1; 
  segment.asval[0] = htons (asno);

  return aspath_parse ((caddr_t) &segment,
		       AS_HEADER_SIZE + (segment.length * AS_VALUE_SIZE));
}

/* Return next token and point for string parse. */
char *
aspath_gettoken (char *buf, int *token, u_short *asno)
{
  char *p;

  p = buf;

  /* Skip space. */
  while (isspace (*p))
    p++;

  /* Check the end of the string and type specify characters
     (e.g. {}()). */
  switch (*p)
    {
    case '\0':
      return NULL;
      break;
    case '{':
      *token = AS_TOKEN_SET_START;
      p++;
      return p;
      break;
    case '}':
      *token = AS_TOKEN_SET_END;
      p++;
      return p;
      break;
    case '(':
      *token = AS_TOKEN_CONFED_START;
      p++;
      return p;
      break;
    case ')':
      *token = AS_TOKEN_CONFED_END;
      p++;
      return p;
      break;
    }

  /* Check actual AS value. */
  if (isdigit (*p)) 
    {
      u_short asval;

      *token = AS_TOKEN_ASVAL;
      asval = (*p - '0');
      p++;
      while (isdigit (*p)) 
	{
	  asval *= 10;
	  asval += (*p - '0');
	  p++;
	}
      *asno = asval;
      return p;
    }
  
  /* There is no match then return unknown token. */
  *token = AS_TOKEN_UNKNOWN;
  return  p++;
}

struct aspath *
aspath_str2aspath (char *str)
{
  int token;
  u_short as_type;
  u_short asno;
  struct aspath *aspath;
  int needtype;

  aspath = aspath_new ();

  /* We start default type as AS_SEQUENCE. */
  as_type = AS_SEQUENCE;
  needtype = 1;

  while ((str = aspath_gettoken (str, &token, &asno)) != NULL)
    {
      switch (token)
	{
	case AS_TOKEN_ASVAL:
	  if (needtype)
	    {
	      aspath_segment_add (aspath, as_type);
	      needtype = 0;
	    }
	  aspath_as_add (aspath, asno);
	  break;
	case AS_TOKEN_SET_START:
	  as_type = AS_SET;
	  aspath_segment_add (aspath, as_type);
	  needtype = 0;
	  break;
	case AS_TOKEN_SET_END:
	  as_type = AS_SEQUENCE;
	  needtype = 1;
	  break;
	case AS_TOKEN_CONFED_START:
	  as_type = AS_CONFED_SEQUENCE;
	  aspath_segment_add (aspath, as_type);
	  needtype = 0;
	  break;
	case AS_TOKEN_CONFED_END:
	  as_type = AS_SEQUENCE;
	  needtype = 1;
	  break;
	}
    }
  return aspath;
}

/* Make hash value by raw aspath data. */
unsigned int
aspath_key_make (struct aspath *aspath)
{
  unsigned int key = 0;
  int length;
  caddr_t pnt;

  length = aspath->length;
  pnt = aspath->data;

  while (length)
    key += pnt[--length];

  return key %= HASHTABSIZE;
}

/* If two aspath have same value then return 1 else return 0 */
int
aspath_cmp (struct aspath *as1, struct aspath *as2)
{
  if (as1->length == as2->length 
      && !memcmp (as1->data, as2->data, as1->length))
    return 1;
  else
    return 0;
}

/* AS path hash initialize. */
void
aspath_init ()
{
  ashash = hash_new (HASHTABSIZE);
  ashash->hash_key = aspath_key_make;
  ashash->hash_cmp = aspath_cmp;
}

/* return and as path value */
const char *
aspath_print (struct aspath *as)
{
  static char buf[BUFSIZ];
  int space;
  u_char type;
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  space = 0;
  type = AS_SEQUENCE;
  pnt = as->data;
  end = as->data + as->length;
  assegment = (struct assegment *) pnt;

  bzero(buf, BUFSIZ);

  if (as->length == 0)
    return "";

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;

      /* If assegment type is changed, print previous type's end
         character. */
      if (assegment->type != type)
	{
	  strlcat (buf, aspath_delimiter[type].end, BUFSIZ);
	  type = assegment->type;
	}

      if (space)
	strlcat (buf, " ", BUFSIZ);

      strlcat (buf, aspath_delimiter[assegment->type].start, BUFSIZ);
      space = 0;

      for (i = 0; i < assegment->length; i++)
	{
	  if (space)
	    strlcat (buf, " ", BUFSIZ);
	  else
	    space = 1;
	  snprintf (buf + strlen (buf), BUFSIZ - strlen (buf), "%d",
		    ntohs (assegment->asval[i]));
	}

      pnt += (assegment->length * 2) + 2;
    }

  strlcat(buf, aspath_delimiter[assegment->type].end, BUFSIZ);

  return buf;
}

/* Printing functions */
void
aspath_print_vty (struct vty *vty, struct aspath *as)
{
  int space;
  u_char type;
  caddr_t pnt;
  caddr_t end;
  struct assegment *assegment;

  space = 0;
  type = AS_SEQUENCE;
  pnt = as->data;
  end = as->data + as->length;
  assegment = (struct assegment *) pnt;

  if (as->length == 0)
    return;

  while (pnt < end)
    {
      int i;
      assegment = (struct assegment *) pnt;

      /* If assegment type is changed, print previous type's end
         character. */
      if (assegment->type != type)
	{
	  vty_out (vty, "%s", aspath_delimiter[type].end);
	  type = assegment->type;
	}

      if (space)
	vty_out (vty, " ");

      vty_out (vty, "%s", aspath_delimiter[assegment->type].start);
      space = 0;

      for (i = 0; i < assegment->length; i++)
	{
	  if (space)
	    vty_out (vty, " ");
	  else
	    space = 1;
	  vty_out (vty, "%d", ntohs (assegment->asval[i]));
	}

      pnt += (assegment->length * 2) + 2;
    }

  vty_out (vty, "%s", aspath_delimiter[assegment->type].end);
}

/* Print all aspath and hash information.  This function is used from
   `show ip bgp paths' command. */
void
aspath_print_all_vty (struct vty *vty)
{
  int i;
  HashBacket *mp;

  for (i = 0; i < HASHTABSIZE; i++)
    if ((mp = hash_head (ashash, i)) != NULL)
      while (mp) 
	{
	  vty_out (vty, "[%x:%d] (%d) ", 
		   mp, i, ((struct aspath *)mp->data)->refcnt);
	  aspath_print_vty (vty, mp->data);
	  vty_out (vty, "\r\n");
	  mp = mp->next;
	}
}

#define ASPATH_TEST
#ifdef ASPATH_TEST
/* For test aspath functions. */
void
aspath_test ()
{
  struct aspath *as1;
  struct aspath *as2;

  as1 = aspath_val2as (2519);
  printf("%s\n", aspath_print (as1));

  as2 = aspath_val2as (2519);
  printf("%s\n", aspath_print (as2));

  printf ("hash check %p %p\n", as1, as2);

  as1 = aspath_str2aspath ("2519 2561");
  as2 = aspath_str2aspath ("2519 (2561) {1}");
  printf("%s\n", aspath_print (as1));
  printf("%s\n", aspath_print (as2));

  aspath_add_left (as2, 7675);
  printf ("test: %s\n", aspath_print (as2));

  as1 = aspath_empty_aspath ();
  printf ("empty aspath : %s\n", aspath_print (as1));

  aspath_add_left (as1, 65502);
  printf ("test: %s\n", aspath_print (as1));

  printf ("same %d\n", aspath_cmp (as1, as2));
}
#endif /* ASPATH_TEST */
