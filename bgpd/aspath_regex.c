/*
 * Copyright (c) 1997, 1998
 *	Ikuo Nakagawa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: aspath_regex.c,v 1.6 1998/03/06 10:07:06 kunihiro Exp $
 */
#define ZEBRA
#define RADIX_REGEXP
#define DEBUG

#ifndef ZEBRA
#include "defines.h"
#endif /* ! ZEBRA */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ZEBRA

#include "debug.h"
#include "mleak.h"

#define ASPATH_PRIVATE
#include "aspath.h"
#else
#include <config.h>
#include <sys/types.h>
#include "bgp_aspath.h"

FILE *dp = NULL;
int loglevel = 7;

#define _lp(level,log) \
        { \
                if (dp && (level) <= loglevel) { \
                        extern int errno; \
                        register int tmperrno = errno; \
			/* proclog(dp); */ \
			/* fprintf log; */ \
                        errno = tmperrno; \
                } \
        }

#define aspath_hop_count(p)	((p)->hop_count)

#define FREE(p)         free(p)
#define MALLOC(siz)     malloc(siz)
#define CALLOC(n,siz)   calloc(n, siz)
#define REALLOC(p,siz)  realloc(p, siz)
#define STRDUP(p)       strdup(p)

#ifdef DEBUG
#define _dp(level,log)  _lp(level,log)
#else /* !defined(DEBUG) */
#define _dp(level,log)  ((void)0)
#endif /* !defined(DEBUG) */
#endif /* ! ZEBRA */

/* constants for limitations */
#define N_INFINITE	(-1)

/* an AS PATH regular expression object */
struct regex_obj_t {
	int flag;
	int type;
	int mincnt;
	int maxcnt;
	int minlen;
	int maxlen;
	char *strregex;
	union {
		struct aspath_regex_t *regex;
		u_short *pasn;
		u_short asn;
		/* void *data; */
	} u;
};

/* a segment of AS PATH regular expression objects */
struct regex_seg_t {
	int n_objects;			/* # of used objects */
	int max_objects;		/* # of allocated objects */
	int minlen;			/* minimum length of regexp */
	int maxlen;			/* maximum length of regexp */
	char *strregex;			/* in string format */
	struct regex_obj_t *objects;	/* array of objects */
};

/* type declaration of AS PATH regular expression */
struct aspath_regex_t {
	int n_segments;			/* # of used objects */
	int max_segments;		/* # of allocated objects */
	int minlen;			/* minimum length of regexp */
	int maxlen;			/* maximum length of regexp */
	char *strregex;			/* in string format */
	struct regex_seg_t *segments;	/* array of segments */
};

#define TYPE_NONE	0
#define TYPE_REGEXP	1
#define TYPE_ASN	2
#define TYPE_ANY	3
#define TYPE_RANGE	4
#define TYPE_NEG_RANGE	5
#define TYPE_BEGIN	6
#define TYPE_END	7

#if 0
/* internal use only */
static const char *
type_string(int type)
{
	switch (type) {
	case TYPE_NONE:
		return "none";
	case TYPE_REGEXP:
		return "regexp";
	case TYPE_ASN:
		return "asn";
	case TYPE_ANY:
		return "any";
	case TYPE_RANGE:
		return "range";
	case TYPE_NEG_RANGE:
		return "neg-range";
	case TYPE_BEGIN:
		return "begin";
	case TYPE_END:
		return "end";
	default:
		return "unrecognized";
	}
}
#endif

#define SKIPSPACE(p)	{ while (*(p) == ' ' || *(p) == '\t') { (p)++; } }
#define ENDOFSTRING(p)	{ while (*(p)) { (p)++; } }
#define ISDIGIT(ch)	((ch) >= '0' && (ch) <= '9')
#define NUMBER(array)	(sizeof(array) / sizeof((array)[0]))

/* prototypes for static functions */
static int check_obj(
	const struct regex_obj_t *op,
	const ASPATH *aspath, int off, int len);
static int check_seg(
	const struct regex_seg_t *sp,
	const ASPATH *aspath, int off, int len);
static int check_multi_regex(
	const struct regex_obj_t *p, /* must be regex object */
	const ASPATH *info,
	int off, int len, int n_times);
static int check_regex(
	const ASPATH_regex *rp,
	const ASPATH *aspath, int off, int len);

/* representation in a string format */
static const char *regex_obj_set_string(struct regex_obj_t *);
static const char *regex_seg_set_string(struct regex_seg_t *);
static const char *regex_set_string(ASPATH_regex *);

/* free compiled expression */
void
aspath_regex_free(ASPATH_regex *regex)
{
	int n;

	/* free all alternatives */
	for (n = 0; n < regex->n_segments; n++) {
		struct regex_seg_t *seg = &regex->segments[n];
		int i;

		/* free data used by objects */
		for (i = 0; i < seg->n_objects; i++) {
			struct regex_obj_t *p = &seg->objects[i];

			switch (p->type) {
			case TYPE_REGEXP:
				aspath_regex_free(p->u.regex);
				break;
			case TYPE_RANGE:
			case TYPE_NEG_RANGE:
				FREE(p->u.pasn);
				break;
			default:
				break;
			}
			if (p->strregex) {
				FREE(p->strregex);
			}
		}
		if (seg->objects) {
			FREE(seg->objects);
		}
		if (seg->strregex) {
			FREE(seg->strregex);
		}
	}
	if (regex->segments) {
		FREE(regex->segments);
	}
	if (regex->strregex) {
		FREE(regex->strregex);
	}
	FREE(regex);
}

/* macros for special meta charactors */
#define GROUP_BEGIN	'('
#define GROUP_END	')'
#define REPEAT_BEGIN	'{'
#define REPEAT_END	'}'

#ifdef ZEBRA
/* Copy from radix/src/aspath.c*/
/*
 * Cut an AS number from a string. For example, if `*pp' points
 * "AS521+ AS433", cutasn works as follows:
 *  1. Cuts a AS number, e.g., cutasn stores 521 to `*pasn'.
 *  2. Updates the pointer, e.g., let `*pp' := *pp + 6.
 * Cutasn returns 0 on success, and -1 otherwise.
 */
int
aspath_cutasn(const char **pp, u_short *pasn)
{
	const char *p;
	u_long asn;

	p = *pp;
	if (!(*p == 'A' || *p == 'a')) {
		return -1;
	}

	p++;
	if (!(*p == 'S' || *p == 's')) {
		return -1;
	}

	p++;
	if (!ISDIGIT(*p)) {
		return -1;
	}

	asn = 0;
	do {
		asn = asn * 10 + (*p - '0');
		if (asn > 0xffff) {
			return -1;
		}
		p++;
	} while (ISDIGIT(*p)) ;

	*pp = p;
	*pasn = asn;

	/* success */
	return 0;
}
#endif /* ZEBRA */
/* parse regular expressions */
static ASPATH_regex *
aspath_regex_parse(const char **ppat)
{
	static const char zz[] = "aspath_regex_parse";
	ASPATH_regex *regex = NULL;
	struct regex_seg_t *seg = NULL;
	const char *pat;
	u_short asn;
	int i, minlen = 0, maxlen = 0;

	/* create a new object */
	if (!(regex = CALLOC(1, sizeof(*regex)))) {
		_lp(5, (dp, "%s: CALLOC - %s\n", zz, strerror(errno)));
		return NULL;
	}

	/* set first pointer */
	pat = *ppat;
	SKIPSPACE(pat);

	/* goto main loop - until end-of-string or end-of-group */
	while (*pat && *pat != GROUP_END) {
		struct regex_obj_t *p;

		/* check a regular expression boundary */
		if (*pat == '|') {
			if (!seg) {
				_lp(5, (dp, "%s: empty pattern detected\n",
					zz));
				aspath_regex_free(regex);
				return NULL;
			}
			seg->minlen = minlen;
			seg->maxlen = maxlen;
			seg = NULL;
			pat++;
		}

		/* check if we should create a new array */
		if (!seg) {
			/* create a new object */
			if (regex->n_segments >= regex->max_segments) {
				struct regex_seg_t *sp = regex->segments;
				int num = regex->max_segments + 4;

				sp = sp ? REALLOC(sp, num * sizeof(*sp))
					: MALLOC(num * sizeof(*sp));
				if (!sp) {
					_lp(5, (dp, "%s: REALLOC/MALLOC - %s\n",
						zz, strerror(errno)));
					aspath_regex_free(regex);
					return NULL;
				}
				regex->segments = sp;
				regex->max_segments = num;
			}
			seg = &regex->segments[regex->n_segments];
			regex->n_segments++;
			memset(seg, 0, sizeof(*seg));
			minlen = maxlen = 0;
		}

		/* create a new object */
		if (seg->n_objects >= seg->max_objects) {
			struct regex_obj_t *op = seg->objects;
			int num = seg->max_objects + 8;

			op = op ? REALLOC(op, num * sizeof(*op))
				: MALLOC(num * sizeof(*op));
			if (!op) {
				_lp(5, (dp, "%s: REALLOC/MALLOC - %s\n",
					zz, strerror(errno)));
				aspath_regex_free(regex);
				return NULL;
			}
			seg->objects = op;
			seg->max_objects = num;
		}
		p = &seg->objects[seg->n_objects];
		seg->n_objects++;
		memset(p, 0, sizeof(*p));
		p->type = TYPE_ANY;

		/* check the first charactor */
		if (*pat == '^') {
			p->type = TYPE_BEGIN;
			pat++;
		} else if (*pat == '$') {
			p->type = TYPE_END;
			pat++;
		} else if (*pat == GROUP_BEGIN) {
			ASPATH_regex *tmprp;

			/* skip this charactor */
			pat++;

			if (!(tmprp = aspath_regex_parse(&pat))) {
				_dp(5, (dp, "%s: can't parse \"%s\"\n",
					zz, pat));
				aspath_regex_free(regex);
				return NULL;
			}

			/* and skip spaces - this may be eliminated */
			SKIPSPACE(pat);

			/* check end-of-group */
			if (*pat != GROUP_END) {
				_dp(5, (dp, "%s: no end-of-group found\n", zz));
				aspath_regex_free(tmprp);
				aspath_regex_free(regex);
				return NULL;
			}

			/* skip end-of-group */
			pat++;

			/* store this data */
			p->u.regex = tmprp;
			p->type = TYPE_REGEXP;
		} else if (*pat == '[') {
			const char *savepat;
			int type, ch_range, i, cnt;
			u_short *pasn;

			pat++;
			SKIPSPACE(pat);
			if (*pat == '^') {
				pat++;
				SKIPSPACE(pat);
				type = TYPE_NEG_RANGE;
			} else {
				type = TYPE_RANGE;
			}
			savepat = pat; /* save pointer */
			ch_range = 0;
			cnt = 0;
			while (aspath_cutasn(&pat, &asn) == 0) {
				ch_range = 0;
				cnt++;
				SKIPSPACE(pat);
				if (*pat == '-') {
					ch_range = 1;
					cnt++;
					pat++;
					SKIPSPACE(pat);
				}
			}
			SKIPSPACE(pat);
			if (*pat != ']') {
				aspath_regex_free(regex);
				return NULL;
			}
			if (ch_range) {
				aspath_regex_free(regex);
				return NULL;
			}
			if (!(pasn = MALLOC(sizeof(*pasn) * (cnt + 1)))) {
				aspath_regex_free(regex);
				return NULL;
			}
			pasn[0] = cnt;
			pat = savepat; /* restore pointer and parse again */
			i = 0;
			while (i < cnt && aspath_cutasn(&pat, &asn) == 0) {
				i++;
				pasn[i] = asn;
				SKIPSPACE(pat);
				if (*pat == '-') {
					i++;
					pat++;
					SKIPSPACE(pat);
					pasn[i] = 0; /* range */
				}
			}
			SKIPSPACE(pat);
			assert(*pat == ']');
			assert(i == cnt);
			pat++;
			p->u.pasn = pasn;
			p->type = type;
		} else if (*pat == '.') {
			pat++;
			p->type = TYPE_ANY;
		} else if (aspath_cutasn(&pat, &asn) == 0) {
			p->u.asn = asn;
			p->type = TYPE_ASN;
		} else {
			_dp(5, (dp, "%s: `%c' unrecognized charactor\n",
				zz, *pat));
			aspath_regex_free(regex);
			return NULL;
		}

		/* special postfix charactor */
		if (*pat == '~') {
			p->flag = 1;
			pat++;
		}

		/* postfix - minimum and maximum number of repeat */
		if (*pat == '?') {
			pat++;
			p->mincnt = 0;
			p->maxcnt = 1;
		} else if (*pat == '*') {
			pat++;
			p->mincnt = 0;
			p->maxcnt = N_INFINITE; /* infinit */
		} else if (*pat == '+') {
			pat++;
			p->mincnt = 1;
			p->maxcnt = N_INFINITE;
		} else if (*pat == '{') {
			int val;

			pat++;
			if (!ISDIGIT(*pat)) {
				aspath_regex_free(regex);
				return NULL;
			}

			val = 0;
			do {
				val = val * 10 + (*pat - '0');
				pat++;
			} while (ISDIGIT(*pat)) ;
			p->mincnt = p->maxcnt = val;

			if (*pat == ',') {
				pat++;

				if (ISDIGIT(*pat)) {
					val = 0;
					do {
						val = val * 10 + (*pat - '0');
						pat++;
					} while (ISDIGIT(*pat)) ;
					p->maxcnt = val;
				} else {
					p->maxcnt = N_INFINITE;
				}
			}

			if (*pat != '}') {
				aspath_regex_free(regex);
				return NULL;
			}
			pat++;
		} else {
			p->mincnt = p->maxcnt = 1;
		}

		/* calculate length */
		switch (p->type) {
		case TYPE_BEGIN:
		case TYPE_END:
			p->minlen = 0;
			p->maxlen = 0;
			break;
		case TYPE_ANY:
		case TYPE_ASN:
		case TYPE_RANGE:
		case TYPE_NEG_RANGE:
			p->minlen = p->mincnt;
			p->maxlen = p->maxcnt;
			break;
		case TYPE_REGEXP:
			p->minlen = p->u.regex->minlen * p->mincnt;
			if (p->u.regex->maxlen == 0 || p->maxcnt == 0) {
				p->maxlen = 0;
			} else if (p->u.regex->maxlen == N_INFINITE) {
				p->maxlen = N_INFINITE;
			} else if (p->maxcnt == N_INFINITE) {
				p->maxlen = N_INFINITE;
			} else {
				p->maxlen = p->u.regex->maxlen * p->maxcnt;
			}
			break;
		default:
			abort();
			/* NOTREACHED */
		}

		/* update length */
		minlen += p->minlen;
		if (maxlen == N_INFINITE) {
			;
		} else if (p->maxlen == N_INFINITE) {
			maxlen = N_INFINITE;
		} else {
			maxlen += p->maxlen;
		}

		/* skip leading spaces */
		SKIPSPACE(pat);
	}

	/* store minimum and maximum length values */
	if (seg) {
		seg->minlen = minlen;
		seg->maxlen = maxlen;
	}

	/* check the number of segments */
	if (regex->n_segments < 1) {
		_lp(5, (dp, "%s: no segment found\n", zz));
		aspath_regex_free(regex);
		return NULL;
	}

	/* search minimam value and maximum value of length */
	minlen = regex->segments[0].minlen;
	maxlen = regex->segments[0].maxlen;
	for (i = 1; i < regex->n_segments; i++) {
		if (minlen > regex->segments[i].minlen) {
			minlen = regex->segments[i].minlen;
		}
		if (maxlen == N_INFINITE) {
			;
		} else if (regex->segments[i].maxlen == N_INFINITE) {
			maxlen = N_INFINITE;
		} else if (maxlen < regex->segments[i].maxlen) {
			maxlen = regex->segments[i].maxlen;
		}
	}

	/* store minlen and maxlen */
	regex->minlen = minlen;
	regex->maxlen = maxlen;

	/* restore the pointer */
	*ppat = pat;

	/* store string representation */
	regex_set_string(regex);

	/* and return success code */
	return regex;
}

/*
 */
ASPATH_regex *
aspath_regex_comp(const char *pat)
{
	static const char zz[] = "aspath_regex_comp";
	ASPATH_regex *rp;

	if (!(rp = aspath_regex_parse(&pat))) {
		_lp(6, (dp, "%s: failed to compile \"%s\"\n", zz, pat));
		return NULL;
	}

	/* and check end-of-string */
	if (*pat) {
		_lp(6, (dp, "%s: `%c' remains\n", zz, *pat));
		aspath_regex_free(rp);
		return NULL;
	}

	/* return success */
	return rp;
}

/* dump regexp patterns */
static const char *
regex_obj_set_string(struct regex_obj_t *op)
{
	static const char zz[] = "regex_obj_set_string";
	char rep[32], *prep;

	if (op->strregex) {
		return op->strregex;
	}

	/* check special charactor for postfix */
	if (op->flag) {
		rep[0] = '~';
		prep = &rep[1];
	} else {
		prep = &rep[0];
	}

	if (op->mincnt == 1 && op->maxcnt == 1) {
		rep[0] = '\0';
	} else if (op->mincnt == 0 && op->maxcnt == 1) {
		strcpy(prep, "?");
	} else if (op->mincnt == 0 && op->maxcnt == N_INFINITE) {
		strcpy(prep, "*");
	} else if (op->mincnt == 1 && op->maxcnt == N_INFINITE) {
		strcpy(prep, "+");
	} else if (op->mincnt == op->maxcnt) {
		sprintf(prep, "{%d}", op->mincnt);
	} else if (op->maxcnt == N_INFINITE) {
		sprintf(prep, "{%d,}", op->mincnt);
	} else {
		sprintf(prep, "{%d,%d}", op->mincnt, op->maxcnt);
	}

	/* put type in string format */
	switch (op->type) {
	case TYPE_BEGIN:
		if (!(op->strregex = STRDUP("^"))) {
			_lp(5, (dp, "%s: STRDUP\n", zz));
			return NULL;
		}
		break;
	case TYPE_END:
		if (!(op->strregex = STRDUP("$"))) {
			_lp(5, (dp, "%s: STRDUP\n", zz));
			return NULL;
		}
		break;
	case TYPE_ANY:
		if (!(op->strregex = MALLOC(strlen(rep) + 2))) {
			_lp(5, (dp, "%s: MALLOC\n", zz));
			return NULL;
		}
		sprintf(op->strregex, ".%s", rep);
		break;
	case TYPE_ASN:
		if (!(op->strregex = MALLOC(strlen(rep) + 8))) {
			_lp(5, (dp, "%s: MALLOC\n", zz));
			return NULL;
		}
		sprintf(op->strregex, "AS%d%s", op->u.asn, rep);
		break;
	case TYPE_RANGE:
	case TYPE_NEG_RANGE:
		if (op->u.pasn == NULL) {
			_lp(5, (dp, "%s: no pasn for range\n", zz));
			return NULL;
		} else {
			int len, sep, i, n;
			char *p;

			n = op->u.pasn[0];
			len = n * 8 + 5 + strlen(rep);

			if (!(op->strregex = MALLOC(len))) {
				_lp(5, (dp, "%s: MALLOC\n", zz));
				return NULL;
			}
			p = op->strregex;
			*p++ = '[';
			if (op->type == TYPE_NEG_RANGE) {
				*p++ = '^';
			}

			sep = 0;
			for (i = 0; i < n; i++) {
				if (op->u.pasn[i + 1] > 0) {
					if (sep) {
						*p++ = sep;
						sep = 0;
					}
					sprintf(p, "AS%d", op->u.pasn[i + 1]);
					ENDOFSTRING(p);
					sep = ' ';
				} else {
					sep = '-';
				}
			}
			assert(sep == 0 || sep == ' ');
			*p++ = ']';
			strcpy(p, rep);
		}
		break;
	case TYPE_REGEXP:
		if (!regex_set_string(op->u.regex)) {
			_lp(5, (dp, "%s: regex_set_string returns NULL\n",
				zz));
			return NULL;
		} else {
			int len;

			len = strlen(op->u.regex->strregex) + strlen(rep) + 3;
			op->strregex = MALLOC(len);
			sprintf(op->strregex, "(%s)%s",
				op->u.regex->strregex, rep);
		}
		break;
	default:
		_lp(5, (dp, "type=%d unrecognized, abort\n", op->type));
		abort();
		/* NOTREACHED */
	}

	/* result... */
	return op->strregex;
}

/**/
const char *
regex_seg_set_string(struct regex_seg_t *sp)
{
	static const char zz[] = "regex_seg_set_string";
	int i, sumlen = 0;
	char *bp;

	if (sp->strregex) {
		return sp->strregex;
	}

	for (i = 0; i < sp->n_objects; i++) {
		const char *cp;

		if (!(cp = regex_obj_set_string(&sp->objects[i]))) {
			_lp(5, (dp,
				"%s: obj_set_string[%d] returns null\n",
				zz, i));
			return NULL;
		}
		sumlen += strlen(cp) + 1;
	}

	if (!(sp->strregex = MALLOC(sumlen + 1))) {
		_lp(5, (dp, "%s: MALLOC - %s\n", zz, strerror(errno)));
		return NULL;
	}

	bp = sp->strregex;
	for (i = 0; i < sp->n_objects; i++) {
		if (i > 0) {
			*bp++ = ' ';
		}
		strcpy(bp, sp->objects[i].strregex);
		ENDOFSTRING(bp);
	}

	return sp->strregex;
}

/* string */
static const char *
regex_set_string(ASPATH_regex *rp)
{
	static const char zz[] = "regex_set_string";
	char *str;
	int i, sumlen;

	if (rp->strregex) {
		return rp->strregex;
	}

	for (i = sumlen = 0; i < rp->n_segments; i++) {
		if (!regex_seg_set_string(&rp->segments[i])) {
			_lp(5, (dp, "%s: regex_seg_set_string returns NULL\n",
				zz));
			return NULL;
		}
		sumlen += strlen(rp->segments[i].strregex) + 1;
	}

	if (!(rp->strregex = MALLOC(sumlen + 1))) {
		_lp(5, (dp, "%s: MALLOC - %s\n", zz, strerror(errno)));
		return NULL;
	}

	str = rp->strregex;
	for (i = 0; i < rp->n_segments; i++) {
		if (i > 0) {
			*str++ = '|';
		}
		strcpy(str, rp->segments[i].strregex);
		ENDOFSTRING(str);
	}

	return rp->strregex;
}

/* get string */
const char *
aspath_regex_string(const ASPATH_regex *regex)
{
	return regex->strregex;
}

/* dump regexp */
void
aspath_regex_dump(ASPATH_regex *rp)
{
	if (aspath_regex_string(rp)) {
		_dp(5, (dp, "%s\n", rp->strregex));
	}
}

/* check if asn is in the range */
static int
check_range(const struct regex_obj_t *p, u_short asn)
{
	int i, n;

	i = 0;
	n = p->u.pasn[0];
	while (i < n) {
		u_short tmpasn = p->u.pasn[i + 1];

		if (i + 2 < n && p->u.pasn[i + 2] == 0) {
			u_short tmpasn2 = p->u.pasn[i + 3];

			if (tmpasn >= tmpasn2) {
				u_short s;

				s = tmpasn;
				tmpasn = tmpasn2;
				tmpasn2 = s;
			}
			if (asn >= tmpasn && asn <= tmpasn2) {
				break; /* match */
			}
			i++, i++, i++;
		} else {
			if (asn == tmpasn) {
				break; /* just match */
			}
			i++;
		}
	}

	/* check result */
	if (i < n) { /* in the range  */
		if (p->type == TYPE_RANGE) {
			return 0; /* match */
		}
	} else { /* out of the range */
		if (p->type == TYPE_NEG_RANGE) {
			return 0; /* match */
		}
	}

	/* or no match */
	return -1;
}

/* regexp */
static int
check_multi_regex(
	const struct regex_obj_t *p,
	const ASPATH *info, int off, int len, int n)
{
#ifdef DEBUG
	static const char zz[] = "check_multi_regex";
#endif
	int i;
	int maxlen;
	ASPATH_regex *rp;

	/* logging */
	_dp(7, (dp, "%s <%s> min=%d max=%d info=%p off=%d len=%d, cnt=%d\n",
		zz, p->strregex,
		p->minlen, p->maxlen, info, off, len, n));

	/* verify variable ranges */
	assert(off >= 0);
	assert(len >= 0);
	assert(off + len <= aspath_hop_count(info));
	assert(n > 0);
	assert(p->type == TYPE_REGEXP);

	rp = p->u.regex;
	maxlen = len;
	if (rp->maxlen != N_INFINITE && rp->maxlen < len) {
		maxlen = rp->maxlen;
	}

	if (n == 1) {
		if (maxlen < len) {
			return -1;
		} else if (check_regex(rp, info, off, len)) {
			return -1;
		} else {
			return 0;
		}
	}

	for (i = maxlen; i > 0; i--) {
		if (check_regex(rp, info, off, i)) {
			continue;
		}
		/* or found */
		if (p->flag) {
			int nn, j;

			nn = len / i;
			if (len % i || nn < n || nn > n) {
				continue;
			}
			for (j = 1; j < nn ; j++) {
				if (memcmp(&info->pasn[off],
					&info->pasn[off + i * j], i * 2)) {
					break;
				}
			}
			if (j < nn) {
				break;
			}
			return 0; /* match */
		} else {
			if (!check_multi_regex(
				p, info, off + i, len - i, n - 1)) {
				return 0;
			}
		}
	}

	return -1;
}

/* check multiple any ASs */
static int
check_obj(const struct regex_obj_t *p, const ASPATH *info, int off, int len)
{
	static const char zz[] = "check_obj";
	int i;

	/* logging */
	_dp(7, (dp, "%s <%s> min=%d max=%d info=%p off=%d len=%d\n",
		zz, p->strregex,
		p->minlen, p->maxlen, info, off, len));

	/* assersion for debug purpose */
	assert(off >= 0);
	assert(len >= 0);
	assert(p->mincnt >= 0);
	assert(p->maxcnt == N_INFINITE || p->mincnt <= p->maxcnt);
	assert(p->minlen >= 0);
	assert(p->maxlen == N_INFINITE || p->minlen <= p->maxlen);

	/* check upper bound */
	if (p->maxlen != N_INFINITE && len > p->maxlen) {
		_lp(5, (dp, "%s: too large length=%d\n", zz, len));
		return -1; /* no match */
	}

	/* check lower bound */
	if (len < p->minlen) {
		_lp(5, (dp, "%s: too small len=%d\n", zz, len));
		return -1; /* no match */
	}

	/* special type - BEGIN */
	if (p->type == TYPE_BEGIN) {
		if (len == 0 && off == 0) {
			_dp(7, (dp, "%s: matches to begin\n", zz));
			return 0; /* match with len zero */
		} else {
			_dp(7, (dp, "%s: does not match to begin\n", zz));
			return -1; /* no match */
		}
	}

	/* special type - END */
	if (p->type == TYPE_END) {
		if (len == 0 && off == aspath_hop_count(info)) {
			_dp(7, (dp, "%s: matches to end\n", zz));
			return 0; /* match with len zero */
		} else {
			_dp(7, (dp, "%s: does not match to end\n", zz));
			return -1; /* no match */
		}
	}

	/* special case of len == 0 */
	if (len == 0) {
		/* len >= p->minlen and p->minlen >= 0 were checked */
		assert(p->minlen == 0);
		/* assert(p->mincnt == 0); */
		_dp(7, (dp, "%s: matches with len=zero\n", zz));
		return 0; /* success */
	}

	/* or check multiple times of regular expression */
	if (p->type == TYPE_ANY) {
		if (p->flag) {
			u_short asn = info->pasn[off];

			for (i = 1; i < len; i++) {
				if (info->pasn[off + i] != asn) {
					return -1; /* no match */
				}
			}
		}
		_dp(7, (dp, "%s: matches any len=%d\n", zz, len));
		return 0; /* match */
	}

	/* specified AS# */
	if (p->type == TYPE_ASN) {
		for (i = 0; i < len; i++) {
			if (info->pasn[off + i] != p->u.asn) {
				return -1; /* no match */
			}
		}
		_dp(7, (dp, "%s: matches asn len=%d\n", zz, len));
		return 0; /* match */
	}

	/* range of AS numbers */
	if (p->type == TYPE_RANGE || p->type == TYPE_NEG_RANGE) {
		if (p->flag) {
			u_short asn;

			if (check_range(p, info->pasn[off])) {
				return -1; /* no match */
			}
			asn = info->pasn[off];
			for (i = 1; i < len; i++) {
				if (info->pasn[off + i] != asn) {
					return -1;
				}
			}
		} else {
			for (i = 0; i < len; i++) {
				if (check_range(p, info->pasn[off + i])) {
					return -1; /* no match */
				}
			}
		}
		return 0;
	}

	/* regular expression is not supported */
	if (p->type == TYPE_REGEXP) {
		int maxcnt = p->maxcnt;

		if (maxcnt == N_INFINITE) {
			maxcnt = len;
		}
		for (i = maxcnt; i >= p->mincnt; i--) {
			if (i == 0) {
				return 0;
			}
			if (!check_multi_regex(p, info, off, len, i)) {
				return 0;
			}
		}
		return -1;
	}

	/* or unrecognized type */
	_lp(5, (dp, "%s: type=%d unrecognized, abort\n", zz, p->type));
	abort();
	/* NOTREACHED */
}

/* generate the first array of object length */
static int
plen_first(const struct regex_seg_t *sp, int *plen, int len)
{
	struct regex_obj_t *op;
	int i, spclen, sumlen;

#ifdef DEBUG
	/* caluclate sum of length */
	for (i = sumlen = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		plen[i] = op->minlen;
		sumlen += plen[i];
	}

	/* minimum length must be sum of minlen[i] */
	assert(sp->minlen == sumlen);
#endif

	/* sumlen must be less than the target length */
	assert(sp->minlen <= len);
	assert(sp->maxlen == N_INFINITE || sp->maxlen >= len);

	/* check space (this can be zero) */
	spclen = len - sp->minlen;

	/* update this segment */
	for (i = sumlen = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		int maxlen = op->maxlen;
		int minlen = op->minlen;

		/* for debug purpose only */
		assert(maxlen == N_INFINITE || minlen <= maxlen);

		/* check padding */
		if (maxlen == N_INFINITE) {
			break; /* can be large enouch */
		} else if (sumlen + maxlen - minlen >= spclen) {
			break; /* enough to achieve the first array */
		} else {
			sumlen += maxlen - minlen;
			plen[i] = maxlen;
		}
	}

	/* update this index */
	if (i < sp->n_objects) {
		/* padding at current index */
		plen[i] = spclen - sumlen + op->minlen;

		/* and fill remaining */
		for (i++, op++; i < sp->n_objects; i++, op++) {
			plen[i] = op->minlen;
		}
	}

#ifdef DEBUG
	/* validate the array */
	for (i = sumlen = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		assert(plen[i] >= op->minlen);
		assert(op->maxlen == N_INFINITE || plen[i] <= op->minlen);
		sumlen += plen[i];
	}
	assert(sumlen == len);
#endif

	/* return success value */
	return 0;
}

/* generate the first array of object length */
static int
plen_next(const struct regex_seg_t *sp, int *plen, int len)
{
	struct regex_obj_t *op;
	int i, hasspc, sumlen;

#ifdef DEBUG
	int minlen;

	/* caluclate sum of length */
	minlen = sumlen = 0;
	for (i = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		minlen += op->minlen;
		sumlen += plen[i];
	}

	/* verify this array */
	assert(sp->minlen == minlen);
	assert(len == sumlen);
#endif

	/* sumlen must be less than the target length */
	assert(sp->minlen <= len);
	assert(sp->maxlen == N_INFINITE || sp->maxlen >= len);

	/* copy sum of plen[i] */
	sumlen = len;

	/* update this segment */
	hasspc = 0;
	for (i = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		int maxlen = op->maxlen;
		int minlen = op->minlen;

		/* for debug purpose only */
		assert(maxlen == N_INFINITE || minlen <= maxlen);
		assert(maxlen == N_INFINITE || plen[i] <= maxlen);
		assert(plen[i] >= minlen);

		/* check padding */
		if (hasspc) {
			if (maxlen == N_INFINITE || maxlen > plen[i]) {
				break;
			}
		}
		if (plen[i] > minlen) {
			hasspc = 1;
			sumlen -= plen[i];
			plen[i] = minlen;
			sumlen += plen[i];
		}
	}

	/* check end-of-update */
	if (i >= sp->n_objects) {
		return -1;
	}

	/* or update this index */
	plen[i]++;
	sumlen++;

	/* and re-generate array */
	for (i = 0; sumlen < len && i < sp->n_objects; i++) {
		op = &sp->objects[i];

		if (op->maxlen == N_INFINITE) {
			plen[i] += len - sumlen;
			sumlen = len;
		} else if (op->maxlen - plen[i] >= len - sumlen) {
			plen[i] += len - sumlen;
			sumlen = len;
		} else if (op->maxlen > plen[i]) {
			sumlen -= plen[i];
			plen[i] = op->maxlen;
			sumlen += plen[i];
		} else {
			;
		}
	}

#ifdef DEBUG
	/* validate the array */
	for (i = sumlen = 0, op = sp->objects; i < sp->n_objects; i++, op++) {
		assert(plen[i] >= op->minlen);
		assert(op->maxlen == N_INFINITE || plen[i] <= op->maxlen);
		sumlen += plen[i];
	}
	assert(sumlen == len);
#endif

	/* return success value */
	return 0;
}

/* execute a regular expression */
static int
check_seg(
	const struct regex_seg_t *sp, const ASPATH *info, int off, int len)
{
	static const char zz[] = "check_seg";
	int tmplen[16], *ptrlen = NULL, *plen;
	int i, ret = -1;

	/* logging */
	_dp(7, (dp, "%s <%s> min=%d max=%d info=%p off=%d len=%d\n",
		zz, sp->strregex, sp->minlen, sp->maxlen,
		info, off, len));

	/* assertion */
	assert(off >= 0);
	assert(len >= 0);

	/* check special case */
	if (sp->n_objects < 1) {
		_dp(7, (dp, "%s matches by empty expression\n", zz));
		return 0; /* an empty expression matches to all */
	}

	/* check minimum length */
	if (sp->minlen > len) {
		_lp(5, (dp, "%s len=%d is smaller than minlen=%d\n",
			zz, len, sp->minlen));
		return -1;
	}

	/* we use an array for len */
	if (sp->n_objects > NUMBER(tmplen)) {
		if (!(ptrlen = MALLOC(sp->n_objects * sizeof(*ptrlen)))) {
			_lp(5, (dp, "%s: MALLOC - %s\n", zz, strerror(errno)));
			return -1;
		}
		plen = ptrlen;
	} else {
		plen = tmplen;
	}

	/* initial values */
	if (plen_first(sp, plen, len) < 0) {
		_lp(5, (dp, "%s: plen_first returns -1\n", zz));
		return -1;
	}

	for (;;) {
		int offtmp = off, match = 1;

#ifdef DEBUG
{
	int k;

	_dp(7, (dp, "%s segment = {", zz));
	for (k = 0; k < sp->n_objects; k++) {
		_dp(7, (dp, "%s %d", (k > 0 ? "," : ""), plen[k]));
	}
	_dp(7, (dp, " }\n"));
}
#endif

		/* check... */
		for (i = 0; i < sp->n_objects; i++) {
			struct regex_obj_t *p = &sp->objects[i];

			if (check_obj(p, info, offtmp, plen[i])) {
				match = 0;
				break;
			}
			offtmp += plen[i];
		}

		/* result */
		if (match) {
			assert(offtmp == off + len);
			ret = 0;
			_dp(7, (dp, "%s matches, return o.k.\n", zz));
			break;
		}

		/* update this segment */
		if (plen_next(sp, plen, len) < 0) {
			_dp(7, (dp, "%s no more update, break loop\n", zz));
			break; /* done */
		}
	}

	/* free temporary array if we used */
	if (ptrlen) {
		FREE(ptrlen);
	}

	/* return result */
	_dp(7, (dp, "%s returns %d\n", zz, ret));
	return ret;
}

/* execute regular expressions in alternative */
static int
check_regex(const ASPATH_regex *regex, const ASPATH *info, int off, int len)
{
#ifdef DEBUG
	static const char zz[] = "check_regex";
#endif
	int i;

	for (i = 0; i < regex->n_segments; i++) {
		const struct regex_seg_t *sp = &regex->segments[i];

		if (sp->minlen > len) {
			_dp(7, (dp,
				"%s seg=<%s> off=%d len=%d min=%d skipped\n",
				zz, sp->strregex, off, len, sp->minlen));
		} else if (sp->maxlen != N_INFINITE && sp->maxlen < len) {
			_dp(7, (dp,
				"%s seg=<%s> off=%d len=%d max=%d skipped\n",
				zz, sp->strregex, off, len, sp->maxlen));
		} else if (!check_seg(sp, info, off, len)) {
			_dp(7, (dp, "%s seg=<%s> off=%d len=%d matches\n",
				zz, sp->strregex, off, len));
			return 0; /* match */
		}
	}

	/* debug log */
	_dp(7, (dp, "%s regex=<%s> off=%d len=%d no match\n",
		zz, regex->strregex, off, len));

	/* return no match */
	return -1;
}

/* execute regular expression */
int
aspath_regex_exec(const ASPATH_regex *rp, const ASPATH *info)
{
#ifdef DEBUG
	static const char zz[] = "aspath_regex_exec";
	char tmp[512];
#endif
	int off, len, hop_count;

	/* for debug purpose only */
#ifdef DEBUG
	/* aspath_print(info, tmp, sizeof(tmp)); XXX temporary commented out 
	   -- Kunihiro Ishiguro <kunihiro@zebra.org> */
#endif

	/* debug log before compare */
	_dp(7, (dp, "%s aspath=<%s> regexp=<%s> min=%d max=%d\n",
		zz, tmp, aspath_regex_string(rp), rp->minlen, rp->maxlen));

	/* initial offset */
	off = 0;

	/* store hop count first */
	hop_count = aspath_hop_count(info);

	/* check the maximum length of expression */
	len = hop_count;
	if (rp->maxlen != N_INFINITE && rp->maxlen < len) {
		len = rp->maxlen;
	}

	/* longer posion is prefered */
	for (; len >= rp->minlen; len--) {
		for (off = 0; off + len <= hop_count; off++) {
			if (!check_regex(rp, info, off, len)) {
				break;
			}
		}
		if (off + len <= hop_count) {
			break;
		}
	}

	/* check the result */
	if (len >= rp->minlen) {
		_dp(7, (dp,
			"%s aspath=<%s> off=%d len=%d matches regexp=<%s>\n",
			zz, tmp, off, len, aspath_regex_string(rp)));
		return 0; /* match */
	} else {
		_dp(7, (dp,
			"%s aspath=<%s> does NOT match regexp=<%s>\n",
			zz, tmp, aspath_regex_string(rp)));
		return -1; /* no match */
	}
}
