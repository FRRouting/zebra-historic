/*
 * $Id: roken.h,v 1.2 1999/02/19 17:01:49 developer Exp $
 *
 * Copyright (C) 1998 by Magnus Ahltorp 
 */

#ifdef HAVE_REPAIRABLE_HTONL
#define htonl(x) __cpu_to_be32(x)
#define ntohl(x) __be32_to_cpu(x)
#define htons(x) __cpu_to_be16(x)
#define ntohs(x) __be16_to_cpu(x)
#endif
