/*
 * $Id: dropline.c,v 1.3 1999/02/19 17:01:47 developer Exp $
 *
 * Drop line from stdio. -- Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 */

#include <zebra.h>

void
dropline (FILE *fp)
{
  int c;

  while ((c = getc (fp)) != '\n')
    ;
}
