/*
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
