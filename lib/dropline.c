/* Drop line from stdio. -- Kunihiro Ishiguro <kunihiro@zebra.org> */

#include <stdio.h>

void
dropline (FILE *fp)
{
  int c;

  while ((c = getc (fp)) != '\n')
    ;
}
