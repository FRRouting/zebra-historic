/*
 * $Id: pid_output.c,v 1.4 1999/02/19 17:01:48 developer Exp $
 */

#include <zebra.h>

pid_t
pid_output (char *path)
{
  FILE *fp;
  pid_t pid;

  pid = getpid();

  fp = fopen (path, "w");
  if (fp != NULL) {
    fprintf (fp, "%d\n", pid);
    fclose (fp);
    return -1;
  }

  return pid;
}
