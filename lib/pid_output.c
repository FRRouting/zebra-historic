#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

pid_t
pid_output (path)
     char *path;
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
