/* Zebra guile interface.
   Copyright (C) 1998, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <libguile.h>
#include <guile/gh.h>

static SCM scm_mark_bgp (SCM obj);
static size_t scm_free_bgp (SCM vect);
static int scm_print_bgp (SCM vect, SCM port, scm_print_state *pstate);
static SCM scm_equalp_bgp (SCM a, SCM b);

/* Tag of scheme type of bgp. */
long scm_tag_bgp;

static scm_smobfuns bgp_funs =
{
  scm_mark0, scm_free_bgp, scm_print_bgp, scm_equalp_bgp
};

static int
scm_print_bgp (SCM vect, SCM port, scm_print_state *pstate)
{
  long num;

  num = (long) SCM_CDR (vect);
  scm_puts ("#<bgp ", port);
  scm_intprint (num, 10, port);
  scm_putc ('>', port);
  return 1;
}

static size_t
scm_free_bgp (SCM obj)
{
  /* dummy function. */
  return 10;
}

static SCM
scm_equalp_bgp (SCM a, SCM b)
{
  
  return SCM_BOOL_F;
}

/* Make bgp instance. */
SCM
scm_router_bgp (SCM as_number)
{
  SCM cell;
  long num;

  SCM_ASSERT (SCM_INUMP (as_number), as_number, SCM_ARG1, "router-bgp");

  SCM_DEFER_INTS;

  num = gh_scm2long (as_number);
  SCM_NEWCELL (cell);
  SCM_SETCAR (cell, scm_tag_bgp);
  SCM_SETCDR (cell, num);

  SCM_ALLOW_INTS;

  return cell;
}

static void
init_bgp ()
{
  scm_tag_bgp  = scm_newsmob (&bgp_funs);
}

/* Install scheme procudures. */
void
init_guile_zebra ()
{
  void hoge_init ();

  init_bgp ();

  gh_new_procedure ("router-bgp", scm_router_bgp, 1, 0, 0);

#if 0
  hoge_init ();
  cmd_init ();
  vty_init ();
  memory_init ();

  bgp_init ();
#endif
}

void
main_prog (int argc, char **argv)
{
  /* Install zebra related scheme procedures. */
  init_guile_zebra ();

  /* Invoke interpreter. */
  gh_repl (argc, argv);

  exit (0);
}

int
main (int argc, char **argv)
{
  /* hoge_init (); */

  /* Guile high-level library entry point. */
  gh_enter (argc, argv, main_prog);

  /* Not reached */
  return 0;			
}
