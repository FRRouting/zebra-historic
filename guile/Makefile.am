## Process this file with Automake to create Makefile.in

INCLUDES = @GUILE_CFLAGS@
DEFS = @DEFS@ -DPACKAGE=\"zebra-guile\" -DVERSION=\"@VERSION@\" -DHAVE_LIBDL=1  -I. -I$(srcdir)

bin_PROGRAMS = zebra-guile
zebra_guile_SOURCES = zebra-guile.c
zebra_guile_LDADD = @GUILE_LDFLAGS@ ../bgpd/libbgp.a ../lib/libzebra.a
