## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir)/lib -I$(top_srcdir)/zebra
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

sbin_PROGRAMS = ripngd

ripngd_SOURCES = \
	ripng_main.c ripng_interface.c ripngd.c ripng_zebra.c ripng_route.c \
	ripng_debug.c

ripngd_LDADD = ../lib/libzebra.a

sysconf_DATA = ripngd.conf.sample
