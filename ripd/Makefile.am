## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir)/lib -I$(top_srcdir)/zebra
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

sbin_PROGRAMS = ripd

ripd_SOURCES = \
	rip_main.c ripd.c rip_zebra.c rip_interface.c

ripd_LDADD = ../lib/libzebra.a

sysconf_DATA = ripd.conf.sample
