## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir)/lib -I$(top_srcdir)/zebra
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

sbin_PROGRAMS = ospfd

ospfd_SOURCES = \
	ospf_main.c ospfd.c

ospfd_LDADD = ../lib/libzebra.a

sysconf_DATA = ospfd.conf.sample
