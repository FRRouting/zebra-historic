## Process this file with automake to produce Makefile.in.

INCLUDES = -I.. -I$(top_srcdir)/lib -I$(top_srcdir)/zebra
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

sbin_PROGRAMS = bgpd

bgpd_SOURCES = \
	bgp_main.c bgpd.c bgp_fsm.c bgp_aspath.c bgp_community.c bgp_attr.c \
	bgp_peer.c bgp_dump.c bgp_view.c bgp_route.c bgp_zebra.c bgp_open.c \
	bgp_routemap.c aspath_regex.c

bgpd_LDADD = ../lib/libzebra.a

sysconf_DATA = bgpd.conf.sample
