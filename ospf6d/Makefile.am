## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libospf6.a
sbin_PROGRAMS = ospf6d

libospf6_a_SOURCES = \
	ospf6_dump.c ospf6d.c ospf6_interface.c ospf6_network.c \
	ospf6_neighbor.c ospf6_mesg.c ospf6_lsa.c ospf6_spf.c ospf6_zebra.c

noinst_HEADERS = \
	ospf6_area.h ospf6_dump.h ospf6_interface.h ospf6_lsa.h \
	ospf6_mesg.h ospf6_neighbor.h ospf6_network.h ospf6_proto.h \
	ospf6_spf.h ospf6_types.h ospf6_zebra.h ospf6d.h

ospf6d_SOURCES = \
	ospf6_main.c $(libospf6_a_SOURCES)

ospf6d_LDADD = ../lib/libzebra.a

sysconf_DATA = ospf6d.conf.sample

EXTRA_DIST = $(sysconf_DATA)

install-sysconfDATA: $(sysconf_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@list='$(sysconf_DATA)'; for p in $$list; do \
	  if test -f $(srcdir)/$$p; then \
	    echo " $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p; \
	  else if test -f $$p; then \
	    echo " $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p; \
	  fi; fi; \
	done
