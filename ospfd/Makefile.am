## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libospf.a
sbin_PROGRAMS = ospfd

libospf_a_SOURCES = \
	ospfd.c ospf_zebra.c ospf_interface.c ospf_ism.c ospf_neighbor.c \
	ospf_nsm.c ospf_dump.c ospf_network.c ospf_packet.c

noinst_HEADERS = \
	ospf_dump.h ospf_interface.h ospf_ism.h ospf_neighbor.h \
	ospf_network.h ospf_nsm.h ospf_packet.h ospf_zebra.h ospfd.h

ospfd_SOURCES = \
	ospf_main.c $(libospf_a_SOURCES)

ospfd_LDADD = ../lib/libzebra.a

sysconf_DATA = ospfd.conf.sample

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

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

## File dependency.
ospfd.o: ospfd.c ../lib/thread.h ../lib/vty.h ../lib/command.h \
 ../lib/vector.h ../lib/linklist.h ../lib/prefix.h ../lib/table.h \
 ../lib/if.h ../lib/memory.h ../lib/log.h ../ospfd/ospfd.h \
 ../ospfd/ospf_network.h ../ospfd/ospf_dump.h \
 ../ospfd/ospf_interface.h ../ospfd/ospf_ism.h ../ospfd/ospf_zebra.h
ospf_dump.o: ospf_dump.c ../lib/thread.h ../lib/log.h ../ospfd/ospfd.h \
 ../ospfd/ospf_interface.h ../ospfd/ospf_ism.h ../ospfd/ospf_dump.h
ospf_interface.o: ospf_interface.c ../lib/linklist.h ../lib/prefix.h \
 ../lib/if.h ../lib/memory.h ../lib/command.h ../lib/vector.h \
 ../lib/vty.h ../lib/thread.h ../lib/stream.h ../lib/log.h \
 ../ospfd/ospfd.h ../ospfd/ospf_interface.h ../ospfd/ospf_ism.h \
 ../ospfd/ospf_packet.h ../zebra/zebra.h
ospf_ism.o: ospf_ism.c ../lib/thread.h ../lib/linklist.h ../lib/if.h \
 ../lib/log.h ../ospfd/ospfd.h ../ospfd/ospf_interface.h \
 ../ospfd/ospf_ism.h ../ospfd/ospf_dump.h
ospf_main.o: ospf_main.c ../lib/version.h ../lib/getopt.h \
 ../lib/linklist.h ../lib/if.h ../lib/vector.h ../lib/vty.h \
 ../lib/command.h ../lib/thread.h ../lib/log.h \
 ../ospfd/ospf_interface.h ../ospfd/ospfd.h ../zebra/zebra.h
ospf_network.o: ospf_network.c ../lib/thread.h ../lib/log.h \
 ../lib/linklist.h ../lib/if.h ../lib/prefix.h ../ospfd/ospfd.h \
 ../ospfd/ospf_packet.h ../ospfd/ospf_network.h
ospf_packet.o: ospf_packet.c ../lib/linklist.h ../lib/prefix.h \
 ../lib/if.h ../lib/thread.h ../lib/stream.h ../lib/log.h \
 ../ospfd/ospfd.h ../ospfd/ospf_interface.h ../ospfd/ospf_packet.h
ospf_zebra.o: ospf_zebra.c ../lib/vector.h ../lib/memory.h \
 ../lib/thread.h ../lib/buffer.h ../lib/network.h ../lib/prefix.h \
 ../lib/linklist.h ../lib/client.h ../lib/stream.h ../lib/command.h \
 ../lib/vty.h ../lib/if.h ../lib/log.h ../zebra/zebra.h \
 ../ospfd/ospfd.h ../ospfd/ospf_interface.h ../ospfd/ospf_ism.h \
 ../ospfd/ospf_zebra.h
