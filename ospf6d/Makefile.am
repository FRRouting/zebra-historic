## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libospf6.a
sbin_PROGRAMS = ospf6d

libospf6_a_SOURCES = \
	ospf6_dump.c ospf6d.c ospf6_interface.c ospf6_network.c \
	ospf6_neighbor.c ospf6_mesg.c ospf6_lsa.c ospf6_spf.c \
	ospf6_rtable.c ospf6_zebra.c ospf6_ism.c ospf6_dbex.c \
	ospf6_lsdb.c

noinst_HEADERS = \
	ospf6_area.h ospf6_dump.h ospf6_interface.h ospf6_lsa.h \
	ospf6_mesg.h ospf6_neighbor.h ospf6_network.h ospf6_proto.h \
	ospf6_spf.h ospf6_rtable.h ospf6_types.h ospf6_zebra.h ospf6d.h \
	ospf6_rtable.h ospf6_ism.h ospf6_dbex.h ospf6_lsdb.h

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

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

## File dependency.
ospf6_dbex.o: ospf6_dbex.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6d.o: ospf6d.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_dump.o: ospf6_dump.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_interface.o: ospf6_interface.c ospf6d.h ../zebra/zebra.h \
 ../lib/version.h ../lib/log.h ../lib/vty.h ../lib/linklist.h \
 ../lib/thread.h ../lib/vector.h ../lib/command.h ../lib/memory.h \
 ../lib/sockunion.h ../lib/if.h ../lib/prefix.h ../lib/stream.h \
 ../lib/filter.h ../lib/client.h ../lib/zclient.h ospf6_types.h \
 ospf6_interface.h ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h \
 ospf6_spf.h ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_ism.o: ospf6_ism.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_lsa.o: ospf6_lsa.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_lsdb.o: ospf6_lsdb.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_main.o: ospf6_main.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_mesg.o: ospf6_mesg.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_neighbor.o: ospf6_neighbor.c ospf6d.h ../zebra/zebra.h \
 ../lib/version.h ../lib/log.h ../lib/vty.h ../lib/linklist.h \
 ../lib/thread.h ../lib/vector.h ../lib/command.h ../lib/memory.h \
 ../lib/sockunion.h ../lib/if.h ../lib/prefix.h ../lib/stream.h \
 ../lib/filter.h ../lib/client.h ../lib/zclient.h ospf6_types.h \
 ospf6_interface.h ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h \
 ospf6_spf.h ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_network.o: ospf6_network.c ospf6d.h ../zebra/zebra.h \
 ../lib/version.h ../lib/log.h ../lib/vty.h ../lib/linklist.h \
 ../lib/thread.h ../lib/vector.h ../lib/command.h ../lib/memory.h \
 ../lib/sockunion.h ../lib/if.h ../lib/prefix.h ../lib/stream.h \
 ../lib/filter.h ../lib/client.h ../lib/zclient.h ospf6_types.h \
 ospf6_interface.h ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h \
 ospf6_spf.h ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_rtable.o: ospf6_rtable.c ospf6d.h ../zebra/zebra.h \
 ../lib/version.h ../lib/log.h ../lib/vty.h ../lib/linklist.h \
 ../lib/thread.h ../lib/vector.h ../lib/command.h ../lib/memory.h \
 ../lib/sockunion.h ../lib/if.h ../lib/prefix.h ../lib/stream.h \
 ../lib/filter.h ../lib/client.h ../lib/zclient.h ospf6_types.h \
 ospf6_interface.h ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h \
 ospf6_spf.h ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_spf.o: ospf6_spf.c ospf6d.h ../zebra/zebra.h ../lib/version.h \
 ../lib/log.h ../lib/vty.h ../lib/linklist.h ../lib/thread.h \
 ../lib/vector.h ../lib/command.h ../lib/memory.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h ../lib/stream.h ../lib/filter.h \
 ../lib/client.h ../lib/zclient.h ospf6_types.h ospf6_interface.h \
 ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h ospf6_spf.h \
 ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
ospf6_zebra.o: ospf6_zebra.c ospf6d.h ../zebra/zebra.h \
 ../lib/version.h ../lib/log.h ../lib/vty.h ../lib/linklist.h \
 ../lib/thread.h ../lib/vector.h ../lib/command.h ../lib/memory.h \
 ../lib/sockunion.h ../lib/if.h ../lib/prefix.h ../lib/stream.h \
 ../lib/filter.h ../lib/client.h ../lib/zclient.h ospf6_types.h \
 ospf6_interface.h ospf6_ism.h ospf6_lsa.h ospf6_lsdb.h ospf6_dbex.h \
 ospf6_spf.h ospf6_rtable.h ospf6_area.h ospf6_mesg.h ospf6_dump.h \
 ospf6_neighbor.h ospf6_network.h ospf6_proto.h ospf6_zebra.h
