## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = librip.a
sbin_PROGRAMS = ripd

librip_a_SOURCES = \
	ripd.c rip_zebra.c rip_interface.c rip_debug.c rip_snmp.c \
	rip_routemap.c

noinst_HEADERS = \
	ripd.h rip_debug.h

ripd_SOURCES = \
	rip_main.c $(librip_a_SOURCES)

ripd_LDADD = ../lib/libzebra.a

sysconf_DATA = ripd.conf.sample

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
ripd.o: ripd.c ../lib/if.h ../lib/linklist.h ../lib/command.h \
 ../lib/vector.h ../lib/vty.h ../lib/prefix.h ../lib/table.h \
 ../lib/thread.h ../lib/memory.h ../lib/roken.h ../lib/log.h \
 ../lib/stream.h ../lib/filter.h ../lib/sockunion.h ../lib/routemap.h \
 ../zebra/zebra.h ../ripd/ripd.h ../ripd/rip_debug.h
rip_debug.o: rip_debug.c ../lib/command.h ../lib/vector.h ../lib/vty.h \
 ../ripd/rip_debug.h
rip_interface.o: rip_interface.c ../zebra/zebra.h ../lib/command.h \
 ../lib/vector.h ../lib/vty.h ../lib/if.h ../lib/linklist.h \
 ../lib/sockunion.h ../lib/prefix.h ../lib/memory.h ../lib/network.h \
 ../lib/table.h ../lib/roken.h ../lib/log.h ../lib/stream.h \
 ../lib/thread.h ../lib/zclient.h ../lib/client.h ../lib/filter.h \
 ../zebra/connected.h ../ripd/ripd.h ../ripd/rip_debug.h
rip_main.o: rip_main.c ../lib/version.h ../lib/thread.h \
 ../lib/vector.h ../lib/vty.h ../lib/command.h ../lib/memory.h \
 ../lib/prefix.h ../lib/log.h ../lib/filter.h ../lib/if.h \
 ../lib/linklist.h ../zebra/zebra.h ../ripd/ripd.h
rip_routemap.o: rip_routemap.c ../zebra/zebra.h ../lib/memory.h \
 ../lib/prefix.h ../lib/routemap.h ../lib/command.h ../lib/vector.h \
 ../lib/vty.h ../lib/filter.h ../lib/if.h ../lib/linklist.h \
 ../lib/log.h ../ripd/ripd.h
rip_snmp.o: rip_snmp.c
rip_zebra.o: rip_zebra.c ../zebra/zebra.h ../lib/thread.h \
 ../lib/command.h ../lib/vector.h ../lib/vty.h ../lib/prefix.h ripd.h \
 ../lib/if.h ../lib/linklist.h ../lib/buffer.h ../lib/network.h \
 ../lib/client.h ../lib/stream.h ../lib/log.h ../lib/zclient.h \
 ../lib/routemap.h ../ripd/rip_debug.h
