## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

LIB_IPV6 = @LIB_IPV6@

ipforward = @IPFORWARD@
if_method = @IF_METHOD@
rt_method = @RT_METHOD@
rtread_method = @RTREAD_METHOD@

otherobj = $(ipforward) $(if_method) $(rt_method) $(rtread_method)

sbin_PROGRAMS = zebra client

zebra_SOURCES = \
	zebra.c main.c interface.c connected.c ioctl.c rib.c redistribute.c \
	debug.c

noinst_HEADERS = \
	connected.h ioctl.h rib.h rt.h zebra.h redistribute.h debug.h

zebra_LDADD = ../lib/libzebra.a $(otherobj)

client_SOURCES = \
	client_main.c

sysconf_DATA = zebra.conf.sample

EXTRA_DIST = $(sysconf_DATA) if_ioctl.c if_netlink.c if_proc.c if_sysctl.c \
	ipforward_aix.c ipforward_ews.c ipforward_proc.c \
	ipforward_solaris.c ipforward_sysctl.c rt_ioctl.c rt_netlink.c \
	rt_socket.c rtread_netlink.c rtread_proc.c rtread_sysctl.c

zebra : $(zebra_OBJECTS) $(otherobj) ../lib/libzebra.a
	$(CC) -g -o zebra $(zebra_OBJECTS) $(otherobj) ../lib/libzebra.a $(LIBS) $(LIB_IPV6)

client : client_main.o ../lib/libzebra.a
	$(CC) -g -o client client_main.o ../lib/libzebra.a $(LIBS) $(LIB_IPV6)

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
client_main.o: client_main.c ../zebra/zebra.h ../lib/prefix.h \
 ../lib/client.h
connected.o: connected.c ../zebra/zebra.h ../lib/prefix.h \
 ../lib/linklist.h ../lib/if.h rib.h
debug.o: debug.c ../lib/command.h ../lib/vector.h ../lib/vty.h debug.h
if_ioctl.o: if_ioctl.c ../lib/linklist.h ../lib/if.h \
 ../lib/sockunion.h ../lib/prefix.h ../lib/memory.h ../lib/log.h \
 ioctl.h ../lib/dropline.h connected.h
if_netlink.o: if_netlink.c
if_proc.o: if_proc.c
if_sysctl.o: if_sysctl.c ../lib/linklist.h ../lib/sockunion.h \
 ../lib/if.h ../lib/prefix.h connected.h ../lib/memory.h ioctl.h \
 ../lib/log.h
interface.o: interface.c ../lib/linklist.h ../lib/if.h ../lib/vty.h \
 ../lib/sockunion.h ../lib/prefix.h ../lib/vector.h ../lib/command.h \
 ../lib/memory.h ioctl.h connected.h
ioctl.o: ioctl.c ../lib/linklist.h ../lib/if.h ../lib/prefix.h ioctl.h \
 rt.h ../lib/log.h
ipforward_aix.o: ipforward_aix.c
ipforward_ews.o: ipforward_ews.c
ipforward_proc.o: ipforward_proc.c ../lib/dropline.h
ipforward_solaris.o: ipforward_solaris.c ../lib/memory.h
ipforward_sysctl.o: ipforward_sysctl.c ../lib/log.h
main.o: main.c ../zebra/zebra.h ../lib/version.h ../lib/command.h \
 ../lib/vector.h ../lib/vty.h ../lib/thread.h ../lib/filter.h \
 ../lib/if.h ../lib/linklist.h ../lib/memory.h ../lib/prefix.h \
 ../lib/log.h ../zebra/debug.h ../zebra/rib.h
redistribute.o: redistribute.c ../lib/vector.h ../lib/vty.h \
 ../lib/command.h ../lib/prefix.h ../lib/table.h ../lib/stream.h \
 ../lib/client.h ../lib/linklist.h ../zebra/zebra.h ../zebra/rib.h \
 ../zebra/redistribute.h
rib.o: rib.c ../lib/prefix.h ../lib/table.h ../lib/memory.h \
 ../lib/vector.h ../lib/vty.h ../lib/str.h ../lib/command.h \
 ../lib/linklist.h ../lib/if.h rib.h rt.h ../lib/log.h \
 ../zebra/zebra.h ../zebra/redistribute.h
rt_ioctl.o: rt_ioctl.c ../zebra/zebra.h ../lib/prefix.h ../lib/log.h
rt_netlink.o: rt_netlink.c ../lib/linklist.h ../lib/if.h ../lib/log.h \
 ../zebra/zebra.h ../lib/prefix.h connected.h rib.h ../lib/thread.h
rtread_netlink.o: rtread_netlink.c
rtread_proc.o: rtread_proc.c ../zebra/zebra.h ../lib/prefix.h \
 ../lib/log.h rib.h
rtread_sysctl.o: rtread_sysctl.c ../lib/prefix.h ../lib/sockunion.h \
 ../lib/memory.h ../lib/str.h rib.h ../lib/log.h ../zebra/zebra.h
rt_socket.o: rt_socket.c ../zebra/zebra.h ../lib/thread.h \
 ../lib/prefix.h ../lib/sockunion.h ../lib/log.h ../lib/linklist.h \
 ../lib/if.h
zebra.o: zebra.c ../lib/prefix.h ../lib/linklist.h ../lib/command.h \
 ../lib/vector.h ../lib/vty.h ../lib/if.h ../lib/thread.h \
 ../lib/stream.h ../lib/buffer.h ../lib/memory.h rib.h ../lib/roken.h \
 ../lib/network.h ../lib/sockunion.h ../lib/log.h ../lib/table.h \
 ../zebra/zebra.h ../zebra/redistribute.h ../zebra/debug.h
