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
	zebra.c main.c interface.c connected.c ioctl.c rib.c redistribute.c

zebra_LDADD = ../lib/libzebra.a $(otherobj)

client_SOURCES = \
	client_main.c

sysconf_DATA = zebra.conf.sample

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
