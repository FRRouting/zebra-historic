## Process this file with automake to produce Makefile.in.

INCLUDES = -I.. -I$(srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

LIB_IPV6 = @LIB_IPV6@

ipforward = @IPFORWARD@
if_method = @IF_METHOD@
rt_method = @RT_METHOD@
rtread_method = @RTREAD_METHOD@
krt_method = @KERNEL_METHOD@

otherobj = $(ipforward) $(if_method) $(rt_method) $(krt_method) \
	$(rtread_method)

sbin_PROGRAMS = zebra client

zebra_SOURCES = \
	zebra.c main.c if.c ifa.c ioctl.c rib.c redistribute.c rtable.c

zebra_LDADD = ../lib/libzebra.a $(otherobj)

client_SOURCES = \
	client_main.c

sysconf_DATA = zebra.conf.sample

zebra : $(zebra_OBJECTS) $(otherobj) ../lib/libzebra.a
	$(CC) -g -o zebra $(zebra_OBJECTS) $(otherobj) ../lib/libzebra.a $(LIBS) $(LIB_IPV6)

client : client_main.o ../lib/libzebra.a
	$(CC) -g -o client client_main.o ../lib/libzebra.a $(LIBS) $(LIB_IPV6)
