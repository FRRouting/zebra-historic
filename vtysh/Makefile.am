## Process this file with Automake to create Makefile.in

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -I. -I$(srcdir)

LIBS = @LIBS@ @CURSES@

bin_PROGRAMS = vtysh

vtysh_SOURCES = vtysh.c vtysh_cmd.c
noinst_HEADERS = vtysh.h
vtysh_LDADD = ../lib/libzebra.a

EXTRA_DIST = extract.pl

rebuild:
	./extract.pl ../zebra/*.c ../ripd/*.c ../ripngd/*.c ../ospfd/*.c ../ospf6d/*.c ../bgpd/*.c >vtysh_cmd.c

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

## File dependency.
vtysh.o: vtysh.c ../lib/version.h ../lib/command.h ../lib/vector.h \
 ../lib/vty.h ../vtysh/vtysh.h
vtysh_cmd.o: vtysh_cmd.c ../lib/command.h ../lib/vector.h ../lib/vty.h \
 vtysh.h
