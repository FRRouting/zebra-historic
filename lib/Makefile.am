## Process this file with automake to produce Makefile.in.

INCLUDES = -I$(top_srcdir)/zebra @INCLUDES@

noinst_LIBRARIES = libzebra.a

libzebra_a_SOURCES = \
	version.c network.c pid_output.c getopt.c getopt1.c daemon.c \
	print_version.c log.c checksum.c multicast.c vector.c linklist.c \
	dropline.c vty.c command.c host.c sockunion.c radix.c route.c \
	route.c thread.c if.c memory.c buffer.c buffer.c table.c client.c \
	hash.c filter.c routemap.c

version.c: Makefile
	echo '' >version.c
	echo 'char *host_name = "$(host_alias)";' >>version.c
