## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

noinst_LIBRARIES = libzebra.a

libzebra_a_SOURCES = \
	version.c network.c pid_output.c getopt.c getopt1.c daemon.c \
	print_version.c checksum.c vector.c linklist.c dropline.c \
	vty.c command.c sockunion.c prefix.c thread.c if.c memory.c \
	buffer.c buffer.c table.c client.c hash.c filter.c routemap.c \
	distribute.c stream.c str.c log.c regex.c plist.c zclient.c

noinst_HEADERS = \
	buffer.h client.h command.h dropline.h filter.h getopt.h hash.h \
	if.h linklist.h log.h memory.h network.h prefix.h regex-gnu.h \
	roken.h routemap.h sockunion.h str.h stream.h table.h thread.h \
	vector.h version.h vty.h zebra.h plist.h zclient.h

version.c: Makefile
	echo '' >version.c
	echo 'char *host_name = "$(host_alias)";' >>version.c

depend:
	@$(CPP) -MM $(INCLUDES) $(LDFLAGS) *.c

## File dependency.
buffer.o: buffer.c memory.h buffer.h roken.h
checksum.o: checksum.c
client.o: client.c ../zebra/zebra.h prefix.h client.h stream.h \
 network.h roken.h
command.o: command.c vector.h vty.h command.h memory.h log.h version.h
daemon.o: daemon.c
distribute.o: distribute.c hash.h linklist.h if.h filter.h memory.h \
 vector.h vty.h command.h
dropline.o: dropline.c
filter.o: filter.c prefix.h filter.h memory.h vector.h vty.h command.h
getopt1.o: getopt1.c getopt.h
getopt.o: getopt.c
hash.o: hash.c hash.h memory.h log.h
if.o: if.c linklist.h vector.h vty.h command.h if.h sockunion.h \
 prefix.h ../zebra/connected.h memory.h buffer.h str.h log.h
linklist.o: linklist.c linklist.h memory.h
log.o: log.c log.h memory.h
memory.o: memory.c log.h memory.h vector.h vty.h command.h
network.o: network.c
pid_output.o: pid_output.c
plist.o: plist.c prefix.h command.h vector.h vty.h memory.h plist.h
prefix.o: prefix.c prefix.h vty.h sockunion.h memory.h log.h
print_version.o: print_version.c version.h
regex.o: regex.c regex-gnu.h
routemap.o: routemap.c linklist.h memory.h vector.h prefix.h \
 routemap.h vty.h command.h
sockunion.o: sockunion.c prefix.h vty.h sockunion.h memory.h roken.h \
 str.h log.h
str.o: str.c str.h
stream.o: stream.c stream.h memory.h network.h prefix.h
table.o: table.c prefix.h table.h memory.h
thread.o: thread.c thread.h memory.h log.h
vector.o: vector.c vector.h memory.h
version.o: version.c
vty.o: vty.c linklist.h buffer.h version.h command.h vector.h vty.h \
 sockunion.h thread.h memory.h str.h log.h prefix.h filter.h
zclient.o: zclient.c ../zebra/zebra.h stream.h network.h thread.h \
 memory.h prefix.h client.h zclient.h log.h
