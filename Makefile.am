## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ @GUILE@ doc

EXTRA_DIST = aczebra.m4 guile.m4 SERVICES TODO

dist-hook:
	mkdir $(distdir)/tools
	cp -p $(srcdir)/tools/*.pl $(distdir)/tools
	cp -p $(srcdir)/tools/*.el $(distdir)/tools
