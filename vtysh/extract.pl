#! /usr/bin/perl
##
## Virtual terminal interface shell command extractor.
## Copyright (C) 2000 Kunihiro Ishiguro
## 
## This file is part of GNU Zebra.
## 
## GNU Zebra is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 2, or (at your option) any
## later version.
## 
## GNU Zebra is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with GNU Zebra; see the file COPYING.  If not, write to the Free
## Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
## 02111-1307, USA.  
##

print <<EOF;
#include <zebra.h>
#include "command.h"
#include "vtysh.h"

EOF

$hash{'router_rip_cmd'} = "ignore";
$hash{'router_ripng_cmd'} = "ignore";
$hash{'router_ospf_cmd'} = "ignore";
$hash{'router_ospf6_cmd'} = "ignore";
$hash{'router_bgp_cmd'} = "ignore";

foreach (@ARGV) {
    $file = $_;

    open (FH, "$file");
    local $/; undef $/;
    $line = <FH>;
    close (FH);

    @defun = ($line =~ /(?:DEFUN|ALIAS)\s*\((.+?)\)\n/sg);
    @install = ($line =~ /install_element \([A-Z_]+, &[^;]*;\n/sg);

    ($protocol) = ($file =~ /\/([a-z0-9]+)\//);
    $protocol = "VTYSH_" . uc $protocol;

    foreach (@defun) {
	my (@arg);
	@arg = split (/,/);
	$arg[0] = '';

	# Actual input command string.
	$cmd = "$arg[2]";
	$cmd =~ s/^\s+//g;
	$cmd =~ s/\s+$//g;

	# Get VTY command structure.  This is needed for searching
	# install_element() command.
	$struct = "$arg[1]";
	$struct =~ s/^\s+//g;
	$struct =~ s/\s+$//g;

	$arg_str = join (", ", @arg);

	if (! grep (/$protocol/, @{$hashp{$struct}}) 
	    && $hash{$struct} ne "ignore") {
	    $hash{$struct} = "$arg_str";
	    push (@{$hashp{$struct}}, $protocol);
	    $install{$struct . $protocol} = $struct;
	}
    }

    foreach (@install) {
	$struct = $_;
	($index) = ($struct =~ /&([^\)]+)/);
	if (defined ($install{$index . $protocol})) {
	    push (@init, $struct);
	}
    }
}

foreach (keys %hash) {
    if ($hash{$_} ne "ignore") {
	@{$hashp{$_}} = join ("|", @{$hashp{$_}});
	print "DEFSH (@{$hashp{$_}}$hash{$_})\n\n";
    }
}

print <<EOF;
void
vtysh_init_cmd ()
{
EOF

foreach (@init) {
    print;
}

print <<EOF
}
EOF
