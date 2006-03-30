# Makefile.am - libtun6/ directory Makefile for miredo
# $Id$

# ***********************************************************************
# *  Copyright (C) 2004-2006 Rémi Denis-Courmont.                       *
# *  This program is free software; you can redistribute and/or modify  *
# *  it under the terms of the GNU General Public License as published  *
# *  by the Free Software Foundation; version 2 of the license.         *
# *                                                                     *
# *  This program is distributed in the hope that it will be useful,    *
# *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
# *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
# *  See the GNU General Public License for more details.               *
# *                                                                     *
# *  You should have received a copy of the GNU General Public License  *
# *  along with this program; if not, you can get it from:              *
# *  http://www.gnu.org/copyleft/gpl.html                               *
# ***********************************************************************

localedir = @datadir@/locale

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@ \
	-D_REENTRANT -D_GNU_SOURCE -DLOCALEDIR=\"$(localedir)\"
AM_CFLAGS = -std=c99
LIBINTL = @LIBINTL@

lib_LTLIBRARIES = libtun6.la
check_PROGRAMS = libtun6-diagnose
TESTS = $(check_PROGRAMS)

# libtun6.a
libtun6_la_SOURCES = tun6.c
libtun6_la_LIBADD = @LTLIBINTL@
libtun6_la_LDFLAGS = -no-undefined
include_libtun6dir = $(includedir)/libtun6
include_libtun6_HEADERS = tun6.h

# libtun6-diagnose
libtun6_diagnose_SOURCES = diagnose.c
libtun6_diagnose_LDADD = libtun6.la
