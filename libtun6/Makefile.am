# Makefile.am - libtun6/ directory Makefile for miredo
# $Id$

# ***********************************************************************
# *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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
	-D_REENTRANT -DLOCALEDIR=\"$(localedir)\"
LIBINTL = @LIBINTL@

lib_LTLIBRARIES = libtun6.la
check_PROGRAMS = libtun6-diagnose
TESTS = $(check_PROGRAMS)

include_libtun6dir = $(includedir)/libtun6
include_libtun6_HEADERS = tun6.h

# libtun6.a
libtun6_la_SOURCES = tun6.c diag.c
libtun6_la_LIBADD = @LTLIBINTL@ ../compat/libcompat.la
libtun6_la_LDFLAGS = -no-undefined -export-symbols-regex tun6_.* \
	-version-info 1:0:1

# libtun6 versions:
# 0) First stable shared release (0.8.2)
# 1) tun_wait_recv() (0.9.x)

# libtun6-diagnose
libtun6_diagnose_SOURCES = test_diag.c
libtun6_diagnose_LDADD = libtun6.la
