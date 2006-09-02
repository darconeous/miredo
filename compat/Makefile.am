# Makefile.am - compat/ directory Makefile for miredo

# ***********************************************************************
# *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

AM_CPPFLAGS = -D_REENTRANT -I@top_srcdir@

noinst_LTLIBRARIES = libcompat.la
libcompat_la_SOURCES = fixups.h dummy.c barrier.h pselect.h
libcompat_la_LIBADD = $(LTLIBOBJS)
libcompat_la_LDFLAGS = -no-undefined

check_PROGRAMS = test-strlcpy
TESTS = $(check_PROGRAMS)
test_strlcpy_SOURCES = test-strlcpy.c
test_strlcpy_LDADD = libcompat.la
