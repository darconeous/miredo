# Makefile.am - src/ directory Makefile for miredo
# $Id$

# ***********************************************************************
# *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

datadir = @datadir@
localedir = $(datadir)/locale

# _GNU_SOURCE is needed for old glibc on Linux
AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@ \
	-DLOCALEDIR=\"$(localedir)\" -D_GNU_SOURCE

sbin_PROGRAMS = miredo

#FIXME: don't rebuild every time
#BUILT_SOURCES = host.h
#CLEANFILES = $(BUILT_SOURCES)

#host.h: Makefile
#	{ \
#		echo '#define PACKAGE_HOST "$(host)"' ; \
#		echo '#define PACKAGE_BUILD "$(build)"' ; \
#	} > $@

# miredo
miredo_SOURCES = main.c miredo.cpp miredo.h

if TEREDO_RELAY
miredo_SOURCES += relay.cpp relay.h privproc.cpp privproc.h
endif

if TEREDO_SERVER
miredo_SOURCES += server.cpp server.h
endif

miredo_LDADD = @LIBINTL@ ../libtun6/libtun6.a ../libteredo/libteredo.a

