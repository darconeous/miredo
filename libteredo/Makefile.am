# Makefile.am - libteredo/ directory Makefile for miredo
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

SUBDIRS = . test
localedir = @datadir@/locale
LTLIBINTL = @LTLIBINTL@

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@ \
	-D_REENTRANT -D_GNU_SOURCE -DLOCALEDIR=\"$(localedir)\"
AM_CFLAGS = -std=c99

LIBADD = $(LTLIBINTL) ../compat/libcompat.la

noinst_LTLIBRARIES = libteredo-server.la
lib_LTLIBRARIES = libteredo.la

include_libteredodir = $(includedir)/libteredo
include_libteredo_HEADERS = teredo.h tunnel.h
common_SOURCES =	teredo.c teredo.h teredo-udp.h \
			v4global.c v4global.h checksum.h

# libteredo.la
libteredo_la_SOURCES =	$(common_SOURCES) init.c relay.c \
			packets.c packets.h peerlist.c peerlist.h
if TEREDO_CLIENT
libteredo_la_SOURCES += security.c security.h maintain.c maintain.h \
			md5.c md5.h
endif
libteredo_la_LIBADD = @LIBJUDY@ $(LIBADD)
libteredo_la_LDFLAGS = -no-undefined -static
# will be static as long as the API is not quite stabilized

# libteredo-server.la
libteredo_server_la_SOURCES =	$(common_SOURCES) server.c server.h
libteredo_server_la_LIBADD = $(LIBADD)
libteredo_server_la_LDFLAGS = -no-undefined -static
# libteredo-server is static given it hardly make sense to reuse it
# outside miredo-server (which is itself way less commonly used
# than miredo)

