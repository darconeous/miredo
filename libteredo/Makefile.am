# Makefile.am - libteredo/ directory Makefile for miredo
# $Id$

# ***********************************************************************
# *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@ -D_REENTRANT

noinst_LTLIBRARIES = libteredo-server.la
lib_LTLIBRARIES = libteredo.la
check_PROGRAMS = libteredo-unit libteredo-regress

TESTS = libteredo-unit libteredo-regress

include_libteredodir = $(includedir)/libteredo
include_libteredo_HEADERS = teredo.h relay-udp.h relay.h
common_SOURCES =	teredo.c teredo-udp.cpp teredo.h \
			v4global.c v4global.h checksum.h

# libteredo.la
libteredo_la_SOURCES =	$(common_SOURCES) init.c \
			relay-udp.cpp relay-udp.h relay.cpp relay.h \
			packets.cpp packets.h peerlist.cpp peerlist.h
libteredo_la_CFLAGS =
libteredo_la_LDFLAGS =
if TEREDO_CLIENT
libteredo_la_SOURCES += security.c security.h maintain.cpp maintain.h
libteredo_la_CFLAGS += @LIBGCRYPT_CFLAGS@
libteredo_la_LDFLAGS += @LIBGCRYPT_LIBS@
endif

# libteredo-server.la
libteredo_server_la_SOURCES =	$(common_SOURCES) \
				server-udp.cpp server-udp.h \
				server.cpp server.h

# libteredo-unit
libteredo_unit_SOURCES = unit.c
libteredo_unit_CFLAGS = $(libteredo_la_CFLAGS)
libteredo_unit_LDFLAGS = $(libteredo_la_LDFLAGS)
libteredo_unit_LDADD = libteredo.la

# libteredo-regress
libteredo_regress_SOURCES = regress.c

