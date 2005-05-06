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

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@
noinst_LIBRARIES = libteredo.a libteredo-server.a

common_SOURCES =	teredo.c teredo.h \
			v4global.c v4global.h \
			teredo-udp.cpp teredo-udp.h

# libteredo.a
libteredo_a_SOURCES =	$(common_SOURCES) \
			relay-udp.cpp relay-udp.h relay.cpp relay.h \
			packets.cpp packets.h queue.cpp queue.h \
			peerlist.cpp peerlist.h
if TEREDO_CLIENT
libteredo_a_SOURCES += security.cpp security.h maintain.cpp
endif

# libteredo-server.a
libteredo_server_a_SOURCES =	$(common_SOURCES) \
				server-udp.cpp server-udp.h \
				server.cpp server.h

