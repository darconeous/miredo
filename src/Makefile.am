# Makefile.am - src/ directory Makefile for miredo
# $Id: Makefile.am,v 1.4 2004/07/11 10:08:13 rdenisc Exp $

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

AM_CPPFLAGS = -I@top_srcdir@/include -I@top_srcdir@

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
miredo_SOURCES = ../include/teredo.c main.c miredo.cpp miredo.h \
			teredo-udp.cpp teredo-udp.h \
			relay.cpp relay.h \
			server.h server.cpp \
			common_pkt.h common_pkt.cpp
miredo_LDADD = ../libtun6/libtun6.a

