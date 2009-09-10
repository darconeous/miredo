# Makefile.am - libteredo/ directory Makefile for miredo

# ***********************************************************************
# *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
# *  This program is free software; you can redistribute and/or modify  *
# *  it under the terms of the GNU General Public License as published  *
# *  by the Free Software Foundation; version 2 of the license, or (at  *
# *  your option) any later version.                                    *
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
	-D_REENTRANT -DLOCALEDIR=\"$(localedir)\"

LIBADD = ../compat/libcompat.la libteredo-common.la

noinst_LTLIBRARIES = libteredo-common.la libteredo-server.la
lib_LTLIBRARIES = libteredo.la
bin_PROGRAMS = teredo-mire
EXTRA_DIST = libteredo.sym

include_libteredodir = $(includedir)/libteredo
include_libteredo_HEADERS = teredo.h teredo-udp.h tunnel.h

# libteredo-common.la
libteredo_common_la_SOURCES =	teredo.c v4global.c v4global.h \
				checksum.h debug.h
libteredo_common_la_LDFLAGS = -no-undefined

# libteredo.la
libteredo_la_SOURCES =	init.c relay.c security.c security.h md5.c md5.h \
			packets.c packets.h peerlist.c peerlist.h \
			clock.c clock.h iothread.c iothread.h stub.c
if TEREDO_CLIENT
libteredo_la_SOURCES += maintain.c maintain.h
endif
libteredo_la_DEPENDENCIES = libteredo.sym $(LIBADD)
libteredo_la_LIBADD = @LIBJUDY@ @LIBRT@ $(LTLIBINTL) $(LIBADD)
libteredo_la_LDFLAGS = -no-undefined -export-symbols $(srcdir)/libteredo.sym \
	-version-info 5:0:0

# libteredo versions:
# 0) First stable shared release (0.8.2)
# 1) teredo_run_async() added, teredo_register_readset() deprecated (0.9.2)
# 2) teredo_set_relay_mode() added, teredo_set_cone_*() deprecated (0.9.5)
# -- backward compatibility break --
# 3) remove teredo_register_readset() (1.0.0)
# 4) added internal teredo_send_bubble, teredo_cksum (1.1.0)
# -- backward compatibility break --
# 5) added teredo_packet.dest_ipv4, removed teredo_set_cone_ignore() (1.1.7)

# libteredo-server.la
libteredo_server_la_SOURCES = server.c server.h
libteredo_server_la_LIBADD = $(LTLIBINTL) $(LIBADD)
libteredo_server_la_LDFLAGS = -no-undefined -static
# libteredo-server is static given it hardly make sense to reuse it
# outside miredo-server (which is itself way less commonly used
# than miredo)

# teredo-mire
teredo_mire_SOURCES = mire.c
teredo_mire_LDADD = libteredo.la
