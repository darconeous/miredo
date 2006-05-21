# Makefile.am - src/ directory Makefile for miredo
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

datadir = @datadir@
localedir = $(datadir)/locale
top_srcdir = @top_srcdir@
sysconfdir = @sysconfdir@

LIBINTL = @LIBINTL@
LTLIBINTL = @LTLIBINTL@
LIBCAP = @LIBCAP@

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir) -D_REENTRANT \
	-D_GNU_SOURCE -D_APPLE_C_SOURCE \
	-DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"
AM_CFLAGS = -std=c99

sbin_PROGRAMS = miredo miredo-server miredo-checkconf isatapd
noinst_LTLIBRARIES = libmiredo.la
TESTS = miredo-checkconf

#BUILT_SOURCES = $(srcdir)/svnversion.stamp

libmiredo_la_SOURCES = main.c miredo.cpp miredo.h \
			conf.cpp conf.h binreloc.c binreloc.h
libmiredo_la_LIBADD = $(LTLIBINTL) $(LIBCAP) $(BINRELOC_LIBS) \
			../compat/libcompat.la
libmiredo_la_LDFLAGS = -static -no-undefined

# miredo
miredo_SOURCES = relay.c dummy.cpp
if TEREDO_CLIENT
miredo_SOURCES += privproc.c privproc.h addrwatch.c addrwatch.h
endif
miredo_LDADD = ../libtun6/libtun6.la ../libteredo/libteredo.la libmiredo.la \
		$(LIBINTL)

# miredo-server
miredo_server_SOURCES = server.c dummy.cpp
miredo_server_LDADD = ../libteredo/libteredo-server.la libmiredo.la $(LIBINTL)

# miredo-checkconf
miredo_checkconf_SOURCES = checkconf.cpp
miredo_checkconf_LDADD = libmiredo.la $(LIBINTL)

# isatapd
isatapd_SOURCES = isatap.c dummy.cpp
isatapd_LDADD = ../libtun6/libtun6.la libmiredo.la $(LIBINTL)

install-exec-local:
	$(install_sh) -d "$(DESTDIR)$(localstatedir)/run"

# SVN version
#$(srcdir)/svnversion.stamp:
#	{ \
#		echo -n 'const char *const svn_version = "' ; \
#		LANG=C svnversion -n "$(top_srcdir)" 2>/dev/null || \
#		echo -n exported ; \
#		echo '";' ; \
#	} > $(srcdir)/svnversion.stamp
#	if ! diff svnversion.stamp svnversion.c 2>/dev/null; then \
#		cat $(srcdir)/svnversion.stamp > $(srcdir)/svnversion.c ; \
#	fi
#
#.PHONY: $(srcdir)/svnversion.stamp

