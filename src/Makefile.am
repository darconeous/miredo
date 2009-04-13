# Makefile.am - src/ directory Makefile for miredo

# ***********************************************************************
# *  Copyright © 2004-2009 Rémi Denis-Courmont.                         *
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

datadir = @datadir@
localedir = $(datadir)/locale
top_srcdir = @top_srcdir@
sysconfdir = @sysconfdir@

LIBINTL = @LIBINTL@
LTLIBINTL = @LTLIBINTL@
LIBCAP = @LIBCAP@

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir) -D_REENTRANT \
	-DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\"

sbin_PROGRAMS = miredo miredo-server miredo-checkconf
noinst_LTLIBRARIES = libmiredo.la
TESTS =

#BUILT_SOURCES = $(srcdir)/svnversion.stamp

libmiredo_la_SOURCES = main.c miredo.c miredo.h \
			conf.c conf.h binreloc.c binreloc.h
libmiredo_la_LIBADD = $(LTLIBINTL) $(LIBCAP) $(BINRELOC_LIBS) \
			../compat/libcompat.la
libmiredo_la_LDFLAGS = -no-undefined -static
#libmiredo_la_LDFLAGS = -no-undefined -release @VERSION@
# libmiredo is dynamic only to reduce executables size (all the code is
# reused at least three times); stable API is not quite an objective
# right now (<miredo.h> and <conf.h> are not installed by the way).
# That is why we use -release at the moment.

# miredo
miredo_SOURCES = relayd.c
if TEREDO_CLIENT
miredo_SOURCES += privproc.c privproc.h
TESTS += miredo-checkconf
endif
miredo_LDADD = ../libtun6/libtun6.la ../libteredo/libteredo.la libmiredo.la \
		@LIBRT@ $(LIBINTL)

# miredo-server
miredo_server_SOURCES = serverd.c
miredo_server_LDADD = ../libteredo/libteredo-server.la libmiredo.la $(LIBINTL)

# miredo-checkconf
miredo_checkconf_SOURCES = checkconf.c
miredo_checkconf_LDADD = libmiredo.la $(LIBINTL)

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

