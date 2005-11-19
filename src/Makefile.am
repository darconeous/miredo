# Makefile.am - src/ directory Makefile for miredo
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

datadir = @datadir@
localedir = $(datadir)/locale
top_srcdir = @top_srcdir@
sysconfdir = @sysconfdir@
LIBINTL = @LIBINTL@

# _GNU_SOURCE is needed for old glibc on Linux
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir) -D_REENTRANT \
	-D_GNU_SOURCE \
	-DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DBR_PTHREADS=0

if MIREDO_CHROOT
AM_CPPFLAGS += -DMIREDO_CHROOT=\"$(miredo_chroot)\"
endif

sbin_PROGRAMS = miredo miredo-server
noinst_LIBRARIES = libmiredo.a
check_PROGRAMS = miredo-checkconf
dist_check_SCRIPTS = test_conf.sh
TESTS = test_conf.sh

#BUILT_SOURCES = $(srcdir)/svnversion.stamp

libmiredo_a_SOURCES = main.c miredo.cpp miredo.h \
			conf.cpp conf.h prefix.c prefix.h

# miredo
miredo_SOURCES = relay.cpp
if TEREDO_CLIENT
miredo_SOURCES += privproc.c privproc.h
endif
miredo_LDADD = $(LIBINTL) libmiredo.a \
		../libtun6/libtun6.a ../libteredo/libteredo.la

# miredo-server
miredo_server_SOURCES = server.cpp
miredo_server_LDADD = $(LIBINTL) libmiredo.a ../libteredo/libteredo-server.la

# miredo-checkconf
miredo_checkconf_SOURCES = test_conf.cpp conf.cpp

# Automake does not support checking for MIREDO_CHROOT || MIREDO_PIDFILE
# so we always create the directory
install-exec-local:
	test -z "$(DESTDIR)$(localstatedir)/run/miredo" || \
	$(install_sh) -d "$(DESTDIR)$(localstatedir)/run/miredo"

uninstall-local:
	-rmdir "$(DESTDIR)$(localstatedir)/run/miredo"
	-rmdir "$(DESTDIR)$(localstatedir)/run"
	-rmdir "$(DESTDIR)$(localstatedir)"

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

