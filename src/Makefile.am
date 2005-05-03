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

# _GNU_SOURCE is needed for old glibc on Linux
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir) -D_GNU_SOURCE \
	-DLOCALEDIR=\"$(localedir)\" -DSYSCONFDIR=\"$(sysconfdir)\" \
	-DBR_PTHREADS=0

if MIREDO_CHROOT
AM_CPPFLAGS += -DMIREDO_CHROOT=\"$(miredo_chroot)\"
endif
if MIREDO_PIDFILE
AM_CPPFLAGS += -DMIREDO_PIDFILE=\"$(miredo_pidfile)\"
endif

sbin_PROGRAMS = miredo

#BUILT_SOURCES = svnversion.c
#CLEANFILES = $(BUILT_SOURCES)
#
#svnversion.c:
#	{ \
#		echo -n 'const char *const svn_version = "' ; \
#		svnversion -n $(top_srcdir) 2>/dev/null; \
#		echo '";' ; \
#	} > $@
#
#.PHONY: svnversion.c

# miredo
miredo_SOURCES = main.c miredo.cpp miredo.h conf.cpp conf.h \
                 prefix.c prefix.h

if TEREDO_RELAY
miredo_SOURCES += relay.cpp relay.h privproc.cpp privproc.h
endif

miredo_LDADD = @LIBINTL@ ../libtun6/libtun6.a ../libteredo/libteredo.a

# Automake does not support checking for MIREDO_CHROOT || MIREDO_PIDFILE
# so we always create the directory
install-exec-local:
	test -z "$(DESTDIR)$(localstatedir)/run/miredo" || \
	$(mkdir_p) "$(DESTDIR)$(localstatedir)/run/miredo"

uninstall-local:
	-rmdir "$(DESTDIR)$(localstatedir)/run/miredo"
	-rmdir "$(DESTDIR)$(localstatedir)/run"
	-rmdir "$(DESTDIR)$(localstatedir)"
