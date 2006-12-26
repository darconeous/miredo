# Makefile.am - master Makefile for miredo

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

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = po doc misc compat libteredo libtun6 src
DIST_SUBDIRS = m4 $(SUBDIRS)
noinst_HEADERS = include/gettext.h
EXTRA_DIST = autogen.sh autopackage/default.apspec.in

if CONF_SAMPLE
# For user's convenience, we install miredo.conf
# iif it does not already exist.
# Packagers will probably use --disable-sample-conf
# and copy their own default (or those in misc/) to @sysconfdir@

example = $(examplesdir)/miredo.conf
conf = $(sysconfdir)/miredo.conf

install-data-hook:
	@echo "************************"
	@echo "* Miredo configuration *"
	@echo "************************"
	@echo " "
	@echo "A sample configuration file has been installed at:"
	@echo "  $(examplesdir)/miredo.conf"
	@echo " "
	@if test ! -e "$(DESTDIR)$(conf)"; then \
		mkdir -p -- "$(DESTDIR)$(sysconfdir)" || exit $$? ; \
		cp -- "$(DESTDIR)$(example)" "$(DESTDIR)$(conf)" || exit $$?; \
		echo "No pre-existing configuration file for Miredo" ; \
		echo "could be found, so the sample as been copied as" ; \
		echo "  $(conf) too." ; \
	else \
		echo "There was already a configuration file at:" ; \
		echo "  $(conf) - it was not modified." ; \
	fi
	@echo " "
	@echo "Please take time to review the settings and adjust them"
	@echo "if necessary. Once finished, save the file as:"
	@echo "  $(conf) and run miredo (as root)."
endif

# Safe automatic ChangeLog update
DISTCLEANFILES = stamp-svn

distclean-local:
	test "$(top_srcdir)" = "$(top_builddir)" || rm -f ChangeLog

dist-hook: stamp-svn

distcheck-hook:
	cd doc && $(MAKE) $(AM_MAKEFLAGS) distcheck-hook

stamp-svn:
	@rev=$$(LANG=C svnversion "$(srcdir)" 2>/dev/null || echo exported) ; \
	oldrev=$$(cat stamp-svn 2>/dev/null || true) ; \
	if test "$$rev" != "$$oldrev"; then \
		echo "New SVN revision is $$rev." ; \
		if test "$$rev" != "exported"; then \
			echo -n "Rebuilding ChangeLog... " ; \
			LANG=C svn -v --non-interactive log "$(srcdir)" > ChangeLog.tmp || exit $$? ; \
			cat "$(srcdir)/ChangeLog.old" >> ChangeLog.tmp ; \
			mv -f ChangeLog.tmp ChangeLog || exit $$? ; \
			echo "OK" ; \
		fi ; \
		echo "$$rev" > $@ ; \
	fi

ChangeLog:
	$(MAKE) $(AM_MAKEFLAGS) stamp-svn
	touch $@

.PHONY: distcheck-hook stamp-svn
