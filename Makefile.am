# Makefile.am - master Makefile for miredo

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

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = \
	-Wall \
	check-news \
	std-options \
	dist-bzip2 \
	no-dist-gzip \
	no-exeext

SUBDIRS = po doc misc compat libteredo libtun6 src
DIST_SUBDIRS = m4 $(SUBDIRS)
noinst_HEADERS = include/gettext.h
EXTRA_DIST = autogen.sh autopackage/default.apspec.in Doxyfile.in

doc: Doxyfile
	doxygen $<

if CONF_SAMPLE
# For user's convenience, we install miredo.conf
# iif it does not already exist.
# Packagers will probably use --disable-sample-conf
# and copy their own default (or those in misc/) to @sysconfdir@/miredo/

example = $(examplesdir)/miredo.conf
confdir = $(sysconfdir)/miredo
conf = $(confdir)/miredo.conf

install-data-hook:
	@echo "************************"
	@echo "* Miredo configuration *"
	@echo "************************"
	@echo " "
	@echo "An example configuration file has been installed at:"
	@echo "  $(examplesdir)/miredo.conf"
	@echo " "
	@if test ! -e "$(DESTDIR)$(conf)"; then \
		mkdir -p -- "$(DESTDIR)$(confdir)" || exit $$? ; \
		cp -- "$(DESTDIR)$(example)" "$(DESTDIR)$(conf)" || exit $$?; \
		echo "No pre-existing configuration file for Miredo" ; \
		echo "could be found, so the example as been copied as" ; \
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

DISTCLEANFILES = ChangeLog

distcheck-hook:
	cd doc && $(MAKE) $(AM_MAKEFLAGS) distcheck-hook

# ChangeLog
ChangeLog: ChangeLog.old
	test -d "$(srcdir)/.git"
	rm -f -- ChangeLog
	(cd "$(srcdir)" && git log && cat ChangeLog.old) > ChangeLog

.PHONY: ChangeLog

# Test coverage
lcov.info:
	find -name '*.gcda' -delete
	$(MAKE) $(AM_MAKEFLAGS) check
	lcov --directory . --capture --output $@.tmp
	lcov --remove $@.tmp '*test*' '*include*' --output $@
	rm -f $@.tmp

lcov-report: lcov.info
	rm -Rf lcov
	mkdir -p lcov
	genhtml $< -o lcov

lcov:
	rm -f lcov.info
	$(MAKE) $(AM_MAKEFLAGS) lcov-report

.PHONY: distcheck-hook stamp-svn lcov doc

