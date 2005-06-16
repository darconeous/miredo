# Makefile.am - master Makefile for miredo
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

SUBDIRS = m4 po libtun6 libteredo src misc

man5_MANS = doc/miredo.conf.5 doc/miredo-server.conf.5
man8_MANS = doc/miredo.8 doc/miredo-server.8
noinst_HEADERS = include/gettext.h

EXTRA_DIST = admin/config.rpath admin/mkinstalldirs \
		$(man5_MANS) $(man8_MANS) autopackage/default.apspec.in
# doc -- it might not be a good idea to include the doc directory inside
#        official releases.
ACLOCAL_AMFLAGS = -I m4

miredo_conf = $(sysconfdir)/miredo.conf

install-data-hook:
	@echo "************************"
	@echo "* Miredo configuration *"
	@echo "************************"
	@echo " "
	@echo "A sample configuration file has been installed at:"
	@echo "  $(miredo_conf)-dist"
	@echo " "
	@if test ! -e "$(DESTDIR)$(miredo_conf)"; then \
		cp -- "$(DESTDIR)$(miredo_conf)-dist" "$(DESTDIR)$(miredo_conf)" ; \
		echo "No pre-existing configuration file for Miredo" ; \
		echo "could be found, so the sample as been copied as" ; \
		echo "  $(miredo_conf) too." ; \
	else \
		echo "There was already a configuration file at:" ; \
		echo "  $(miredo_conf) - it was not modified." ; \
	fi
	@echo " "
	@echo "Please take time to review the settings and adjust them"
	@echo "if necessary. Once finished, save the file as:"
	@echo "  $(miredo_conf) and run miredo (as root)."

