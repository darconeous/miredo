# Makefile.am - misc Makefile for miredo
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

EXTRA_DIST = miredo.sh-in miredo-server.sh-in
dist_sysconf_DATA = miredo.conf-dist miredo-server.conf-dist
noinst_SCRIPTS = miredo.sh miredo-server.sh
CLEANFILES = $(noinst_SCRIPTS)

edit = sed \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@sbindir\@,$(sbindir),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g'

miredo.sh: Makefile

miredo-server.sh: Makefile

.sh-in.sh:
	rm -f -- $@ $@.tmp
	$(edit) $< > $@.tmp
	chmod -- +x $@.tmp
	mv -- $@.tmp $@

