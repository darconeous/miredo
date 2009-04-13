# Makefile.am - doc Makefile for miredo

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

man1_MANS = teredo-mire.1
man5_MANS = miredo.conf.5 miredo-server.conf.5
man8_MANS = miredo.8 miredo-server.8 miredo-checkconf.8
SOURCES_MAN = $(man1_MANS) $(man5_MANS) \
	miredo.8-in miredo-server.8-in miredo-checkconf.8-in

EXTRA_DIST = $(SOURCES_MAN)
CLEANFILES = $(man8_MANS)

edit = sed \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@confdir\@,$(sysconfdir)/miredo,g'

$(man8_MANS): Makefile

.8-in.8:
	rm -f -- $@
	$(edit) $< > $@

distcheck-hook:
	cd $(srcdir) && \
	cat $(SOURCES_MAN) | grep -ve '\.\\"' | iconv -f ASCII >/dev/null
