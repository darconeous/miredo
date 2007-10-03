# Makefile.am - misc Makefile for miredo

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

confdir = $(sysconfdir)/miredo

MOSTLYCLEANFILES = $(examples_DATA) $(conf_SCRIPTS)

# Configuration files
dist_noinst_DATA = miredo.conf-in miredo-server.conf-in isatapd.conf-in
examples_DATA = miredo.conf miredo-server.conf isatapd.conf

.conf-in.conf:
	rm -f -- $@
	sed -e 's,@sbindir\@,$(sbindir),g' < $< > $@

# Hook scripts
dist_noinst_SCRIPTS = client-hook.iproute client-hook.bsd
conf_SCRIPTS = client-hook

client-hook: client-hook.$(hook_suffix)
	cat $< > $@

