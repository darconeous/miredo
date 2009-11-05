# Makefile.am - misc Makefile for miredo

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

confdir = $(sysconfdir)/miredo

MOSTLYCLEANFILES = $(examples_DATA) $(conf_SCRIPTS)

sed_verbose = $(sed_verbose_$(V))
sed_verbose_ = $(sed_verbose_$(AM_DEFAULT_VERBOSITY))
sed_verbose_0 = @echo "  SED    $@";
cat_verbose = $(cat_verbose_$(V))
cat_verbose_ = $(cat_verbose_$(AM_DEFAULT_VERBOSITY))
cat_verbose_0 = @echo "  CAT    $@";

# Configuration files
dist_noinst_DATA = miredo.conf-in miredo-server.conf-in
examples_DATA = miredo.conf miredo-server.conf

.conf-in.conf:
	$(AM_V_at)rm -f -- $@
	$(sed_verbose)sed -e 's,@sbindir\@,$(sbindir),g' < $< > $@

# Hook scripts
dist_noinst_SCRIPTS = client-hook.iproute client-hook.bsd
conf_SCRIPTS = client-hook

client-hook: client-hook.$(hook_suffix)
	$(cat_verbose)cat $(srcdir)/client-hook.$(hook_suffix) \
		> client-hook.tmp
	$(AM_V_at)mv -f -- client-hook.tmp client-hook

