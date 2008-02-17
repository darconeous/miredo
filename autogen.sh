#! /bin/sh
# GIT package rebuild script
#
# ***********************************************************************
# *  Copyright © 2002-2008 Rémi Denis-Courmont.                         *
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

set -xe

if test -f doc/miredo.8-in ; then
	true
elif test -f ../doc/miredo.8-in; then
	cd ..
else
	echo "You must run this script from your miredo SVN directory."
	false
fi

echo "Autoreconf in $PWD ..."

autoreconf -sfi
unlink po/Makevars.template

mkdir -p include/
for d in /usr /usr/local /opt/gettext /opt/local/share/gettext \
		/usr/pkg "$HOME"; do
	if test -f "$d/share/gettext/gettext.h" ; then
		cp -f -- "$d/share/gettext/gettext.h" include/gettext.h
	fi
done

set +x

test -f "include/gettext.h" || {
echo "Error: can't find <gettext.h> convenience C header."
echo "Please put a link to it by hand as include/gettext.h"
exit 1
}
sed \
	-e 's,!__STRICT_ANSI__,!defined(__STRICT_ANSI__),g' \
	-e 's,if ENABLE_NLS,ifdef ENABLE_NLS,g' \
	-i include/gettext.h

echo ""
echo "Type \`./configure' to configure the package for your system"
echo "(type \`./configure -- help' for help)."
echo "Then you can use the usual \`make', \`make install', etc."

