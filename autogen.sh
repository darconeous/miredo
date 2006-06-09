#!/bin/sh
# SVN package rebuild script
# $Id$
#
# ***********************************************************************
# *  Copyright © 2002-2005 Rémi Denis-Courmont.                         *
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

if test ! -f doc/miredo.8-in ; then
	echo "You must run this script from your miredo SVN directory."
	exit 1
fi

echo "Creating admin directory ..."
test -d admin || mkdir admin || exit 1

echo "Running \`autopoint' ..."
autopoint -f || {
echo "Error: gettext is probably not on your system, or it does not work."
echo "You need GNU gettext version 0.12.1 or higher."
exit 1
}

unlink po/Makevars.template

# Official <gettext.h> currently has a bug whereby it includes <libintl.h>
# even if it doesn't exists (when compiling C++ against uClibc++), so we
# use a custom version at the moment.
#for d in /usr /usr/local /opt/gettext /usr/pkg $HOME ; do
#	if test -f $d/share/gettext/gettext.h ; then
#		test -z "$gettext_h" && ln -sf $d/share/gettext/gettext.h \
#					include/gettext.h
#		gettext_h=ok
#	fi
#done

echo "Generating \`aclocal.m4' with aclocal ..."
aclocal -I m4 || {
echo "Error: autoconf is probably not on your system, or it does not work."
echo "You need GNU autoconf 2.54 or higher, as well as GNU gettext 0.12.1."
exit 1
}
echo "Generating \`config.h.in' with autoheader ..."
autoheader || exit 1
echo "Installing libtool with libtoolize ..."
libtoolize --force || {
echo "Error: libtool is probably not on your system, or it is too old."
echo "You need GNU libtool to rebuild this package."
exit 1
}
echo "Generating \`Makefile.in' with automake ..."
automake -Wall --add-missing || {
echo "Error: automake is probably not on your system, or it is too old."
echo "You need GNU automake 1.7 higher to rebuild this package."
exit 1
}
echo "Generating \`configure' script with autoconf ..."
autoconf || exit 1
echo "Done."

#test -z $gettext_h && {
#echo "Error: can't find <gettext.h> convenience C header."
#echo "Please put a link to it by hand in src/gettext.h"
#}

echo ""
echo "Type \`./configure' to configure the package for your system"
echo "(type \`./configure -- help' for help)."
echo "Then you can use the usual \`make', \`make install', etc."

