# Makefile.am - misc Makefile for miredo
# $Id: Makefile.am 224 2004-11-01 17:14:13Z remi $

# ***********************************************************************
# *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

EXTRA_DIST = miredo miredo.sh
dist_sysconf_DATA = miredo.conf-dist

install-exec-hook:
	@echo "************************"
	@echo "* Miredo configuration *"
	@echo "************************"
	@echo " "
	@echo "A sample configuration file has been installed at:"
	@echo "  $(sysconfdir)/miredo.conf-dist"
	@echo " "
	@echo "Please take time to review the settings and adjust them"
	@echo "if necessary. Once finished, save the file as:"
	@echo "  $(sysconfdir)/miredo.conf"
	@echo " "
	@echo "************************************************"
	@echo "* Miredo WON'T run without configuration file! *"
	@echo "************************************************"

