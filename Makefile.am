# Makefile.am - master Makefile for miredo
# $Id: Makefile.am,v 1.3 2004/06/26 19:55:28 rdenisc Exp $

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

SUBDIRS = m4 include src
man8_MANS = miredo.8
EXTRA_DIST = $(man8_MANS)
# doc -- it might not be a good idea to include the doc directory inside
#        official releases.
ACLOCAL_AMFLAGS = -I m4
