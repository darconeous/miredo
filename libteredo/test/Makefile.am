# Makefile.am - libteredo/ directory Makefile for miredo
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

AM_CPPFLAGS = -I@top_srcdir@ -I@top_srcdir@/libteredo -D_REENTRANT

check_PROGRAMS = libteredo-unit libteredo-regress

TESTS = libteredo-unit libteredo-regress

if TEREDO_CLIENT
AM_CFLAGS = @LIBGCRYPT_CFLAGS@
AM_LDFLAGS = @LIBGCRYPT_LIBS@
endif

# libteredo-unit
libteredo_unit_SOURCES = unit.c dummy.cpp
libteredo_unit_LDADD = ../libteredo.la

# libteredo-regress
libteredo_regress_SOURCES = regress.c

