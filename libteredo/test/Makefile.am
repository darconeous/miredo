# Makefile.am - libteredo/ directory Makefile for miredo
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

AM_CPPFLAGS = -I@top_srcdir@ -I@top_srcdir@/libteredo -D_REENTRANT
AM_CFLAGS = -std=c99

check_PROGRAMS = libteredo-addrcmp libteredo-list libteredo-stresslist
TESTS = $(check_PROGRAMS)

if TEREDO_CLIENT
check_PROGRAMS += md5test libteredo-hmac
endif

# libteredo-addr
libteredo_addrcmp_SOURCES = addrcmp.c

# libteredo-list
libteredo_list_SOURCES = list.c
libteredo_list_LDADD = ../libteredo.la

# libteredo-stresslist
libteredo_stresslist_SOURCES = stresslist.c
libteredo_stresslist_LDADD = ../libteredo.la

# libteredo-hmac
libteredo_hmac_SOURCES = hmac.c
libteredo_hmac_LDADD = ../libteredo.la

# md5main
md5test_SOURCES = md5test.c ../md5.c
#md5test_LDADD = -lm

