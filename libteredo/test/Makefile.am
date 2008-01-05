# Makefile.am - libteredo/ directory Makefile for miredo

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

AM_CPPFLAGS = -I@top_srcdir@ -I@top_srcdir@/libteredo -D_REENTRANT
AM_LDFLAGS = -static
LDADD = ../libteredo.la

check_PROGRAMS = \
	libteredo-list \
	libteredo-stresslist \
	libteredo-test \
	libteredo-clock \
	libteredo-v4global \
	libteredo-addrcmp \
	md5test
TESTS = $(check_PROGRAMS)

if TEREDO_CLIENT
check_PROGRAMS += libteredo-hmac
endif

# libteredo-list
libteredo_list_SOURCES = list.c

# libteredo-stresslist
libteredo_stresslist_SOURCES = stresslist.c

# libteredo-hmac
libteredo_hmac_SOURCES = hmac.c

# libteredo-test
libteredo_test_SOURCES = teredo.c

# libteredo-clock
libteredo_clock_SOURCES = clock.c

# libteredo-v4global
libteredo_v4global_SOURCES = v4global.c

# libteredo-addrcmp
libteredo_addrcmp_SOURCES = addrcmp.c

# md5main
md5test_SOURCES = md5test.c
#md5test_LDADD = -lm
