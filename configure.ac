dnl configure.ac - Configure script for miredo
dnl based on earlier configure.ac from tcpreen by the same author

dnl Process this file with GNU Autoconf to produce a configure script

dnl ***********************************************************************
dnl *  Copyright (C) 2002-2004 Remi Denis-Courmont.                       *
dnl *  This program is free software; you can redistribute and/or modify  *
dnl *  it under the terms of the GNU General Public License as published  *
dnl *  by the Free Software Foundation; version 2 of the license.         *
dnl *                                                                     *
dnl *  This program is distributed in the hope that it will be useful,    *
dnl *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
dnl *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
dnl *  See the GNU General Public License for more details.               *
dnl *                                                                     *
dnl *  You should have received a copy of the GNU General Public License  *
dnl *  along with this program; if not, you can get it from:              *
dnl *  http://www.gnu.org/copyleft/gpl.html                               *
dnl ***********************************************************************

AC_COPYRIGHT([Copyright (C) 2004 Rémi Denis-Courmont])
AC_INIT([miredo], [0.1.0], [rdenis@simphalempin.com])

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AS_MESSAGE(checking required programs...)
AC_PROG_CC
AC_PROG_CXX
AM_INIT_AUTOMAKE([dist-bzip2])

# Checks for libraries.

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
RDC_STRUCT_SOCKADDR_LEN

# Checks for library functions.
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntoa, [nsl])
AC_SEARCH_LIBS(inet_aton, [resolv])

# Defines for <config.h>
AH_BOTTOM([
#define _( str ) (str)
#define N_( str ) (str)
])

# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile include/Makefile src/Makefile])
AC_OUTPUT

