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
AC_INIT([miredo], [0.1.1], [rdenis@simphalempin.com])
INVOCATION="$0 $*"

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_HEADERS([config.h])

AC_DEFINE_UNQUOTED(PACKAGE_CONFIGURE_INVOCATION, "$INVOCATION",
                [Define to the command line used to invoke the configure script.])
RDC_BUILD_HOSTNAME


# Checks for programs.
AS_MESSAGE(checking required programs...)
AC_PROG_CC
AC_PROG_CXX
AM_INIT_AUTOMAKE([dist-bzip2])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([linux/if_tun.h linux/ipv6.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN

# Checks for library functions.
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntoa, [nsl])
dnl AC_SEARCH_LIBS(inet_aton, [resolv])
RDC_REPLACE_FUNC_GETOPT_LONG


# Checks for optionnal features
AH_TEMPLATE(MIREDO_UNPRIV_USER,
	    [Define to the system user name to be used by miredo.])
AC_ARG_ENABLE([miredo-user],
	      AS_HELP_STRING([--enable-miredo-user],
			     [make miredo setuid to a non-root user (default 'miredo')]),
	      [case "${enableval}" in
		  yes) ac_cv_miredo_user="miredo" ;;
		  *) ac_cv_miredo_user="${enableval}" ;;
	       esac],
	      [ac_cv_miredo_user="miredo"])
AC_CACHE_CHECK([whether to use a non-root system user],
	       [ac_cv_miredo_user],
	       [ac_cv_miredo_user="miredo"])
if test x$ac_cv_miredo_user != xno; then
    AC_DEFINE_UNQUOTED(MIREDO_UNPRIV_USER, "$ac_cv_miredo_user")
fi

AH_TEMPLATE(MIREDO_UNPRIV_GROUP,
	    [Define to the system group name to be used by miredo.])
AC_ARG_ENABLE([miredo-group],
	      AS_HELP_STRING([--enable-miredo-group],
			     [make miredo setgid to that group (default 'nogroup')]),
	      [case "${enableval}" in
		  yes) ac_cv_miredo_group="nogroup" ;;
		  *) ac_cv_miredo_group="${enableval}" ;;
	       esac],
	      [ac_cv_miredo_group="nogroup"])
AC_CACHE_CHECK([whether to use a non-root system group],
	       [ac_cv_miredo_group],
	       [ac_cv_miredo_group="nogroup"])
if test x$ac_cv_miredo_group != xno; then
    AC_DEFINE_UNQUOTED(MIREDO_UNPRIV_GROUP, "$ac_cv_miredo_group")
fi


# Defines for <config.h>
AH_BOTTOM([
#define _( str ) (str)
#define N_( str ) (str)
])

# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile include/Makefile src/Makefile])
AC_OUTPUT

