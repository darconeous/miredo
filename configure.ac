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
AC_INIT([miredo], [0.1.2], [rdenis@simphalempin.com])
AC_PREREQ(2.59)
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
AC_PROG_RANLIB
AM_INIT_AUTOMAKE([dist-bzip2])


# Checks for libraries.


# Checks for header files.
AC_CHECK_HEADERS([sys/socket.h linux/if_tun.h sys/uio.h])
AC_CHECK_HEADERS([netinet6/in6_var.h], [], [],
[#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
])


# Checks for typedefs, structures, and compiler characteristics.
dnl AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN


# Checks for library functions.
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntoa, [nsl])
dnl AC_SEARCH_LIBS(inet_aton, [resolv])
RDC_REPLACE_FUNC_GETOPT_LONG
AC_CHECK_FUNCS([clearenv])

AC_CHECK_LIB([ssl], RAND_bytes, [openssl=true], [openssl=false])
AH_TEMPLATE(USE_OPENSSL,
            [Define to 1 if you wan to use the OpenSSL library.])
AS_IF([test "${openssl}" = true], AC_DEFINE(USE_OPENSSL)
	OPENSSL_LIBS="-lssl")
AC_SUBST(OPENSSL_LIBS)


# Checks for optionnal features
AC_ARG_ENABLE([miredo-user],
	      AS_HELP_STRING([--enable-miredo-user],
			     [user to run as (default 'miredo')]))
AS_IF([test "x${enable_miredo_user}" = "x" || test "${enable_miredo_user}" = "yes"],
	[enable_miredo_user="miredo"])
AH_TEMPLATE(MIREDO_DEFAULT_USERNAME,
            [Define to the system user name to be used by miredo.])
AS_IF([test "${enable_miredo_user}" != "no"],
	AC_DEFINE_UNQUOTED(MIREDO_DEFAULT_USERNAME, "$enable_miredo_user"))


# Defines for <config.h>
AH_BOTTOM([
#define gettext( str )		(str)
#define gettext_noop( str )	(str)
#define _( str )		gettext (str)
#define N_( str )		gettext_noop (str)
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile libtun6/Makefile libteredo/Makefile src/Makefile])
AC_OUTPUT

AS_IF([test "${openssl}" = false],
echo "WARNING: OpenSSL v0.9.5 or more recent is highly recommended to use"
echo "         Miredo as a Teredo client. However, It could not be found on"
echo "         your system."
)
