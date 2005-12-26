dnl configure.ac - Configure script for miredo
dnl based on earlier configure.ac from tcpreen by the same author

dnl Process this file with GNU Autoconf to produce a configure script

dnl ***********************************************************************
dnl *  Copyright (C) 2002-2005 Remi Denis-Courmont.                       *
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

AC_COPYRIGHT([Copyright (C) 2004-2005 Remi Denis-Courmont])
AC_INIT(miredo, 0.6.0, rdenis@simphalempin.com)
AC_PREREQ(2.59)
INVOCATION="$0 $*"

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_HEADERS(config.h)

AC_DEFINE_UNQUOTED(PACKAGE_CONFIGURE_INVOCATION, "$INVOCATION",
                [Define to the command line used to invoke the configure script.])
RDC_BUILD_HOSTNAME


# Checks for programs.
AS_MESSAGE(checking required programs...)
AC_PROG_CC
AC_PROG_CXX
AC_DISABLE_SHARED
AC_PROG_LIBTOOL
AM_INIT_AUTOMAKE([check-news dist-bzip2 std-options])


# Checks for libraries.
AM_BINRELOC
AM_GNU_GETTEXT([external])
AH_TEMPLATE(HAVE_LINUX,
		[Define to 1 if the host kernel is Linux.])
AH_TEMPLATE(HAVE_FREEBSD,
		[Define to 1 if the host kernel is FreeBSD.])
AH_TEMPLATE(HAVE_OPENBSD,
		[Define to 1 if the host kernel is OpenBSD.])
AH_TEMPLATE(HAVE_NETBSD,
		[Define to 1 if the host kernel is NetBSD.])
AH_TEMPLATE(HAVE_DARWIN,
		[Define to 1 if the host kernel is Darwin (e.g. Mac OS X).])


#AC_CANONICAL_HOST
case $host_os in
  *linux*)
	AC_DEFINE(HAVE_LINUX)
	;;
  *freebsd*)
	AC_DEFINE(HAVE_FREEBSD)
	;;
  *openbsd*)
	AC_DEFINE(HAVE_OPENBSD)
	;;
  *netbsd*)
	AC_DEFINE(HAVE_NETBSD)
	;;
  *darwin*)
	AC_DEFINE(HAVE_DARWIN)
	;;
  *)
	AS_WARN(You have an unrecognized operating system.)
	;;
esac

AC_DEFINE_UNQUOTED(PACKAGE_BUILD, "$build",
                   [Define to the canonical build-system name])
AC_DEFINE_UNQUOTED(PACKAGE_HOST, "$host",
                   [Define to the canonical host-system name])

# Checks for header files.
AC_CHECK_HEADERS([sys/capability.h libintl.h])
dnl Judy.h


# Checks for typedefs, structures, and compiler characteristics.
AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN
dnl AC_CHECK_SIZEOF([void *])


# Checks for library functions.
RDC_REPLACE_FUNC_GETOPT_LONG
AC_CHECK_FUNCS([clearenv strlcpy])
dnl AC_CHECK_LIB([Judy], [JudyLIns])

# Socket stuff
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntop, [nsl])
dnl AC_SEARCH_LIBS(inet_aton, [resolv])

# POSIX threads
AC_SEARCH_LIBS(pthread_create, [pthread c_r])

# POSIX capabilities
AC_CHECK_LIB(cap, cap_set_proc)
AH_BOTTOM([
#ifndef HAVE_SYS_CAPABILITY_H
# undef HAVE_LIBCAP
#endif
])


# Checks for optionnal features

# Teredo client
AC_MSG_CHECKING([whether to enable Teredo client support])
AC_ARG_ENABLE(teredo-client,
	      [AS_HELP_STRING(--disable-teredo-client,
			      [do not compile Teredo client (enabled by default)])])
AH_TEMPLATE(MIREDO_TEREDO_CLIENT,
	    [Define to 1 if the Teredo client support is enabled])
AM_CONDITIONAL(TEREDO_CLIENT, [test "x${enable_teredo_client}" != "xno"])
AS_IF([test "x${enable_teredo_client}" != "xno"],
	[AC_DEFINE(MIREDO_TEREDO_CLIENT)
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)])

# chroot path
AC_MSG_CHECKING([directory to chroot to])
AC_ARG_ENABLE(chroot,
	      [AS_HELP_STRING(--enable-chroot,
	      		      [path to chroot to (PREFIX/var/run/miredo by default)])])
AS_IF([test "x${enable_chroot}" = "x" || test "${enable_chroot}" = "yes"],
	[enable_chroot='${localstatedir}/run/miredo'])
AM_CONDITIONAL(MIREDO_CHROOT, [test "${enable_chroot}" != "no"])
AS_IF([test "${enable_chroot}" != "no"],
	[AC_SUBST(miredo_chroot, "${enable_chroot}")
	AC_MSG_RESULT(${enable_chroot})],
	[AC_MSG_RESULT(not using chroot)])

# unprivileged user
AC_MSG_CHECKING([user to run as])
AC_ARG_ENABLE(miredo-user,
	      [AS_HELP_STRING(--enable-miredo-user,
			      [run as a specific user (disabled by default)])])
AS_IF([test "${enable_miredo_user}" = "yes"],
	[enable_miredo_user="miredo"])
AS_IF([test "x${enable_miredo_user}" = "x" || test "${enable_miredo_user}" = "no"],
	[enable_miredo_user="nobody"])
AH_TEMPLATE(MIREDO_DEFAULT_USERNAME,
            [Define to the system user name to be used by miredo.])
AS_IF([test "${enable_miredo_user}" != "root"],
	[AC_DEFINE_UNQUOTED(MIREDO_DEFAULT_USERNAME, "${enable_miredo_user}")
	AC_MSG_RESULT(${enable_miredo_user})],
	[AC_MSG_RESULT(root)
	AC_MSG_WARN([Running as root is DANGEROUS!])])

# Defines for <config.h>
AH_BOTTOM([
#define _( str )		gettext (str)
#define N_( str )		gettext_noop (str)
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile misc/Makefile libtun6/Makefile libteredo/Makefile libteredo/test/Makefile src/Makefile po/Makefile.in ])
AC_OUTPUT
