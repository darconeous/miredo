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

AC_COPYRIGHT([Copyright (C) 2004 Remi Denis-Courmont])
AC_INIT(miredo, 0.3.3, rdenis@simphalempin.com)
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
AC_PROG_RANLIB
AM_INIT_AUTOMAKE([dist-bzip2])


# Checks for libraries.
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

# Checks for header files.
AC_CHECK_HEADERS(sys/capability.h)


# Checks for typedefs, structures, and compiler characteristics.
dnl AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN


# Checks for library functions.

# Socket stuff
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntoa, [nsl])
dnl AC_SEARCH_LIBS(inet_aton, [resolv])

# POSIX threads
AC_SEARCH_LIBS(pthread_create, [pthread libc_c lthread])

# POSIX capabilities
AC_CHECK_LIB(cap, cap_set_proc)
AH_BOTTOM([
#ifndef HAVE_SYS_CAPABILITY_H
# undef HAVE_LIBCAP
#endif
])

RDC_REPLACE_FUNC_GETOPT_LONG
AC_CHECK_FUNCS(clearenv)


# Checks for optionnal features
AC_MSG_CHECKING([enabled Miredo features])
miredo_features=""
# Teredo server
AC_ARG_ENABLE(teredo-server,
	      [AS_HELP_STRING(--disable-teredo-server,
			      [do not compile Teredo server (enabled by default)])])
AH_TEMPLATE(MIREDO_TEREDO_SERVER,
	    [Define to 1 if the Teredo server support is enabled])
AS_IF([test "x${enable_teredo_server}" != "xno"],
	[AC_DEFINE(MIREDO_TEREDO_SERVER)
	miredo_features="server ${miredo_features}"])
AM_CONDITIONAL(TEREDO_SERVER, [test "x${enable_teredo_server}" != "xno"])

# Teredo relay (includes Teredo client)
AC_ARG_ENABLE(teredo-relay,
	      [AS_HELP_STRING(--disable-teredo-relay,
			      [do not compile Teredo relay & client (enabled by default)])])
AH_TEMPLATE(MIREDO_TEREDO_RELAY,
	    [Define to 1 if the Teredo relay/client support is enabled])
AS_IF([test "x${enable_teredo_relay}" != "xno"],
	[AC_DEFINE(MIREDO_TEREDO_RELAY)
	miredo_features="relay ${miredo_features}"])
AM_CONDITIONAL(TEREDO_RELAY, [test "x${enable_teredo_relay}" != "xno"])

# Teredo client (requires Teredo relay)
AC_ARG_ENABLE(teredo-client,
	      [AS_HELP_STRING(--disable-teredo-client,
			      [do not compile Teredo client (enabled by default)])])
AH_TEMPLATE(MIREDO_TEREDO_CLIENT,
	    [Define to 1 if the Teredo client support is enabled])
AS_IF([test "x${enable_teredo_relay}" != "xno" && test "x${enable_teredo_client}" != "xno"],
	[AC_DEFINE(MIREDO_TEREDO_CLIENT)
	miredo_features="client ${miredo_features}"])
AM_CONDITIONAL(TEREDO_CLIENT, [test "x${enable_teredo_relay}" != "xno" && test "x${enable_teredo_client}" != "xno"])

AS_IF([test "x${miredo_features}" = "x"],
	[AC_MSG_ERROR([all components disabled])])
AC_MSG_RESULT([Teredo ${miredo_features}])

# chroot path
AC_ARG_ENABLE(chroot,
	      [AS_HELP_STRING(--enable-chroot,
	      		      [path to chroot to (${prefix}/var/run/miredo by default)])])
AS_IF([test "x${enable_chroot}" = "x" || test "${enable_chroot}" = "yes"],
	[enable_chroot='${localstatedir}/run/miredo'])
AS_IF([test "${enable_chroot}" != "no"],
	[AC_SUBST(miredo_chroot, "$enable_chroot")])
AM_CONDITIONAL(MIREDO_CHROOT, [test "${enable_chroot}" != "no"])

# unprivileged user
AC_ARG_ENABLE(miredo-user,
	      [AS_HELP_STRING(--enable-miredo-user,
			      [run as a specific user (disabled by default)])])
AS_IF([test "${enable_miredo_user}" = "yes"],
	[enable_miredo_user="miredo"])
AH_TEMPLATE(MIREDO_DEFAULT_USERNAME,
            [Define to the system user name to be used by miredo.])
AS_IF([test "x${enable_miredo_user}" != "x" && test "${enable_miredo_user}" != "no"],
	[AC_DEFINE_UNQUOTED(MIREDO_DEFAULT_USERNAME, "$enable_miredo_user")])

# pidfile path
AC_ARG_ENABLE(pidfile,
	      [AS_HELP_STRING([--enable-pidfile],
			      [path to the pidfile (${enabled by default)])])
AS_IF([test "x${enable_pidfile}" = "x" || test "${enable_pidfile}" = "yes"],
	[enable_pidfile='${localstatedir}/run/miredo.pid'])
AS_IF([test "${enable_pidfile}" != "no"],
	[AC_SUBST(miredo_pidfile, "$enable_pidfile")])
AM_CONDITIONAL(MIREDO_PIDFILE, [test "${enable_pidfile}" != "no"])


# Defines for <config.h>
AH_BOTTOM([
#define _( str )		gettext (str)
#define N_( str )		gettext_noop (str)
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile misc/Makefile include/Makefile libtun6/Makefile libteredo/Makefile src/Makefile po/Makefile.in ])
AC_OUTPUT
