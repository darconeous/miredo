dnl configure.ac - Configure script for miredo
dnl based on earlier configure.ac from tcpreen by the same author

dnl Process this file with GNU Autoconf to produce a configure script

dnl ***********************************************************************
dnl *  Copyright © 2002-2006 Rémi Denis-Courmont.                         *
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

AC_COPYRIGHT([Copyright (C) 2004-2006 Remi Denis-Courmont])
AC_INIT(miredo, 0.8.2, rdenis@simphalempin.com)
AC_PREREQ(2.59)
INVOCATION="$0 $*"

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_LIBOBJ_DIR(compat)
AC_CONFIG_HEADERS(config.h)

AC_DEFINE_UNQUOTED(PACKAGE_CONFIGURE_INVOCATION, "$INVOCATION",
                [Define to the command line used to invoke the configure script.])
RDC_BUILD_HOSTNAME


# Checks for programs.
AS_MESSAGE([checking required programs...])
AC_PROG_CC
dnl AC_PROG_CC_C99
AC_PROG_CXX
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AM_INIT_AUTOMAKE([check-news dist-bzip2 no-dist-gzip no-exeext std-options])


# Checks for libraries.
AS_MESSAGE([checking required libraries...])
AM_BINRELOC
AM_GNU_GETTEXT_VERSION([0.12.1])
AM_GNU_GETTEXT([external])
AH_TEMPLATE(HAVE_LINUX,
		[Define to 1 if the host kernel is Linux.])
AH_TEMPLATE(HAVE_FREEBSD,
		[Define to 1 if the host kernel is FreeBSD (or derivative).])
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
  *freebsd*|*dragonfly*)
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
AS_MESSAGE([checking header files...])
AC_CHECK_HEADERS([libintl.h net/if_tun.h net/if_var.h])


# Checks for typedefs, structures, and compiler characteristics.
AS_MESSAGE([checking target characteristics...])
AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN


# Checks for library functions.
AS_MESSAGE([checking library functions...])
RDC_REPLACE_FUNC_GETOPT_LONG
AC_REPLACE_FUNCS([clearenv closefrom pselect strlcpy])

# Socket stuff
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntop, [nsl])
dnl AC_SEARCH_LIBS(inet_aton, [resolv])

# POSIX threads
AC_SEARCH_LIBS(pthread_create, [pthread c_r])
AC_CHECK_FUNC([pthread_barrier_wait],, [AC_LIBOBJ([barrier])])

# POSIX capabilities
LIBCAP=""
AC_CHECK_HEADERS([sys/capability.h], [
	AC_CHECK_LIB(cap, cap_set_proc, [
		LIBCAP="-lcap"
		AC_DEFINE(HAVE_LIBCAP, 1,
			  [Define to 1 if you have the `cap' library (-lcap).])
	])
])
AC_SUBST(LIBCAP)

# Checks for optionnal features
AS_MESSAGE([checking optional features...])

# Judy
AC_ARG_WITH(Judy,
	    [AS_HELP_STRING(--without-Judy,
	    		    [do not use Judy dynamic arrays (default automatic)])])
have_Judy=no
LIBJUDY=""
AS_IF([test "${with_Judy}" != "no"], [
	AC_CHECK_HEADERS([Judy.h], [
		AC_CHECK_LIB(Judy, JudyHSIns, [
			have_Judy=yes
			LIBJUDY="-lJudy"
			AC_DEFINE(HAVE_LIBJUDY, 1,
				  [Define to 1 if you the `Judy' library (-lJudy).])
		])
	])
])
AC_SUBST(LIBJUDY)
AC_MSG_CHECKING([whether to use Judy dynamic arrays])
AC_MSG_RESULT([${have_Judy}])
AS_IF([test "x${have_Judy}" = "xno" && test "x${with_Judy}" = "xyes"],
	[AC_MSG_ERROR([Judy requested while not available])])

# Teredo client
AC_MSG_CHECKING([whether to include Teredo client support])
AC_ARG_ENABLE(teredo-client,
	      [AS_HELP_STRING(--disable-teredo-client,
			      [do not compile Teredo client (default enabled)])])
AH_TEMPLATE(MIREDO_TEREDO_CLIENT,
	    [Define to 1 if the Teredo client support is enabled])
AM_CONDITIONAL(TEREDO_CLIENT, [test "x${enable_teredo_client}" != "xno"])
AS_IF([test "x${enable_teredo_client}" != "xno"],
	[AC_DEFINE(MIREDO_TEREDO_CLIENT)
	AC_MSG_RESULT(yes)],
	[AC_MSG_RESULT(no)])

# Debugging
AC_MSG_CHECKING([whether to compile debug code])
AC_ARG_ENABLE(debug,
	      [AS_HELP_STRING(--enable-debug,
			       [compile debug code (default disabled)])])
AH_TEMPLATE(NDEBUG,
	    [Define to 1 if debug code should NOT be compiled])
AS_IF([test "x${enable_debug}" = "x"], [enable_debug=no])
AS_IF([test "x${enable_debug}" = "xno"],
	[AC_DEFINE(NDEBUG)], [enable_debug=yes])
AC_MSG_RESULT(${enable_debug})

# unprivileged user
AC_MSG_CHECKING([user to run as])
AC_ARG_ENABLE(miredo-user,
	      [AS_HELP_STRING(--enable-miredo-user,
			      [run as a user (default nobody)])])
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
#define _( str )		dgettext (PACKAGE_NAME, str)
#define N_( str )		gettext_noop (str)

#ifdef __cplusplus
extern "C" {
#endif
#if !HAVE_CLEARENV
int clearenv (void);
#endif
#if !HAVE_CLOSEFROM
int closefrom (int lowfd);
#endif
#if !HAVE_STRLCPY
# include <stddef.h>
size_t strlcpy (char *tgt, const char *str, size_t len);
#endif
#ifdef __cplusplus
}
#endif
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile doc/Makefile misc/Makefile compat/Makefile libtun6/Makefile libteredo/Makefile libteredo/test/Makefile src/Makefile po/Makefile.in ])
AC_OUTPUT
