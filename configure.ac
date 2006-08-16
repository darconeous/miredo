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
AC_INIT(miredo, 0.9.9, miredo-devel_no_bulk_mail@remlab.net)
AC_PREREQ(2.59c)
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

AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_DEFINE(_APPLE_C_SOURCE, 1, [Define to fix pthread_cancel() on Mac OS X.])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE([check-news dist-bzip2 no-dist-gzip no-exeext std-options])


# Checks for libraries.
AS_MESSAGE([checking required libraries...])
AM_BINRELOC
AM_GNU_GETTEXT_VERSION([0.12.1])
AM_GNU_GETTEXT([external])

LIBRT=""
AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"])
AC_SUBST(LIBRT)
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntop, [nsl])
AC_CHECK_LIB(resolv, res_init)

# POSIX threads
AC_ARG_VAR(PTHREAD_CFLAGS, [C compiler flags for POSIX threads])
AS_IF([test "${PTHREAD_CFLAGS}"], [
	CFLAGS="${CFLAGS} ${PTHREAD_CFLAGS}"
])
AC_ARG_VAR(PTHREAD_LDFLAGS, [Linker flags for POSIX threads])
AC_ARG_VAR(PTHREAD_LIBS, [Same as PTHREAD_LFLAGS])
AS_IF([test "${PTHREAD_LDFAGS}${PTHREAD_LIBS}"], [
	# Neat! the packaging system tells us how to use pthread
	LIBS="${PTHREAD_LDFLAGS} ${PTHREAD_LIBS} ${LIBS}"
], [
	AC_CHECK_LIB(pthread, pthread_create)
])

AC_DEFINE_UNQUOTED(PACKAGE_BUILD, "$build",
                   [Define to the canonical build-system name])
AC_DEFINE_UNQUOTED(PACKAGE_HOST, "$host",
                   [Define to the canonical host-system name])


# Checks for header files.
AS_MESSAGE([checking header files...])
AC_HEADER_ASSERT
AC_CHECK_HEADERS([libintl.h net/if_tun.h net/tun/if_tun.h])
AC_CHECK_HEADERS([net/if_var.h],,,
[#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
])


# Checks for typedefs, structures, and compiler characteristics.
AS_MESSAGE([checking target characteristics...])
AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN
AC_CHECK_TYPE([clockid_t],, [
  AC_DEFINE([clockid_t], [int], [Define to int if clockid_t is not supported.])],
[#include <time.h>
])


# Checks for library functions.
AS_MESSAGE([checking library functions...])
AC_CHECK_FUNCS([devname_r])
RDC_REPLACE_FUNC_GETOPT_LONG
LIBS_save="$LIBS"
LIBS="$LIBRT $LIBS"
AC_REPLACE_FUNCS([clearenv closefrom pselect strlcpy clock_gettime clock_nanosleep])
LIBS="$LIBS_save"

AC_CHECK_FUNC([pthread_barrier_wait], [
  AC_DEFINE([HAVE_PTHREAD_BARRIER], 1, [Define to 1 if you have pthread_barrier_*.])
], [
  AC_LIBOBJ([barrier])
])

# Checks for optionnal features
AS_MESSAGE([checking optional features...])

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


# Judy
AC_ARG_WITH(Judy,
	    [AS_HELP_STRING(--with-Judy,
	    		    [use Judy dynamic arrays (default automatic)])])
use_Judy=no
LIBJUDY=""
AS_IF([test "${with_Judy}" != "no"], [
	AC_CHECK_HEADERS([Judy.h], [
		AC_CHECK_LIB(Judy, JudyHSIns, [
			use_Judy=yes
			LIBJUDY="-lJudy"
			AC_DEFINE(HAVE_LIBJUDY, 1,
				  [Define to 1 if you the `Judy' library (-lJudy).])
		], [
			AS_IF([test "${with_judy}"], [
				AC_MSG_ERROR([Judy requested while not available])
			])
		])
	])
])
AC_SUBST(LIBJUDY)
AC_MSG_CHECKING([whether to use Judy dynamic arrays])
AC_MSG_RESULT([${use_Judy}])
AS_IF([test "${use_Judy}" = "no"], [
	AC_MSG_WARN([Miredo is considerably less scalable without libJudy!])
])


# Teredo client
AC_MSG_CHECKING([whether to include Teredo client support])
AC_ARG_ENABLE(teredo-client,
	[AS_HELP_STRING(--disable-teredo-client,
		[do not compile Teredo client (default enabled)])],,
	[enable_teredo_client="yes"])
AM_CONDITIONAL(TEREDO_CLIENT, [test "${enable_teredo_client}" != "no"])
AS_IF([test "${enable_teredo_client}" != "no"], [
	AC_DEFINE(MIREDO_TEREDO_CLIENT, 1,
		[Define to 1 if the Teredo client support must be compiled.])
])
AC_MSG_RESULT([${enable_teredo_client}])


# Configuration files installation
AC_MSG_CHECKING([how to install configuration files])
AC_ARG_ENABLE(erase-conf,
	[AS_HELP_STRING(--enable-erase-conf,
		[erase configuration files (default disabled)])],,
	[enable_erase_conf="no"])
AC_ARG_ENABLE(sample-conf,
	[AS_HELP_STRING(--disable-sample-conf,
		[do not install sample config files (default enabled)])],,
	[enable_sample_conf="yes"])
AM_CONDITIONAL(CONF_ERASE, [test "${enable_erase_conf}" != "no"])
AM_CONDITIONAL(CONF_SAMPLE, [test "${enable_sample_conf}" != "no"])
AS_IF([test "${enable_erase_conf}" != "no"], [
	conf_msg="replace existing"
], [
	AS_IF([test "${enable_sample_conf}" != "no"], [
		conf_msg="install samples"
	], [
		conf_msg="do nothing"
	])
])
AC_MSG_RESULT([${conf_msg}])


# Unprivileged user
AC_MSG_CHECKING([user to run as])
AC_ARG_ENABLE(miredo-user,
	[AS_HELP_STRING(--enable-miredo-user,
		[run as a specific user (default nobody)])], [
	AS_IF([test "${enable_miredo_user}" = "yes"],
		[enable_miredo_user="miredo"])
	AS_IF([test "${enable_miredo_user}" = "no"],
		[enable_miredo_user="root"])
], [
	enable_miredo_user="nobody"
])
AC_MSG_RESULT([${enable_miredo_user}])
AS_IF([test "${enable_miredo_user}" != "root"], [
	AC_DEFINE_UNQUOTED(MIREDO_DEFAULT_USERNAME, "${enable_miredo_user}",
		[Define to the default system username to be used.])
], [
	AC_MSG_WARN([Running as root is DANGEROUS!])
])


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
#if !HAVE_CLOCK_GETTIME
# include <time.h>
# ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME 0
# endif
int clock_gettime (clockid_t id, struct timespec *now);
#endif
#if !HAVE_CLOCK_NANOSLEEP
# include <time.h>
# ifndef TIMER_ABSTIME
#  define TIMER_ABSTIME 1
# endif
# undef _POSIX_CLOCK_SELECTION
# define _POSIX_CLOCK_SELECTION (-1)
# undef _POSIX_MONOTONIC_CLOCK
# define _POSIX_MONOTONIC_CLOCK (-1)
int clock_nanosleep (clockid_t id, int flags, const struct timespec *ts,
                     struct timespec *ots);
#endif
#ifdef __cplusplus
}
#endif
])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile doc/Makefile compat/Makefile libtun6/Makefile libteredo/Makefile libteredo/test/Makefile src/Makefile po/Makefile.in ])
AC_OUTPUT
