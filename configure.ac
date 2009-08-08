dnl configure.ac - Configure script for miredo
dnl based on earlier configure.ac from tcpreen by the same author

dnl Process this file with GNU Autoconf to produce a configure script

dnl ***********************************************************************
dnl *  Copyright © 2004-2008 Rémi Denis-Courmont.                         *
dnl *  This program is free software; you can redistribute and/or modify  *
dnl *  it under the terms of the GNU General Public License as published  *
dnl *  by the Free Software Foundation; version 2 of the license, or (at  *
dnl *  your option) any later version.                                    *
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

AC_COPYRIGHT([Copyright (C) 2004-2009 Remi Denis-Courmont])
AC_INIT(miredo, 1.2.0, miredo-devel_no_bulk_mail@remlab.net)
AC_PREREQ(2.59c)
INVOCATION="$0 $ac_configure_args"

AS_MESSAGE(checking system...)
AC_CONFIG_SRCDIR(configure.ac)
AC_CONFIG_AUX_DIR(admin)
AC_CONFIG_MACRO_DIR(m4)
AC_CONFIG_LIBOBJ_DIR(compat)
AC_CONFIG_HEADERS(config.h)

AC_DEFINE_UNQUOTED(PACKAGE_CONFIGURE_INVOCATION, "$INVOCATION",
                [Define to the command line used to invoke the configure script.])
RDC_BUILD_HOSTNAME
AC_CANONICAL_HOST


# Checks for programs.
AS_MESSAGE([checking required programs...])

AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_DEFINE(_APPLE_C_SOURCE, 1, [Define to fix pthread_cancel() on Mac OS X.])

dnl Work-around for libtool bug (from Darren Salt)
LT_PREREQ([2.2.0])
LT_INIT
AM_INIT_AUTOMAKE


# Checks for libraries.
AS_MESSAGE([checking required libraries...])
AM_BINRELOC
AM_GNU_GETTEXT_VERSION([0.16.1])
AM_GNU_GETTEXT([external])

LIBRT=""
AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"])
AC_SUBST(LIBRT)
RDC_FUNC_SOCKET
AC_SEARCH_LIBS(inet_ntop, [nsl])
AC_SEARCH_LIBS(devname, [freebsd])
AC_CHECK_LIB(resolv, res_init)

# Oooh, evil platform-rather-than-feature tests
case "${host_os}" in
	darwin*)
		AC_DEFINE(HAVE_SYSTEMCONFIGURATION_FRAMEWORK, 1,
		          [Define to 1 if Apple's SystemConfiguration framework is available.])
		CFLAGS="${CFLAGS} -framework SystemConfiguration"
		AC_DEFINE(HAVE_COREFOUNDATION_FRAMEWORK, 1,
		          [Define to 1 if Apple's CoreFoundation framework is available.])
		CFLAGS="${CFLAGS} -framework CoreFoundation"
		;;
esac

AC_MSG_CHECKING([which hook scripts to use])
case "${host_os}" in
	*linux*)
		hook_suffix=iproute
		;;
	*)
		hook_suffix=bsd
		;;
esac
AC_MSG_RESULT([${hook_suffix}])
AC_SUBST(hook_suffix)


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
RDC_PROG_CC_WFLAGS([all extra undef pointer-arith bad-function-cast cast-align write-strings aggregate-return strict-prototypes old-style-definition missing-prototypes missing-noreturn packed nested-externs redundant-decls volatile-register-var])
#shadow fails because of ntohl()
#cast-qual fails because of const/iovec, libcap, Judy
# padded unreachable-code missing-format-attribute inline

AC_C_BIGENDIAN
RDC_STRUCT_SOCKADDR_LEN
AC_CHECK_TYPE([clockid_t],, [
  AC_DEFINE([clockid_t], [int], [Define to int if clockid_t is not supported.])],
[#include <time.h>
])


# Checks for library functions.
AS_MESSAGE([checking library functions...])
RDC_REPLACE_FUNC_GETOPT_LONG
LIBS_save="$LIBS"
LIBS="$LIBRT $LIBS"
AC_CHECK_FUNCS([devname_r pthread_condattr_setclock timer_create])
AC_REPLACE_FUNCS([clearenv closefrom strlcpy clock_gettime clock_nanosleep fdatasync])
LIBS="$LIBS_save"

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
	    		    [use Judy dynamic arrays (default enabled)])],,
	    [with_Judy=yes])
LIBJUDY=""
AS_IF([test "${with_Judy}" != "no"], [
	AC_CHECK_HEADERS([Judy.h], [
		AC_CHECK_LIB(Judy, JudyHSIns, [
			LIBJUDY="-lJudy"
			AC_DEFINE(HAVE_LIBJUDY, 1,
				  [Define to 1 if you the `Judy' library (-lJudy).])
		])
	])
	AS_IF([test "x${LIBJUDY}" = "x"], [
		AC_MSG_WARN([If you don't care about scalability, re-run configure with '--without-Judy'.])
		AC_MSG_ERROR([Required Judy dynamic arrays library missing.])
	])

])
AC_SUBST(LIBJUDY)


# Test coverage build
AC_MSG_CHECKING([whether to build for test coverage])
AC_ARG_ENABLE(coverage,
	[AS_HELP_STRING(--enable-coverage,
		[build for test coverage (default disabled)])],,
	[enable_coverage="no"])
AS_IF([test "${enable_coverage}" != "no"], [
	CFLAGS="${CFLAGS} -g -O0 -fprofile-arcs -ftest-coverage"
	LDFLAGS="${LDFLAGS} -lgcov"
	AC_MSG_RESULT(yes)
], [
	AC_MSG_RESULT(no)
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
AC_ARG_ENABLE(examplesdir,
	[AS_HELP_STRING(--enable-examplesdir,
		[install sample config files (default ${docdir}/examples)])],,
	[enable_examplesdir='${docdir}/examples'])
AS_IF([test "x${enable_examplesdir}" != "xno"],
	[examplesdir="${enable_examplesdir}"])
AC_SUBST(examplesdir)

AC_ARG_ENABLE(sample-conf,
	[AS_HELP_STRING(--disable-sample-conf,
		[do not install sample config files (default enabled)])],,
	[enable_sample_conf="yes"])
AM_CONDITIONAL(CONF_SAMPLE, [test "${enable_sample_conf}" != "no"])


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
AH_BOTTOM([#include "compat/fixups.h"])


# END
AS_MESSAGE(writing results...)
AC_CONFIG_FILES([Makefile m4/Makefile doc/Makefile misc/Makefile compat/Makefile libtun6/Makefile libteredo/Makefile libteredo/test/Makefile src/Makefile po/Makefile.in Doxyfile])
AC_OUTPUT
