# sockaddr.m4
# Copyright (C) 2003-2004 Remi Denis-Courmont
# <rdenis (at) simphalempin (dot) com>.
# This file (sockaddr.m4) is free software; unlimited permission to
# copy and/or distribute it , with or without modifications, as long
# as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

AC_DEFUN([RDC_STRUCT_SOCKADDR_LEN],
[AH_TEMPLATE(HAVE_SA_LEN, [Define to 1 if `struct sockaddr' has a `sa_len' member.])
AC_CACHE_CHECK([if struct sockaddr has a sa_len member],
rdc_cv_struct_sockaddr_len,
[AC_TRY_COMPILE(
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#elif HAVE_WINSOCK2_H
# include <winsock2.h>
#endif], [struct sockaddr addr; addr.sa_len = 0;],
rdc_cv_struct_sockaddr_len=yes, rdc_cv_struct_sockaddr_len=no)])
if test $rdc_cv_struct_sockaddr_len = yes; then
  AC_DEFINE(HAVE_SA_LEN)
fi
]) 

AC_DEFUN([RDC_STRUCT_SOCKADDR_STORAGE],
[AH_TEMPLATE(sockaddr_storage, [Define to `sockaddr' if <sys/socket.h> does not define.])
AH_TEMPLATE(ss_family, [Define to `sa_family' if <sys/socket.h> does not define.])
AC_CACHE_CHECK([for struct sockaddr_storage in sys/socket.h],
rdc_cv_struct_sockaddr_storage,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#elif HAVE_WINSOCK2_H
# include <winsock2.h>
#endif], [struct sockaddr_storage addr;], rdc_cv_struct_sockaddr_storage=yes,
rdc_cv_struct_sockaddr_storage=no)])
if test $rdc_cv_struct_sockaddr_storage = no; then
  AC_DEFINE(sockaddr_storage, sockaddr)
  AC_DEFINE(ss_family, sa_family)
fi 
])

AC_DEFUN([RDC_TYPE_SOCKLEN_T],
[AH_TEMPLATE(socklen_t, [Define to `int' if <sys/socket.h> does not define.])
AC_CACHE_CHECK([for socklen_t in sys/socket.h],
rdc_cv_type_socklen_t,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif], [socklen_t len;], rdc_cv_type_socklen_t=yes, rdc_cv_type_socklen_t=no)
])
if test $rdc_cv_type_socklen_t = no; then
  AC_DEFINE(socklen_t, int)
fi
])

AC_DEFUN([RDC_FUNC_SOCKET],
[AC_SEARCH_LIBS(socket, [socket], $1, $2)
])

AC_DEFUN([RDC_FUNC_GETADDRINFO],
[gai_support=yes
AC_CHECK_FUNCS([getaddrinfo getnameinfo gai_strerror],,
gai_support=no)
AC_LIBSOURCES([getaddrinfo.h, getaddrinfo.c])dnl
if test $gai_support = no; then
  AC_CHECK_HEADERS([arpa/inet.h netinet/in.h])
  AC_SEARCH_LIBS(gethostbyaddr, [resolv])
  AC_LIBOBJ(getaddrinfo)
fi
])

