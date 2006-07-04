/*
 * tun6.h - IPv6 tunnel interface declaration
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license.         *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.               *
 *  See the GNU General Public License for more details.               *
 *                                                                     *
 *  You should have received a copy of the GNU General Public License  *
 *  along with this program; if not, you can get it from:              *
 *  http://www.gnu.org/copyleft/gpl.html                               *
 ***********************************************************************/

#ifndef LIBTUN6_TUN6_H
# define LIBTUN6_TUN6_H

# include <stddef.h> /* NULL */
# include <stdbool.h>
# include <sys/types.h>
# include <sys/select.h>

# define LIBTUN6_ERRBUF_SIZE 4096

# if __STDC_VERSION__ < 199901L
#  ifndef inline
#   define inline
#  endif
#  ifndef restrict
#   define restrict
#  endif
# endif

# ifdef __GNUC__
#  define LIBTUN6_NONNULL __attribute__ ((nonnull))
#  if __GNUC__ >= 3
#   define LIBTUN6_PURE __attribute__ ((pure))
#  else
#   define LIBTUN6_PURE
#  endif
#  if __GNUC__ >= 4
#   define LIBTUN6_WARN_UNUSED __attribute__ ((warn_unused_result))
#  else
#   define LIBTUN6_WARN_UNUSED
#  endif
# else
#  define LIBTUN6_NONNULL
#  define LIBTUN6_WARN_UNUSED
#  define LIBTUN6_PURE
# endif

struct ip6_hdr;
struct in6_addr;

typedef struct tun6 tun6;

# ifdef __cplusplus
extern "C" {
# endif
int tun6_driver_diagnose (char *errbuf) LIBTUN6_NONNULL;

/*
 * All functions are thread-safe.
 *
 * All functions reports error messages via syslog(). You should hence call
 * openlog() before you create a tunnel.
 */

tun6 *tun6_create (const char *req_name) LIBTUN6_WARN_UNUSED;
void tun6_destroy (tun6 *t) LIBTUN6_NONNULL;

int tun6_getId (const tun6 *t) LIBTUN6_NONNULL;

int tun6_setState (tun6 *t, bool up) LIBTUN6_NONNULL;
static inline int tun6_bringUp (tun6 *t)
{
	return tun6_setState (t, true);
}

static inline int tun6_bringDown (tun6 *t)
{
	return tun6_setState (t, false);
}

int tun6_addAddress (tun6 *restrict t, const struct in6_addr *restrict addr,
                     unsigned prefix_len) LIBTUN6_NONNULL;
int tun6_delAddress (tun6 *restrict t, const struct in6_addr *restrict addr,
                     unsigned prefix_len) LIBTUN6_NONNULL;

int tun6_setMTU (tun6 *t, unsigned mtu) LIBTUN6_NONNULL;

int tun6_addRoute (tun6 *restrict t, const struct in6_addr *restrict addr,
                   unsigned prefix_len, int relative_metric) LIBTUN6_NONNULL;
int tun6_delRoute (tun6 *restrict t, const struct in6_addr *restrict addr,
                   unsigned prefix_len, int relative_metric) LIBTUN6_NONNULL;

int tun6_registerReadSet (const tun6 *restrict t, fd_set *restrict readset)
	LIBTUN6_NONNULL LIBTUN6_PURE;

int tun6_recv (tun6 *restrict t, const fd_set *restrict readset,
               void *buf, size_t len) LIBTUN6_NONNULL;
int tun6_wait_recv (tun6 *restrict t, void *buf, size_t len) LIBTUN6_NONNULL;
int tun6_send (tun6 *restrict t, const void *packet, size_t len)
	LIBTUN6_NONNULL;

# ifdef __cplusplus
}
# endif /* C++ */

#endif /* ifndef LIBTUN6_TUN6_H */
