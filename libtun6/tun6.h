/*
 * tun6.h - IPv6 tunnel interface declaration
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2006 Remi Denis-Courmont.                       *
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

struct ip6_hdr;
struct in6_addr;

typedef struct tun6 tun6;

# ifdef __cplusplus
extern "C" {
# endif
int tun6_driver_diagnose (char *errbuf);

/*
 * All functions are thread-safe.
 *
 * All functions reports error messages via syslog(). You should hence call
 * openlog() before you create a tunnel.
 */

tun6 *tun6_create (const char *req_name);
void tun6_destroy (tun6 *t);

int tun6_setState (tun6 *t, bool up);
static inline int tun6_bringUp (tun6 *t)
{
	return tun6_setState (t, true);
}

static inline int tun6_bringDown (tun6 *t)
{
	return tun6_setState (t, false);
}

int tun6_addAddress (tun6 *t, const struct in6_addr *addr,
                     unsigned prefix_len);
int tun6_delAddress (tun6 *t, const struct in6_addr *addr,
                     unsigned prefix_len);

int tun6_setMTU (tun6 *t, unsigned mtu);

int tun6_addRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
                   int relative_metric);
int tun6_delRoute (tun6 *t, const struct in6_addr *addr, unsigned prefix_len,
                   int relative_metric);

int tun6_registerReadSet (const tun6 *t, fd_set *readset);

int tun6_recv (const tun6 *t, const fd_set *readset, void *buf, size_t len);
int tun6_send (const tun6 *t, const void *packet, size_t len);

# ifdef __cplusplus
}
# endif /* C++ */

#endif /* ifndef LIBTUN6_TUN6_H */
