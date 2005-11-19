/*
 * tun6.h - IPv6 interface class declaration
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

/*
 * Tries to allocate a tunnel interface from the kernel.
 * req_name may be an interface name for the virtual network device (it might
 * be ignored on some OSes). If NULL, an internal default will be used.
 *
 * Returns NULL on error.
 */
tun6 *tun6_create (const char *req_name);

/*
 * Removes a tunnel from the kernel.
 * BEWARE: if you fork, child processes must call tun6_destroy() too.
 *
 * The kernel will destroy the tunnel interface once all processes called
 * tun6_destroy and/or were terminated.
 */
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

/*
 * Registers file descriptors in an fd_set for use with select(). Returns the
 * "biggest" file descriptor registered (useful as the first parameter to
 * select()).
 */
int tun6_registerReadSet (const tun6 *t, fd_set *readset);

/*
 * Checks an fd_set, receives a packet and puts the result in <buffer>.
 * <maxlen>, which is the length of the buffer in bytes, should be 65535.
 *
 * This function will block if there is no input.
 *
 * Returns the packet length on success,
 * -1 if no packet were to be received.
 */
int tun6_recv (const tun6 *t, const fd_set *readset, void *buf, size_t len);

/*
 * Sends an IPv6 packet at <packet>, of length <len>.
 * Returns the number of bytes succesfully transmitted on success,
 * -1 on error.
 */
int tun6_send (const tun6 *t, const void *packet, size_t len);

# ifdef __cplusplus
}
# endif /* C++ */

#endif /* ifndef LIBTUN6_TUN6_H */
