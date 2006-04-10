/*
 * tunnel.h - libteredo public C API
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

#ifndef LIBTEREDO_TUNNEL_H
# define LIBTEREDO_TUNNEL_H

# include <stdbool.h>

# ifdef __cplusplus
extern "C" {
# endif

int libteredo_preinit (bool use_client);
void libteredo_terminate (bool use_client);

struct in6_addr;
struct ip6_hdr;

typedef struct libteredo_tunnel libteredo_tunnel;

libteredo_tunnel *libteredo_create (uint32_t ipv4, uint16_t port);
void libteredo_destroy (libteredo_tunnel *t);
int libteredo_register_readset (libteredo_tunnel *t, fd_set *rdset);
void libteredo_run (libteredo_tunnel *t);

int libteredo_set_prefix (libteredo_tunnel *t, uint32_t pref);
int libteredo_set_cone_flag (libteredo_tunnel *t, bool flag);

int libteredo_set_client_mode (libteredo_tunnel *t, const char *s1,
                                      const char *s2);

void libteredo_set_cone_ignore (libteredo_tunnel *t, bool ignore);

void *libteredo_set_privdata (libteredo_tunnel *, void *);
void *libteredo_get_privdata (const libteredo_tunnel *);

typedef void (*libteredo_recv_cb) (void *, const void *, size_t);
void libteredo_set_recv_callback (libteredo_tunnel *t, libteredo_recv_cb cb);
int libteredo_send (libteredo_tunnel *t, const struct ip6_hdr *buf, size_t n);

typedef void (*libteredo_icmpv6_cb) (void *, const void *, size_t,
                                     const struct in6_addr *dst);
void libteredo_set_icmpv6_callback (libteredo_tunnel *t,
                                    libteredo_icmpv6_cb cb);

typedef void (*libteredo_state_up_cb) (void *, const struct in6_addr *,
                                       uint16_t);
typedef void (*libteredo_state_down_cb) (void *);
void libteredo_set_state_cb (libteredo_tunnel *t, libteredo_state_up_cb u,
                             libteredo_state_down_cb d);

# ifdef __cplusplus
}
# endif /* ifdef __cplusplus */
#endif /* ifndef MIREDO_TUNNEL_H */
