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

int teredo_startup (bool use_client);
void teredo_cleanup (bool use_client);

struct in6_addr;
struct ip6_hdr;

typedef struct teredo_tunnel teredo_tunnel;

teredo_tunnel *teredo_create (uint32_t ipv4, uint16_t port);
void teredo_destroy (teredo_tunnel *t);
void teredo_run (teredo_tunnel *t);
int teredo_run_async (teredo_tunnel *t);

int teredo_set_prefix (teredo_tunnel *t, uint32_t pref);
int teredo_set_cone_flag (teredo_tunnel *t, bool flag);

int teredo_set_client_mode (teredo_tunnel *t, const char *s1,
                                      const char *s2);

void teredo_set_cone_ignore (teredo_tunnel *t, bool ignore);

void *teredo_set_privdata (teredo_tunnel *, void *);
void *teredo_get_privdata (const teredo_tunnel *);

typedef void (*teredo_recv_cb) (void *, const void *, size_t);
void teredo_set_recv_callback (teredo_tunnel *t, teredo_recv_cb cb);
int teredo_transmit (teredo_tunnel *t, const struct ip6_hdr *buf, size_t n);

typedef void (*teredo_icmpv6_cb) (void *, const void *, size_t,
                                     const struct in6_addr *dst);
void teredo_set_icmpv6_callback (teredo_tunnel *t, teredo_icmpv6_cb cb);

typedef void (*teredo_state_up_cb) (void *, const struct in6_addr *,
                                       uint16_t);
typedef void (*teredo_state_down_cb) (void *);
void teredo_set_state_cb (teredo_tunnel *t, teredo_state_up_cb u,
                             teredo_state_down_cb d);

# ifdef __cplusplus
}
# endif /* ifdef __cplusplus */
#endif /* ifndef MIREDO_TUNNEL_H */
