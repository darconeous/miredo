/*
 * peerlist.h - Teredo relay internal peers list declaration
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

#ifndef LIBTEREDO_PEERLIST_H
# define LIBTEREDO_PEERLIST_H

# define TEREDO_TIMEOUT 30 // seconds
# define MAXQUEUE 1280u // bytes

typedef struct teredo_queue teredo_queue;

typedef struct teredo_peer
{
	teredo_queue *queue;
	size_t queue_left;
	teredo_clock_t last_rx;
	teredo_clock_t last_tx;
	uint32_t mapped_addr;
	uint16_t mapped_port;
	unsigned trusted:1;
	unsigned bubbles:3;
	unsigned pings:3;
	unsigned last_ping:9;
} teredo_peer;


typedef void (*teredo_dequeue_cb) (void *, const void *, size_t);

#ifdef __cplusplus
extern "C" {
#endif

void teredo_enqueue_in (teredo_peer *restrict peer, const void *restrict data,
                        size_t len, uint32_t ip, uint16_t port);

void teredo_enqueue_out (teredo_peer *restrict peer,
                         const void *restrict data, size_t len);
teredo_queue *teredo_peer_queue_yield (teredo_peer *peer);
void teredo_queue_emit (teredo_queue *q, int fd, uint32_t ipv4, uint16_t port,
                        teredo_dequeue_cb cb, void *r);

#ifdef __cplusplus
}
#endif

static inline void SetMapping (teredo_peer *peer, uint32_t ip, uint16_t port)
{
	peer->mapped_addr = ip;
	peer->mapped_port = port;
}

static inline void TouchReceive (teredo_peer *peer, teredo_clock_t now)
{
	peer->last_rx = now;
}

static inline void TouchTransmit (teredo_peer *peer, teredo_clock_t now)
{
	peer->last_tx = now;
}


static inline
bool IsValid (const teredo_peer *peer, teredo_clock_t now)
{
	return (now - peer->last_rx) <= 30;
}


typedef struct teredo_peerlist teredo_peerlist;

struct in6_addr;

# ifdef __cplusplus
extern "C" {
# endif

teredo_peerlist *teredo_list_create (unsigned max, unsigned expiration);
void teredo_list_destroy (teredo_peerlist *l);
void teredo_list_reset (teredo_peerlist *l, unsigned max);

teredo_peer *teredo_list_lookup (teredo_peerlist *restrict list,
                                 const struct in6_addr *restrict addr,
                                 bool *restrict create);
void teredo_list_release (teredo_peerlist *l);

# ifdef __cplusplus
}
# endif


#endif /* ifndef LIBTEREDO_PEERLIST_H */
