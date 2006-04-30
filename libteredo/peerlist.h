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
	time_t last_rx;
	time_t last_tx;
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

void teredo_peer_queue (teredo_peer *peer, const void *data, size_t len,
                        bool incoming);
void teredo_peer_dequeue (teredo_peer *peer, int fd,
                          teredo_dequeue_cb cb, void *r);

#ifdef __cplusplus
}
#endif

static inline void SetMapping (teredo_peer *peer, uint32_t ip, uint16_t port)
{
	peer->mapped_addr = ip;
	peer->mapped_port = port;
}

static inline void TouchReceive (teredo_peer *peer, time_t now)
{
	peer->last_rx = now;
}

static inline void TouchTransmit (teredo_peer *peer, time_t now)
{
	peer->last_tx = now;
}

static inline
void QueueIncoming (teredo_peer *peer, const void *data, size_t len)
{
	teredo_peer_queue (peer, data, len, true);
}

static inline
void QueueOutgoing (teredo_peer *peer, const void *data, size_t len)
{
	teredo_peer_queue (peer, data, len, false);
}

static inline
void Dequeue (teredo_peer *peer, int fd, teredo_dequeue_cb cb, void *r)
{
	teredo_peer_dequeue (peer, fd, cb, r);
}


static inline
bool IsValid (const teredo_peer *peer, time_t now)
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

teredo_peer *teredo_list_lookup (teredo_peerlist *list, time_t atime,
                                 const struct in6_addr *addr, bool *create);
void teredo_list_release (teredo_peerlist *l);

# ifdef __cplusplus
}
# endif


#endif /* ifndef LIBTEREDO_PEERLIST_H */
