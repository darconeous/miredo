/*
 * peerlist.h - Teredo relay internal peers list declaration
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

#ifndef LIBTEREDO_PEERLIST_H
# define LIBTEREDO_PEERLIST_H

# ifdef __cplusplus
# define TEREDO_TIMEOUT 30 // seconds
# define MAXQUEUE 1280u // bytes

class teredo_peer
{
	private:
		void Queue (const void *data, size_t len, bool incoming);
		struct packet;

		packet *queue;
		size_t queue_left;
		time_t last_rx;
		time_t last_tx;
		time_t last_ping;

	public:
		uint32_t mapped_addr;
		uint16_t mapped_port;
		unsigned trusted:1;
		unsigned pings:2;
		unsigned bubbles:3;

		teredo_peer (void) : queue (NULL), queue_left (TeredoRelay::MaxQueueBytes)
		{
		}
		~teredo_peer (void);

	public:
		void SetMapping (uint32_t ip, uint16_t port)
		{
			mapped_addr = ip;
			mapped_port = port;
		}

		void SetMappingFromPacket (const teredo_packet *p)
		{
			SetMapping (p->source_ipv4, p->source_port);
		}

		void TouchReceive (void)
		{
			time (&last_rx);
		}

		void TouchTransmit (time_t now)
		{
			last_tx = now;
		}

		void QueueIncoming (const void *data, size_t len)
		{
			Queue (data, len, true);
		}

		void QueueOutgoing (const void *data, size_t len)
		{
			Queue (data, len, false);
		}

		void Dequeue (int fd, TeredoRelay *r);

		/* FIXME: use this */
		bool IsValid (time_t now) const
		{
			return (now - last_rx) > 30;
		}

		int CountBubble (time_t now);
		int CountPing (time_t now);
};

# endif

typedef struct teredo_peerlist teredo_peerlist;

struct in6_addr;

# ifdef __cplusplus
extern "C" {
# else
typedef struct teredo_peer teredo_peer; /* FIXME: temporary */
# endif

teredo_peerlist *teredo_list_create (unsigned max, unsigned expiration);
void teredo_list_destroy (teredo_peerlist *l);

teredo_peer *teredo_list_lookup (teredo_peerlist *list, time_t atime,
                                 const struct in6_addr *addr, bool *create);
void teredo_list_release (teredo_peerlist *l);

# ifdef __cplusplus
}
# endif


#endif /* ifndef LIBTEREDO_PEERLIST_H */
