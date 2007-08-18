/*
 * peerlist.c - Teredo relay internal peers list manipulation
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdlib.h> /* malloc() / free() */
#include <assert.h>

#include <inttypes.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>

#ifndef NDEBUG
# define JUDYERROR_NOTEST 1
#endif
#ifdef HAVE_JUDY_H
# include <Judy.h>
#endif

#include "teredo.h"
#include "teredo-udp.h" // FIXME: ugly
#include "debug.h"
#include "clock.h"
#include "peerlist.h"

/*
 * Packets queueing
 */
struct teredo_queue
{
	teredo_queue *next;
	size_t length;
	uint32_t ipv4;
	uint16_t port;
	bool incoming;
	uint8_t data[];
};

static const unsigned teredo_MaxQueueBytes = 1280;


static inline void teredo_peer_init (teredo_peer *peer)
{
	peer->queue = NULL;
	peer->queue_left = teredo_MaxQueueBytes;
}


static inline void teredo_peer_destroy (teredo_peer *peer)
{
	teredo_queue *p = peer->queue;

	while (p != NULL)
	{
		teredo_queue *buf;

		buf = p->next;
		free (p);
		p = buf;
	}
}


static void teredo_peer_queue (teredo_peer *restrict peer,
                               const void *restrict data, size_t len,
                               uint32_t ip, uint16_t port, bool incoming)
{
	teredo_queue *p;

	if (len > peer->queue_left)
		return;
	peer->queue_left -= len;

	p = (teredo_queue *)malloc (sizeof (*p) + len);
	p->length = len;
	memcpy (p->data, data, len);
	p->ipv4 = ip;
	p->port = port;
	p->incoming = incoming;

	p->next = peer->queue;
	peer->queue = p;
}


void teredo_enqueue_in (teredo_peer *restrict peer, const void *restrict data,
                        size_t len, uint32_t ip, uint16_t port)
{
	teredo_peer_queue (peer, data, len, ip, port, true);
}


void teredo_enqueue_out (teredo_peer *restrict peer,
                         const void *restrict data, size_t len)
{
	teredo_peer_queue (peer, data, len, 0, 0, false);
}


teredo_queue *teredo_peer_queue_yield (teredo_peer *peer)
{
	teredo_queue *q = peer->queue;
	peer->queue = NULL;
	peer->queue_left = teredo_MaxQueueBytes;
	return q;
}


void teredo_queue_emit (teredo_queue *q, int fd, uint32_t ipv4, uint16_t port,
                        teredo_dequeue_cb cb, void *opaque)
{
	while (q != NULL)
	{
		teredo_queue *buf;

		buf = q->next;
		if (q->incoming)
		{
			if ((ipv4 == q->ipv4) && (port == q->port))
				cb (opaque, q->data, q->length);
		}
		else
			teredo_send (fd, q->data, q->length, ipv4, port);
		free (q);
		q = buf;
	}
}


/*** Peer list handling ***/
typedef struct teredo_listitem
{
	struct teredo_listitem **pprev, *next;
	teredo_peer peer;
	union teredo_addr key;
} teredo_listitem;

struct teredo_peerlist
{
	teredo_listitem *recent, *old;
	unsigned left;
	unsigned expiration;
	pthread_t gc;
	pthread_mutex_t lock;
#ifdef HAVE_LIBJUDY
	Pvoid_t PJHSArray;
#endif
};


static inline teredo_listitem *listitem_create (void)
{
	teredo_listitem *entry = malloc (sizeof (*entry));
	if (entry != NULL)
		teredo_peer_init (&entry->peer);
	return entry;
}


static inline void listitem_destroy (teredo_listitem *entry)
{
	teredo_peer_destroy (&entry->peer);
	free (entry);
}


static void listitem_recdestroy (teredo_listitem *entry)
{
	while (entry != NULL)
	{
		teredo_listitem *buf = entry->next;
		listitem_destroy (entry);
		entry = buf;
	}
}


/**
 * Peer list garbage collector entry point.
 *
 * @return never ever.
 */
static LIBTEREDO_NORETURN void *garbage_collector (void *data)
{
	struct teredo_peerlist *l = (struct teredo_peerlist *)data;

	for (;;)
	{
		struct timespec delay = { .tv_sec = l->expiration };
		while (clock_nanosleep (CLOCK_REALTIME, 0, &delay, &delay));

		int state;
		pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &state);
		/* cancel-unsafe section starts */
		pthread_mutex_lock (&l->lock);

		// remove expired peers from hash table
		for (teredo_listitem *p = l->old; p != NULL; p = p->next)
		{
#ifdef HAVE_LIBJUDY
			int Rc_int;
			JHSD (Rc_int, l->PJHSArray, (uint8_t *)&p->key, 16);
			assert (Rc_int);
#endif
			l->left++;
		}

		// unlinks old peers
		teredo_listitem *old = l->old;

		// moves recent peers to old peers area
		l->old = l->recent;
		l->recent = NULL;
		if (l->old != NULL)
			l->old->pprev = &l->old;

		pthread_mutex_unlock (&l->lock);

		// Perform possibly expensive memory release without the lock
		listitem_recdestroy (old);

		/* cancel-unsafe section ends */
		pthread_setcancelstate (state, NULL);
	}
}


teredo_peerlist *teredo_list_create (unsigned max, unsigned expiration)
{
	/*printf ("Peer size: %u/%u bytes\n",sizeof (teredo_peer),
	        sizeof (teredo_listitem));*/
	assert (expiration > 0);

	teredo_peerlist *l = (teredo_peerlist *)malloc (sizeof (*l));
	if (l == NULL)
		return NULL;

	memset (l, 0, sizeof (l));
	pthread_mutex_init (&l->lock, NULL);
	l->recent = l->old = NULL;
	l->left = max;
	l->expiration = expiration;
#ifdef HAVE_LIBJUDY
	l->PJHSArray = (Pvoid_t)NULL;
#endif

	if (pthread_create (&l->gc, NULL, garbage_collector, l))
	{
		pthread_mutex_destroy (&l->lock);
		free (l);
		return NULL;
	}

	return l;
}


void teredo_list_reset (teredo_peerlist *l, unsigned max)
{
	pthread_mutex_lock (&l->lock);

#ifdef HAVE_LIBJUDY
	// detach old array
	Pvoid_t array = l->PJHSArray;
	l->PJHSArray = (Pvoid_t)NULL;
#endif

	teredo_listitem *recent = l->recent, *old = l->old;
	// unlinks peers and resets lists
	l->recent = l->old = NULL;
	l->left = max;

	pthread_mutex_unlock (&l->lock);

	/* the mutex is not needed for actual memory release */
	listitem_recdestroy (old);
	listitem_recdestroy (recent);

#ifdef HAVE_LIBJUDY
	// destroy the old array that was detached before unlocking
	Word_t Rc_word;
	JHSFA (Rc_word, array);
#endif
}


void teredo_list_destroy (teredo_peerlist *l)
{
	teredo_list_reset (l, 0);

	pthread_cancel (l->gc);
	pthread_join (l->gc, NULL);
	pthread_mutex_destroy (&l->lock);

	free (l);
}


teredo_peer *teredo_list_lookup (teredo_peerlist *restrict list,
                                 const struct in6_addr *restrict addr,
                                 bool *restrict create)
{
	teredo_listitem *p;

	pthread_mutex_lock (&list->lock);

#ifdef HAVE_LIBJUDY
	teredo_listitem **pp = NULL;

	/* Judy dynamic array-based fast lookup */
	{
		void *PValue;

		if (create != NULL)
		{
			JHSI (PValue, list->PJHSArray, (uint8_t *)addr, 16);
			if (PValue == PJERR)
			{
				pthread_mutex_unlock (&list->lock);
				return NULL;
			}
			pp = (teredo_listitem **)PValue;
			p = *pp;
		}
		else
		{
			JHSG (PValue, list->PJHSArray, (uint8_t *)addr, 16);
			pp = (teredo_listitem **)PValue;
			p = (pp != NULL) ? *pp : NULL;
		}

	}
#else
	/* Slow O(n) simplistic peer lookup */
	p = NULL;

	for (p = list->recent; p != NULL; p = p->next)
		if (IN6_ARE_ADDR_EQUAL (&p->key, addr))
			break;

	if (p == NULL)
		for (p = list->old; p != NULL; p = p->next)
			if (IN6_ARE_ADDR_EQUAL (&p->key, addr))
				break;
#endif

	if (p != NULL)
	{
		/* peer was already in list */
		assert (*(p->pprev) == p);
		assert ((p->next == NULL) || (p->next->pprev == &p->next));

		if (create != NULL)
			*create = false;

		/* move peer to the top of the head of the "recent" list */
		if (list->recent != p)
		{
			// unlinks
			if (p->next != NULL)
				p->next->pprev = p->pprev;
			*(p->pprev) = p->next;

			// inserts at head
			p->next = list->recent;
			if (p->next != NULL)
				p->next->pprev = &p->next;

			list->recent = p;
			p->pprev = &list->recent;

			assert (*(p->pprev) == p);
			assert ((p->next == NULL) || (p->next->pprev == &p->next));
		}

		return &p->peer;
	}

	assert (p == NULL);

	/* otherwise, peer was not in list */
	if (create == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	*create = true;

	/* Allocates a new peer entry */
	if (list->left > 0)
		p = listitem_create ();

	if (p == NULL)
	{
#ifdef HAVE_LIBJUDY
		int Rc_int;
		JHSD (Rc_int, list->PJHSArray, (uint8_t *)addr, sizeof (*addr));
#endif
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	/* Puts new entry at the head of the list */
	p->next = list->recent;
	if (p->next != NULL)
		p->next->pprev = &p->next;

	p->pprev = &list->recent;
	list->recent = p;
	p->pprev = &list->recent;

	list->left--;

	assert (*(p->pprev) == p);
	assert ((p->next == NULL) || (p->next->pprev == &p->next));

#ifdef HAVE_LIBJUDY
	*pp = p;
#endif
	memcpy (&p->key.ip6, addr, sizeof (struct in6_addr));
	return &p->peer;
}


void teredo_list_release (teredo_peerlist *l)
{
	pthread_mutex_unlock (&l->lock);
}
