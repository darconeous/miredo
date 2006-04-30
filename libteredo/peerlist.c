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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <time.h>
#include <stdlib.h> /* malloc() / free() */
#include <assert.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>
#include <errno.h>

#ifndef NDEBUG
# define JUDYERROR_NOTEST 1
#endif
#if HAVE_JUDY_H
# include <Judy.h>
#endif

#include "teredo.h"
#include "teredo-udp.h" // FIXME: ugly
#include "debug.h"
#include <stdbool.h>
#include "peerlist.h"

/*
 * Packets queueing
 */
struct teredo_queue
{
	teredo_queue *next;
	size_t length;
	bool incoming;
	uint8_t data[];
};

static const unsigned teredo_MaxQueueBytes = 1280;


static inline void teredo_peer_init (teredo_peer *peer)
{
	peer->queue = NULL;
	peer->queue_left = teredo_MaxQueueBytes;
}


static void teredo_peer_destroy (teredo_peer *peer)
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


void teredo_peer_queue (teredo_peer *peer, const void *data, size_t len,
                        bool incoming)
{
	teredo_queue *p;

	if (len > peer->queue_left)
		return;
	peer->queue_left -= len;

	p = (teredo_queue *)malloc (sizeof (*p) + len);
	p->length = len;
	memcpy (p->data, data, len);
	p->incoming = incoming;

	p->next = peer->queue;
	peer->queue = p;
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
			cb (opaque, q->data, q->length);
		else
			teredo_send (fd, q->data, q->length, ipv4, port);
		free (q);
		q = buf;
	}
}


/*** Peer list handling ***/
typedef struct teredo_listitem
{
	struct teredo_listitem *prev, *next;
	teredo_peer peer;
	union teredo_addr key;
	time_t atime;
} teredo_listitem;

struct teredo_peerlist
{
	teredo_listitem sentinel;
	unsigned left;
	unsigned expiration;
	pthread_t gc;
	pthread_mutex_t lock;
	pthread_cond_t cond;
#if HAVE_LIBJUDY
	Pvoid_t PJHSArray;
#endif
	bool running;
};


/**
 * Peer list garbage collector entry point.
 * Thread cancellation-safe.
 *
 * @return never ever.
 */
static void *garbage_collector (void *data)
{
	struct teredo_peerlist *l = (struct teredo_peerlist *)data;

	pthread_mutex_lock (&l->lock);

	while (l->running)
	{
		while (l->sentinel.prev != &l->sentinel)
		{
			struct timespec deadline;

			deadline.tv_sec = l->sentinel.prev->atime + l->expiration;
			deadline.tv_nsec = 0;

			if (pthread_cond_timedwait (&l->cond, &l->lock,
			                            &deadline) != ETIMEDOUT)
			{
				if (!l->running)
					goto out;
				continue;
			}

			teredo_listitem *victim = NULL;

			for (teredo_listitem *p = l->sentinel.prev;
			     p != &l->sentinel;
			     p = p->prev)
			{
				if ((p->atime + l->expiration) > (unsigned)deadline.tv_sec)
					break;

				/*
				 * The victim was not touched in the mean time... destroy it.
				 */
#if HAVE_LIBJUDY
				int Rc_int;
				JHSD (Rc_int, l->PJHSArray, (uint8_t *)&p->key, 16);
#endif
				victim = p;
				l->left++;
			}

			if (victim != NULL)
			{
				victim->prev->next = &l->sentinel;
				l->sentinel.prev->next = NULL;
				l->sentinel.prev = victim->prev;
			}

			pthread_mutex_unlock (&l->lock);

			// Perform possibly expensive memory release without the lock
			while (victim != NULL)
			{
				teredo_listitem *buf = victim->next;
				teredo_peer_destroy (&victim->peer);
				free (victim);
				victim = buf;
			}

			pthread_mutex_lock (&l->lock);
		}

		/* wait until there the list is not empty */
		pthread_cond_wait (&l->cond, &l->lock);
	}

out:
	pthread_mutex_unlock (&l->lock);
	return NULL;
}

/**
 * Creates an empty peer list.
 *
 * @return NULL on error (see errno for actual problem).
 */
teredo_peerlist *teredo_list_create (unsigned max, unsigned expiration)
{
	/*printf ("Peer size: %u/%u bytes\n",sizeof (teredo_peer),
	        sizeof (teredo_listitem));*/

	teredo_peerlist *l = (teredo_peerlist *)malloc (sizeof (*l));
	if (l == NULL)
		return NULL;

	memset (l, 0, sizeof (l));
	pthread_mutex_init (&l->lock, NULL);
	pthread_cond_init (&l->cond, NULL);
	l->sentinel.next = l->sentinel.prev = &l->sentinel;
	l->left = max;
	l->expiration = expiration;
#if HAVE_LIBJUDY
	l->PJHSArray = (Pvoid_t)NULL;
#endif
	l->running = true;

	if (pthread_create (&l->gc, NULL, garbage_collector, l))
	{
		pthread_cond_destroy (&l->cond);
		pthread_mutex_destroy (&l->lock);
		free (l);
		return NULL;
	}

	return l;
}

/**
 * Empties an existing unlocked list. Always succeeds.
 *
 * @param max new value for maximum number of items allowed.
 */
void teredo_list_reset (teredo_peerlist *l, unsigned max)
{
	pthread_mutex_lock (&l->lock);

#if HAVE_LIBJUDY
	Pvoid_t array = l->PJHSArray;
	l->PJHSArray = (Pvoid_t)NULL;
#endif	

	teredo_listitem *p = l->sentinel.next;
	l->left = max;

	if (p != &l->sentinel)
	{
		assert (l->sentinel.prev != &l->sentinel);
		l->sentinel.prev->next = NULL;

		// resets garbage collector
		pthread_cond_signal (&l->cond);
		l->sentinel.next = l->sentinel.prev = &l->sentinel;
	}
	else
		p = NULL;

	pthread_mutex_unlock (&l->lock);

	/* the mutex is not needed for actual memory release */
	while (p != NULL)
	{
		teredo_listitem *buf = p->next;
		teredo_peer_destroy (&p->peer);
		free (p);
		p = buf;
	}

#if HAVE_LIBJUDY
	long Rc_word;
	JHSFA (Rc_word, array);
#endif
}

/**
 * Destroys an existing unlocked list.
 */
void teredo_list_destroy (teredo_peerlist *l)
{
	teredo_list_reset (l, 0);

	pthread_mutex_lock (&l->lock);
	l->running = false;
	pthread_cond_signal (&l->cond);
	pthread_mutex_unlock (&l->lock);

	pthread_join (l->gc, NULL);
	pthread_cond_destroy (&l->cond);
	pthread_mutex_destroy (&l->lock);

	free (l);
}

/**
 * Locks the list and looks up a peer in an unlocked list.
 * On success, the list must be unlocked with teredo_list_release(), otherwise
 * the next call to teredo_list_lookup will deadlock. Unlocking the list after
 * a failure is not defined.
 *
 * @param atime time value to be used for garbage collection of the peer.
 * When current time exceeds (atime + expiration), the peer is destroyed.
 * The expiration value (in seconds) is specified defined when calling
 * teredo_list_create()). atime should normally be the result of time().
 * It is not computed internally to allow clock caching (and avoid thousands
 * of system call for the current time).
 *
 * @param create if not NULL, the peer will be added to the list if it is not
 * present already, and *create will be true on return. If create is not NULL
 * but the peer was already present, *create will be false on return.
 * *create is undefined on return in case of error.
 *
 * @return The peer if found or created. NULL on error (when create is not
 * NULL), or if the peer was not found (when create is NULL).
 */
teredo_peer *teredo_list_lookup (teredo_peerlist *list, time_t atime,
                                 const struct in6_addr *addr, bool *create)
{
	teredo_listitem *p;

	pthread_mutex_lock (&list->lock);

#if HAVE_LIBJUDY
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
	bool found = false;
	p = list->sentinel.next;
	while (p != &list->sentinel)
	{
		if (t6cmp (&p->key, (const union teredo_addr *)addr) == 0)
		{
			found = true;
			break;
		}
		p = p->next;
	}

	if (!found)
		p = NULL;
#endif

	if (p != NULL)
	{
		/* peer was already in list */
		assert (p->prev->next == p);
		assert (p->next->prev == p);

		if (create != NULL)
			*create = false;
	
		/* touch peer toward garbage collector */
		p->atime = atime;
		if (p->prev != NULL)
		{
			/* remove peer from list */
			p->prev->next = p->next;
			p->next->prev = p->prev;
	
			/* bring peer to the head of the list if it is not already */
			p->next = list->sentinel.next;
			p->next->prev = p;
			p->prev = &list->sentinel;
			list->sentinel.next = p;
		}
	
		return &p->peer;
	}

	/* otherwise, peer was not in list */
	if (create == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	*create = true;

	/* Allocates a new peer entry */
	p = (list->left != 0) ? (teredo_listitem *)malloc (sizeof (*p)) : NULL;

	if (p == NULL)
	{
#if HAVE_LIBJUDY
		int Rc_int;
		JHSD (Rc_int, list->PJHSArray, (uint8_t *)addr, sizeof (*addr));
#endif
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	teredo_peer_init (&p->peer);

	if (list->sentinel.next == &list->sentinel)
		/* tell GC the list is no longer empty */
		pthread_cond_signal (&list->cond);

	/* Puts new entry at the head of the list */
	p->next = list->sentinel.next;
	p->next->prev = p;
	p->prev = &list->sentinel;
	list->sentinel.next = p;

	list->left--;

	assert (p->next->prev == p);
	assert (p->prev->next == p);

#if HAVE_LIBJUDY
	*pp = p;
#endif
	memcpy (&p->key.ip6, addr, sizeof (struct in6_addr));
	p->atime = atime;
	return &p->peer;
}


/**
 * Unlocks a list that was locked by teredo_list_lookup().
 */
void teredo_list_release (teredo_peerlist *l)
{
	pthread_mutex_unlock (&l->lock);
}
