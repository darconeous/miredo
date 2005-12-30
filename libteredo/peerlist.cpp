/*
 * peerlist.cpp - Teredo relay internal peers list manipulation
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#include "teredo.h"
#include "teredo-udp.h"
#include "relay.h"
#include "peerlist.h"


/*
 * Big TODO:
 * - suppress the replied flag which is non-standard,
 * - replace expiry (4 bytes) with last_rx and last_tx
 *   (both could be one byte),
 *
 * - check last RX date in relay code for conformance
 */

/*
 * Packets queueing
 */
typedef struct teredo_peer::packet
{
	packet *next;
	size_t length;
	bool incoming;
	uint8_t data[];
} packet;

unsigned TeredoRelay::MaxQueueBytes = 1280;

teredo_peer::~teredo_peer (void)
{
	while (queue != NULL)
	{
		packet *buf;

		buf = queue->next;
		free (queue);
		queue = buf;
	}
}


void teredo_peer::Queue (const void *data, size_t len, bool incoming)
{
	packet *p;

	if (len > queue_left)
		return;
	queue_left -= len;

	p = (packet *)malloc (sizeof (*p) + len);
	p->length = len;
	memcpy (p->data, data, len);
	p->incoming = incoming;

	p->next = queue;
	queue = p;
}


void teredo_peer::Dequeue (int fd, TeredoRelay *r)
{
	packet *ptr;

	/* lock peer */
	ptr = queue;
	queue = NULL;
	queue_left = TeredoRelay::MaxQueueBytes;
	/* unlock */

	while (ptr != NULL)
	{
		packet *buf;

		buf = ptr->next;
		if (ptr->incoming)
			r->SendIPv6Packet (ptr->data, ptr->length);
		else
			teredo_send (fd, ptr->data, ptr->length,
			             mapped_addr, mapped_port);
		free (ptr);
		ptr = buf;
	}
}


/*** Peer list handling ***/
typedef struct teredo_listitem
{
	struct teredo_listitem *prev, *next;
	teredo_peer *peer; /* TODO: not a pointer */
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
};


static void cleanup_mutex (void *data)
{
	pthread_mutex_unlock ((pthread_mutex_t *)data);
}


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
	pthread_cleanup_push (cleanup_mutex, &l->lock);

	for (;;)
	{
		while (l->sentinel.next != &l->sentinel)
		{
			teredo_listitem *victim = l->sentinel.prev;
			struct timespec deadline = { 0, 0 };

			assert (victim != &l->sentinel);
			deadline.tv_sec = victim->atime + l->expiration;
			/*deadline.tv_nsec = 0;*/
			
			while (pthread_cond_timedwait (&l->cond, &l->lock,
			                               &deadline) != ETIMEDOUT);

			while ((victim->atime + l->expiration) <= (unsigned)deadline.tv_sec)
			{
				/*
				 * The victim was not touched in the mean time... destroy it.
				 */
				victim->prev->next = victim->next;
				victim->next->prev = victim->prev;
				l->left++;

				assert (victim != &l->sentinel);
				delete victim->peer;
				free (victim);

				/* delete all victims from the same expiry time */
				victim = l->sentinel.prev;
				if (victim == &l->sentinel)
					break;
			}
		}

		/* wait until there the list is not empty */
		pthread_cond_wait (&l->cond, &l->lock);
	}

	pthread_cleanup_pop (1); /* dead code */
	return NULL;
}

/**
 * Creates an empty peer list.
 *
 * @return NULL on error (see errno for actual problem).
 */
extern "C"
teredo_peerlist *teredo_list_create (unsigned max, unsigned expiration)
{
	teredo_peerlist *l = (teredo_peerlist *)malloc (sizeof (*l));
	if (l == NULL)
		return NULL;

	memset (l, 0, sizeof (l));
	pthread_mutex_init (&l->lock, NULL);
	pthread_cond_init (&l->cond, NULL);
	l->sentinel.next = l->sentinel.prev = &l->sentinel;
	l->left = max;
	l->expiration = expiration;

	if (pthread_create (&l->gc, NULL, garbage_collector, l))
	{
		free (l);
		return NULL;
	}

	return l;
}

/**
 * Empties and destroys an existing list.
 */
extern "C"
void teredo_list_destroy (teredo_peerlist *l)
{
	teredo_listitem *p = l->sentinel.next;

	pthread_cancel (l->gc);
	pthread_join (l->gc, NULL);
	pthread_cond_destroy (&l->cond);
	pthread_mutex_destroy (&l->lock);

	while (p != &l->sentinel)
	{
		teredo_listitem *buf = p->next;
		delete p->peer;
		free (p);
		p = buf;
	}
	free (l);
}

/**
 * Locks the list and looks up a peer in a list.
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
extern "C"
teredo_peer *teredo_list_lookup (teredo_peerlist *list, time_t atime,
                                 const struct in6_addr *addr, bool *create)
{
	/* FIXME: all this code is highly suboptimal, but it works */
	teredo_listitem *p;

	pthread_mutex_lock (&list->lock);

	/* Slow O(n) simplistic peer lookup */
	for (p = list->sentinel.next; p != &list->sentinel; p = p->next)
		if (t6cmp (&p->key, (const union teredo_addr *)addr) == 0)
		{
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

			return p->peer;
		}

	if (create == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	*create = true;

	/* Allocates a new peer entry */
	if (list->left != 0)
	{
		p = (teredo_listitem *)malloc (sizeof (*p));
		if (p != NULL)
		{
			try
			{
				p->peer = new teredo_peer;
			}
			catch (...)
			{
				free (p);
				p = NULL;
			}
		}
	}
	else
		p = NULL;

	if (p == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

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

	memcpy (&p->key.ip6, addr, sizeof (struct in6_addr));
	p->atime = atime;
	return p->peer;
}


/**
 * Unlocks a list that was locked by teredo_list_lookup().
 */
extern "C"
void teredo_list_release (teredo_peerlist *l)
{
	pthread_mutex_unlock (&l->lock);
}
