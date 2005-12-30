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
 * - check expiry time in relay code rather than peer list code,
 * - replace expiry (4 bytes) with last_rx and last_tx
 *   (both could be one byte),
 * - implement garbage collector (needed if expiry is suppressed)
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
struct teredo_peerlist
{
	teredo_peer *head, *tail;
	unsigned left;
	pthread_t gc;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};


static void cleanup_mutex (void *data)
{
	pthread_mutex_unlock ((pthread_mutex_t *)data);
}


static void *garbage_collector (void *data)
{
	struct teredo_peerlist *l = (struct teredo_peerlist *)data;

	pthread_mutex_lock (&l->lock);
	pthread_cleanup_push (cleanup_mutex, &l->lock);

	for (;;)
	{
		/* wait until there the list is not empty */
		while (pthread_cond_wait (&l->cond, &l->lock));

		while (l->tail != NULL)
		{
			teredo_peer *victim = l->tail;
			struct timespec deadline = { 0, 0 };

			deadline.tv_sec = victim->expiry;
			/*deadline.tv_nsec = 0; */
			while (pthread_cond_timedwait (&l->cond, &l->lock,
			                               &deadline) != ETIMEDOUT);

			while (victim->expiry <= deadline.tv_sec)
			{
				/*
				 * The victim was not touched in the mean time... destroy it.
				 */
				assert (victim == l->tail);
				l->tail = victim->prev;
				l->tail->next = NULL;
				l->left++;

				delete victim; /* NOTE: delete != free() */

				/* delete all victims from the same expiry time */
				victim = l->tail;
			}
		}
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
teredo_peerlist *teredo_list_create (unsigned max)
{
	teredo_peerlist *l = (teredo_peerlist *)malloc (sizeof (*l));
	if (l == NULL)
		return NULL;

	pthread_mutex_init (&l->lock, NULL);
	pthread_cond_init (&l->cond, NULL);
	if (pthread_create (&l->gc, NULL, garbage_collector, l))
	{
		free (l);
		return NULL;
	}

	l->head = l->tail = NULL;
	l->left = max;
	return l;
}

/**
 * Empties and destroys an existing list.
 */
extern "C"
void teredo_list_destroy (teredo_peerlist *l)
{
	teredo_peer *p = l->head;

	pthread_cancel (l->gc);
	pthread_join (l->gc, NULL);
	pthread_cond_destroy (&l->cond);
	pthread_mutex_destroy (&l->lock);

	while (p != NULL)
	{
		teredo_peer *buf = p->next;
		delete p;
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
 * @param create if not NULL, the peer will be added to the list if it is not
 * present already, and *create will be true on return. If create is not NULL
 * but the peer was already present, *create will be false on return.
 * *create is undefined on return in case of error.
 *
 * @return The peer if found or created. NULL on error (when create is not
 * NULL), or if the peer was not found (when create is NULL).
 */
extern "C"
teredo_peer *teredo_list_lookup (teredo_peerlist *list,
                                 const struct in6_addr *addr, bool *create)
{
	/* FIXME: all this code is highly suboptimal, but it works */
	teredo_peer *p;
	time_t now;

	time (&now);

	pthread_mutex_lock (&list->lock);

	/* Slow O(n) simplistic peer lookup */
	for (p = list->head; p != NULL; p = p->next)
		if (t6cmp (&p->addr, (const union teredo_addr *)addr) == 0)
		{
			assert (((p->next == NULL) && (p == list->tail))
			     || (p->next->prev == p));

			if (create != NULL)
				*create = false;
			return p;
		}

	assert (p == NULL);

	if (create == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	*create = true;

	/* Allocates a new peer entry */
	if (list->left != 0)
	{
		try
		{
			p = new teredo_peer;
		}
		catch (...)
		{
			p = NULL;
		}
	}

	if (p == NULL)
	{
		pthread_mutex_unlock (&list->lock);
		return NULL;
	}

	/* Puts new entry at the tail of the list */
	p->prev = list->tail;
	p->next = NULL;

	if (list->tail == NULL)
	{
		list->head = p;
		/* tell GC the list is no longer empty */
		pthread_cond_signal (&list->cond);
	}
	else
		list->tail->next = p;
	list->tail = p;
	list->left--;

	memcpy (&p->addr.ip6, addr, sizeof (struct in6_addr));
	return p;
}


/**
 * Unlocks a list that was locked by teredo_list_lookup().
 */
extern "C"
void teredo_list_release (teredo_peerlist *l)
{
	pthread_mutex_unlock (&l->lock);
}
