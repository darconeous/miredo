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

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>

#include <libteredo/relay-udp.h>

#include "queue.h"
#include <libteredo/relay.h>
#include "peerlist.h"

void
TeredoRelay::peer::DestroyList (void *head)
{
	peer *p = (peer *)head;

	while (p != NULL)
	{
		peer *buf = p->next;
		delete p;
		p = buf;
	}
}


/*
 * It's pretty much the same as memcmp(), but it is optimized to
 * compare Teredo addresses (the first bytes tend to be always the same,
 * while the last ones are most often different).
 */
inline int t6cmp (const union teredo_addr *a1, const union teredo_addr *a2)
{
	return (a1->t6_addr32[3] - a2->t6_addr32[3])
	    && (a1->t6_addr32[2] - a2->t6_addr32[2])
	    && (a1->t6_addr32[1] - a2->t6_addr32[1])
	    && (a1->t6_addr32[0] - a2->t6_addr32[0]);
}

/* 
 * Allocates a peer entry. It is up to the caller to fill informations
 * correctly.
 */
unsigned TeredoRelay::MaxPeers = 1024;

TeredoRelay::peer *TeredoRelay::AllocatePeer (const struct in6_addr *addr)
{
	time_t now;
	peer *p;

	time (&now);

	/* Tries to recycle a timed-out peer entry */
	for (p = (peer *)list.ptr; p != NULL; p = p->next)
		if (p->IsExpired (now))
		{
			p->outqueue.Trash (MAXQUEUE);
#ifdef MIREDO_TEREDO_CLIENT
			p->inqueue.Trash (MAXQUEUE);
#endif
			break;
		}

	if (list.peerNumber >= MaxPeers)
		return NULL;

	/* Otherwise allocates a new peer entry */
	if (p == NULL)
	{
		try
		{
			p = new peer;
		}
		catch (...)
		{
			return NULL;
		}

		/* Puts new entry at the head of the list */
		p->next = (peer *)list.ptr;
		list.ptr = p;
		list.peerNumber++;
	}

	memcpy (&p->addr.ip6, addr, sizeof (struct in6_addr));
	return p;
}


/*
 * Returns a pointer to the first peer entry matching <addr>,
 * or NULL if none were found.
 * TODO: avoid doing two lookups (easy with Judy, not so easy without)
 * when inserting a new item
 */
TeredoRelay::peer *TeredoRelay::FindPeer (const struct in6_addr *addr)
{
	/* Slow O(n) simplistic peer lookup */
	for (peer *p = (peer *)list.ptr; p != NULL; p = p->next)
		if (t6cmp (&p->addr, (const union teredo_addr *)addr) == 0)
		{
			time_t now;
			time (&now);

			return !p->IsExpired (now) ? p : NULL;
		}

	return NULL;
}
