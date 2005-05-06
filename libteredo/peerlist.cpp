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
#include <sys/time.h>
#include <netinet/in.h>

#include <libteredo/relay-udp.h>

#include "queue.h"
#include <libteredo/relay.h>
#include "peerlist.h"

/* FIXME: Releases peers list entries */
/*	peer *p = head;

	while (p != NULL)
	{
		peer *buf = p->next;
		delete p;
		p = buf;
	}
*/


/* 
 * Allocates a peer entry. It is up to the caller to fill informations
 * correctly.
 *
 * FIXME: number of entry should be bound
 */
TeredoRelay::peer *TeredoRelay::AllocatePeer (const struct in6_addr *addr)
{
	struct timeval now;
	gettimeofday (&now, NULL);
	peer *p;

	/* Tries to recycle a timed-out peer entry */
	for (p = head; p != NULL; p = p->next)
		if (p->IsExpired (now))
		{
			p->outqueue.Trash ();
			p->inqueue.Trash ();
			break;
		}

	/* Otherwise allocates a new peer entry */
	if (p == NULL)
	{
		try
		{
			p = new peer (&sock, this);
		}
		catch (...)
		{
			return NULL;
		}

		/* Puts new entry at the head of the list */
		p->next = head;
		head = p;
	}

	memcpy (&p->addr, addr, sizeof (struct in6_addr));
	return p;
}


/*
 * Returns a pointer to the first peer entry matching <addr>,
 * or NULL if none were found.
 */
TeredoRelay::peer *TeredoRelay::FindPeer (const struct in6_addr *addr)
{
	struct timeval now;

	gettimeofday(&now, NULL);

	for (peer *p = head; p != NULL; p = p->next)
		if (memcmp (&p->addr, addr, sizeof (struct in6_addr)) == 0)
			if (!p->IsExpired (now))
				return p; // found!

	return NULL;
}
