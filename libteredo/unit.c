/*
 * unit.c - Libteredo unit tests
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005 Remi Denis-Courmont.                            *
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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h> /* sleep () */

#include "teredo.h"
#include "relay.h"
#include "security.h"
#include "peerlist.h"

int test_HMAC (void)
{
#ifdef MIREDO_TEREDO_CLIENT
	struct in6_addr src, dst;
	uint8_t hmac[LIBTEREDO_HMAC_LEN];

	puts ("Checking libteredo HMAC...");
	puts ("That should take about 30 seconds...");
	libteredo_preinit ();
	libteredo_client_preinit ();

	memcpy (&src, "\x3f\xfe\x83\x1f\x8a\xc3\x9d\xdd"
	              "\x80\x00\xf2\x27\x75\x3c\x67\x74", 16);
	memcpy (&dst, "\x20\x02\xc0\x00\x02\x42\x12\x42"
	              "\x13\x43\x14\x44\x15\x45\x16\x46", 16);
	if (!GenerateHMAC (&src, &dst, hmac))
		return -1;
	if (!CompareHMAC (&src, &dst, hmac))
		return -1;

	/* retry after first run */
	if (!GenerateHMAC (&dst, &src, hmac))
		return -1;
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;
	if (CompareHMAC (&src, &dst, hmac))
		/* mixed addresses : should fail */
		return -1;

	hmac[4] ^= 0x40;
	if (CompareHMAC (&dst, &src, hmac))
		/* altered hash : should fail */
		return -1;

	hmac[4] ^= 0x40;
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;

	sleep (3);
	if (!CompareHMAC (&dst, &src, hmac))
		return -1;
	/* should still be valid after 3 seconds */

	sleep (28);
	/* should no longer be valid after 31 seconds */
	if (CompareHMAC (&dst, &src, hmac))
		return -1;

	libteredo_terminate ();
#endif
	return 0;
}


int test_list (void)
{
	teredo_peerlist *l;
	struct in6_addr addr = { };
	unsigned i;

	// test empty list
	l = teredo_list_create (0);
	if (l == NULL)
		return -1;
	else
	{
		bool create;

		if (teredo_list_lookup (l, &addr, &create) != NULL)
			return -1;

		teredo_list_destroy (l);
	}

	// test real list
	l = teredo_list_create (255);
	if (l == NULL)
		return -1;

	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;
		bool create;

		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, &addr, i & 1 ? &create : NULL);
		if (i & 1)
		{
			// item should have been created
			if ((!create) || (p == NULL))
				return -1;
			teredo_list_release (l);
		}
		else
		{
			// item did not exist and should not have been found
			if (p != NULL)
				return -1;
		}
	}

	/* FIXME can't test lookup until IsExpired() / Touch*() are handled
	 * properly inside the peer list */
	teredo_list_destroy (l);

	return 0;
}

int main (void)
{
	/* UNIT TEST 1: ping HMAC stuff */
	//if (test_HMAC ())
	//	return 1;

	/* UNIT TEST 2: peer list lookups */
	if (test_list ())
		return 1;

	return 0;
}
