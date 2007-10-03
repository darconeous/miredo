/*
 * list.c - Libteredo peer list tests
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005 Rémi Denis-Courmont.                              *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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
#include <stdio.h>
#include <time.h>
#include <stdlib.h> // putenv()

#include <inttypes.h> /* for Mac OS X */
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#include "teredo.h"
#include "clock.h"
#include "peerlist.h"


static void wait (unsigned sec)
{
	printf ("Waiting %d second%s...\n", sec, (sec != 1) ? "s" : "");
	nanosleep (&(struct timespec){ sec, 0 }, NULL);
}


static teredo_peer *
lookup (teredo_peerlist *l, struct in6_addr *addr, bool *create)
{
	teredo_peer *p = teredo_list_lookup (l, addr, create);
	if (p != NULL)
		teredo_list_release (l);
	return p;
}


static bool try_lookup (teredo_peerlist *l, struct in6_addr *addr)
{
	return lookup (l, addr, NULL) != NULL;
}


static bool try_insert (teredo_peerlist *l, struct in6_addr *addr)
{
	bool created;
	return (lookup (l, addr, &created) != NULL) && created;
}


static int test_list (teredo_peerlist *l)
{
	struct in6_addr addr = { { } };

	puts ("Initial insertion test...");
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[12] = i;
		if ((i & 1) ? !try_insert (l, &addr) : try_lookup (l, &addr))
			return -1;
	}

	puts ("Initial lookup test...");
	// lookup tests
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[12] = i;
		if ((i & 1) != try_lookup (l, &addr))
			return -1;
	}

	wait (1);
	addr.s6_addr[0] = 1;
	puts ("Further insertion test...");
	for (unsigned i = 0; i < 256; i++)
	{

		addr.s6_addr[12] = i;
		if ((i & 1) ? ((i < 255) != try_insert (l, &addr))
		            : try_lookup (l, &addr))
			// items 1, 3...253 should have been created
			// items 255 should cause an overflow
			// items 0, 2... 254 did not exist and should not have been found
			return -1;
	}

	puts ("Lookup test...");
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[0] = 0;
		addr.s6_addr[12] = i;

		if (((i & 3) == 3) && !try_lookup (l, &addr))
			// item was created earlier
			return -1;

		addr.s6_addr[0] = 1;
		if (((i & 1) && (i < 255)) != try_lookup (l, &addr))
			return -1;
	}

	wait (2);
	puts ("Further lookup test...");
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[0] = 0;
		addr.s6_addr[12] = i;
		if ((i & 3) == 3)
		{
			if (!try_lookup (l, &addr))
				return -1;
		}

		addr.s6_addr[0] = 1;
		if (((i & 1) && (i != 255)) != try_lookup (l, &addr))
			return -1;
	}

	wait (2);
	addr.s6_addr[0] = 0;

	puts ("Partial expiration test...");
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[12] = i;
		if ((i & 3) == 3)
			continue;
		if (try_lookup (l, &addr))
			return -1;
	}

	wait (5);

	puts ("Full expiration test...");
	for (unsigned i = 0; i < 256; i++)
	{
		addr.s6_addr[12] = i;
		if ((i & 1) ? !try_insert (l, &addr) : try_lookup (l,  &addr))
			return -1;
	}

	return 0;
}


int main (void)
{
	struct in6_addr addr = { { } };

	putenv ((char *)"MALLOC_CHECK_=2");

	puts ("Basic empty list test...");
	teredo_peerlist *l = teredo_list_create (0, 3);
	if (l == NULL)
		return -1;
	else
	{
		bool create;

		if (teredo_list_lookup (l, &addr, &create) != NULL)
			return -1;

		teredo_list_destroy (l);
	}

	puts ("Advanced empty list test...");
	l = teredo_list_create (0, 3);
	if (l == NULL)
		return -1;
	else
	{
		bool create;

		if (teredo_list_lookup (l, &addr, &create) != NULL)
			return -1;

		teredo_list_reset (l, 1);
		// should now be able to insert a single item
		if (teredo_list_lookup (l, &addr, &create) == NULL)
			return -1;
		teredo_list_release (l);

		addr.s6_addr[12] = 10;
		if (teredo_list_lookup (l, &addr, &create) != NULL)
			return -1;

		teredo_list_reset (l, 1);
		teredo_list_reset (l, 1);
		teredo_list_destroy (l);
	}

	puts ("List creation test...");
	l = teredo_list_create (255, 2);
	if (l == NULL)
		return -1;

	if (test_list (l))
		return 1;

	wait (7);
	if (test_list (l))
		return 1;

	puts ("Final list release...");
	teredo_list_destroy (l);
	puts ("Done.");

	return 0;
}
