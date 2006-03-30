/*
 * list.c - Libteredo peer list tests
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005 Rémi Denis-Courmont.                            *
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
#include <stdio.h>
#include <time.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#include "teredo.h"
#include "peerlist.h"

int main (void)
{
	teredo_peerlist *l;
	struct in6_addr addr = { { } };
	unsigned i;
	time_t now;

	// test empty list
	l = teredo_list_create (0, 0);
	time (&now);
	if (l == NULL)
		return -1;
	else
	{
		bool create;

		if (teredo_list_lookup (l, now, &addr, &create) != NULL)
			return -1;

		teredo_list_destroy (l);
	}

	// further test empty list
	l = teredo_list_create (0, 0);
	time (&now);
	if (l == NULL)
		return -1;
	else
	{
		bool create;

		if (teredo_list_lookup (l, now, &addr, &create) != NULL)
			return -1;

		teredo_list_reset (l, 1);
		// should now be able to insert a single item
		if (teredo_list_lookup (l, now, &addr, &create) == NULL)
			return -1;
		teredo_list_release (l);

		addr.s6_addr[12] = 10;
		if (teredo_list_lookup (l, now, &addr, &create) != NULL)
			return -1;

		teredo_list_reset (l, 1);
		teredo_list_reset (l, 1);
		teredo_list_destroy (l);
	}

	// test real list
	l = teredo_list_create (255, 3);
	if (l == NULL)
		return -1;

	// initial insertion tests
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;
		bool create;

		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, now, &addr, i & 1 ? &create : NULL);
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

	// lookup tests
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;

		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, now, &addr, NULL);
		if (i & 1)
		{
			// item was created earlier
			if (p == NULL)
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

	puts ("Waiting 2 seconds...");
	sleep (2);
	time (&now);
	addr.s6_addr[0] = 1;
	// test further insertions
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;
		bool create;

		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, now, &addr, i & 1 ? &create : NULL);
		if ((i & 1) && (i != 255))
		{
			// item should have been created... except the last one
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

	// lookup tests
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;

		addr.s6_addr[0] = 0;
		addr.s6_addr[12] = i;
		if ((i & 3) == 3)
		{
			p = teredo_list_lookup (l, now, &addr, NULL);
			{
				// item was created earlier
				if (p == NULL)
					return -1;
				teredo_list_release (l);
			}
		}

		addr.s6_addr[0] = 1;
		p = teredo_list_lookup (l, now, &addr, NULL);
		if ((i & 1) && (i != 255))
		{
			// item was created earlier
			if (p == NULL)
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

	puts ("Waiting 2 seconds...");
	sleep (2);
	time (&now);
	// further lookup tests
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;

		addr.s6_addr[0] = 0;
		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, now, &addr, NULL);
		// item should not/no longet exist
		if ((i & 3) == 3)
		{
			if (p == NULL)
				return -1;
			teredo_list_release (l);
		}
		else
		{
			if (p != NULL)
				return -1;
		}

		addr.s6_addr[0] = 1;
		p = teredo_list_lookup (l, now, &addr, NULL);
		if ((i & 1) && (i != 255))
		{
			// item was created earlier
			if (p == NULL)
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

	puts ("Waiting 4 seconds...");
	sleep (4);

	// everything should have been deleted now
	for (i = 0; i < 256; i++)
	{
		teredo_peer *p;
		bool create;

		addr.s6_addr[12] = i;
		p = teredo_list_lookup (l, now, &addr, i & 1 ? &create : NULL);
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

	teredo_list_destroy (l);

	return 0;
}
