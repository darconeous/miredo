/*
 * stresslist.c - Libteredo peer list stress tests
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2005-2006 Remi Denis-Courmont.                       *
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
#include <stdlib.h>

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#include "teredo.h"
#include "peerlist.h"

static void make_address (struct in6_addr *addr)
{
	unsigned i;

	for (i = 0; i < 16; i += sizeof (int))
		*((int *)(addr->s6_addr + i)) = rand ();
}


#define NUM 32768

int main (void)
{
	teredo_peerlist *l;
	struct in6_addr addr = { };
	unsigned i;
	time_t seed, now;
	clock_t t1, t2;

	time (&now);
	setvbuf (stdout, NULL, _IONBF, 0);

	l = teredo_list_create (NUM, 1000000);
	if (l == NULL)
		return -1;

	srand ((unsigned int)(seed = now));
	t1 = clock ();

	// initial insertion tests
	for (i = 0; i < NUM; i++)
	{
		teredo_peer *p;
		bool create;

		make_address (&addr);
		p = teredo_list_lookup (l, now, &addr, &create);
		if ((!create) || (p == NULL))
			return -1;
		teredo_list_release (l);
		if ((i & 0xff) == 0)
			fputc ('.', stdout);
	}

	t2 = clock ();
	printf ("\n%f insertions per second\n",
	        (CLOCKS_PER_SEC * (float)NUM) / (float)(t2 - t1));

	srand ((unsigned int)(seed = now));
	t1 = clock ();

	// lookup tests
	for (i = 0; i < NUM; i++)
	{
		teredo_peer *p;

		make_address (&addr);
		p = teredo_list_lookup (l, now, &addr, NULL);
		if (p == NULL)
			return -1;
		teredo_list_release (l);
		if ((i & 0xff) == 0)
			fputc ('.', stdout);
	}

	t2 = clock ();
	printf ("\n%f lookups per second\n",
	        (CLOCKS_PER_SEC * (float)NUM) / (float)(t2 - t1));

	teredo_list_destroy (l);
	return 0;
}
