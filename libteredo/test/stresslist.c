/*
 * stresslist.c - Libteredo peer list stress tests
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2005-2006 Rémi Denis-Courmont.                         *
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
#include <stdlib.h>
#include <signal.h>
#include <limits.h>

#include <inttypes.h> /* for Mac OS X */
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>

#include "teredo.h"
#include "clock.h"
#include "peerlist.h"

static void make_address (struct in6_addr *addr)
{
	unsigned i;

	for (i = 0; i < 16; i += sizeof (int))
		*((int *)(addr->s6_addr + i)) = rand ();
}


static volatile int count = 0;

static void alarm_handler (int sig)
{
	count++;
	signal (sig, alarm_handler);
	alarm (1);
	if (write (2, ".", 1) == 1)
		fsync (2);
}

#define STRESS_DELAY 10

int main (void)
{
	teredo_peerlist *l;
	struct in6_addr addr = { { } };
	unsigned long i;
	time_t seed;
	clock_t t;

	signal (SIGALRM, alarm_handler);
	alarm (1);

	time (&seed);

	l = teredo_list_create (UINT_MAX, 1000000);
	if (l == NULL)
		return -1;

	// Insertion stress test
	srand ((unsigned int)seed);
	t = clock ();
	for (i = 0; (count < STRESS_DELAY) && (i < 100000); i++)
	{
		teredo_peer *p;
		bool create;

		make_address (&addr);
		p = teredo_list_lookup (l, &addr, &create);
		if ((!create) || (p == NULL))
			return -1;
		teredo_list_release (l);
	}
	t = clock () - t;

	printf ("\n%lu inserts/s\n",
			(unsigned long)((float)i * CLOCKS_PER_SEC / t));

	// Lookup stress test
	srand ((unsigned int)seed);
	seed += 10;
	t = clock ();
	for (unsigned long j = 0; j < i; j++)
	{
		teredo_peer *p;

		make_address (&addr);
		p = teredo_list_lookup (l, &addr, NULL);
		if (p == NULL)
			return -1;
		teredo_list_release (l);
	}
	t = clock () - t;

	printf ("\n%lu lookups/s\n",
	        (unsigned long)((float)i * CLOCKS_PER_SEC / t));

	teredo_list_destroy (l);

	signal (SIGALRM, SIG_IGN);
	fputc ('\n', stderr);
	return 0;
}
