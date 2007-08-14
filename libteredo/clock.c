/*
 * clock.c - Fast-lookup 1Hz clock
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <time.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h> // _POSIX_*
#include <pthread.h>

#include "clock.h"
#include "debug.h"

typedef struct clock_data_t
{
	pthread_mutex_t   lock;
	pthread_cond_t    cond;

	unsigned long     value;
	clockid_t         id;
	bool              present;
	bool              active;
} clock_data_t;


/* TODO: stop the clock when it has not been used for a while to avoid useless
 * wakeups? */
static LIBTEREDO_NORETURN void *clock_thread (void *o)
{
	clock_data_t *context = (clock_data_t *)o;
	clockid_t id = context->id;

	for (;;)
	{
		struct timespec ts;
		clock_gettime (id, &ts);

		pthread_mutex_lock (&context->lock);
		context->value = ts.tv_sec;

		if (!context->active)
			/* Avoid polling when the process is idling */
			pthread_cond_wait (&context->cond, &context->lock);

		context->active = false;
		pthread_mutex_unlock (&context->lock);

		ts.tv_sec++;
		ts.tv_nsec = 0;

		clock_nanosleep (id, TIMER_ABSTIME, &ts, NULL);
	}
}


unsigned long teredo_clock (void)
{
	static clock_data_t clk =
	{
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.cond = PTHREAD_COND_INITIALIZER,
		.value = 0,
		.id = CLOCK_REALTIME,
		.present = false,
		.active = false
	};
	unsigned long value;

	pthread_mutex_lock (&clk.lock);
	if (!clk.present)
	{
		pthread_t th;

#if (_POSIX_CLOCK_SELECTION - 0 >= 0) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
		/* Run-time POSIX monotonic clock detection */
		struct timespec res;
		if (clock_getres (CLOCK_MONOTONIC, &res) == 0)
			clk.id = CLOCK_MONOTONIC;
#endif

		if (pthread_create (&th, NULL, clock_thread, &clk) == 0)
		{
			pthread_detach (th);
			clk.present = true;
		}
	}

	if (!clk.active)
	{
		struct timespec ts;

		clock_gettime (clk.id, &ts);
		clk.value = ts.tv_sec;

		clk.active = true;
		pthread_cond_signal (&clk.cond);
	}

	value = clk.value;
	pthread_mutex_unlock (&clk.lock);

	return value;
}


int teredo_clock_create (void)
{
	return 0;
}


void teredo_clock_destroy (void)
{
}


