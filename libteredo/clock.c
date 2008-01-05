/*
 * clock.c - Fast-lookup 1Hz clock
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#include <time.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h> // DELAYTIMER_MAX

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h> // _POSIX_*
#include <pthread.h>

#include "clock.h"
#include "debug.h"

#ifdef HAVE_TIMER_CREATE
typedef struct clock_data_t
{
	timer_t           handle;
	teredo_clock_t    value;
	bool              active;
} clock_data_t;


static void clock_tick (union sigval val)
{
	clock_data_t *context = (clock_data_t *)(val.sival_ptr);

	int orun = timer_getoverrun (context->handle);
	context->value += 1 + orun;

	if (orun == DELAYTIMER_MAX)
		/* We have a big problem, let next caller fix it */
		context->active = false;

	if (!context->active)
	{
		struct itimerspec it =
		{
			.it_value = { .tv_sec = 0, .tv_nsec = 0 },
		};
		timer_settime (context->handle, 0, &it, NULL);
	}

	context->active = false;
}


unsigned long teredo_clock (void)
{
	static clock_data_t clk =
	{
		.value = 0,
		.active = false
	};
	static struct
	{
		pthread_mutex_t lock;
		clockid_t       id;
		bool            present;
	} priv = { PTHREAD_MUTEX_INITIALIZER, CLOCK_REALTIME, false };

	teredo_clock_t value;

	pthread_mutex_lock (&priv.lock);
	if (!priv.present)
	{
		struct sigevent ev;

		memset (&ev, 0, sizeof (ev));
		ev.sigev_notify = SIGEV_THREAD;
		ev.sigev_value.sival_ptr = &clk;
		ev.sigev_notify_function = clock_tick;

#if (_POSIX_CLOCK_SELECTION - 0 >= 0) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
		/* Run-time POSIX monotonic clock detection */
		struct timespec res;
		if (clock_getres (CLOCK_MONOTONIC, &res) == 0)
			priv.id = CLOCK_MONOTONIC;
#endif

		if (timer_create (priv.id, &ev, &clk.handle) == 0)
			priv.present = true;
	}

	if (!clk.active)
	{
		struct itimerspec it;

		clock_gettime (priv.id, &it.it_value);
		clk.value = it.it_value.tv_sec;

		if (priv.present)
		{
			it.it_value.tv_sec++;
			it.it_value.tv_nsec = 0;
			it.it_interval.tv_sec = 1;
			it.it_interval.tv_nsec = 0;

			clk.active = true;
			timer_settime (clk.handle, TIMER_ABSTIME, &it, NULL);
		}
	}

	value = clk.value;
	pthread_mutex_unlock (&priv.lock);

	return value;
}
#else
unsigned long teredo_clock (void)
{
	struct timespec ts;

	clock_gettime (CLOCK_REALTIME, &ts);
	return ts.tv_sec;
}
#endif

