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

#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>

#include "clock.h"
#include "debug.h"

typedef struct clock_data_t
{
	unsigned long    value;
	clockid_t        id;
	pthread_rwlock_t lock;
	pthread_t        thread;
} clock_data_t;


/**
 * Userland low-precision (1 Hz) clock
 *
 * This is way faster than calling time() for every packet transmitted or
 * received. The first implementation was using POSIX timers, but it might
 * be a bit overkill to spawn a thread every second to simply increment an
 * integer. Also, POSIX timers with thread event delivery has a terrible
 * portability at the time of writing (June 2006). Basically, recent
 * GNU/Linux have it, and that's about it... no uClibc support, only in
 * -current for FreeBSD...
 */
static LIBTEREDO_NORETURN void *clock_thread (void *o)
{
	clock_data_t *context = (clock_data_t *)o;
	clockid_t id = context->id;

	for (;;)
	{
		struct timespec ts;
		clock_gettime (id, &ts);

		pthread_rwlock_wrlock (&context->lock);
		context->value = ts.tv_sec;
		pthread_rwlock_unlock (&context->lock);

		ts.tv_sec++;
		ts.tv_nsec = 0;

		clock_nanosleep (id, TIMER_ABSTIME, &ts, NULL);
	}
}


static clock_data_t data;


unsigned long teredo_clock (void)
{
	clock_data_t *context = (clock_data_t *)&data;
	unsigned long value;

	pthread_rwlock_rdlock (&context->lock);
	value = context->value;
	pthread_rwlock_unlock (&context->lock);
	return value;
}


static unsigned users = 0;
static pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Starts the clock. Thread-safe.
 *
 * TODO:
 * - use monotonic clock if available
 *
 * @return 0 in case of success, an errno in case of error.
 */
int teredo_clock_create (void)
{
	int val = -1;

	pthread_mutex_lock (&user_mutex);

	if (users == 0)
	{
		clock_data_t *ctx = (clock_data_t *)&data;
	
		struct timespec ts;
		clock_gettime (CLOCK_REALTIME, &ts);
	
		ctx->value = ts.tv_sec;
		ctx->id = CLOCK_REALTIME;
	
		val = pthread_rwlock_init (&ctx->lock, NULL);
		if (val == 0)
		{
			val = pthread_create (&ctx->thread, NULL, clock_thread, ctx);
			if (val == 0)
				users = 1;
			else
				pthread_rwlock_destroy (&ctx->lock);
		}
	}
	else
	if (users < UINT_MAX)
		users++;

	pthread_mutex_unlock (&user_mutex);
	return val;
}


/**
 * Stops the clock. Thread-safe.
 *
 * @return nothing (always succeeds when defined).
 */
void teredo_clock_destroy (void)
{
	pthread_mutex_lock (&user_mutex);
	assert (users > 0);

	if (--users == 0)
	{
		clock_data_t *ctx = (clock_data_t *)&data;

		pthread_cancel (ctx->thread);
		pthread_join (ctx->thread, NULL);
		pthread_rwlock_destroy (&ctx->lock);
	}
	pthread_mutex_unlock (&user_mutex);
}


