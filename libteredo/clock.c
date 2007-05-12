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
#include <unistd.h> // _POSIX_*
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

int teredo_clock_create (void)
{
	int val = -1;

	pthread_mutex_lock (&user_mutex);

	if (users == 0)
	{
		clock_data_t *ctx = (clock_data_t *)&data;
		struct timespec ts;

#if (_POSIX_CLOCK_SELECTION - 0 >= 0) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
		/* Run-time POSIX monotonic clock detection */
		ctx->id = CLOCK_MONOTONIC;
		if (clock_gettime (CLOCK_MONOTONIC, &ts))
#endif
		{
			ctx->id = CLOCK_REALTIME;
			clock_gettime (CLOCK_REALTIME, &ts);
		}
	
		ctx->value = ts.tv_sec;
	
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


