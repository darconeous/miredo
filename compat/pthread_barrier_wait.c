/*
 * pthread_barrier replacement with pthread_mutex and pthread_cond.
 * $Id$
 *
 * NOTE:
 * - No attributes are defined. In particular, process-shared barriers
 *   are not supported.
 *
 * The author would consider relicensing under BSD(-like) terms on demand.
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

#include <errno.h>
#include <pthread.h>

#include "barrier.h"

extern int
pthread_barrier_init (pthread_barrier_t *barrier, pthread_barrierattr_t *attr,
                      unsigned int count)
{
	int val;

	(void)attr;
	val = pthread_mutex_init (&barrier->mutex, NULL);
	if (val == 0)
	{
		val = pthread_cond_init (&barrier->cond, NULL);
		if (val == 0)
		{
			barrier->count = count;
			return 0;
		}
		(void)pthread_mutex_destroy (&barrier->mutex);
	}
	return val;
}


extern int
pthread_barrier_destroy (pthread_barrier_t *barrier)
{
	int val;

	/*
	 * By locking the mutex before destroying the condition,
	 * it becomes fairly unlikely that we'll manage to destroy the
	 * condition, but not the mutex. It is not really required though.
	 */
	val = pthread_mutex_trylock (&barrier->mutex);
	if (val)
		return val;

	val = pthread_cond_destroy (&barrier->cond);
	if (val)
		return val;
	(void)pthread_mutex_unlock (&barrier->mutex);
	return pthread_mutex_destroy (&barrier->mutex);
}


extern int
pthread_barrier_wait (pthread_barrier_t *barrier)
{
	int val;
	
	val = pthread_mutex_lock (&barrier->mutex);
	if (val)
		return val;

	if (barrier->count == 0)
		val = EINVAL;
	else
	{
		barrier->count--;
		if (barrier->count > 0)
		{
			int status;

			/*
			 * pthread_barrier_wait() is NOT a cancellation point, and it is
			 * of course not async-cancellation safe.
			 */
			(void)pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &status);
			(void)pthread_cond_wait (&barrier->cond, &barrier->mutex);
			(void)pthread_setcancelstate (status, NULL);
			val = 0;
		}
		else
		{
			(void)pthread_cond_broadcast (&barrier->cond);
			val = PTHREAD_BARRIER_SERIAL_THREAD;
		}
	}
	(void)pthread_mutex_unlock (&barrier->mutex);

	return val;
}


extern int
pthread_barrierattr_init (pthread_barrierattr_t *attr)
{
	attr->dummy = attr;
	return 0;
}


extern int
pthread_barrierattr_destroy (pthread_barrierattr_t *attr)
{
	if (attr->dummy != attr)
		return EINVAL;

	attr->dummy = NULL;
	return 0;
}
