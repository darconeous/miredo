/*
 * pthread_barrier replacement with pthread_mutex and pthread_cond.
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


#ifndef __MIREDO_COMPAT_BARRIER_H
# define __MIREDO_COMPAT_BARRIER_H

# ifndef PTHREAD_BARRIER_SERIAL_THREAD
#  define PTHREAD_BARRIER_SERIAL_THREAD (-1)

typedef struct
{
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	unsigned int count;
} pthread_barrier_t;

typedef struct
{
	void *dummy;
} pthread_barrierattr_t;

#  ifdef __cplusplus
extern "C" {
#  endif

int pthread_barrier_init (pthread_barrier_t *barrier,
                          pthread_barrierattr_t *attr, unsigned int count);
int pthread_barrier_destroy (pthread_barrier_t *barrier);
int pthread_barrier_wait (pthread_barrier_t *barrier);
int pthread_barrierattr_init (pthread_barrierattr_t *attr);
int pthread_barrierattr_destroy (pthread_barrierattr_t *attr);

#  ifdef __cplusplus
}
#  endif
# endif /* !PTHREAD_BARRIER_SERIAL_THREAD */
#endif /* __MIREDO_COMPAT_BARRIER_H */
