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


#ifndef MIREDO_COMPAT_BARRIER_H
# define MIREDO_COMPAT_BARRIER_H

# ifndef HAVE_PTHREAD_BARRIER_WAIT
/*
 * Of course, someone had to mess with barriers. uclibc does not support them,
 * but still defines not only PTHREAD_BARRIER_SERIAL_THREAD, but also, the
 * associated typedefs, and *even* _POSIX_BARRIERS (!!) which is supposed to
 * mean that they are supported. No thanks.
 */
#  undef _POSIX_BARRIERS
#  define _POSIX_BARRIES (-1)

#  undef PTHREAD_BARRIER_SERIAL_THREAD
#  define PTHREAD_BARRIER_SERIAL_THREAD (-1)

#  define pthread_barrier_t           compat_pthread_barrier_t
#  define pthread_barrier_init        compat_pthread_barrier_init
#  define pthread_barrier_destroy     compat_pthread_barrier_destroy
#  define pthread_barrier_wait        compat_pthread_barrier_wait

#  define pthread_barrierattr_t       compat_pthread_barrierattr_t
#  define pthread_barrierattr_init    compat_pthread_barrierattr_init
#  define pthread_barrierattr_destroy compat_pthread_barrierattr_destroy

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
# endif /* !HAVE_PTHREAD_BARRIER */
#endif /* MIREDO_COMPAT_BARRIER_H */
