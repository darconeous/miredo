/*
 * debug.h - libteredo transparent threading debugging
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

#ifndef LIBTEREDO_COMMON_H
# define LIBTEREDO_COMMON_H

# ifdef __GNUC__
#  define LIBTEREDO_NORETURN __attribute__ ((noreturn))
# else
#  define LIBTEREDO_NORETURN
# endif

# ifndef NDEBUG
#  include <syslog.h>
#  include <stdarg.h>

static inline void debug (const char *str, ...)
{
	va_list ap;
	va_start (ap, str);
	vsyslog (LOG_DEBUG, str, ap);
	va_end (ap);
}

#  ifdef __linux__
#   include <errno.h>
#   include <assert.h>
#   undef PTHREAD_MUTEX_INITIALIZER
#   define PTHREAD_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP

static inline int
d_pthread_mutex_init (pthread_mutex_t *mutex, pthread_mutexattr_t *pattr)
{
	pthread_mutexattr_t attr;

	if (pattr == NULL)
	{
		pattr = &attr;
		pthread_mutexattr_init (&attr);
	}

	pthread_mutexattr_settype (pattr, PTHREAD_MUTEX_ERRORCHECK_NP);
	int res = pthread_mutex_init (mutex, pattr);

	if (pattr == &attr)
		pthread_mutexattr_destroy (&attr);
	return res;
}
#   define pthread_mutex_init(m, a) d_pthread_mutex_init (m, a)

static inline int d_pthread_mutex_lock (pthread_mutex_t *mutex)
{
	int err = pthread_mutex_lock (mutex);
	assert (err != EDEADLK);
	assert (err == 0);
	return 0;
}
#   define pthread_mutex_lock(m) d_pthread_mutex_lock (m)

static inline int d_pthread_mutex_unlock (pthread_mutex_t *mutex)
{
	int err = pthread_mutex_unlock (mutex);
	assert (err != EPERM);
	assert (err == 0);
	return 0;
}
#   define pthread_mutex_unlock(m) d_pthread_mutex_unlock (m)

#endif /* ifdef __linux__ */

# else /* ifndef NDEBUG */
#  define debug( ... ) (void)0
# endif

#endif /* ifndef LIBTEREDO_COMMON_H */
