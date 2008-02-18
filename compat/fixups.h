/*
 * Various fixes for obsolete, or plain broken, C libraries.
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

#ifdef MIREDO_COMPAT_FIXUPS_H
# error How come you include this header twice?!
#endif

#define MIREDO_COMPAT_FIXUPS_H 1

#define _( str )		dgettext (PACKAGE_NAME, str)
#define N_( str )		gettext_noop (str)

#ifdef __cplusplus
# define EXTERN extern "C"
#else
# define EXTERN
#endif

/* Non standard */
#ifndef HAVE_CLEARENV
EXTERN int clearenv (void);
#endif

/* Non standard but useful OpenBSDism */
#ifndef HAVE_CLOSEFROM
EXTERN int closefrom (int lowfd);
#endif

/* Another useful BSDism */
#ifndef HAVE_STRLCPY
# include <stddef.h>
EXTERN size_t strlcpy (char *tgt, const char *str, size_t len);
#endif

/* _Standard_ POSIX - for broken and obsolete OSes */
#ifndef HAVE_CLOCK_GETTIME
# include <time.h>
# ifndef CLOCK_REALTIME
#  define CLOCK_REALTIME 0
# endif
EXTERN int clock_gettime (clockid_t id, struct timespec *now);
#endif

/* Standard POSIX, even less commonly supported */
#ifndef HAVE_CLOCK_NANOSLEEP
# include <time.h>
# ifndef TIMER_ABSTIME
#  define TIMER_ABSTIME 1
# endif

/*
 * Well, I could forgive implementors who don't define some recent POSIX
 * groups, but some actually pretend to support what they don't, which is
 * really stupid, pointless and annoying.
 */
# undef _POSIX_MONOTONIC_CLOCK
# define _POSIX_MONOTONIC_CLOCK (-1)

EXTERN int clock_nanosleep (clockid_t id, int flags,
                            const struct timespec *ts, struct timespec *ots);

#endif

#ifndef HAVE_PTHREAD_CONDATTR_SETCLOCK
/*
 * Of course, some libc versions define this to 0 even though they don't
 * provide the implementation. Otherwise, my life would be too easy.
 */
# undef _POSIX_CLOCK_SELECTION
# define _POSIX_CLOCK_SELECTION (-1)
#endif

#ifndef HAVE_FDATASYNC
EXTERN int fdatasync (int fd);
#endif
