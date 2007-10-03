/*
 * clock_nanosleep.c - clock_nanosleep() replacement
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
#include <sys/time.h>
#include <errno.h>

int clock_nanosleep (clockid_t id, int flags, const struct timespec *ts,
                     struct timespec *ots)
{
	if (id != CLOCK_REALTIME)
		return EINVAL;

	if (flags & TIMER_ABSTIME)
	{
		struct timespec mine;

		if (clock_gettime (id, &mine))
			return errno;

		if (mine.tv_sec > ts->tv_sec)
			return 0; // behind schedule

		if (mine.tv_nsec > ts->tv_nsec)
		{
			if (mine.tv_sec == ts->tv_sec)
				return 0; // behind schedule too

			mine.tv_nsec = 1000000000 + ts->tv_nsec - mine.tv_nsec;
			mine.tv_sec++;
		}
		else
			mine.tv_nsec = ts->tv_nsec - mine.tv_nsec;

		mine.tv_sec = ts->tv_sec - mine.tv_sec;

		/* With TIMER_ABSTIME, clock_nanosleep ignores <ots> */
		return nanosleep (&mine, NULL) ? errno : 0;
	}

	return nanosleep (ts, ots) ? errno : 0;
}

