/*
 * closefrom.c - closefrom() replacement
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

#include <sys/types.h>
#include <sys/time.h> /* for <sys/resource.h> */
#include <sys/resource.h> /* getrlimit() */
#include <unistd.h>
#include <errno.h> /* errno */

/**
 * BSD closefrom() replacement.
 *
 * We don't handle EINTR error properly;
 * this replacement is obviously not atomic.
 */
extern int closefrom (int fd)
{
	struct rlimit lim;
	unsigned found = 0;
	int saved_errno;

	if (getrlimit (RLIMIT_NOFILE, &lim))
		return -1;

	saved_errno = errno;
	while ((unsigned)fd < lim.rlim_max)
		if (close (fd++) == 0)
			found++;

	if (found == 0)
	{
		errno = EBADF;
		return -1;
	}
	errno = saved_errno;
	return 0;
}
