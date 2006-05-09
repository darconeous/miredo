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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h> /* for <sys/resource.h> */
#include <sys/resource.h> /* getrlimit() */
#include <unistd.h>
#include <errno.h> /* errno */
#include <sys/select.h> /* FD_SETSIZE */

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

	/*
	 * Make sure closefrom() does not take ages if the file number limit
	 * is very big. closefrom() is not supposed to setrlimit(), but it is
	 * not standard, neither common (Darwin, Linux don't have it at the
	 * moment, and IIRC, FreeBSD and NetBSD neither).
	 *
	 * Rather than put some completely arbitrary limit, we use FD_SETSIZE.
	 * As such we can warranty that subsequent FD_SET() won't overflow.
	 * Miredo has a O(1) open file descriptors number behavior anyway. If
	 * you want to use this in another project, you should first consider
	 * using BSD kqueue/Linux epoll or a portable wrapper of these
	 * scalable I/O polling calls, and *THEN* use a higher limit here
	 * instead of FD_SETSIZE.
	 *
	 * Mac OS X returns (2^31 - 1) as its limit, and closefrom() is way
	 * too long (and intensive) in this case. Linux usually returns 1024,
	 * though root can raise the limit to 1048576.
	 */
	if (lim.rlim_max > FD_SETSIZE)
	{
		if (lim.rlim_cur > FD_SETSIZE)
			lim.rlim_cur = FD_SETSIZE;
		lim.rlim_max = FD_SETSIZE;
		setrlimit (RLIMIT_NOFILE, &lim);
	}

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
