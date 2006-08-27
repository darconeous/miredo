/*
 * addrwatch.c - Watch system IPv6 addresses
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

#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h> // clock_gettime()

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h> // O_RDONLY
#include <pthread.h>
#include <errno.h>

#include "miredo.h"
#include "addrwatch.h"

struct miredo_addrwatch
{
	pthread_t thread;

	int self_scope;
	int if_inet6_fd;
	int pipefd[2];
	bool status;
};


/**
 * @return never ever. Thread must be cancelled.
 */
static void *addrwatch (void *opaque)
{
	struct miredo_addrwatch *data = (struct miredo_addrwatch *)opaque;
	struct timespec deadline;

	clockid_t clock_id = CLOCK_REALTIME;
#if (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
	if (clock_gettime (CLOCK_MONOTONIC, &deadline) == 0)
		clock_id = CLOCK_MONOTONIC;
	else
#endif
		clock_gettime (CLOCK_REALTIME, &deadline);

	for (;;)
	{
		int state;
		pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &state);

		if (lseek (data->if_inet6_fd, 0, SEEK_SET) == -1)
			goto wait;

		char buf[8192];
		int val = read (data->if_inet6_fd, buf, sizeof (buf));
		if (val == -1)
			goto wait;

		char *ptr = buf, *next;
		bool found = false;
		while ((next = memchr (ptr, '\n', val)) != NULL)
		{
			*next++ = '\0';
			val -= (next - ptr);

			unsigned p;
			int id;

			if (sscanf (ptr, "%04x%*s %02x", &p, &id) == 2)
			{
				if ((id != data->self_scope) && ((p & 0xe000) == 0x2000))
				{
					found = true;
					break;
				}
			}
			ptr = next;
		}

		/* Update status */
		if (data->status != found)
		{
			data->status = found;
			(void)write (data->pipefd[1], &found, sizeof (found));
		}

	wait:
		pthread_setcancelstate (state, NULL);
		deadline.tv_sec += 5;
		clock_nanosleep (clock_id, TIMER_ABSTIME, &deadline, NULL);
	}

	return NULL; // dead code
}


/**
 * Starts a thread that checks if global Internet IPv6 connectivity
 * appears to be available. This is used to determine whether the
 * Teredo tunnel is to be used as the default route, or merely to reach
 * other Teredo clients.
 *
 * @param self_scope interface identifier (scope_id) of our own tunnel
 * interface, that will be excluded from the checks.
 *
 * @return 0 on success, -1 on error.
 */
miredo_addrwatch *miredo_addrwatch_start (int self_scope)
{
	miredo_addrwatch *data = (miredo_addrwatch *)malloc (sizeof (*data));
	if (data == NULL)
		return NULL;

	memset (data, 0, sizeof (data));

	int fd = open ("/proc/net/if_inet6", O_RDONLY);
	if (fd != -1)
	{
		miredo_setup_nonblock_fd (fd);

		data->if_inet6_fd = fd;
		data->self_scope = self_scope;
		data->status = true;

		if (pipe (data->pipefd) == 0)
		{
			miredo_setup_nonblock_fd (data->pipefd[0]);
			miredo_setup_fd (data->pipefd[1]);

			if (pthread_create (&data->thread, NULL, addrwatch, data) == 0)
				return data;
		}

		(void)close (fd);
	}

	return NULL;
}

/**
 * Releases resources allocated by miredo_addrwatch_start().
 */
void miredo_addrwatch_stop (miredo_addrwatch *data)
{
	assert (data != NULL);

	(void)pthread_cancel (data->thread);
	(void)pthread_join (data->thread, NULL);

	(void)close (data->pipefd[1]);
	(void)close (data->pipefd[0]);
	(void)close (data->if_inet6_fd);
	free (data);
}


/**
 * @return file descriptor that gets readable whenever the state changes
 * (though it might also get readable with no changes).
 */
int miredo_addrwatch_getfd (miredo_addrwatch *self)
{
	return (self != NULL) ? self->pipefd[0] : -1;
}


/**
 * @return the current addrwatch state (true or false).
 */
int miredo_addrwatch_available (miredo_addrwatch *self)
{
	if (self == NULL)
		return 0;

	bool val;
	while (read (self->pipefd[0], &val, sizeof (val)) > 0);

	return self->status ? 1 : 0;
}
