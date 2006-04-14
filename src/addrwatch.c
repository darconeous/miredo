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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h> // O_RDONLY
#include <pthread.h>
#include <errno.h>

#include "miredo.h"
#include "addrwatch.h"

struct miredo_addrwatch
{
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	int self_scope;
	int if_inet6_fd;
	int pipefd[2];
	bool status;
};

/*
 * This thread is not supposed to be canceled.
 * It stops when cond is signaled.
 */
static void *addrwatch (void *opaque)
{
	struct miredo_addrwatch *data = (struct miredo_addrwatch *)opaque;
	struct timeval deadline;

	gettimeofday (&deadline, NULL);

	(void)pthread_mutex_lock (&data->mutex);
	int val;

	do
	{
		if (lseek (data->if_inet6_fd, 0, SEEK_SET) == -1)
			goto wait;

		char buf[8192];
		val = read (data->if_inet6_fd, buf, sizeof (buf));
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
			(void)write (data->pipefd[1], &found, sizeof (found));
			data->status = found;
		}

	wait:
		deadline.tv_sec += 5;

		do
		{
			struct timespec ts;
			ts.tv_sec = deadline.tv_sec;
			ts.tv_nsec = deadline.tv_usec * 1000;
			val = pthread_cond_timedwait (&data->cond, &data->mutex, &ts);
		}
		while (val && (val != ETIMEDOUT));
	}
	while (val);

	(void)pthread_mutex_unlock (&data->mutex);
	return NULL;
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
	(void)pthread_mutex_init (&data->mutex, NULL);
	(void)pthread_cond_init (&data->cond, NULL);

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

	(void)pthread_mutex_lock (&data->mutex);
	(void)pthread_cond_signal (&data->cond);
	(void)pthread_mutex_unlock (&data->mutex);

	(void)pthread_join (data->thread, NULL);
	(void)pthread_cond_destroy (&data->cond);
	(void)pthread_mutex_destroy (&data->mutex);

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

	pthread_mutex_lock (&self->mutex);
	val = self->status;
	pthread_mutex_unlock (&self->mutex);
	return val ? 1 : 0;
}
