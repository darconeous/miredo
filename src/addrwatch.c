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

#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
#include <SystemConfiguration/SystemConfiguration.h>
#endif

struct miredo_addrwatch
{
	pthread_t thread;

	int self_scope;
	int pipefd[2];
	bool status;
#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
	SCDynamicStoreRef dynamic_store;
	CFRunLoopSourceRef run_loop_source_ref;
	CFRunLoopRef	run_loop;
#else
	int if_inet6_fd;
#endif

};

#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
static void miredoSCUpdate(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info)
{
	miredo_addrwatch* me=(miredo_addrwatch*)info;
	char found=0;
	CFDictionaryRef plist;
	plist=SCDynamicStoreCopyValue(store,CFSTR("State:/Network/Global/IPv6"));
	if(plist) {
		CFRelease(plist);
		found=1;
	} else {
		found=0;
	}
	if(me->status!=found) {
		if(found)
			fprintf(stderr,"Native IPv6 connectivity obtained!\n");
		else 
			fprintf(stderr,"Native IPv6 connectivity lost!\n");
		me->status=found;
		while (write (me->pipefd[1], &found, 1) == 0);
	}
}

static CFStringRef miredoSCDescribe(const void* info) {
	return CFSTR("miredo");
}
#endif


/**
 * @return never ever. Thread must be cancelled.
 */
static LIBTEREDO_NORETURN void *addrwatch (void *opaque)
{
	struct miredo_addrwatch *data = (struct miredo_addrwatch *)opaque;

#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
	data->run_loop=CFRunLoopGetCurrent();
	CFRunLoopAddSource(
		data->run_loop,
		data->run_loop_source_ref,
		kCFRunLoopCommonModes
	);
	CFRunLoopRun();
	fprintf(stderr,"warning: addrwatch exited!\n");
#else

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
		ssize_t val = read (data->if_inet6_fd, buf, sizeof (buf));
		if (val == -1)
			goto wait;

		char *ptr = buf, *next;
		char found = 0;
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
					found = 1;
					break;
				}
			}
			ptr = next;
		}

		/* Update status */
		if (data->status != (found != 0))
		{
			data->status = (found != 0);
			while (write (data->pipefd[1], &found, 1) == 0);
		}
	wait:
		pthread_setcancelstate (state, NULL);
		deadline.tv_sec += 5;
		clock_nanosleep (clock_id, TIMER_ABSTIME, &deadline, NULL);
	}
#endif
	// dead code
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

#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
	fprintf(stderr,"Starting addrwatch...\n");
	SCDynamicStoreContext context={
		.version=0,
		.info=(void*)data,
		.copyDescription=miredoSCDescribe,
	};

	data->dynamic_store=SCDynamicStoreCreate(
		NULL,
		CFSTR("miredo"),
		miredoSCUpdate,
		&context
	);
	data->run_loop_source_ref=SCDynamicStoreCreateRunLoopSource ( 
		NULL, 
		data->dynamic_store, 
		0
	);
	{
		CFArrayRef keys;
		keys=CFArrayCreateMutable(NULL,1,&kCFTypeArrayCallBacks);
		CFArrayAppendValue(keys,CFSTR("State:/Network/Global/IPv6"));
		if(!SCDynamicStoreSetNotificationKeys ( 
			data->dynamic_store, 
			keys, 
			NULL
		)) {
			fprintf(stderr,"Unable to set notification keys!\n");
		}
		CFRelease(keys);
	}

	data->self_scope = self_scope;
	{
		CFDictionaryRef plist;
		plist=SCDynamicStoreCopyValue(data->dynamic_store,CFSTR("State:/Network/Global/IPv6"));
		if(plist) {
			CFRelease(plist);
			data->status =1;
		} else {
			data->status =0;
		}
	}
	if (pipe (data->pipefd) == 0)
	{
		miredo_setup_nonblock_fd (data->pipefd[0]);
		miredo_setup_fd (data->pipefd[1]);

		if (pthread_create (&data->thread, NULL, addrwatch, data) == 0)
			return data;
	}
	fprintf(stderr,"error: addrwatch start failed!\n");
#else
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
#endif

	return NULL;
}

/**
 * Releases resources allocated by miredo_addrwatch_start().
 */
void miredo_addrwatch_stop (miredo_addrwatch *data)
{
	assert (data != NULL);

#ifdef HAS_SYSTEMCONFIGURATION_FRAMEWORK
	//CFRunLoopSourceContext context;
	//CFRunLoopSourceGetContext(data->run_loop_source_ref,&context);
	//if(context.cancel)context.cancel(context.info);
	CFRunLoopStop(data->run_loop);
	CFRelease(data->run_loop_source_ref);
	CFRelease(data->dynamic_store);
#else
	(void)pthread_cancel (data->thread);
	(void)pthread_join (data->thread, NULL);

	(void)close (data->pipefd[1]);
	(void)close (data->pipefd[0]);
	(void)close (data->if_inet6_fd);
#endif
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

	char val;
	while (read (self->pipefd[0], &val, 1) > 0);

	return self->status ? 1 : 0;
}
