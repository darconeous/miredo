/*
 * queue.cpp - Thread-safe packets queue class definition
 * $Id: relay.h 175 2004-10-16 09:48:22Z remi $
 */

/***********************************************************************
 *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

# include <pthread.h>
# include <stdlib.h> // malloc(), free()
# include <string.h> // memcpy()

# include "queue.h"

#include <syslog.h> //FIXME: remove

PacketsQueue::PacketsQueue (size_t maxbytes)
	: max (maxbytes), left (maxbytes), head (NULL), tail (NULL)
{
	pthread_mutex_init (&mutex, NULL);
}


int
PacketsQueue::Queue (const void *p, size_t len)
{

	void *d = malloc (len);
	if (d == NULL)
		return -1;

	struct packet_list *e = (struct packet_list *)
					malloc (sizeof (struct packet_list));
	if (e == NULL)
	{
		free (d);
		return -1;
	}

	syslog (LOG_DEBUG, "DEBUG: queueing packet (%u bytes)", len);
	memcpy (d, p, len);
	e->data = d;
	e->len = len;
	e->next = NULL;

	int retval = 0;

	pthread_mutex_lock (&mutex);
	if (len <= left)
	{
		left -= len;
		if (tail != NULL)
			tail->next = e;
		else
			head = e;
		tail = e;
	}
	else
		retval = -1;
	pthread_mutex_unlock (&mutex);

	return retval;
}


int
PacketsQueue::Flush (void)
{
	int retval = 0;
	struct packet_list *ptr;

	pthread_mutex_lock (&mutex);
	left = max;
	ptr = head;
	head = NULL;
	tail = NULL;
	pthread_mutex_unlock (&mutex);

	while (ptr != NULL)
	{
		retval |= (SendPacket (ptr->data, ptr->len) != (int)ptr->len);
		syslog (LOG_DEBUG, "DEBUG: flushing packet (%u bytes)", ptr->len);

		struct packet_list *buf = ptr->next;
		free (ptr->data);
		free (ptr);
		ptr = buf;
	}	

	return retval ? -1 : 0;
}


void
PacketsQueue::Trash (void)
{
	struct packet_list *ptr;

	pthread_mutex_lock (&mutex);
	left = max;
	ptr = head;
	head = NULL;
	tail = NULL;
	pthread_mutex_unlock (&mutex);

	unsafe_Trash (ptr);
}


void
PacketsQueue::unsafe_Trash (struct packet_list *ptr)
{
	while (ptr != NULL)
	{
		struct packet_list *buf = ptr;
		ptr = buf->next;
		free (buf->data);
		free (buf);
	}
}


PacketsQueue::~PacketsQueue (void)
{
	pthread_mutex_destroy (&mutex);
	unsafe_Trash (head);
}

