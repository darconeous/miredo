/*
 * queue.cpp - Thread-safe packets queue class definition
 * $Id$
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

#include <stdlib.h> // malloc(), free()
#include <string.h> // memcpy()

#include "queue.h"

void
PacketsQueueCallback::SendPacket(const void *, size_t)
{
}

static PacketsQueueCallback oblivion;

int
PacketsQueue::Queue (const void *p, size_t len)
{
	if (len > left)
		return 1;

	struct packet_list *e =
		(struct packet_list *)malloc (sizeof (struct packet_list) + len);
	if (e == NULL)
		return -1;

	memcpy (e->data, p, len);
	e->len = len;
	e->next = NULL;

	left -= len;

	/* lock */
	*tail = e;
	tail = &e->next;
	/* unlock */

	return 0;
}


void
PacketsQueue::Flush (PacketsQueueCallback& cb, size_t totalbytes)
{
	struct packet_list *ptr;

	/* lock */
	left = totalbytes;
	ptr = head;
	head = NULL;
	tail = &head;
	/* unlock */

	while (ptr != NULL)
	{
		struct packet_list *buf = ptr->next;

		cb.SendPacket (ptr->data, ptr->len);
		free (ptr);
		ptr = buf;
	}
}


void
PacketsQueue::Trash (size_t max)
{
	Flush (oblivion, max);
}
