/*
 * queue.h - Packets queue class declaration
 * $Id$
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

#ifndef LIBMIREDO_QUEUE_H
# define LIBMIREDO_QUEUE_H

# include <stddef.h>
# include <stdint.h>

class PacketsQueueCallback
{
	public:
		virtual void SendPacket(const void *data, size_t len);
		virtual ~PacketsQueueCallback (void) { }
};

class PacketsQueue
{
	private:
		size_t left;
		struct packet_list
		{
			struct packet_list *next;
			size_t len;
			uint8_t data[0];
		} *head, **tail;

	public:
		PacketsQueue (size_t max) : left (max), head (NULL), tail (&head)
		{
		}

		~PacketsQueue (void)
		{
			Trash (0);
		}

		/* 
		 * Queues one packet. Return 0 on success, 1 if the queue is
		 * full, and -1 if there was an errro (ENOMEN).
		 */
		int Queue (const void *p, size_t len);

		/*
		 * Flushes the packets queue through SendPacket()
		 */
		void Flush (PacketsQueueCallback& cb, size_t newmax);

		/*
		 * Flushes the packets queue to nowhere.
		 */
		void Trash (size_t newmax);
};

#endif /* ifndef LIBMIREDO_QUEUE_H */
