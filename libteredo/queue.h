/*
 * queue.h - Thread-safe packets queue class declaration
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

#ifndef LIBMIREDO_QUEUE_H
# define LIBMIREDO_QUEUE_H

# include <stddef.h>
# include <pthread.h>

class PacketsQueue
{
	private:
		size_t max, left;
		struct packet_list
		{
			void *data;
			size_t len;

			struct packet_list *next;
		} *head, *tail;

		pthread_mutex_t mutex;

		virtual int SendPacket (const void *p, size_t len) = 0;

		void unsafe_Trash (struct packet_list *h);

	protected:
		PacketsQueue (size_t totalbytes);

	public:
		/* 
		 * Queues one packet. Return 0 on success, 1 if the queue is
		 * full, and -1 if there was an errro (ENOMEN).
		 */
		int Queue (const void *p, size_t len);

		/*
		 * Flushes the packets queue through SendPacket()
		 */
		int Flush (void);

		/*
		 * Flushes the packets queue to nowhere.
		 */
		void Trash (void);

		virtual ~PacketsQueue (void);
};

#endif /* ifndef LIBMIREDO_QUEUE_H */

