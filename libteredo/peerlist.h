/*
 * peerlist.h - Teredo relay internal peers list declaration
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

#ifndef LIBTEREDO_PEERLIST_H
# define LIBTEREDO_PEERLIST_H

# define TEREDO_TIMEOUT 30 // seconds
# define MAXQUEUE 1280u // bytes


class TeredoRelay::peer
{
	public:
		union teredo_addr addr;
		struct
		{
			uint32_t addr;
			uint16_t port;
		} mapping;

		peer *next;

	private:
		struct packet;
		packet *queue;
		size_t queue_left;
		void Queue (const void *data, size_t len, bool incoming);
		time_t expiry;

	public:
		peer (void) : queue (NULL), queue_left (TeredoRelay::MaxQueueBytes)
		{
		}

		union
		{
			struct
			{
				unsigned trusted:1;
				unsigned replied:1;
				unsigned bubbles:2;
				unsigned pings:2;
				unsigned dummy:10;
			} flags;
			uint16_t all_flags;
		} flags;

	private:
		void Touch (void)
		{
			time (&expiry);
			expiry += TEREDO_TIMEOUT;
		}

	public:
		void SetMapping (uint32_t ip, uint16_t port)
		{
			mapping.addr = ip;
			mapping.port = port;
		}

		void SetMappingFromPacket (const TeredoPacket& p)
		{
			SetMapping (p.GetClientIP (), p.GetClientPort ());
		}

		void TouchReceive (void)
		{
			flags.flags.replied = 1;
			Touch ();
		}

		void TouchTransmit (void)
		{
			if (flags.flags.replied == 0)
				Touch ();
		}

		void QueueIncoming (const void *data, size_t len)
		{
			Queue (data, len, true);
		}

		void QueueOutgoing (const void *data, size_t len)
		{
			Queue (data, len, false);
		}

		void Dequeue (TeredoRelay *r);
		void Reset (void);

		~peer (void)
		{
			Reset ();
		}

		bool IsExpired (const time_t now) const
		{
			return ((signed)(now - expiry)) > 0;
		}

		static void DestroyList (void *head);
};

#endif /* ifndef LIBTEREDO_PEERLIST_H */
