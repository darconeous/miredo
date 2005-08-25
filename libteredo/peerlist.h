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


/*
 * Queueing of packets from Teredo toward the IPv6
 */
class TeredoRelay::InDequeue : public PacketsQueueCallback
{
	private:
		TeredoRelay *relay;

		virtual void SendPacket (const void *p, size_t len)
		{
			relay->SendIPv6Packet (p, len);
		}

	public:
		InDequeue (TeredoRelay *r) : relay (r)
		{
		}
};


/*
 * Queueing of packets from IPv6 toward local Teredo client
 */
class OutDequeue : public PacketsQueueCallback
{
	private:
		TeredoRelayUDP *udp;
		uint32_t ipv4;
		uint16_t port;

		virtual void SendPacket (const void *p, size_t len)
		{
			udp->SendPacket (p, len, ipv4, port);
		}

	public:
		OutDequeue (TeredoRelayUDP *u, uint32_t ip, uint16_t p)
			: udp (u), ipv4 (ip), port (p)
		{
		}
};


class TeredoRelay::peer
{
	public:
		union teredo_addr addr;
		union
		{
			struct
			{
				uint32_t mapped_addr;
				uint16_t mapped_port;
			} mapping;
			uint8_t nonce[8]; /* only for client toward non-client */
		} u1;
	
		peer *next;

		PacketsQueue outqueue;
#ifdef MIREDO_TEREDO_CLIENT
		/* TODO: merge both queues */
		PacketsQueue inqueue;
#endif

		peer () : outqueue (MAXQUEUE)
#ifdef MIREDO_TEREDO_CLIENT
			, inqueue (MAXQUEUE)
#endif
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
				unsigned nonce:1; // mapped_* unset, nonce set
				unsigned dummy:9;
			} flags;
			uint16_t all_flags;
		} flags;

	private:
		time_t expiry;

		void Touch (void)
		{
			time (&expiry);
			expiry += TEREDO_TIMEOUT;
		}

	public:
		void SetMapping (uint32_t ip, uint16_t port)
		{
			u1.mapping.mapped_addr = ip;
			u1.mapping.mapped_port = port;
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

		void Flush (TeredoRelay *r)
		{
#ifdef MIREDO_TEREDO_CLIENT
			InDequeue icb (r);
			inqueue.Flush (icb, MAXQUEUE);
#endif
			OutDequeue ocb (&r->sock, u1.mapping.mapped_addr,
			                u1.mapping.mapped_port);
			outqueue.Flush (ocb, MAXQUEUE);
		}


		bool IsExpired (const time_t now) const
		{
			return ((signed)(now - expiry)) > 0;
		}

		static void DestroyList (void *head);
};

#endif /* ifndef LIBTEREDO_PEERLIST_H */
