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
# define MAXQUEUE 1280 // bytes


/*
 * Queueng of packets from the IPv6 toward Teredo
 */
class TeredoRelay::OutQueue : public PacketsQueue
{
	private:
		TeredoRelayUDP *sock;
		uint32_t addr;
		uint16_t port;

		virtual int SendPacket (const void *p, size_t len)
		{
			return sock->SendPacket (p, len, addr, port);
		}

	public:
		OutQueue (TeredoRelayUDP *s) : PacketsQueue (MAXQUEUE),
					       sock (s)
		{
		}

		void SetMapping (uint32_t mapped_addr, uint16_t mapped_port)
		{
			addr = mapped_addr;
			port = mapped_port;
		}
};


/*
 * Queueing of packets from Teredo toward the IPv6
 */
class TeredoRelay::InQueue : public PacketsQueue
{
	private:
		TeredoRelay *relay;

		virtual int SendPacket (const void *p, size_t len)
		{
			return relay->SendIPv6Packet (p, len);
		}

	public:
		InQueue (TeredoRelay *r) : PacketsQueue (MAXQUEUE), relay (r)
		{
		}
};


class TeredoRelay::peer
{
	private:
		struct timeval expiry;

	public:
		OutQueue outqueue;
		InQueue inqueue;

		peer (TeredoRelayUDP *sock, TeredoRelay *r)
			: outqueue (sock), inqueue (r)
		{
		}
		
		peer *next;

		struct in6_addr addr;
		uint32_t mapped_addr;
		uint16_t mapped_port;
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
		// TODO: nonce and mapped_* could be union-ed
		uint8_t nonce[8]; /* only for client toward non-client */

	private:
		void Touch (void)
		{
			gettimeofday (&expiry, NULL);
			expiry.tv_sec += TEREDO_TIMEOUT;
		}

	public:
		void SetMapping (uint32_t ip, uint16_t port)
		{
			mapped_addr = ip;
			mapped_port = port;
			outqueue.SetMapping (ip, port);
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

		bool IsExpired (const struct timeval& now) const
		{
			return ((signed)(now.tv_sec - expiry.tv_sec) > 0)
			     || ((now.tv_sec == expiry.tv_sec)
			      && (now.tv_usec >= expiry.tv_usec));
		}
};

#endif /* ifndef LIBTEREDO_PEERLIST_H */
