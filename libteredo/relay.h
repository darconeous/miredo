/*
 * relay.h - Teredo relay peers list declaration
 * $Id: relay.h,v 1.3 2004/07/31 19:58:43 rdenisc Exp $
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#ifndef LIBTEREDO_RELAY_H
# define LIBTEREDO_RELAY_H

# include <inttypes.h>
# include <time.h> // time_t

# include <netinet/in.h> // struct in6_addr

# include <libteredo/teredo-udp.h>

struct ip6_hdr;
union teredo_addr;


class TeredoRelay
{
	private:
		/*** Internal stuff ***/
		bool is_cone;
		uint32_t prefix;

		struct peer
		{
			struct peer *next;

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
				} flags;
				uint16_t all_flags;
			} flags;
			/* nonce: only for client */
			time_t last_rx;
			time_t last_xmit;

			uint8_t *queue;
			size_t queuelen;
		} *head;

		TeredoRelayUDP sock;

		struct peer *AllocatePeer (void);
		struct peer *FindPeer (const struct in6_addr *addr);

		int SendBubble (const union teredo_addr *dst,
				bool indirect) const;

		/*** Callbacks ***/
		/*
		 * Tries to receive a packet from IPv6 Internet.
		 * On success, packet and length attributes must be set to
		 * the address and length of the IPv6 packet.
		 *
		 * Returns 0 on sucess, -1 on error.
		 */
		virtual int ReceiveIPv6Packet (void) = 0;

		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet,
						size_t length) = 0;

	protected:
		const struct ip6_hdr *packet;
		size_t length;

		TeredoRelay (uint32_t pref, uint16_t port);

	public:
		virtual ~TeredoRelay ();

		int operator! (void) const
		{
			return !sock;
		}

		/*
		 * Transmits a packet from IPv6 Internet via Teredo.
		 */
		int ProcessIPv6Packet (void);

		/*
		 * Receives a packet from Teredo to IPv6 Internet.
		 */
		int ProcessTunnelPacket (void);

		// Sets and gets cone flag setting
		void SetCone (bool cone = true)
		{
			is_cone = true;
		}

		bool IsCone (void) const
		{
			return is_cone;
		}

		uint32_t GetPrefix (void) const
		{
			return prefix;
		}
		
		int RegisterReadSet (fd_set *rs) const
		{
			return sock.RegisterReadSet (rs);
		}
};

#endif /* ifndef MIREDO_RELAY_H */

