/*
 * relay.h - Teredo relay peers list declaration
 * $Id: relay.h,v 1.5 2004/07/11 10:08:13 rdenisc Exp $
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

#ifndef MIREDO_RELAY_H
# define MIREDO_RELAY_H

# include <inttypes.h>
# include <time.h> // time_t

# include <netinet/in.h> // struct in6_addr

class MiredoRelayUDP;
class IPv6Tunnel;
union teredo_addr;


class MiredoRelay
{
	private:
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

		const MiredoRelayUDP *sock;
		const IPv6Tunnel *tunnel;

		struct peer *AllocatePeer (void);
		struct peer *FindPeer (const struct in6_addr *addr);

		int SendBubble (const union teredo_addr *dst) const;

	public:
		MiredoRelay (uint32_t pref, MiredoRelayUDP *udp)
			: is_cone (true), prefix (pref), head (NULL),
			  sock (udp)
		{
		}

		~MiredoRelay ();

		void SetTunnel (const IPv6Tunnel *tun)
		{
			tunnel = tun;
		}

		/*
		 * Transmits a packet from IPv6 Internet via Teredo.
		 */
		int TransmitPacket (void);

		/*
		 * Receives a packet from Teredo to IPv6 Internet.
		 */
		int ReceivePacket (void);

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
};

#endif /* ifndef MIREDO_RELAY_H */

