/*
 * relay.h - Teredo relay peers list declaration
 * $Id: relay.h,v 1.8 2004/08/22 15:19:32 rdenisc Exp $
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

# include <libteredo/teredo-udp.h>

struct ip6_hdr;
union teredo_addr;

struct __TeredoRelay_peer;


// big TODO: make all functions re-entrant safe
//           make all functions thread-safe
class TeredoRelay
{
	private:
		/*** Internal stuff ***/
		bool is_cone;
		uint32_t prefix, server_ip;

		struct __TeredoRelay_peer *head;

		TeredoRelayUDP sock;

		struct __TeredoRelay_peer *AllocatePeer (void);
		struct __TeredoRelay_peer *FindPeer (const struct in6_addr *addr);

		int SendBubble (const union teredo_addr *dst,
				bool indirect) const;

		/*** Callbacks ***/
		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet,
						size_t length) = 0;

		/*
		 * Tries to define the Teredo client IPv6 address. This is an
		 * indication that the Teredo tunneling interface is ready.
		 * The default implementation in base class TeredoRelay does
		 * nothing.
		 *
		 * Returns 0 on success, -1 on error.
		 * TODO: handle error in calling function.
		 */
		virtual int NotifyUp (const struct in6_addr *addr);

		/*
		 * Indicates that the Teredo tunneling interface is no longer
		 * ready to process packets.
		 * Any packet sent when the relay/client is down will be
		 * ignored.
		 */
		virtual int NotifyDown (void);

	protected:
		/*
		 * Creates a Teredo relay manually (ie. one that does not
		 * qualify with a Teredo server and has no Teredo IPv6
		 * address). The prefix must therefore be specified.
		 *
		 * If port is nul, the OS will choose an available UDP port
		 * for communication. This is NOT a good idea if you are
		 * behind a fascist firewall, as the port might be blocked.
		 *
		 * TODO: allow the caller to specify an IPv4 address to bind
		 * to.
		 */
		TeredoRelay (uint32_t pref, uint16_t port = 0);

		/*
		 * Creates a Teredo client/relay automatically. The client
		 * will try to qualify and get a Teredo IPv6 address from each
		 * of the servers until one of them works.
		 *
		 * TODO: support for secure qualification
		 */
		TeredoRelay (const char **servers);

	public:
		virtual ~TeredoRelay ();

		/* TODO: return false if qualification is pending or if it
		 failed. */
		int operator! (void) const
		{
			return !sock;
		}

		/*
		 * Transmits a packet from IPv6 Internet via Teredo.
		 */
		int SendPacket (const void *packet, size_t len);

		/*
		 * Receives a packet from Teredo to IPv6 Internet.
		 */
		int ReceivePacket (void);

		/*
		 * Returns true if the relay/client is behind a cone NAT.
		 * The result is not meaningful if the client is not fully
		 * qualified.
		 */
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

