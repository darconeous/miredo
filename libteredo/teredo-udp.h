/*
 * teredo-udp.h - UDP sockets class declaration
 * $Id: teredo-udp.h,v 1.5 2004/08/26 15:04:51 rdenisc Exp $
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

#ifndef MIREDO_TEREDO_UDP_H
# define MIREDO_TEREDO_UDP_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <stddef.h>
# include <inttypes.h>

# include <sys/types.h>
# include <sys/select.h> // fd_set
# include <netinet/in.h> // for <netinet/ip6.h> on FreeBSD
# include <netinet/ip6.h> // struct ip6_hdr

# include <libteredo/teredo.h>

class TeredoCommonUDP
{
	private:
		struct teredo_orig_ind *orig;
		uint8_t *nonce;
		uint32_t last_ip;
		int ip6len;
		uint16_t last_port;

		union
		{
			struct ip6_hdr ip6;
			uint8_t fill[65507];
		} ipv6_buf;
		uint8_t nonce_buf[8];
		struct teredo_orig_ind orig_buf;

	protected:
		/*
		 * Receive a packet. Blocking function.
		 * FIXME: re-entrancy
		 */
		int ReceivePacket (int fd);

	public:
		TeredoCommonUDP ()
		{
		}

		virtual ~TeredoCommonUDP (void);

		/*
		 * Returns a pointer to the IPv6 header of the packet
		 * last received with ReceivePacket().
		 * FIXME: this is utterly contradictory with re-entrant design
		 */
		const struct ip6_hdr *GetIPv6Header (size_t& len) const
		{
			len = ip6len;
			return &ipv6_buf.ip6;
		}

		/*
		 * Returns a pointer to a 8-bytes buffer which countains
		 * the nonce authentication value from the last received
		 * packet. Returns NULL if there was no Teredo
		 * authentication header in that packet.
		 */
		const uint8_t *GetAuthNonce (void) const
		{
			return nonce;
		}

		/*
		 * Returns a pointer to the Origin Indication header of
		 * the last received Teredo packet, or NULL if there was
		 * none.
		 * This structure is properly aligned.
		 */
		const struct teredo_orig_ind *GetOrigInd (void) const
		{
			return orig;
		}

		/*
		 * Returns the IP which sent us the last received packet.
		 * Useful to create an Origin Indication header.
		 */
		uint32_t GetClientIP (void) const
		{
			return last_ip;
		}

		/*
		 * Returns the source port of the last received packet.
		 * Useful to create an Origin Indication header.
		 */
		uint16_t GetClientPort (void) const
		{
			return last_port;
		}
};


class TeredoRelayUDP : public TeredoCommonUDP
{
	private:
		int fd;

	public:
		TeredoRelayUDP (void) : fd (-1)
		{
		}

		virtual ~TeredoRelayUDP (void);

		int ListenPort (uint16_t port = 0);

		int RegisterReadSet (fd_set *readset) const;
		int ReceivePacket (void);
		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const;

		int operator! (void) const
		{
			return fd == -1;
		}	
};


class TeredoServerUDP : public TeredoCommonUDP
{
	private:
		int fd_primary, fd_secondary;
		bool was_secondary;

	public:
		TeredoServerUDP (void) : fd_primary (-1), fd_secondary (-1),
				was_secondary (false)
		{
		}

		virtual ~TeredoServerUDP (void); // closes sockets

		/* 
		 * Opens 2 UDP sockets on Teredo port.
		 * Return 0 on success, -1 on error.
		 */
		int ListenIP (uint32_t ip1, uint32_t ip2);

		/*
		 * Registers sockets in an fd_set for use with
		 * select(). Returns the "biggest" file descriptor
		 * registered (useful as the first parameter to selcet()).
		 */
		int RegisterReadSet (fd_set *readset) const;

		/*
		 * Checks an fd_set, receives a packet from an UDP
		 * socket if it is in the fd_set.
		 * Then, parses Teredo headers.
		 *
		 * Returns 0 on success, -1 if no packet were to be received
		 * or they were not valid Terdo-encapsulated-packets.
		 */
		int ReceivePacket (void);

		/*
		 * Sends an UDP packet at <packet>, of length <len>
		 * to destination <dest_ip> on port <port>.
		 *
		 * If use_secondary_ip is true, the secondary server
		 * adress/socket will be used to send the packet
		 * (used to send Router Advertisement during the qualification
		 * of a Teredo client).
		 */
		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t port,
				bool use_secondary_ip = false) const;

		/*
		 * Sends an UDP packet at <packet>, of length <len>
		 * to the source of the last received packet with
		 * ReceivePacket().
		 */
		int ReplyPacket (const void *packet, size_t len,
				bool use_secondary_ip = false) const;


		/*
		 * Returns true if the packet was received on the
		 * secondary server IP address.
		 */
		bool WasSecondaryIP (void) const
		{
			return was_secondary;
		}

		int operator! (void) const
		{
			return fd_primary == -1 || fd_secondary == -1;
		}
};

#endif /* ifndef MIREDO_TEREDO_UDP_H */

