/*
 * teredo-udp.h - UDP sockets class declaration
 * $Id$
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
# include <sys/types.h>
# include <sys/select.h> // fd_set
# include "teredo.h"

struct ip6_hdr;

class MiredoCommonUDP
{
	private:
		uint32_t last_ip;
		uint16_t last_port;
		uint8_t pbuf[65507];
		struct ip6_hdr *ip6;
		size_t ip6len;
		struct teredo_orig_ind *orig;
		uint8_t *nonce;

	protected:
		int ReceivePacket (int fd);
		static int OpenTeredoSocket (uint32_t ip, uint16_t port);
		static int SendPacket (int fd, const void *packet, size_t len,
					uint32_t dest_ip, uint16_t port);

	public:
		MiredoCommonUDP () : last_ip (0), last_port (0),
			ip6 (NULL), ip6len (0), orig (NULL), nonce (NULL)
		{
		}

		virtual ~MiredoCommonUDP (void);
		//virtual int RegisterReadSet (fd_set *readset) const = 0;
		//virtual int ReceivePacket (const fd_set *readset) = 0;
		virtual int SendPacket (const void *packet, size_t len,
					uint32_t dest_ip,
					uint16_t port) const = 0;

		/*
		 * Returns a pointer to the last received Teredo packet
		 * (by ReceivePacket()).
		 */
		const uint8_t *GetBuffer (void) const
		{
			return pbuf;
		}

		/*
		 * Returns a pointer to the IPv6 header of the packet
		 * last received with ReceivePacket().
		 */
		const struct ip6_hdr *GetIPv6Header (size_t& len) const
		{
			len = ip6len;
			return ip6;
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


class MiredoRelayUDP : public MiredoCommonUDP
{
	private:
		int fd;

	public:
		MiredoRelayUDP (void) : fd (-1)
		{
		}

		virtual ~MiredoRelayUDP (void);

		int ListenIP (uint32_t ip = 0);

		int RegisterReadSet (fd_set *readset) const;
		int ReceivePacket (const fd_set *readset);
		virtual int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const;
};


class MiredoServerUDP : public MiredoCommonUDP
{
	private:
		int fd_primary, fd_secondary;
		bool was_secondary;

	public:
		MiredoServerUDP (void) : fd_primary (-1), fd_secondary (-1),
				was_secondary (false)
		{
		}

		virtual ~MiredoServerUDP (void); // closes sockets

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
		 *
		 * In case of success, one can use GetBuffer, GetIPv6Header,
		 * etc. functions. Otherwise, these functions will return
		 * bogus values.
		 */
		int ReceivePacket (const fd_set *readset);

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
				bool use_secondary_ip) const;
		virtual int SendPacket (const void *packet, size_t len,
					uint32_t dest_ip,
					uint16_t port) const;

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
};


inline int
MiredoServerUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port,
				bool use_secondary_ip) const
{
	return MiredoCommonUDP::SendPacket (use_secondary_ip ? fd_secondary
								: fd_primary,
				packet, len, dest_ip, dest_port);
}


inline int
MiredoServerUDP::ReplyPacket (const void *packet, size_t len,
				bool use_secondary_ip) const
{
	return SendPacket (packet, len, GetClientIP (), GetClientPort (),
				use_secondary_ip);
}

#endif /* ifndef MIREDO_TEREDO_UDP_H */

