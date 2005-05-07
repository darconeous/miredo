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

# include <sys/types.h>
# include <sys/select.h> // fd_set
# include <netinet/in.h> // for <netinet/ip6.h> on FreeBSD
# include <netinet/ip6.h> // struct ip6_hdr

# include <libteredo/teredo.h>

class TeredoPacket
{
	private:
		struct teredo_orig_ind *orig;
		uint8_t *nonce, *ip6;
		uint32_t last_ip;
		int ip6len;
		uint16_t last_port;

		uint8_t buf[65507];
		struct teredo_orig_ind orig_buf;

	public:
		static int OpenSocket (uint32_t bind_ip, uint16_t port);
		static int Send (int fd, const void *data, size_t len,
					uint32_t ip, uint16_t port);
		static void CloseSocket (int fd);

		/*
		 * Receives and parses a Teredo packet from file descriptor
		 * fd. This is not thread-safe (the object should be locked).
		 */
		int Receive (int fd);
		int Receive (const fd_set *readset, int fd);

		/*
		 * Returns a pointer to the IPv6 packet last received with
		 * ReceivePacket() (the packet is NOT aligned, you may have
		 * to copy the first 40 bytes to a struct ip6_hdr).
		 */
		const uint8_t *GetIPv6Packet (size_t& len) const
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
		 * Return the value of the confirmation byte
		 */
		uint8_t GetConfByte (void) const
		{
			return nonce[8];
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
#endif /* ifndef MIREDO_TEREDO_UDP_H */
