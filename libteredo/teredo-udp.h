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
		/*
		 * Receives and parses a Teredo packet from file descriptor
		 * fd. This is not thread-safe (the object should be locked).
		 */
		int Receive (int fd);

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


class TeredoRelayUDP
{
	private:
		int fd;

	public:
		TeredoRelayUDP (void) : fd (-1)
		{
		}

		~TeredoRelayUDP (void);

		// Not thread-safe (you MUST lock the object when calling):
		int ListenPort (uint16_t port = 0, uint32_t ipv4 = 0);

		// Thread safe functions:
		int RegisterReadSet (fd_set *readset) const;
		int ReceivePacket (const fd_set *readset,
					TeredoPacket& packet) const;
		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const;

		int operator! (void) const
		{
			return fd == -1;
		}	
};


# ifdef MIREDO_TEREDO_SERVER
class TeredoServerUDP
{
	private:
		int fd_primary, fd_secondary;

	public:
		TeredoServerUDP (void) : fd_primary (-1), fd_secondary (-1)
		{
		}

		~TeredoServerUDP (void); // closes sockets

		/* 
		 * Opens 2 UDP sockets on Teredo port.
		 * Return 0 on success, -1 on error. Not thread-safe
		 * (you MUST lock the object when calling).
		 */
		int ListenIP (uint32_t ip1, uint32_t ip2);

		/*
		 * Registers sockets in an fd_set for use with
		 * select(). Returns the "biggest" file descriptor
		 * registered (useful as the first parameter to selcet()).
		 * Thread-safe.
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
		int ReceivePacket (const fd_set *readset,
					TeredoPacket& packet) const;
		int ReceivePacket2 (const fd_set *readset,
					TeredoPacket& packet) const;

		/*
		 * Sends an UDP packet at <packet>, of length <len>
		 * to destination <dest_ip> on port <port>.
		 *
		 * If use_secondary_ip is true, the secondary server
		 * adress/socket will be used to send the packet
		 * (used to send Router Advertisement during the qualification
		 * of a Teredo client). Thread-safe.
		 */
		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t port,
				bool use_secondary_ip = false) const;

		int operator! (void) const
		{
			return fd_primary == -1 || fd_secondary == -1;
		}
};
# endif /* ifdef MIREDO_TEREDO_SERVER */
#endif /* ifndef MIREDO_TEREDO_UDP_H */

