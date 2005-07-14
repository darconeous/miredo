/*
 * server-udp.h - UDP sockets class declaration for Teredo server
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

#ifndef LIBTEREDO_SERVER_UDP_H
# define LIBTEREDO_SERVER_UDP_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <sys/types.h>
# include <sys/select.h> // fd_set

# include <libteredo/teredo.h>

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
		 * Waits for and receives a packet from an UDP socket.
		 * Then, parses Teredo headers.
		 *
		 * Returns 0 on success, -1 if no packet were to be received
		 * or they were not valid Terdo-encapsulated-packets.
		 */
		int ReceivePacket (TeredoPacket& packet) const
		{
			return packet.ReceiveBlocking (fd_primary);
		}

		int ReceivePacket2 (TeredoPacket& packet) const
		{
			return packet.ReceiveBlocking (fd_secondary);
		}

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

inline int
TeredoServerUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port,
				bool use_secondary_ip) const
{
	return teredo_send (use_secondary_ip ? fd_secondary : fd_primary,
	                    packet, len, dest_ip, dest_port);
}


#endif /* LIBTEREDO_SERVER_UDP_H */
