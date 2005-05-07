/*
 * relay-udp.h - UDP sockets class declaration for Teredo relay
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#ifndef LIBTEREDO_RELAY_UDP_H
# define LIBTEREDO_RELAY_UDP_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <sys/types.h>
# include <sys/select.h> // fd_set

# include <libteredo/teredo-udp.h>

class TeredoRelayUDP
{
	private:
		int fd;

	public:
		TeredoRelayUDP (void) : fd (-1)
		{
		}

		virtual ~TeredoRelayUDP (void);

		// Not thread-safe (you MUST lock the object when calling):
		int ListenPort (uint16_t port = 0, uint32_t ipv4 = 0);

		// Thread safe functions:
		int RegisterReadSet (fd_set *readset) const;
		int ReceivePacket (TeredoPacket& packet) const
		{
			return packet.Receive (fd);
		}

		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const;

		bool operator! (void) const
		{
			return fd == -1;
		}	
};

#if 0
# ifdef MIREDO_TEREDO_CLIENT
class TeredoClientUDP : TeredoRelayUDP
{
	private:
		int mfd;

	public:
		TeredoClientUDP (void);
		virtual ~TeredoClientUDP (void);

		// Thread safe functions:
		int RegisterReadSet (fd_set *readset) const;
		int ReceiveMulticastPacket (const fd_set *readset,
						TeredoPacket& packet) const
		{
			return packet.Receive (readset, mfd);
		}

		int SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const;

		int operator! (void) const
		{
			return mfd == -1 || TeredoRelayUDP::operator! ();
		}	
};
# endif /* ifdef MIREDO_TEREDO_CLIENT */
#endif
#endif /* ifndef LIBTEREDO_RELAY_UDP_H */
