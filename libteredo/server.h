/*
 * server.h - Declarations for server.cpp
 * $Id: server.h,v 1.1 2004/07/22 17:38:29 rdenisc Exp $
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

#ifndef __cplusplus
# error C++ only header
#endif

#ifndef MIREDO_SERVER_H
# define MIREDO_SERVER_H

# include <inttypes.h>

class MiredoServerUDP;
class IPv6Tunnel;

/*
 * Checks and handles an Teredo-encapsulated packet.
 */
class MiredoServer
{
	private:
		uint32_t prefix;
		uint32_t server_ip;
		const MiredoServerUDP *sock;
		const IPv6Tunnel *tunnel;

	public:
		MiredoServer (void)
		{
		}

		~MiredoServer (void)
		{
		}

		void SetPrefix (uint32_t pref)
		{
			prefix = pref;
		}

		void SetServerIP (uint32_t ip)
		{
			server_ip = ip;
		}

		void SetTunnel (const IPv6Tunnel *tun)
		{
			tunnel = tun;
		}

		void SetSocket (const MiredoServerUDP *udp)
		{
			sock = udp;
		}

		int ReceivePacket (void) const;

		uint32_t GetPrefix (void) const
		{
			return prefix;
		}

		uint32_t GetServerIP (void) const
		{
			return server_ip;
		}
};

#endif /* ifndef MIREDO_SERVER_H */

