/*
 * server.h - Declarations for server.cpp
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

#ifndef __cplusplus
# error C++ only header
#endif

#ifndef LIBTEREDO_SERVER_H
# define LIBTEREDO_SERVER_H

# include <inttypes.h>
# include <libteredo/teredo-udp.h>


/*
 * Checks and handles an Teredo-encapsulated packet.
 */
class TeredoServer
{
	private:
		uint32_t prefix;
		uint32_t server_ip;
		TeredoServerUDP sock;

	protected:
		TeredoServer (uint32_t ip1, uint32_t ip2);

		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet,
						size_t length) = 0;

	public:
		virtual ~TeredoServer (void)
		{
		}

		void SetPrefix (uint32_t pref)
		{
			prefix = pref;
		}

		int ProcessTunnelPacket (const fd_set *readset);

		uint32_t GetPrefix (void) const
		{
			return prefix;
		}

		uint32_t GetServerIP (void) const
		{
			return server_ip;
		}

		int operator! (void) const
		{
			return !sock;
		}

		int RegisterReadSet (fd_set *rs) const
		{
			return sock.RegisterReadSet (rs);
		}
};

#endif /* ifndef MIREDO_SERVER_H */

