/*
 * server.h - Declarations for server.cpp
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

#ifndef __cplusplus
# error C++ only header
#endif

#ifndef LIBTEREDO_SERVER_H
# define LIBTEREDO_SERVER_H

# include <libteredo/server-udp.h>


/*
 * Checks and handles an Teredo-encapsulated packet.
 */
class /*sealed*/ TeredoServer
{
	private:
		pthread_t t1, t2;

		/* These are all in network byte order (including MTU!!) */
		uint32_t server_ip, prefix, advLinkMTU;

		TeredoServerUDP sock;
		int fd; // raw IPv6 socket

		bool SendRA (const struct teredo_packet *p,
		             const struct in6_addr *dest_ip6,
		             bool use_secondary_ip) const;
		bool ProcessPacket (bool secondary);
		static void *Thread (void *o);

	public:
		TeredoServer (uint32_t ip1, uint32_t ip2);
		~TeredoServer (void);

		bool Start (void);
		/*
		 * Stop() shall only be called after a successful call to Start().
		 * Start() can then be re-called to restart, and so on.
		 */
		void Stop (void);

		/* Prefix can be changed asynchronously */
		void SetPrefix (uint32_t pref)
		{
			prefix = pref;
		}

		void SetPrefix (const union teredo_addr *pref)
		{
			SetPrefix (pref->teredo.prefix);
		}

		/* AdvLinkMTU can be changed asynchronously */
		void SetAdvLinkMTU (uint16_t mtu = 1280)
		{
			advLinkMTU = htonl (mtu);
		}

		uint32_t GetServerIP (void) const
		{
			return server_ip;
		}

		int operator! (void) const
		{
			return (fd == -1) || !sock;
		}

		operator int (void) const
		{
			return (fd != -1) && !!sock;
		}

		static bool CheckSystem (char *errmsg, size_t len);
};


#endif /* ifndef MIREDO_SERVER_H */

