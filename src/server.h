/*
 * server.h - Linux Teredo server implementation
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

#ifndef MIREDO_SERVER_H
# define MIREDO_SERVER_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <libteredo/server.h>

class IPv6Tunnel;

class MiredoServer : public TeredoServer
{
	private:
		const IPv6Tunnel *tunnel;
		virtual int SendIPv6Packet (const void *packet,
						size_t length);

	public:
		MiredoServer (uint32_t ip1, uint32_t ip2)
			: TeredoServer (ip1, ip2), tunnel (NULL)
		{
		}
		
		//virtual ~MiredoServer (void);

		void SetTunnel (const IPv6Tunnel *tun)
		{
			tunnel = tun;
		}
};

#endif
