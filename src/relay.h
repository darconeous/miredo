/*
 * relay.h - Linux Teredo relay implementation
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

#ifndef MIREDO_RELAY_H
# define MIREDO_RELAY_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <libteredo/relay.h>

class IPv6Tunnel;

class MiredoRelay : public TeredoRelay
{
	private:
		const IPv6Tunnel *tunnel;
		int priv_fd;

		virtual int SendIPv6Packet (const void *packet,
						size_t length);
#ifdef MIREDO_TEREDO_CLIENT
		virtual int NotifyUp (const struct in6_addr *addr);
		virtual int NotifyDown (void);
#endif

	public:
		MiredoRelay (const IPv6Tunnel *tun, uint32_t prefix,
				uint16_t port = 0, uint32_t ipv4 = 0,
				bool cone = true);
#ifdef MIREDO_TEREDO_CLIENT
		MiredoRelay (int fd, const IPv6Tunnel *tun,
				uint32_t server_ip, uint16_t port = 0,
				uint32_t ipv4 = 0);
#endif
		//virtual void ~MiredoRelay (void);
};

#endif
