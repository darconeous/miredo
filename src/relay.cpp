/*
 * relay.cpp - Linux Teredo relay implementation
 * $Id: relay.cpp,v 1.19 2004/08/24 16:00:26 rdenisc Exp $
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <unistd.h> // write()

#include <libtun6/ipv6-tunnel.h>
#include "relay.h"

MiredoRelay::MiredoRelay (const IPv6Tunnel *tun, uint32_t prefix,
				uint16_t port, bool cone)
	: TeredoRelay (prefix, port, cone), tunnel (tun), priv_fd (-1)
{
}


MiredoRelay::MiredoRelay (const IPv6Tunnel *tun, const char *const *servers,
				uint16_t port)
	: TeredoRelay (servers, port), tunnel (tun)
{
}


int MiredoRelay::SendIPv6Packet (const void *packet, size_t length)
{
	return tunnel->SendPacket (packet, length);
}


int MiredoRelay::NotifyUp (const struct in6_addr *addr)
{
	return priv_fd != -1
		? write (priv_fd, addr, sizeof (struct in6_addr))
			== sizeof (struct in6_addr)
		: 0;
}


int MiredoRelay::NotifyDown (void)
{
	return NotifyUp (&in6addr_any);
}
