/*
 * common_pkt.cpp - Common server and relay functions
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include "teredo-udp.h"
#include "libtun6/ipv6-tunnel.h"
#include "common_pkt.h"

#include <syslog.h> // DEBUG
#include <inttypes.h>

int
ForwardPacket (const MiredoCommonUDP *from, const IPv6Tunnel *to)
{
	size_t length;
	const void *p = from->GetIPv6Header (length);
	if (p == NULL)
		return -1;

	syslog (LOG_DEBUG, "Sending raw IPv6 packet\n");
	return to->SendPacket (p, length);
}

/*
 * Checks that ip is a global unicast IPv4 address
 * (Values shoud maybe not be hardcoded that way).
 */
bool
is_ipv4_global_unicast (u_long ip)
{
	ip = ntohl (ip);
	return
		// Check for class A private range 10.0.0.0/24
		((ip & 0xff000000) != 0x0a000000) &&
		// Check for class A loopback range 127.0.0.0/8
		((ip & 0xff000000) != 0x7f000000) &&
		// Check for "Microsoft" private range 169.254.0.0/16
		((ip & 0xffff0000) != 0xa9fe0000) &&
		// Check for class B private range 172.16.0.0/12
		 ((ip & 0xfff00000) != 0xac100000) &&
		// Check for class C private range 192.168.0.0/16
		((ip & 0xffff0000) != 0xc0a80000) &&
		// Class D (Multicast), E, bad classes:
		((ip & 0xe0000000) != 0xe0000000);
}

