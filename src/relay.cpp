/*
 * relay.cpp - Linux Teredo relay implementation
 * $Id: relay.cpp,v 1.15 2004/07/31 19:58:44 rdenisc Exp $
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

#include <libtun6/ipv6-tunnel.h>
#include "relay.h"


int MiredoRelay::ReceiveIPv6Packet (void)
{
	// FIXME: does not handle error. API design problem
	packet = (const struct ip6_hdr *)tunnel->GetPacket (length);
	return 0;
}


int MiredoRelay::SendIPv6Packet (const void *_packet, size_t _length)
{
	return tunnel->SendPacket (_packet, _length);
}
