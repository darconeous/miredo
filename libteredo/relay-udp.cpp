/*
 * relay-udp.cpp - UDP sockets class definition for Teredo relay
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

#include <gettext.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/select.h>

#include <syslog.h> // syslog()

#include <libteredo/relay-udp.h>

/*** TeredoRelayUDP implementation ***/
TeredoRelayUDP::~TeredoRelayUDP (void)
{
	TeredoPacket::CloseSocket (fd);
}


int TeredoRelayUDP::ListenPort (uint16_t port, uint32_t ipv4)
{
	// Closes former socket:
	TeredoPacket::CloseSocket (fd);

	fd = TeredoPacket::OpenSocket (ipv4, port);
	return fd != -1 ? 0 : -1;
}


int
TeredoRelayUDP::RegisterReadSet (fd_set *readset) const
{
	if (fd != -1)
		FD_SET (fd, readset);
	return fd;
}


int
TeredoRelayUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const
{
	return TeredoPacket::Send (fd, packet, len, dest_ip, dest_port);
}


/*** TeredoClientUDP implementation ***/
#ifdef MIREDO_TEREDO_CLIENT
TeredoClientUDP::TeredoClientUDP (void)
{
	mfd = TeredoPacket::OpenSocket (htonl (TEREDO_DISCOVERY_IP),
					htons (IPPORT_TEREDO));
}


TeredoClientUDP::~TeredoClientUDP (void)
{
	TeredoPacket::CloseSocket (mfd);
}


int
TeredoClientUDP::RegisterReadSet (fd_set *readset) const
{
	if (mfd != -1)
		FD_SET (mfd, readset);

	int maxfd = TeredoRelayUDP::RegisterReadSet (readset);
	return (maxfd > mfd) ? maxfd : mfd;
}
#endif
