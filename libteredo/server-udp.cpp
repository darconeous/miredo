/*
 * server-udp.cpp - UDP sockets class definition for Teredo server
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

#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include <libteredo/teredo-udp.h>
#include <libteredo/server-udp.h>


/*** TeredoServerUDP implementation ***/
TeredoServerUDP::~TeredoServerUDP ()
{
	TeredoPacket::CloseSocket (fd_primary);
	TeredoPacket::CloseSocket (fd_secondary);
}


int TeredoServerUDP::ListenIP (uint32_t ip1, uint32_t ip2)
{
	if (!is_ipv4_global_unicast (ip1)
	 || !is_ipv4_global_unicast (ip2))
	{
		syslog (LOG_ERR, _("Teredo server UDP socket error: "
			"Server IPv4 addresses must be global unicast."));
		return -1;
	}

	if (ip1 == INADDR_ANY || ip2 == INADDR_ANY)
	{
		syslog (LOG_ERR, _("Teredo server UDP socket error: "
			"Server IPv4 addresses must not be wildcard."));
		return -1;
	}

	TeredoPacket::CloseSocket (fd_primary);
	TeredoPacket::CloseSocket (fd_secondary);

	fd_primary = TeredoPacket::OpenSocket (ip1, htons (IPPORT_TEREDO));
	if (fd_primary == -1)
		return -1;

	fd_secondary = TeredoPacket::OpenSocket (ip2, htons (IPPORT_TEREDO));
	if (fd_secondary == -1)
	{
		TeredoPacket::CloseSocket (fd_primary);
		return -1;
	}

	return 0;
}


int TeredoServerUDP::RegisterReadSet (fd_set *readset) const
{
	int maxfd = -1;
	if (fd_primary != -1)
	{
		FD_SET (fd_primary, readset);
		if (fd_primary > maxfd)
			maxfd = fd_primary;
	}
	
	if (fd_secondary != -1)
	{
		FD_SET (fd_secondary, readset);
		if (fd_secondary > maxfd)
			maxfd = fd_secondary;
	}
	return maxfd;
}


int
TeredoServerUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port,
				bool use_secondary_ip) const
{
	return TeredoPacket::Send (use_secondary_ip
					? fd_secondary : fd_primary,
					packet, len, dest_ip, dest_port);
}
