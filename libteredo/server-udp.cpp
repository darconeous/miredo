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
#include <unistd.h>

#include <syslog.h> // syslog()

#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include <libteredo/teredo.h>
#include <libteredo/server-udp.h>


/*** TeredoServerUDP implementation ***/
TeredoServerUDP::~TeredoServerUDP ()
{
	if (fd_primary != -1)
	{
		close (fd_primary);
		close (fd_secondary);
	}
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

	if (fd_primary != -1)
	{
		close (fd_primary);
		close (fd_secondary);
	}

	fd_primary = teredo_socket (ip1, htons (IPPORT_TEREDO));
	if (fd_primary == -1)
	{
		syslog (LOG_ERR, _("Primary socket: %m"));
		fd_secondary = -1;
		return -1;
	}

	fd_secondary = teredo_socket (ip2, htons (IPPORT_TEREDO));
	if (fd_secondary == -1)
	{
		syslog (LOG_ERR, _("Secondary socket: %m"));
		close (fd_primary);
		fd_primary = -1;
		return -1;
	}

	return 0;
}

