/*
 * teredo.c - Common Teredo helper functions
 * $Id: teredo.c,v 1.3 2004/08/26 13:32:51 rdenisc Exp $
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2002-2004 Remi Denis-Courmont.                       *
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

#include "teredo.h"
#include <inttypes.h>
#include <netinet/ip6.h>

/*
 * Teredo addresses
 */
const struct in6_addr teredo_restrict =
	{ { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		    0, 0, 'T', 'E', 'R', 'E', 'D', 'O' } } };
const struct in6_addr teredo_cone =
	{ { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		    0x80, 0, 'T', 'E', 'R', 'E', 'D', 'O' } } };


int
in6_matches_teredo_client (const union teredo_addr *ip6, uint32_t ip,
				uint16_t port)
{
	return (ip == (uint32_t)~ip6->teredo.client_ip)
		&& (port == (uint16_t)~ip6->teredo.client_port);
}

int
in6_matches_teredo_server (const union teredo_addr *ip6, uint32_t ip)
{
	return ip6->teredo.server_ip == ip;
}

int
in6_is_teredo_addr_cone (const union teredo_addr *ip6)
{
	return ip6->teredo.flags & htons (TEREDO_FLAGS_CONE);
}


/*
 * Returns true if prefix can be used as a Teredo prefix.
 * As per RFC3513, anything could be used for Teredo (unicast)
 * except the multicast range (ff00::/8).
 */
int
is_valid_teredo_prefix (uint32_t prefix)
{
	return (prefix & 0xff000000) != 0xff000000;
}

