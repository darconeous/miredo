/*
 * relay-packets.h - helpers to send Teredo packet from relay/client
 * $Id: relay-packets.h,v 1.3 2004/08/29 17:30:08 rdenisc Exp $
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

#ifndef __LIBTEREDO_TEREDO_PACKETS_H
# define __LIBTEREDO_TEREDO_PACKETS_H

# include <sys/types.h>
# include <netinet/in.h>

# include "teredo.h"
# include "teredo-udp.h"

/*
 * Sends a Teredo Bubble to the server (if indirect is true) or the client (if
 * indirect is false) specified in Teredo address <dst>.
 * Returns 0 on success, -1 on error.
 * FIXME: do not use link-local addresses in bubbles.
 */
int
SendBubble (const TeredoRelayUDP& sock, const struct in6_addr *d,
		bool cone, bool indirect = true);

/*
 * Sends a Teredo Bubble to the specified IPv4/port tuple.
 * Returns 0 on success, -1 on error.
 */
int
SendBubble (const TeredoRelayUDP& sock, uint32_t ip, uint16_t port,
		const struct in6_addr *src, const struct in6_addr *dst);

/*
 * Sends a router solication with an Authentication header to the server.
 * If secondary is true, the packet will be sent to the server's secondary
 * IPv4 adress instead of the primary one.
 *
 * Returns 0 on success, -1 on error.
 */
int
SendRS (const TeredoRelayUDP& sock, uint32_t server_ip, unsigned char *nonce,
	bool cone, bool secondary);


/*
 * Validates a router advertisement from the Teredo server.
 * The RA must be of type cone if and only if cone is true.
 * Prefix, flags, mapped port and IP are returned through newaddr.
 *
 * Assumptions:
 * - newaddr must be 4-bytes aligned.
 * - newaddr->teredo.server_ip must be set to the server's expected IP by the
 *   caller.
 * - IPv6 header is valid (ie. version 6, plen matches packet's length).
 */
bool
ParseRA (const TeredoPacket& packet, union teredo_addr *newaddr, bool cone);

int
SendPing (const TeredoRelayUDP& sock, const union teredo_addr *src,
		const struct in6_addr *dst, uint8_t *nonce);

#endif
