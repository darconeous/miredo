/*
 * teredo-udp.cpp - UDP sockets class definition
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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
#include <string.h> // memcpy()

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <libteredo/teredo.h>

/*** TeredoPacket implementation ***/

/*
 * Parses a Teredo packet header.
 * Supports either blocking and non-blocking file descriptors.
 */
int
TeredoPacket::Receive (int fd)
{
	int length;

	// Receive a UDP packet
	{
		struct sockaddr_in ad;
		socklen_t alen = sizeof (ad);

		length = recvfrom (fd, buf, sizeof (buf), 0,
					(struct sockaddr *)&ad, &alen);

		if (length < 0)
			return -1;

		last_ip = ad.sin_addr.s_addr;
		last_port = ad.sin_port;
	}

	// Check type of Teredo header:
	uint8_t *ptr = buf;
	orig = NULL;
	nonce = NULL;

	// Parse Teredo headers
	if (length < 40)
		return -1; // too small

	// Teredo Authentication header
	if ((ptr[0] == 0) && (ptr[1] == teredo_auth_hdr))
	{
		ptr += 2;
		length -= 13;
		if (length < 0)
			return -1; // too small

		/* ID and Auth */
		uint8_t id_len = *ptr++;
		uint8_t au_len = *ptr++;

		length -= id_len + au_len;
		if (length < 0)
			return -1;

		/* TODO: secure qualification */
		ptr += id_len + au_len;

		/* Nonce + confirmation byte */
		nonce = ptr;
		ptr += 9;
	}

	// Teredo Origin Indication
	if ((ptr[0] == 0) && (ptr[1] == teredo_orig_ind))
	{
		length -= sizeof (orig_buf);
		if (length < 0)
			return -1; // too small

		memcpy (&orig_buf, ptr, sizeof (orig_buf));
		orig = &orig_buf;
		ptr += sizeof (orig_buf);
	}

	// length <= 65507 = sizeof(buf)
	ip6len = length;
	ip6 = ptr;

	return 0;
}


int
TeredoPacket::ReceiveBlocking (int fd)
{
	fd_set readset;
	int val;

	FD_ZERO (&readset);
	FD_SET (fd, &readset);
	val = select (fd + 1, &readset, NULL, NULL, NULL);
	return (val == 1) ? Receive (fd) : -1;
}
