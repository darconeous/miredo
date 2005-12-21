/*
 * teredo-udp.h - Low-level Teredo packets handling
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

#ifndef LIBTEREDO_TEREDO_UDP_H
# define LIBTEREDO_TEREDO_UDP_H

# include <unistd.h> /* close() -> teredo_close() */

typedef struct teredo_packet
{
	struct teredo_orig_ind *orig;
	uint8_t *nonce, *ip6;

	uint32_t source_ipv4;
	uint16_t source_port;
	uint16_t ip6_len;

	struct teredo_orig_ind orig_buf;
	uint8_t buf[65507];
} teredo_packet;


# ifdef __cplusplus
extern "C" {
# endif

int teredo_socket (uint32_t bind_ip, uint16_t port);
int teredo_send (int fd, const void *data, size_t len,
                 uint32_t ip, uint16_t port);
int teredo_sendv (int fd, const struct iovec *iov, size_t count,
                  uint32_t ip, uint16_t port);
int teredo_recv (int fd, struct teredo_packet *p);
int teredo_wait_recv (int fd, struct teredo_packet *p);

# ifdef __cplusplus
}
# endif

# define teredo_close( fd ) close( fd )

#endif /* ifndef LIBTEREDO_TEREDO_UDP_H */
