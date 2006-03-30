/*
 * teredo-udp.h - Low-level Teredo packets handling
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2005 Rémi Denis-Courmont.                         *
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

# define MAX_TEREDO_PACKET_SIZE 65507
# define MIN_TEREDO_PACKET_SIZE 1288
# define TEREDO_PACKET_SIZE MAX_TEREDO_PACKET_SIZE

typedef struct teredo_packet
{
	uint8_t *auth_nonce; /* NULL if auth not present */
	uint8_t  auth_conf_byte; /* 0 if nonce == NULL */

	uint8_t *ip6; /* always defined */
	uint16_t ip6_len; /* always defined though possibly < 40 */

	/* IPv4 and UDP port numbers are always in network byte order */
	/* Origin indication data is de-obfuscated */

	uint32_t source_ipv4; /* always defined */
	uint16_t source_port; /* always defined */

	uint16_t orig_port; /* 0 if orig indication not present */
	uint32_t orig_ipv4; /* 0 if orig indication not present */

	uint8_t  buf[TEREDO_PACKET_SIZE];
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
