/**
 * @file teredo-udp.h
 * @brief Low-level Teredo packets handling
 *
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

/** Maximum possible size of a Teredo packet */
# define MAX_TEREDO_PACKET_SIZE 65507
/** Maximum size of a Teredo packet with standard tunnel MTU */
# define MIN_TEREDO_PACKET_SIZE 1288

/** Buffer size for Teredo packet reception */
# define TEREDO_PACKET_SIZE MAX_TEREDO_PACKET_SIZE


/**
 * Structure to receive Teredo-encapsulated IPv6 packets
 */
typedef struct teredo_packet
{
	/** NULL if auth not present */
	uint8_t *auth_nonce;
	/** authentication header confirmation byte, 0 if nonce == NULL */
	uint8_t  auth_conf_byte;

	/** (unaligned) IPv6 packet (header + payload) */
	struct ip6_hdr *ip6;
	/** IPv6 packet byte size, possibly < 40 for invalid packets */
	uint16_t ip6_len;

	/** @note IPv4 and UDP port numbers are always in network byte order */
	/** @note Origin indication data is de-obfuscated */

	/** Source IPv4 address */
	uint32_t source_ipv4;
	/** Source UDP port */
	uint16_t source_port;

	/** Origin indication UDP port, or 0 if absent */
	uint16_t orig_port;
	/** Origin indication IPv4 address, or 0 if absent */
	uint32_t orig_ipv4;

	/** Internal buffer for UDP datagram reception */
	uint8_t  buf[TEREDO_PACKET_SIZE+7];
} teredo_packet;

struct iovec;

# ifdef __cplusplus
extern "C" {
# endif

/**
 * Opens a Teredo UDP/IPv4 socket.
 * Thread-safe, not cancellation-safe.
 *
 * @return -1 on error.
 */
int teredo_socket (uint32_t bind_ip, uint16_t port);

/**
 * Sends an UDP/IPv4 datagram.
 * Thread-safe, cancellation safe, cancellation point.
 *
 * @return number of bytes sent, or -1 on error.
 */
int teredo_send (int fd, const void *data, size_t len,
                 uint32_t ip, uint16_t port);

/**
 * Sends an UDP/IPv4 datagram.
 * Thread-safe, cancellation-safe, cancellation point.
 *
 * @param fd socket from which to send.
 * @param iov scatter-gather array containing the datagram payload.
 * @param count number of entry in the scatter-gather array.
 * @param ip destination IPv4 (network byte order).
 * @param port destination UDP port (network byte order).
 *
 * @return number of bytes sent or -1 on error.
 */
int teredo_sendv (int fd, const struct iovec *iov, size_t count,
                  uint32_t ip, uint16_t port);

/**
 * Receives and parses a Teredo packet from a socket. Never blocks.
 * Thread-safe, cancellation-safe, cancellation point.
 *
 * @param fd socket file descriptor
 * @param p teredo_packet receive buffer
 *
 * @return 0 on success, -1 in error.
 * Errors might be caused by :
 *  - lower level network I/O,
 *  - malformatted packets,
 *  - no data pending.
 */
int teredo_recv (int fd, struct teredo_packet *p);

/**
 * Waits for, receives and parses a Teredo packet from a socket.
 * Thread-safe, cancellation-safe, cancellation point.
 *
 * @param fd socket file descriptor
 * @param p teredo_packet receive buffer
 *
 * @return 0 on success, -1 in error.
 * Errors might be caused by :
 *  - lower level network I/O,
 *  - malformatted packets,
 *  - a race condition if two thread are waiting on the same
 *    non-blocking socket for receiving.
 */
int teredo_wait_recv (int fd, struct teredo_packet *p);

/**
 * Computes an IPv6 layer-3 checksum.
 * The input buffers do not need to be aligned neither of even length.
 * Jumbo datagrams are supported.
 */
uint16_t teredo_cksum (const void *src, const void *dst, uint8_t protocol,
                       const struct iovec *data, size_t n);

# ifdef __cplusplus
}
# endif

/**
 * Closes a Teredo socket opened with teredo_socket().
 * @param fd socket to be closed
 */
# define teredo_close( fd ) close( fd )

#endif /* ifndef LIBTEREDO_TEREDO_UDP_H */
