/*
 * teredo.h - Common Teredo protocol typedefs
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

#ifndef MIREDO_INCLUDE_TEREDO_H
# define MIREDO_INCLUDE_TEREDO_H

/* UDP Teredo port number */
#define IPPORT_TEREDO 3544

#define TEREDO_DISCOVERY_STR	"224.0.0.252"
#define TEREDO_DISCOVERY_IP	0xe00000fc

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

/*
 * Teredo addresses
 */
extern const struct in6_addr teredo_restrict;
extern const struct in6_addr teredo_cone;

#define DEFAULT_TEREDO_PREFIX 0x3ffe831f
#define DEFAULT_TEREDO_PREFIX_STR "3ffe:831f:"

union teredo_addr
{
	struct in6_addr ip6;
	struct
	{
		uint32_t prefix;
		uint32_t server_ip;
		uint16_t flags;
		uint16_t client_port;
		uint32_t client_ip;
	} teredo;
	uint32_t t6_addr32[4];
};

#define TEREDO_FLAG_CONE	0x8000

#define ip6_teredo( ip6 ) (((union teredo_addr *)ip6)->teredo)

/* NOTE: these macros expect 4-byte aligned addresses structs */
#define IN6_MATCHES_TEREDO_CLIENT( ip6, ip4, port ) \
	in6_matches_teredo_client ((const union teredo_addr *)ip6, ip4, port)

#define IN6_IS_TEREDO_ADDR_CONE( ip6 ) \
	(((const union teredo_addr *)(ip6))->teredo.flags \
	& htons (TEREDO_FLAG_CONE))

#define IN6_TEREDO_PREFIX( ip6 ) \
	(((const union teredo_addr *)ip6)->teredo.prefix)
#define IN6_TEREDO_SERVER( ip6 ) \
	(((const union teredo_addr *)ip6)->teredo.server_ip)
#define IN6_TEREDO_IPV4( ip6 ) \
	(~((const union teredo_addr *)ip6)->teredo.client_ip)
#define IN6_TEREDO_PORT( ip6 ) \
	(~((const union teredo_addr *)ip6)->teredo.client_port)

static inline int
in6_matches_teredo_client (const union teredo_addr *ip6, uint32_t ip,
				uint16_t port)
{
	return (((ip ^ ip6->teredo.client_ip) == 0xffffffff)
		&& ((port ^ ip6->teredo.client_port) == 0xffff));
}

/*
 * Returns true if prefix can be used as a Teredo prefix.
 * As per RFC3513, anything could be used for Teredo (unicast)
 * except the multicast range (ff00::/8).
 */
#define is_valid_teredo_prefix( prefix ) \
	((prefix & 0xff000000) != 0xff000000)

/*
 * It's pretty much the same as memcmp(), but it is optimized to
 * compare Teredo addresses (the first bytes tend to be always the same,
 * while the last ones are most often different).
 */
static inline int t6cmp (const union teredo_addr *a1,
                         const union teredo_addr *a2)
{
	return (a1->t6_addr32[3] - a2->t6_addr32[3])
	    || (a1->t6_addr32[2] - a2->t6_addr32[2])
	    || (a1->t6_addr32[1] - a2->t6_addr32[1])
	    || (a1->t6_addr32[0] - a2->t6_addr32[0]);
}

/*
 * Teredo headers
 */
enum
{
	teredo_orig_ind=0,
	teredo_auth_hdr
};

struct teredo_hdr_common
{
	uint8_t zero;
	uint8_t code;
};

struct teredo_orig_ind /* code == 1 */
{
	struct teredo_hdr_common hdr;
	uint16_t orig_port; /* obfuscated port number in network byte order */
	uint32_t orig_addr; /* obfuscated IPv4 address in network byte order */
};

struct teredo_auth_hdr
{
	struct teredo_hdr_common hdr;
	uint8_t id_len;
	uint8_t au_len;
	/* client id and auth value follows */
};

/* 
 * Minimal Teredo auth header
 * BIG FAT WARNING:
 * This structure will probably break alignement in your Teredo packets.
 */
struct teredo_simple_auth
{
	struct teredo_auth_hdr hdr;
	uint8_t nonce[8];
	uint8_t confirmation;
};


struct teredo_packet
{
	struct teredo_orig_ind *orig;
	uint8_t *nonce, *ip6;

	uint32_t source_ipv4;
	uint16_t source_port;
	uint16_t ip6_len;

	struct teredo_orig_ind orig_buf;
	uint8_t buf[65507];
};


# ifdef __cplusplus
extern "C" {
# endif

int teredo_socket (uint32_t bind_ip, uint16_t port);
int teredo_send (int fd, const void *data, size_t len,
                 uint32_t ip, uint16_t port);
int teredo_recv (int fd, struct teredo_packet *p);
int teredo_wait_recv (int fd, struct teredo_packet *p);

# ifdef __cplusplus
}
# endif

# define teredo_close( fd ) close( fd )

# ifdef __cplusplus
class TeredoPacket
{
	private:
		struct teredo_packet p;

	public:
		/*
		 * Receives and parses a Teredo packet from file descriptor
		 * fd. This is not thread-safe (the object should be locked).
		 */
		int Receive (int fd)
		{
			return teredo_recv (fd, &p);
		}

		int ReceiveBlocking (int fd)
		{
			return teredo_wait_recv (fd, &p);
		}

		/*
		 * Returns a pointer to the IPv6 packet last received with
		 * ReceivePacket() (the packet is NOT aligned, you may have
		 * to copy the first 40 bytes to a struct ip6_hdr).
		 */
		const uint8_t *GetIPv6Packet (size_t& len) const
		{
			len = p.ip6_len;
			return p.ip6;
		}

		/*
		 * Returns a pointer to a 8-bytes buffer which countains
		 * the nonce authentication value from the last received
		 * packet. Returns NULL if there was no Teredo
		 * authentication header in that packet.
		 */
		const uint8_t *GetAuthNonce (void) const
		{
			return p.nonce;
		}

		/*
		 * Return the value of the confirmation byte
		 */
		uint8_t GetConfByte (void) const
		{
			return p.nonce[8];
		}

		/*
		 * Returns a pointer to the Origin Indication header of
		 * the last received Teredo packet, or NULL if there was
		 * none.
		 * This structure is properly aligned.
		 */
		const struct teredo_orig_ind *GetOrigInd (void) const
		{
			return p.orig;
		}

		/*
		 * Returns the IP which sent us the last received packet.
		 * Useful to create an Origin Indication header.
		 */
		uint32_t GetClientIP (void) const
		{
			return p.source_ipv4;
		}

		/*
		 * Returns the source port of the last received packet.
		 * Useful to create an Origin Indication header.
		 */
		uint16_t GetClientPort (void) const
		{
			return p.source_port;
		}
};
# endif

#endif /* ifndef MIREDO_INCLUDE_TEREDO_H */

