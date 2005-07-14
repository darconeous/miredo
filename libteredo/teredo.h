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
		| ((port ^ ip6->teredo.client_port) == 0xffff));
}

/*
 * Returns true if prefix can be used as a Teredo prefix.
 * As per RFC3513, anything could be used for Teredo (unicast)
 * except the multicast range (ff00::/8).
 */
#define is_valid_teredo_prefix( prefix ) \
	((prefix & 0xff000000) != 0xff000000)

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


#endif /* ifndef MIREDO_INCLUDE_TEREDO_H */

