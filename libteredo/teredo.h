/**
 * @file teredo.h
 * @brief Common Teredo protocol typedefs
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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

# if __STDC_VERSION__ < 199901L
#  ifndef inline
#   define inline
#  endif
# endif

/* UDP Teredo port number */
#define IPPORT_TEREDO 3544

/* Multicast IPv4 discovery address */
#define TEREDO_DISCOVERY_IPV4	0xe00000fd

/*
 * Teredo addresses
 */
extern const struct in6_addr teredo_restrict;
extern const struct in6_addr teredo_cone;

#define TEREDO_PREFIX          0x20010000
#define TEREDO_PREFIX_OBSOLETE 0x3ffe831f

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

/* The following two flags should never be set */
#define TEREDO_FLAG_MULTICAST	0x0200
#define TEREDO_FLAG_GLOBAL	0x0100

/* Non-standard flags (taken from draft-ietf-ngtrans-shipworm-07) */
#define TEREDO_FLAG_RANDOM	0x4000
#define TEREDO_RANDOM_MASK	0x3cff

#define ip6_teredo( ip6 ) (&((const union teredo_addr *)(ip6))->teredo)

/* NOTE: these macros expect 4-byte aligned addresses structs */
#define IN6_IS_TEREDO_ADDR_CONE( ip6 ) \
	(ip6_teredo (ip6)->flags & htons (TEREDO_FLAG_CONE))

#define IN6_TEREDO_PREFIX( ip6 ) \
	(ip6_teredo (ip6)->prefix)
#define IN6_TEREDO_SERVER( ip6 ) \
	(ip6_teredo (ip6)->server_ip)
#define IN6_TEREDO_IPV4( ip6 ) \
	(ip6_teredo (ip6)->client_ip ^ 0xffffffff)
#define IN6_TEREDO_PORT( ip6 ) \
	(ip6_teredo (ip6)->client_port ^ 0xffff)
#define IN6_TEREDO_FLAGS( ip6 ) \
	(ip6_teredo (ip6)->flags)

#define IN6_MATCHES_TEREDO_CLIENT( ip6, ip4, port ) \
	in6_matches_teredo_client (ip6, ip4, port)

static inline int
in6_matches_teredo_client (const struct in6_addr *ip6,
                           uint32_t ip, uint16_t port)
{
	return !((ip ^ IN6_TEREDO_IPV4 (ip6))
	      || (port ^ IN6_TEREDO_PORT (ip6)));
}

/*
 * Returns true if prefix can be used as a Teredo prefix.
 * As per RFC3513, anything could be used for Teredo (unicast)
 * except the multicast range (ff00::/8).
 */
#define is_valid_teredo_prefix( prefix ) \
	(((prefix) & 0xff000000) != 0xff000000)

/*
 * Teredo headers
 */
enum
{
	teredo_orig_ind=0,
	teredo_auth_hdr
};

struct teredo_orig_ind /* code == 1 */
{
	uint8_t  orig_zero;
	uint8_t  orig_code;
	uint16_t orig_port; /* obfuscated port number in network byte order */
	uint32_t orig_addr; /* obfuscated IPv4 address in network byte order */
};

#endif /* ifndef MIREDO_INCLUDE_TEREDO_H */

