/*
 * teredo.h - Common Teredo protocol typedefs
 * $Id$
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

#ifndef MIREDO_INCLUDE_TEREDO_H
# define MIREDO_INCLUDE_TEREDO_H


#define IPPORT_TEREDO 3544 /* UDP Teredo port number */

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
};

#define TEREDO_FLAG_CONE	0x8000

#define ip6_teredo( ip6 ) (((union teredo_addr *)ip6)->teredo)

/* NOTE: these macros expect 4-byte aligned addresses structs */
#define IN6_MATCHES_TEREDO_CLIENT( ip6, ip4, port ) \
	in6_matches_teredo_client ((const union teredo_addr *)ip6, ip4, port)

#define IN6_MATCHES_TEREDO_SERVER( ip6, ip4 ) \
	in6_matches_teredo_server ((const union teredo_addr *)ip6, ip4)

#define IN6_IS_TEREDO_ADDR_CONE( ip6 ) \
	in6_is_teredo_addr_cone ((const union teredo_addr *)ip6)

#define IN6_TEREDO_PREFIX( ip6 ) \
	(((const union teredo_addr *)ip6)->teredo.prefix)
#define IN6_TEREDO_SERVER( ip6 ) \
	(((const union teredo_addr *)ip6)->teredo.server_ip)
#define IN6_TEREDO_IPV4( ip6 ) \
	(~((const union teredo_addr *)ip6)->teredo.client_ip)
#define IN6_TEREDO_PORT( ip6 ) \
	(~((const union teredo_addr *)ip6)->teredo.client_port)

#ifdef __cplusplus
extern "C" {
#endif
	
int in6_matches_teredo_client (const union teredo_addr *ip6,
				uint32_t ip4, uint16_t port);

int in6_matches_teredo_server (const union teredo_addr *ip6, uint32_t ip4);

int in6_is_teredo_addr_cone (const union teredo_addr *ip6);

/*
 * Returns true if prefix can be used as a Teredo prefix.
 */
int is_valid_teredo_prefix (uint32_t prefix);

#ifdef __cplusplus
}
#endif

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

