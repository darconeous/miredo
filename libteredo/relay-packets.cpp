/*
 * relay-packets.cpp - helpers to send Teredo packet from relay/client
 * $Id: relay-packets.cpp,v 1.3 2004/08/29 17:30:08 rdenisc Exp $
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <inttypes.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h> // router solicication
#include <syslog.h>

#ifdef USE_OPENSSL
# include <openssl/rand.h>
# include <openssl/err.h>
#endif

#include "teredo.h"
#include <v4global.h> // is_ipv4_global_unicast()
#include "teredo-udp.h"

/*
 * Sends a Teredo Bubble to the specified IPv4/port tuple.
 * Returns 0 on success, -1 on error.
 */
int
SendBubble (const TeredoRelayUDP& sock, uint32_t ip, uint16_t port,
		const struct in6_addr *src, const struct in6_addr *dst)
{
	if (ip && is_ipv4_global_unicast (ip))
	{
		struct ip6_hdr hdr;

		hdr.ip6_flow = htonl (0x60000000);
		hdr.ip6_plen = 0;
		hdr.ip6_nxt = IPPROTO_NONE;
		hdr.ip6_hlim = 255;
		memcpy (&hdr.ip6_src, src, sizeof (hdr.ip6_src));
		memcpy (&hdr.ip6_dst, dst, sizeof (hdr.ip6_dst));

		return sock.SendPacket (&hdr, sizeof (hdr), ip, port);
	}

	return 0;
}


/*
 * Sends a Teredo Bubble to the server (if indirect is true) or the client (if
 * indirect is false) specified in Teredo address <dst>.
 * Returns 0 on success, -1 on error.
 * FIXME: do not use link-local addresses in bubbles.
 * FIXME: use the previous function
 */
int
SendBubble (const TeredoRelayUDP& sock, const struct in6_addr *d,
		bool cone, bool indirect = true)
{
	uint32_t ip;
	uint16_t port;
	const union teredo_addr *dst = (const union teredo_addr *)d;

	if (indirect)
	{
		ip = dst->teredo.server_ip;
		port = htons (IPPORT_TEREDO);
	}
	else
	{
		ip = ~dst->teredo.client_ip;
		port = ~dst->teredo.client_port;
	}

	if (ip && is_ipv4_global_unicast (ip))
	{
		struct ip6_hdr hdr;

		hdr.ip6_flow = htonl (0x60000000);
		hdr.ip6_plen = 0;
		hdr.ip6_nxt = IPPROTO_NONE;
		hdr.ip6_hlim = 255;
		memcpy (&hdr.ip6_src, cone ? &teredo_cone : &teredo_restrict,
				sizeof (hdr.ip6_src));
		memcpy (&hdr.ip6_dst, &dst->ip6, sizeof (hdr.ip6_dst));

		return sock.SendPacket (&hdr, sizeof (hdr), ip, port);
	}

	return 0;
}


static uint16_t
sum16 (const uint8_t *data, size_t length, uint32_t sum32 = 0)
{
	size_t wordc = length / 2;

	for (size_t i = 0; i < wordc; i++)
		sum32 += ((uint16_t *)data)[i];
	if (length & 1) // trailing byte if length is odd
		sum32 += ntohs(((uint16_t)(data[length - 1])) << 8);

	while (sum32 > 0xffff)
		sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	
	return sum32;
}

/*
 * Computes an IPv6 16-bits checksum
 */
static uint16_t 
ipv6_sum (const struct ip6_hdr *ip6)
{
	uint32_t sum32 = 0;

	/* Pseudo-header sum */
	for (size_t i = 0; i < 16; i += 2)
		sum32 += *(uint16_t *)(&ip6->ip6_src.s6_addr[i]);
	for (size_t i = 0; i < 16; i += 2)
		sum32 += *(uint16_t *)(&ip6->ip6_dst.s6_addr[i]);

	sum32 += ip6->ip6_plen + ntohs (ip6->ip6_nxt);

	while (sum32 > 0xffff)
		sum32 = (sum32 & 0xffff) + (sum32 >> 16);

	return sum32;
}


static uint16_t
icmp6_checksum (const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6)
{
	return ~sum16 ((uint8_t *)icmp6, ntohs (ip6->ip6_plen),
			ipv6_sum (ip6));
}


/*
 * Sends a router solication with an Authentication header to the server.
 * If secondary is true, the packet will be sent to the server's secondary
 * IPv4 adress instead of the primary one.
 *
 * Returns 0 on success, -1 on error.
 */
static const struct in6_addr in6addr_allrouters =
        { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } };

int
SendRS (const TeredoRelayUDP& sock, uint32_t server_ip, unsigned char *nonce,
	bool cone, bool secondary)
{
	uint8_t packet[13 + sizeof (struct ip6_hdr)
			+ sizeof (struct nd_router_solicit)
			+ sizeof (nd_opt_hdr) + 14],
                *ptr = packet;

	// Authentication header
	// TODO: secure qualification
	{
		struct teredo_simple_auth *auth;

		auth = (struct teredo_simple_auth *)ptr;
		auth->hdr.hdr.zero = 0;
		auth->hdr.hdr.code = teredo_auth_hdr;
		auth->hdr.id_len = auth->hdr.au_len = 0;
#ifdef USE_OPENSSL
		if (!RAND_pseudo_bytes (auth->nonce, 8))
		{
			char buf[120];

			syslog (LOG_WARNING, _("Possibly predictable RS: %s"),
				ERR_error_string (ERR_get_error (), buf));
		}
#else
		memset (auth->nonce, 0, 8);
#endif
		memcpy (nonce, auth->nonce, 8);
		auth->confirmation = 0;

		ptr += 13;
	}

	{
		struct
		{
			struct ip6_hdr ip6;
			struct nd_router_solicit rs;
			struct nd_opt_hdr opt;
			uint8_t lladdr[14];
		} rs;

		rs.ip6.ip6_flow = htonl (0x60000000);
		rs.ip6.ip6_plen = htons (sizeof (rs));
		rs.ip6.ip6_nxt = IPPROTO_ICMPV6;
		rs.ip6.ip6_hlim = 255;
		memcpy (&rs.ip6.ip6_src, cone
			? &teredo_cone : &teredo_restrict,
			sizeof (rs.ip6.ip6_src));
		memcpy (&rs.ip6.ip6_dst, &in6addr_allrouters,
			sizeof (rs.ip6.ip6_dst));
	
		rs.rs.nd_rs_type = ND_ROUTER_SOLICIT;
		rs.rs.nd_rs_code = 0;
		// Checksums are pre-computed
		rs.rs.nd_rs_cksum = htons (cone ? 0x114b : 0x914b);
		rs.rs.nd_rs_reserved = 0;

		/*
		 * Microsoft Windows XP sends a 14 byte nul
		 * source link-layer address (this is useless) when qualifying.
		 * Once qualified, it still sends a source link-layer address,
		 * but it includes sort of an origin indication.
		 * We keep it nul every time. It avoids having to compute the
		 * checksum and it is not specified.
		 */
		rs.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
		rs.opt.nd_opt_len = 2; // 16 bytes

		memset (rs.lladdr, 0, sizeof (rs.lladdr));

		memcpy (ptr, &rs, sizeof (rs));
	}

	if (secondary)
		server_ip = htonl (ntohl (server_ip) + 1);

	return sock.SendPacket (packet, sizeof (packet), server_ip,
				htons (IPPORT_TEREDO));
}


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
ParseRA (const TeredoPacket& packet, union teredo_addr *newaddr, bool cone)
{
	const struct teredo_orig_ind *ind = packet.GetOrigInd ();
	size_t length;

	const struct ip6_hdr *ip6 = packet.GetIPv6Header (length);

	if ((ind == NULL)
	 || memcmp (&ip6->ip6_dst, cone ? &teredo_cone : &teredo_restrict,
			sizeof (ip6->ip6_dst))
	 || (ip6->ip6_nxt != IPPROTO_ICMPV6)
	 || (length < sizeof (struct nd_router_advert)))
		return false;

	// Only read bytes, so no need to align
	const struct nd_router_advert *ra =
		(const struct nd_router_advert *)
			(((uint8_t *)ip6) + sizeof (struct ip6_hdr));
	length -= sizeof (struct nd_router_advert);

	if ((ra->nd_ra_type != ND_ROUTER_ADVERT)
	 || (ra->nd_ra_code != 0)
	 || (length < sizeof (struct nd_opt_prefix_info)))
	/*
	 * We don't check checksum, because it is rather useless.
	 * There were already (at least) two lower-level checksums.
	 */
		return false;

	// Looks for a prefix information option
	const struct nd_opt_prefix_info *pi =
		(const struct nd_opt_prefix_info *)(((uint8_t *)ra)
			+ sizeof (struct nd_router_advert));

	while (pi->nd_opt_pi_type != ND_OPT_PREFIX_INFORMATION)
	{
		if (length < (size_t)(pi->nd_opt_pi_len << 3))
			return 0; // too short
		length -= pi->nd_opt_pi_len << 3;
		if (length < sizeof (struct nd_opt_prefix_info))
			return 0; // too short

		pi = (const struct nd_opt_prefix_info *)
			(((uint8_t *)pi) + (pi->nd_opt_pi_len << 3));
	}

	if ((pi->nd_opt_pi_len != (sizeof (struct nd_opt_prefix_info) >> 3))
	 || (pi->nd_opt_pi_prefix_len != 64))
		return false;

	uint32_t prefix, ip;

	memcpy (&prefix, &pi->nd_opt_pi_prefix, sizeof (prefix));
	memcpy (&ip, ((uint8_t *)&pi->nd_opt_pi_prefix) + 4, sizeof (ip));

	if (!is_valid_teredo_prefix (prefix)
	 || (ip != newaddr->teredo.server_ip))
	{
		syslog (LOG_WARNING, _("Invalid Teredo prefix received"));
		return false;
	}

	newaddr->teredo.prefix = prefix;
	// only accept the cone flag:
	newaddr->teredo.flags = cone ? htons (TEREDO_FLAG_CONE) : 0;
	// ip and port obscured on both sides:
	newaddr->teredo.client_port = ind->orig_port;
	newaddr->teredo.client_ip = ind->orig_addr;
	return true;
}


/*
 * Sends an ICMPv6 Echo request toward an IPv6 node through the Teredo server.
 */
int SendPing (const TeredoRelayUDP& sock, const union teredo_addr *src,
		const struct in6_addr *dst, uint8_t *nonce)
{
	struct
	{
		struct ip6_hdr ip6;
		struct icmp6_hdr icmp6;
                uint32_t payload;
	} ping;

	ping.ip6.ip6_flow = htonl (0x60000000);
	ping.ip6.ip6_plen = htons (sizeof (ping.icmp6) + 4);
	ping.ip6.ip6_nxt = IPPROTO_ICMPV6;
	ping.ip6.ip6_hlim = 21;
	memcpy (&ping.ip6.ip6_src, src, sizeof (ping.ip6.ip6_src));
	memcpy (&ping.ip6.ip6_dst, dst, sizeof (ping.ip6.ip6_dst));
	
	ping.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
	ping.icmp6.icmp6_code = 0;
	ping.icmp6.icmp6_cksum = 0;
	/*
	ping.icmp6.icmp6_id = 0;
	ping.icmp6.icmp6_seq = 0;
	 */
#ifdef USE_OPENSSL
	if (!RAND_pseudo_bytes ((unsigned char *)&ping.icmp6.icmp6_id, 8))
	{
		char buf[120];

		syslog (LOG_WARNING, _("Possibly predictable RS: %s"),
			ERR_error_string (ERR_get_error (), buf));
	}
#else
	memset (&ping.icmp6.icmp6_id, 0, 8);
#endif
	memcpy (nonce, &ping.icmp6.icmp6_id, 8);

	ping.icmp6.icmp6_cksum = icmp6_checksum (&ping.ip6, &ping.icmp6);

	return sock.SendPacket (&ping, sizeof (ping), IN6_TEREDO_SERVER (src),
				htons (IPPORT_TEREDO));
}
