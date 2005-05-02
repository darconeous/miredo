/*
 * packets.cpp - helpers to send Teredo packet from relay/client
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

#include <string.h>
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h> // router solicication
#include <syslog.h>

#include <libteredo/teredo.h>
#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include <libteredo/relay-udp.h>

#include "packets.h"

/*
 * Sends a Teredo Bubble to the specified IPv4/port tuple.
 * Returns 0 on success, -1 on error.
 */
int
SendBubble (const TeredoRelayUDP& sock, uint32_t ip, uint16_t port,
		const struct in6_addr *src, const struct in6_addr *dst)
{
	if (is_ipv4_global_unicast (ip))
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
 */
int
SendBubble (const TeredoRelayUDP& sock, const struct in6_addr *dst,
		bool cone, bool indirect)
{
	uint32_t ip;
	uint16_t port;

	if (indirect)
	{
		ip = IN6_TEREDO_SERVER (dst);
		port = htons (IPPORT_TEREDO);
	}
	else
	{
		ip = IN6_TEREDO_IPV4 (dst);
		port = IN6_TEREDO_PORT (dst);
	}

	return SendBubble (sock, ip, port, cone
				? &teredo_cone : &teredo_restrict, dst);
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
 * Computes an IPv6 Pseudo-header 16-bits checksum
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

/*
 * Computes an ICMPv6 over IPv6 packet checksum
 */
static uint16_t
icmp6_checksum (const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6)
{
	return ~sum16 ((uint8_t *)icmp6, ntohs (ip6->ip6_plen),
			ipv6_sum (ip6));
}


#ifdef MIREDO_TEREDO_CLIENT
/*
 * Sends a router solication with an Authentication header to the server
 * at specified address.
 *
 * Returns 0 on success, -1 on error.
 */
static const struct in6_addr in6addr_allrouters =
        { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } };

int
SendRS (const TeredoRelayUDP& sock, uint32_t server_ip,
        const unsigned char *nonce, bool cone)
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
		memcpy (auth->nonce, nonce, 8);
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
		rs.ip6.ip6_plen = htons (sizeof (rs) - sizeof (rs.ip6));
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

	return sock.SendPacket (packet, sizeof (packet), server_ip,
	                        htons (IPPORT_TEREDO));
}


/*
 * Validates a router advertisement from the Teredo server.
 * The RA must be of type cone if and only if cone is true.
 * Prefix, flags, mapped port and IP are returned through newaddr.
 * If there is a MTU option in the packet, the specified MTU value will
 * be returned at mtu. If not, the value pointed to by mtu will not be
 * modified.
 *
 * Assumptions:
 * - newaddr must be 4-bytes aligned.
 * - newaddr->teredo.server_ip must be set to the server's expected IP by the
 *   caller.
 * - IPv6 header is valid (ie. version 6, plen matches packet's length, and
 *   the full packet is at least 40 bytes long).
 */
bool
ParseRA (const TeredoPacket& packet, union teredo_addr *newaddr, bool cone,
         uint16_t *mtu)
{
	const struct teredo_orig_ind *ind = packet.GetOrigInd ();

	if (ind == NULL)
		return false;

	size_t length;
	// Only read ip6_next (1 byte), so no need to align
	const struct ip6_hdr *ip6 =
		(const struct ip6_hdr *)packet.GetIPv6Packet (length);

	length -= sizeof (*ip6);

	if (memcmp (&ip6->ip6_dst, cone ? &teredo_cone : &teredo_restrict,
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

	uint32_t prefix, ip = INADDR_ANY, net_mtu = 0;

	// Looks for a prefix information option
	for (const struct nd_opt_hdr *hdr = (const struct nd_opt_hdr *)(ra + 1);
	     length >= 8;
	     hdr = (const struct nd_opt_hdr *)
				(((const uint8_t *)hdr) + (hdr->nd_opt_len << 3)))
	{
		if ((length < (size_t)(hdr->nd_opt_len << 3)) /* too short */
		 || (hdr->nd_opt_len == 0) /* invalid */)
			return false;

		switch (hdr->nd_opt_type)
		{
		/* Prefix information option */
		 case ND_OPT_PREFIX_INFORMATION:
		 {
			if (ip != INADDR_ANY)
			{
				/* The Teredo specification excludes multiple prefixes */
				syslog (LOG_ERR, _("Multiple Teredo prefixes received"));
				return false;
			}

			const struct nd_opt_prefix_info *pi = 
				(const struct nd_opt_prefix_info *)hdr;

			if (length < sizeof (*pi))
				return false; // too short

			if (pi->nd_opt_pi_prefix_len != 64)
				return false;

			memcpy (&prefix, &pi->nd_opt_pi_prefix, sizeof (prefix));
			memcpy (&ip, ((uint8_t *)&pi->nd_opt_pi_prefix) + 4, sizeof (ip));
			break;
		 }

		/* MTU option */
		 case ND_OPT_MTU:
		 {
			const struct nd_opt_mtu *mo = (const struct nd_opt_mtu *)hdr;

			if (length < sizeof (*mo))
				return false;

			memcpy (&net_mtu, &mo->nd_opt_mtu_mtu, sizeof (net_mtu));
			net_mtu = ntohl (net_mtu);

			if ((net_mtu < 1280) || (net_mtu > 65535))
				return false; // invalid IPv6 MTU

			break;
		 }
		}

		length -= hdr->nd_opt_len << 3;
	}

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

	if (net_mtu != 0)
		*mtu = (uint16_t)net_mtu;

	return true;
}


/*
 * Sends an ICMPv6 Echo request toward an IPv6 node through the Teredo server.
 */
int SendPing (const TeredoRelayUDP& sock, const union teredo_addr *src,
		const struct in6_addr *dst, const uint8_t *nonce)
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
	memcpy (&ping.icmp6.icmp6_id, nonce, 8);

	ping.icmp6.icmp6_cksum = icmp6_checksum (&ping.ip6, &ping.icmp6);

	return sock.SendPacket (&ping, sizeof (ping), IN6_TEREDO_SERVER (src),
				htons (IPPORT_TEREDO));
}


/*
 * Checks that the packet is an ICMPv6 Echo reply and that it matches the
 * specified nonce value. Returns true if that is the case, false otherwise.
 */
bool
CheckPing (const TeredoPacket& packet, const uint8_t *nonce)
{
	size_t length;
	const struct ip6_hdr *ip6 =
		(const struct ip6_hdr *)packet.GetIPv6Packet (length);

	// Only read bytes, so no need to align
	if ((ip6->ip6_nxt != IPPROTO_ICMPV6)
	 || (length < (sizeof (*ip6) + sizeof (struct icmp6_hdr) + 4)))
		return false;

	const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)(ip6 + 1);

	if (icmp6->icmp6_type == ICMP6_DST_UNREACH)
	{
		/*
		 * NOTE:
		 * Some brain-dead IPv6 nodes/firewalls don't reply to pings (which is
		 * as explicit breakage of the IPv6/ICMPv6 specifications, btw). Some
		 * of these brain-dead hosts reply with ICMPv6 unreachable messages.
		 * We can authenticate them by looking at the payload of the message
		 * and see if it is an ICMPv6 Echo request with the matching nonce in
		 * it. (Yes, it is a nasty kludge)
		 *
		 * NOTE 2:
		 * We don't check source and destination addresses there...
		 */
		length -= sizeof (*ip6) + sizeof (*icmp6);
		ip6 = (const struct ip6_hdr *)(icmp6 + 1);

		if ((length < (sizeof (*ip6) + sizeof (*icmp6) + 4))
		 || (ip6->ip6_nxt != IPPROTO_ICMPV6))
			return false;

		uint16_t plen;
		memcpy (&plen, &ip6->ip6_plen, sizeof (plen));
		if (ntohs (plen) != (sizeof (*icmp6) + 4))
			return false; // not a ping from us

		icmp6 = (const struct icmp6_hdr *)(ip6 + 1);

		if ((icmp6->icmp6_type != ICMP6_ECHO_REQUEST)
		 || (icmp6->icmp6_code != 0))
			return false;
	}
	else
	if ((icmp6->icmp6_type != ICMP6_ECHO_REPLY)
	 || (icmp6->icmp6_code != 0))
		return false;
	
	/* TODO: check the sum(?) */
	return !memcmp (&icmp6->icmp6_id, nonce, 8);
}
#endif


/*
 * Builds an ICMPv6 error message with specified type and code from an IPv6
 * packet. The output buffer should be at least 1280 bytes long.
 * Returns the actual size of the generated error message, or zero if no
 * ICMPv6 packet should be sent. Never fails.
 *
 * It is assumed that the output buffer is properly aligned.
 */
int
BuildICMPv6Error (struct ip6_hdr *out, const struct in6_addr *src,
			uint8_t type, uint8_t code,
			const void *in, uint16_t inlen)
{
	// don't reply if the packet is too small
	if ((inlen < 40)
	// don't reply to multicast
	 || ((*(uint8_t *)(&((const struct ip6_hdr *)in)->ip6_dst)) == 0xff)
	// don't reply to ICMPv6 error
	 || ((((const struct ip6_hdr *)in)->ip6_nxt == IPPROTO_ICMPV6)
	  && ((((const struct icmp6_hdr *)(((const struct ip6_hdr *)in) + 1))
						->icmp6_type & 0x80) == 0)))
		return 0;

	if (inlen + sizeof (struct ip6_hdr) + sizeof (icmp6_hdr) > 1280)
		inlen = 1280 - (sizeof (struct ip6_hdr) + sizeof (icmp6_hdr));
	uint16_t len = sizeof (icmp6_hdr) + inlen;

	out->ip6_flow = htonl (0x60000000);
	out->ip6_plen = htons (len);
	out->ip6_nxt = IPPROTO_ICMPV6;
	out->ip6_hlim = 255;
	memcpy (&out->ip6_src, src, sizeof (struct in6_addr));
	memcpy (&out->ip6_dst, &((const struct ip6_hdr *)in)->ip6_src,
		sizeof (struct in6_addr));
	
	struct icmp6_hdr *h = (struct icmp6_hdr *)(out + 1);
	h->icmp6_type = type;
	h->icmp6_code = code;
	h->icmp6_cksum = 0;
	h->icmp6_data32[0] = 0;

	len += sizeof (struct ip6_hdr);
	memcpy (h + 1, in, len);

	h->icmp6_cksum = icmp6_checksum (out, h);
	return len;
}
