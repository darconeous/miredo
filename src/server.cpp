/*
 * server.cpp - Handling of a single Teredo datagram (server-side).
 * $Id: server.cpp,v 1.4 2004/07/12 08:48:30 rdenisc Exp $
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

#include <stddef.h>
#include <string.h> /* memcpy(), memset() */
#include <inttypes.h>

#include <sys/types.h>
#include <netinet/in.h> // struct in6_addr
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h>

#include <arpa/inet.h> // inet_ntoa()

#include "teredo-udp.h"
#include "common_pkt.h" // TODO: remove
#include "server.h"

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
 * Sends a Teredo-encapsulated Router Advertisement.
 * Returns -1 on error, 0 on success.
 */
static int
teredo_send_ra (const MiredoServerUDP *sock, const struct in6_addr *dest_ip6,
		uint32_t prefix, uint32_t server_ip)
{
	uint8_t packet[13 + 8 + sizeof (struct ip6_hdr)
			+ sizeof (struct nd_router_advert)
			+ sizeof (struct nd_opt_prefix_info)],
		*ptr = packet;

	// Authentification header
	const uint8_t *nonce = sock->GetAuthNonce ();
	if (nonce != NULL)
	{
		struct teredo_simple_auth auth;

		auth.hdr.hdr.zero = 0;
		auth.hdr.hdr.code = teredo_auth_hdr;
		auth.hdr.id_len = auth.hdr.au_len = 0;
		memcpy (&auth.nonce, nonce, 8);
		auth.confirmation = 0;

		memcpy (ptr, &auth, 13);
		ptr += 13;
	}

	// Origin indication header
	{
		struct teredo_orig_ind orig;

		orig.hdr.zero = 0;
		orig.hdr.code = teredo_orig_ind;
		orig.orig_port = ~sock->GetClientPort (); // obfuscate
		orig.orig_addr = ~sock->GetClientIP (); // obfuscate

		memcpy (ptr, &orig, 8);
		ptr += 8;
	}


	{
		struct
		{
			struct ip6_hdr			ip6;
			struct nd_router_advert		ra;
			struct nd_opt_prefix_info	pi;
		} ra;
	
		// IPv6 header
		ra.ip6.ip6_flow = htonl (0x60000000);
		ra.ip6.ip6_plen = htons (sizeof (struct nd_router_advert)
					+ sizeof (struct nd_opt_prefix_info));
		ra.ip6.ip6_nxt = IPPROTO_ICMPV6;
		ra.ip6.ip6_hlim = 255;

		{
			union teredo_addr src;
			src.teredo.prefix = htonl (0xfe800000);
			src.teredo.server_ip = 0;
			src.teredo.flags = htons (TEREDO_FLAGS_CONE);
			src.teredo.client_port = htons (IPPORT_TEREDO);
			src.teredo.client_ip = ~server_ip;

			memcpy (&ra.ip6.ip6_src, &src,
				sizeof (ra.ip6.ip6_src));
		}

		memcpy (&ra.ip6.ip6_dst, dest_ip6, sizeof (ra.ip6.ip6_dst));

		// ICMPv6: Router Advertisement
		ra.ra.nd_ra_type = ND_ROUTER_ADVERT;
		ra.ra.nd_ra_code = 0;
		ra.ra.nd_ra_cksum = 0;
		ra.ra.nd_ra_curhoplimit = 0;
		ra.ra.nd_ra_flags_reserved = 0;
		ra.ra.nd_ra_router_lifetime = 0;
		ra.ra.nd_ra_reachable = 0;
		ra.ra.nd_ra_retransmit = htonl (2000);

		// ICMPv6 option: Prefix information

		ra.pi.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		ra.pi.nd_opt_pi_len = sizeof (ra.pi) >> 3;
		ra.pi.nd_opt_pi_prefix_len = 64;
		ra.pi.nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_AUTO;
		ra.pi.nd_opt_pi_valid_time = 0xffffffff;
		ra.pi.nd_opt_pi_preferred_time = 0xffffffff;
		{
			union teredo_addr pref;

			pref.teredo.prefix = prefix;
			pref.teredo.server_ip = server_ip;
			memset (pref.ip6.s6_addr + 8, 0, 8);
			memcpy (&ra.pi.nd_opt_pi_prefix, &pref.ip6,
				sizeof (ra.pi.nd_opt_pi_prefix));
		}

		// ICMPv6 checksum computation
		ra.ra.nd_ra_cksum = icmp6_checksum (&ra.ip6,
				(struct icmp6_hdr *)&ra.ra);
		memcpy (ptr, &ra, sizeof (ra));
		ptr += sizeof (ra);
	}

	bool use_secondary_ip = sock->WasSecondaryIP ();
	if (IN6_IS_TEREDO_ADDR_CONE (dest_ip6))
		use_secondary_ip = !use_secondary_ip;

	if (!sock->ReplyPacket (packet, ptr - packet, use_secondary_ip)) 
	{
#if 0
		struct in_addr inp;

		inp.s_addr = sock->GetClientIP ();
		syslog (LOG_DEBUG,
			_("Router Advertisement sent to %s (%s)\n"),
			inet_ntoa (inp), IN6_IS_TEREDO_ADDR_CONE(dest_ip6)
				? _("cone flag set")
				: _("cone flag not set"));
#endif
		return 0;
	}

	return -1;
}

/*
 * Forwards a Teredo packet to a client
 */
static int
ForwardUDPPacket (const MiredoServerUDP *sock, bool insert_orig = true)
{
	size_t length;
	const struct ip6_hdr *p = sock->GetIPv6Header (length);

	if ((p == NULL) || (length > 65507))
		return -1;

	union teredo_addr dst;
	memcpy (&dst, &p->ip6_dst, sizeof (dst));
	uint32_t dest_ip = ~dst.teredo.client_ip;

#if 0
	{
		struct in_addr addr;

		addr.s_addr = dest_ip;
		syslog (LOG_DEBUG, "DEBUG: Forwarding packet to %s:%u\n",
			inet_ntoa (addr), ntohs (~dst.teredo.client_port));
	}
#endif
	
	if (!is_ipv4_global_unicast (dest_ip))
		return 0; // ignore invalid client IP

	uint8_t buf[65515];
	unsigned offset;

	// Origin indication header
	// if the Teredo server's address is ours
	// NOTE: I wonder in which legitimate case insert_orig might be
	// false... but the spec implies it could
	if (insert_orig)
	{
		struct teredo_orig_ind orig;
		offset = 8;
		
		orig.hdr.zero = 0;
		orig.hdr.code = teredo_orig_ind;
		orig.orig_port = ~sock->GetClientPort (); // obfuscate
		orig.orig_addr = ~sock->GetClientIP (); // obfuscate
		memcpy (buf, &orig, offset);
	}
	else
		offset = 0;

	memcpy (buf + offset, p, length);
	return sock->SendPacket (buf, length + offset, dest_ip,
					~dst.teredo.client_port);
}

static const struct in6_addr in6addr_allrouters =
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } };

/*
 * Checks and handles an Teredo-encapsulated packet.
 */
int
MiredoServer::ReceivePacket (void) const
{
	// Teredo server check number 3
	if (!is_ipv4_global_unicast (sock->GetClientIP ()))
		return 0;

	// Check IPv6 packet (Teredo server check number 1)
	size_t ip6len;
	const struct ip6_hdr *ip6 = sock->GetIPv6Header (ip6len);
	if (ip6len < 40)
		return 0; // too small
	ip6len -= 40;

	if (((ip6->ip6_vfc >> 4) != 6)
	 || (ntohs (ip6->ip6_plen) != ip6len))
		return 0; // not an IPv6 packet

	uint8_t *buf = ((uint8_t *)ip6) + 40;

	// Teredo server check number 2
	uint8_t proto = ip6->ip6_nxt;
	if ((proto != IPPROTO_NONE || ip6len > 0)	// neither a bubble...
	 && proto != IPPROTO_ICMPV6)	// nor an ICMPv6 message
		return 0; // packet not allowed through server

	// Teredo server check number 4
	if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_src)
	 && IN6_ARE_ADDR_EQUAL (&in6addr_allrouters, &ip6->ip6_dst)
	 && (proto == IPPROTO_ICMPV6)
	 && (ip6len > sizeof (nd_router_solicit))
	 && (((struct icmp6_hdr *)buf)->icmp6_type == ND_ROUTER_SOLICIT))
		// sends a Router Advertisement
		return teredo_send_ra (sock, &ip6->ip6_src, GetPrefix (),
					GetServerIP ());

	// Teredo server check number 5 (in the negative)
	if (!IN6_MATCHES_TEREDO_CLIENT (&ip6->ip6_src, sock->GetClientIP (),
						sock->GetClientPort ())
	// Teredo server check number 6 (in the negative)
	 && (IN6_TEREDO_PREFIX (&ip6->ip6_src) == GetPrefix ()
	  || IN6_TEREDO_SERVER (&ip6->ip6_dst) != GetServerIP ()))
		// Teredo server check number 7
		return 0; // packet not allowed through server

	// Ensures that the packet destination has a global scope
	// (ie 2000::/3). That's not in the spec.
	if ((ip6->ip6_dst.s6_addr[0] & 0xe0) != 0x20)
		return 0; // must be discarded
	
	// Accepts packet:
	if (IN6_TEREDO_PREFIX(&ip6->ip6_dst) != GetPrefix ())
		// forwards packet to native IPv6:
		return ForwardPacket (sock, tunnel);

	// forwards packet over Teredo:
	return ForwardUDPPacket (sock,
		IN6_TEREDO_SERVER (&ip6->ip6_dst) == GetServerIP ());
}

