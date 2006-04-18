/*
 * mire.c s Stateless Teredo ping responder
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006 Rémi Denis-Courmont.                              *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h> // htons()
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <errno.h>

#include <libteredo/teredo-udp.h>
#include <libteredo/checksum.h>

static void
process_icmpv6 (int fd, const struct ip6_hdr *ip6, size_t plen,
                uint32_t ipv4, uint16_t port)
{
	if (plen < sizeof (struct icmp6_hdr))
		return;

	const struct icmp6_hdr *hdr = (const struct icmp6_hdr *)(ip6 + 1);
	/*
	 * - Errors must not raise any answer, unknown ones must be passed to the
	 *   upper layer, but therer's no such upper layer in our case.
	 * - Echo Reply must be passed to the origin of the Echo Request, given we
	 *   never emit Echo Request, we can ignore Echo Replies.
	 * - Echo Request triggers an Echo Reply.
	 * - Other informational messages can be ignored.
	 */
	if (hdr->icmp6_type != ICMP6_ECHO_REQUEST)
		return;
	// FIXME: check checksum (difficult because of non alignment)

	// TODO: use an iovec instead - needs to rewrite checksum though
	struct
	{
		struct ip6_hdr   ip6;
		struct icmp6_hdr icmp6;
		uint8_t          data[plen - sizeof (struct icmp6_hdr)];
	} reply;

	reply.ip6.ip6_vfc = htonl (6 << 28);
	reply.ip6.ip6_plen = htons (plen);
	reply.ip6.ip6_nxt = IPPROTO_ICMPV6;
	reply.ip6.ip6_hlim = 255;
	memcpy (&reply.ip6.ip6_src, &ip6->ip6_dst, sizeof (reply.ip6.ip6_src));
	memcpy (&reply.ip6.ip6_dst, &ip6->ip6_src, sizeof (reply.ip6.ip6_dst));

	reply.icmp6.icmp6_type = ICMP6_ECHO_REPLY;
	reply.icmp6.icmp6_code = 0;
	reply.icmp6.icmp6_cksum = 0;
	memcpy (&reply.icmp6.icmp6_id, &hdr->icmp6_id, plen - 4);

	reply.icmp6.icmp6_cksum = icmp6_checksum (&reply.ip6, &reply.icmp6);

	teredo_send (fd, &reply, sizeof (*ip6) + plen, ipv4, port);
}


static void
process_none (int fd, const struct ip6_hdr *ip6, size_t plen,
              uint32_t ipv4, uint16_t port)
{
	if (plen != 0)
		return;

	/*
	 * Teredo bubbles
	 *
	 * Contrary to normal Teredo relays & clients, this program is completely
	 * stateless. We still have to ensure that we don't reply to a reply to
	 * one of our own packet. Otherwise, it would be trivial to trigger an
	 * infinite packet exchange loop between two instances of this program.
	 * On the other hand, we have to reply to bubble so that we can be reached
	 * from clients and relays that ignores the cone flag; this behavior is
	 * explicitly allowed by the specification, and is actually enabled by
	 * default in miredo.
	 *
	 * To avoid the infinite packet loop, we use a very nasty kludge: we set
	 * the hop limit to a value that's unlikely to ever be used by any other
	 * implementation, and we ignore packets that arrives with that hop limit.
	 */
	if (ip6->ip6_hlim == 0)
		return;

	struct iovec reply[3];
	reply[0].iov_base = "\x60\x00\x00\x00" "\x00\x00" "\x3b" "\x00";
	reply[0].iov_len = 8;
	reply[1].iov_base = (uint8_t *)&ip6->ip6_dst;
	reply[1].iov_len = 16;
	reply[2].iov_base = (uint8_t *)&ip6->ip6_src;
	reply[2].iov_len = 16;
	teredo_sendv (fd, reply, 3, ipv4, port);
}


static void
process_unknown (int fd, const struct ip6_hdr *ip6, size_t plen,
                 uint32_t ipv4, uint16_t port)
{
	plen += sizeof (*ip6);
	if (plen > (1280 - sizeof (struct icmp6_hdr)))
		plen = 1280 - sizeof (struct icmp6_hdr);

	// TODO: use an iovec instead - needs to rewrite checksum though
	struct
	{
		struct ip6_hdr   ip6;
		struct icmp6_hdr icmp6;
		uint8_t          payload[plen];
	} reply;

	reply.ip6.ip6_vfc = htonl (6 << 28);
	reply.ip6.ip6_plen = htons (sizeof (struct icmp6_hdr) + plen);
	reply.ip6.ip6_nxt = IPPROTO_ICMPV6;
	reply.ip6.ip6_hlim = 255;
	memcpy (&reply.ip6.ip6_src, &ip6->ip6_dst, sizeof (reply.ip6.ip6_src));
	memcpy (&reply.ip6.ip6_dst, &ip6->ip6_src, sizeof (reply.ip6.ip6_dst));

	reply.icmp6.icmp6_type = ICMP6_PARAM_PROB;
	reply.icmp6.icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
	reply.icmp6.icmp6_cksum = 0;
	reply.icmp6.icmp6_pptr = htonl (6);

	memcpy (&reply.payload, ip6, plen);
	reply.icmp6.icmp6_cksum = icmp6_checksum (&reply.ip6, &reply.icmp6);

	teredo_send (fd, &reply, 48 + plen, ipv4, port);
}


int main (void)
{
	int fd = teredo_socket (0, htons (3544));
	if (fd == -1)
	{
		perror ("teredo_socket");
		return 1;
	}

	for (;;)
	{
		struct teredo_packet p;
		if (teredo_wait_recv (fd, &p))
		{
			if (errno == EINTR)
				break;
			continue;
		}

		// Beware: the inner IPv6 packet might not be aligned
		// so only single bytes shall be read
		struct ip6_hdr *ip6 = (struct ip6_hdr *)p.ip6;
		uint16_t plen;

		// Check packet size
		if ((p.ip6_len < sizeof (*ip6)) || (p.ip6_len > 1280))
			continue;

		// Check packet validity
		memcpy (&plen, &ip6->ip6_plen, sizeof (plen));
		plen = ntohs (plen);

		if (((ip6->ip6_vfc >> 4) != 6)
		 || ((plen + sizeof (*ip6)) != p.ip6_len))
			continue;

		printf ("Received %d bytes packet\n", plen);
		switch (ip6->ip6_nxt)
		{
			case IPPROTO_NONE:
				process_none (fd, ip6, plen, p.source_ipv4, p.source_port);
				break;

			// TODO: support routing and hop-by-hop headers?

			case IPPROTO_ICMPV6:
				process_icmpv6 (fd, ip6, plen, p.source_ipv4, p.source_port);
				break;

			default:
				process_unknown (fd, ip6, plen, p.source_ipv4, p.source_port);
		}
	}

	teredo_close (fd);
	return 0;
}
