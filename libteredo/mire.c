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

#ifdef HAVE_STDINT_H
# include <stdint.h>
#else
# include <inttypes.h>
#endif
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h> // htons()
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <errno.h>

#include <libteredo/teredo-udp.h>
#include <libteredo/checksum.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif


//#define MIRE_COUNTER 1
//#define MIRE_NOALIGN 1

#ifdef MIRE_COUNTER
#include <signal.h>
static unsigned long count_pkt = 0;
static unsigned long count_bytes = 0;
static void handler (int signum)
{
	signal (signum, handler);
	count_bytes /= 1000;
	printf ("%lu packets/s, %lu.%03lu Mbits/s\n", count_pkt,
		count_bytes / 125, count_bytes % 125 * 8);
	count_pkt = count_bytes = 0;
	if (signum == SIGALRM)
		alarm (1);
}
#endif


static void
process_icmpv6 (int fd, struct ip6_hdr *ip6, size_t plen,
                uint32_t ipv4, uint16_t port)
{
	if (plen < sizeof (struct icmp6_hdr))
		return;

	struct icmp6_hdr *hdr = (struct icmp6_hdr *)(ip6 + 1);
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

#ifndef MIRE_NOALIGN
	struct
	{
		struct ip6_hdr   ip6;
		struct icmp6_hdr icmp6;
		uint8_t          data[plen - sizeof (struct icmp6_hdr)];
	} reply;

	reply.ip6.ip6_flow = htonl (6 << 28);
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
#else
	ip6->ip6_hlim = 255;

	struct in6_addr buf;
	memcpy (&buf, &ip6->ip6_dst, sizeof (buf));
	memcpy (&ip6->ip6_dst, &ip6->ip6_src, sizeof (ip6->ip6_dst));
	memcpy (&ip6->ip6_src, &buf, sizeof (ip6->ip6_src));

	hdr->icmp6_type = ICMP6_ECHO_REPLY;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_cksum = icmp6_checksum (ip6, hdr);

	teredo_send (fd, ip6, sizeof (*ip6) + plen, ipv4, port);
#endif
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
	 * from clients and relays as if we were behind a restricted NAT.
	 *
	 * To avoid the infinite packet loop, we use a very nasty kludge: we put a
	 * dummy *non-empty* payload into our pseudo-bubbles instead of genuine
	 * Teredo bubbles. This should still interoperate against a conformant
	 * Teredo peer (it wants to receive a packet from us, not specifically a
	 * Teredo bubble).
	 */

	struct iovec reply[4];
	reply[0].iov_base = "\x60\x00\x00\x00" "\x00\x04" "\x3b" "\x00";
	reply[0].iov_len = 8;
	reply[1].iov_base = (uint8_t *)&ip6->ip6_dst;
	reply[1].iov_len = 16;
	reply[2].iov_base = (uint8_t *)&ip6->ip6_src;
	reply[2].iov_len = 16;
	reply[3].iov_base = "MIRE";
	reply[3].iov_len = 4;
	teredo_sendv (fd, reply, sizeof (reply) / sizeof (reply[0]), ipv4, port);
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

	reply.ip6.ip6_flow = htonl (6 << 28);
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


static int usage (const char *path)
{
	printf ("Usage: %s\n", path);
	return 0;
}

static int version (void)
{
	puts (PACKAGE_NAME" v"PACKAGE_VERSION);
	return 0;
}

int main(int argc, char *argv[])
{
	static const struct option opts[] =
	{
		{ "help",       no_argument,       NULL, 'h' },
		{ "version",    no_argument,       NULL, 'V' },
		{ NULL,         no_argument,       NULL, '\0'}
	};

	int c;
	while ((c = getopt_long (argc, argv, "hV", opts, NULL)) != -1)
		switch (c)
		{
			case 'h':
				return usage(argv[0]);

			case 'V':
				return version();
		}

	int fd = teredo_socket (0, htons (3544));
	if (fd == -1)
	{
		perror ("teredo_socket");
		return 1;
	}

#ifdef MIRE_COUNTER
	signal (SIGALRM, handler);
	alarm (1);
#endif
	for (;;)
	{
		struct teredo_packet p;
		if (teredo_wait_recv (fd, &p))
			continue;

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
#ifdef MIRE_COUNTER
		count_pkt++;
		count_bytes += plen + 40;
#endif

		if (((ip6->ip6_vfc >> 4) != 6)
		 || ((plen + sizeof (*ip6)) != p.ip6_len))
			continue;

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
