/*
 * mire.c s Stateless Teredo ping responder
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2006-2007 Rémi Denis-Courmont.                         *
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

#include <inttypes.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h> // htons()
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <errno.h>
#include <pthread.h>

#include <libteredo/teredo-udp.h>
#include <libteredo/checksum.h>
#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

#include <libteredo/teredo.h>
#include <stdbool.h>
#include "packets.h"
#include "debug.h"

//#define MIRE_COUNTER 1

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

	ip6->ip6_hlim = 255;

	struct in6_addr buf;
	buf = ip6->ip6_dst;
	ip6->ip6_dst = ip6->ip6_src;
	ip6->ip6_src = buf;;

	hdr->icmp6_type = ICMP6_ECHO_REPLY;
	hdr->icmp6_code = 0;
	hdr->icmp6_cksum = 0;
	hdr->icmp6_cksum = icmp6_checksum (ip6, hdr);

	teredo_send (fd, ip6, sizeof (*ip6) + plen, ipv4, port);
}


static void
process_none (int fd, const struct ip6_hdr *ip6, size_t plen,
              uint32_t ipv4, uint16_t port)
{
	if (plen != 0)
		return;

	teredo_reply_bubble (fd, ipv4, port, ip6);
}


static void
process_unknown (int fd, const struct ip6_hdr *in, size_t plen,
                 uint32_t ipv4, uint16_t port)
{
	plen += sizeof (struct ip6_hdr);
	if (plen > 1232)
		plen = 1232;

	struct ip6_hdr   ip6;
	struct icmp6_hdr icmp6;
	struct iovec iov[] =
	{
		{ &ip6, sizeof (ip6) },
		{ &icmp6, sizeof (icmp6) },
		{ (void *)in, plen }
	};

	ip6.ip6_flow = htonl (6 << 28);
	ip6.ip6_plen = htons (sizeof (struct icmp6_hdr) + plen);
	ip6.ip6_nxt = IPPROTO_ICMPV6;
	ip6.ip6_hlim = 255;
	ip6.ip6_src = in->ip6_dst;
	ip6.ip6_dst = in->ip6_src;

	icmp6.icmp6_type = ICMP6_PARAM_PROB;
	icmp6.icmp6_code = ICMP6_PARAMPROB_NEXTHEADER;
	icmp6.icmp6_cksum = 0;
	icmp6.icmp6_pptr = htonl (6);

	icmp6.icmp6_cksum = teredo_cksum (&ip6.ip6_src, &ip6.ip6_dst,
	                                  IPPROTO_ICMPV6, iov + 1, 2);

	teredo_sendv (fd, iov, sizeof (iov) / sizeof (iov[0]), ipv4, port);
}


/**
 * Receives and validates Teredo packet.
 * @param fd socket from which to receive a packet.
 * @param p pointer to structure where the received packet will be stored.
 *
 * @return payload byte length of received packet, or -1 on error.
 */
static ssize_t
recv_packet (int fd, teredo_packet *p)
{
	if (teredo_wait_recv (fd, p))
		return -1;

	struct ip6_hdr *ip6 = p->ip6;
	uint16_t plen;

	// Check packet size
	if ((p->ip6_len < sizeof (*ip6)) || (p->ip6_len > 1280))
		return -1;

	// Check packet validity
	plen = ntohs (ip6->ip6_plen);
#ifdef MIRE_COUNTER
	count_pkt++;
	count_bytes += plen + 40;
#endif

	if (((ip6->ip6_vfc >> 4) != 6)
	 || ((plen + sizeof (*ip6)) != p->ip6_len))
		return -1;

	return plen;
}


static LIBTEREDO_NORETURN void *server_thread (void *data)
{
	int fdserv = ((int *)data)[0], fd = ((int *)data)[1];

	for (;;)
	{
		struct teredo_packet p;
		ssize_t plen = recv_packet (fdserv, &p);
		if (plen == -1)
			continue;

		if (p.ip6->ip6_nxt == IPPROTO_NONE)
			process_none (fd, p.ip6, plen, p.source_ipv4, p.source_port);
	}
}


static LIBTEREDO_NORETURN int client_thread (int fd)
{
	for (;;)
	{
		struct teredo_packet p;
		ssize_t plen = recv_packet (fd, &p);
		if (plen == -1)
			continue;

		switch (p.ip6->ip6_nxt)
		{
			// TODO: support routing and hop-by-hop headers?

			case IPPROTO_ICMPV6:
				process_icmpv6 (fd, p.ip6, plen,
				                p.source_ipv4, p.source_port);
				break;

			case IPPROTO_NONE: // ignore direct bubbles
			case IPPROTO_ROUTING:
				break;

			default:
				process_unknown (fd, p.ip6, plen, p.source_ipv4, p.source_port);
		}
	}
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

			default:
				return 1;
		}

	int socks[2] = { -1, -1 }, retval = -1;
	pthread_t thserv;

	socks[0] = teredo_socket (0, htons (3544));
	if (socks[0] != -1)
	{
		socks[1] = teredo_socket (0, htons (3545));
		if (socks[1] != -1)
		{
			errno = pthread_create (&thserv, NULL, server_thread, socks);
			if (errno == 0)
			{
#ifdef MIRE_COUNTER
				signal (SIGALRM, handler);
				alarm (1);
#endif
				retval = -client_thread (socks[1]);
			}
			else
				perror ("pthread_create");

			teredo_close (socks[1]);
		}
		else
			perror ("teredo_socket");
		teredo_close (socks[0]);
	}
	else
		perror ("teredo_socket(server)");

	return retval;

	return 0;
}
