/*
 * relay.cpp - Teredo relay peers list definition
 * $Id: relay.cpp,v 1.2 2004/06/20 13:53:35 rdenisc Exp $
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
#include <time.h> // time()
#include <inttypes.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <syslog.h>
#include <arpa/inet.h> // DEBUG: inet_ntoa()

#include <teredo.h>

#include "relay.h"
#include "ipv6-tunnel.h"
#include "teredo-udp.h"
#include "common_pkt.h" // is_ipv4_global_unicast()

#define TEREDO_TIMEOUT 30 // seconds

#define EXPIRED( date, now ) ((((unsigned)now) - (unsigned)date) > 30)
#define ENTRY_EXPIRED( peer, now ) (peer->flags.flags.replied \
					? EXPIRED (peer->last_rx, now) \
					: EXPIRED (peer->last_xmit, now))

/* Releases peers list entries */
MiredoRelay::~MiredoRelay (void)
{
	struct peer *p = head;

	while (p != NULL)
	{
		struct peer *buf = p->next;
		if (p->queue != NULL)
			delete p->queue;
		delete p;
		p = buf;
	}
}


/* 
 * Allocates a peer entry. It is up to the caller to fill informations
 * correctly.
 */
struct MiredoRelay::peer *MiredoRelay::AllocatePeer (void)
{
	time_t now;
	time (&now);

	/* Tries to recycle a timed-out peer entry */
	for (struct peer *p = head; p != NULL; p = p->next)
		if (ENTRY_EXPIRED (p, now))
			return p;

	/* Otherwise allocates a new peer entry */
	struct peer *p;
	try
	{
		p = new struct peer;
	}
	catch (...)
	{
		return NULL;
	}

	/* Puts new entry at the head of the list */
	p->next = head;
	head = p;
	return p;
}


/*
 * Returns a pointer to the first peer entry matching <addr>,
 * or NULL if none were found.
 */
struct MiredoRelay::peer *MiredoRelay::FindPeer (const struct in6_addr *addr)
{
	time_t now;

	time(&now);

	for (struct peer *p = head; p != NULL; p = p->next)
		if (memcmp (&p->addr, addr, sizeof (struct in6_addr)) == 0)
			if (!ENTRY_EXPIRED (p, now))
				return p; // found!
	
	return NULL;
}


/*
 * Sends a Teredo Bubble to the server specified in <dst>.
 * Returns 0 on success, -1 on error.
 */
int MiredoRelay::SendBubble (const union teredo_addr *dst) const
{
	uint32_t dest_ip = dst->teredo.server_ip;
	if (dest_ip && is_ipv4_global_unicast (dest_ip))
	{
		struct ip6_hdr hdr;

		hdr.ip6_flow = htonl (0x60000000);
		hdr.ip6_plen = 0;
		hdr.ip6_nxt = IPPROTO_NONE;
		hdr.ip6_hlim = 255;
		memcpy (&hdr.ip6_src, &myaddr, sizeof (hdr.ip6_src));
		memcpy (&hdr.ip6_dst, &dst->ip6, sizeof (hdr.ip6_dst));

		return sock->SendPacket (&hdr, sizeof (hdr),
				dest_ip, htons (IPPORT_TEREDO));
	}

	return 0;
}


/*
 * Returs true if the packet whose header is passed as a parameter looks
 * like a Teredo bubble to this very relay, false otherwise
 * (It is assumed to be a valid IPv6 packet comming from a Teredo node).
 */
bool MiredoRelay::IsBubble (const struct ip6_hdr *hdr) const
{
	return ((hdr->ip6_plen == 0) && (hdr->ip6_nxt == IPPROTO_NONE)
		&& !memcmp (&hdr->ip6_dst, &myaddr, sizeof (myaddr)));
}


/*
 * Handles a packet coming from the IPv6 Internet, toward a Teredo node
 * (as specified per paragraph 5.4.1).
 * Returns 0 on success, -1 on error.
 */
int MiredoRelay::TransmitPacket (void)
{
	size_t length;
	const uint8_t *buf = tunnel->GetPacket (length);
	struct ip6_hdr ip6;

	if ((length < sizeof (ip6)) || (length > 65507))
		return 0;
	
	memcpy (&ip6, buf, sizeof (ip6_hdr));

	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((sizeof (ip6) + ntohs (ip6.ip6_plen)) != length))
		return 0; // invalid IPv6 packet

	union teredo_addr addr;
	memcpy (&addr.ip6, &ip6.ip6_dst, sizeof (struct in6_addr));

	/* Initial destination address checks */
	if (addr.teredo.prefix != htonl (TEREDO_PREFIX))
	{
		syslog (LOG_WARNING,
			_("Dropped packet with non-Teredo address"
			" (prefix %08x instead of %08x);"
			" Possible routing table misconfiguration."),
			addr.teredo.prefix, TEREDO_PREFIX);
		return 0;
	}

	if (!is_ipv4_global_unicast (~addr.teredo.client_ip))
		return 0;

	/* Case 1 (paragraph 5.4.1) */
	struct peer *p = FindPeer (&addr.ip6);
	{
		struct in_addr a;
		a.s_addr = ~addr.teredo.client_ip;
		syslog (LOG_DEBUG, "DEBUG; packet for %s:%hu\n", inet_ntoa (a),
				~addr.teredo.client_port);
	}
	if (p != NULL)
	{
		if (p->flags.flags.trusted)
		{
			time (&p->last_rx);
			syslog (LOG_DEBUG, "DEBUG: xmit packet to trusted peer\n");
			return sock->SendPacket (buf, length, p->mapped_addr,
							p->mapped_port);
		}
	}
	else
	{
		// Creates an entry
		p = AllocatePeer ();
		if (p == NULL)
		{
			syslog (LOG_ERR, _("Dropped packet: %m\n"));
			return -1;
		}
		syslog (LOG_DEBUG, "DEBUG: allocated new peer\n");
		memcpy (&p->addr, &addr.ip6, sizeof (addr.ip6));
		p->mapped_addr = ~addr.teredo.client_ip;
		p->mapped_port = ~addr.teredo.client_port;
		p->flags.all_flags = 0;
		time (&p->last_xmit);
		p->queue = NULL;
	}

	/* Case 2 */
	/* TODO: send bubble if behind restricted NAT */
	if (IN6_IS_ADDR_TEREDO_CONE (&addr.ip6))
	{
		syslog (LOG_DEBUG, "DEBUG: xmit to new cone peer\n");
		p->flags.flags.trusted = 1;
		return sock->SendPacket (buf, length, p->mapped_addr,
						p->mapped_port);
	}

	/* Case 3 */
	/* TODO: enqueue more than one packet 
	 * (and do this in separate functions) */
	syslog (LOG_DEBUG, "DEBUG: xmit bubble to untrusted non-cone peer's server\n");
	if (p->queue == NULL)
	{
		try
		{
			p->queue = new uint8_t[length];
		}
		catch (...)
		{
			p->queue = NULL;
		}

		if (p->queue != NULL)
		{
			syslog (LOG_DEBUG, "DEBUG: Packet queued for later delivery\n");
			memcpy (p->queue, buf, length);
			p->queuelen = length;
		}
		else
			syslog (LOG_WARNING,
				_("Packet queueing problem: %m\n"));
	}
	else
		syslog (LOG_DEBUG, _("FIXME: packet not queued\n"));


	// Sends no more than one bubble every 2 seconds,
	// and 3 bubbles every 30 secondes
	if (p->flags.flags.bubbles < 3)
	{
		time_t now;
		time (&now);

		if (!p->flags.flags.bubbles || ((now - p->last_xmit) >= 2))
		{
			p->flags.flags.bubbles ++;
			memcpy (&p->last_xmit, &now, sizeof (p->last_xmit));
			syslog (LOG_DEBUG, "DEBUG: sending bubble\n");
			return SendBubble (&addr);
		}
	}
	syslog (LOG_DEBUG, "DEBUG: bubbles exceeded\n");
	return 0;
}


/*
 * Handles a packet coming from the IPv4 Internet over Teredo
 * (as specified per paragraph 5.4.2).
 * Returns 0 on success, -1 on error.
 */
int MiredoRelay::ReceivePacket (void)
{
	size_t length;
	const struct ip6_hdr *buf = sock->GetIPv6Header (length);
	struct ip6_hdr ip6;
	union teredo_addr src;

	// Checks packet
	{
		struct in_addr a;

		a.s_addr = sock->GetClientIP ();
		syslog (LOG_DEBUG, "DEBUG: received UDP packet of length %u from %s:%u\n",
			length, inet_ntoa (a), sock->GetClientPort ());
	}
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0; // invalid packet

	memcpy (&ip6, buf, sizeof (ip6));
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6.ip6_plen) + sizeof (ip6)) != length))
		return 0; // malformatted IPv6 packet

	// Checks source IPv6 address
	memcpy (&src, &ip6.ip6_src, sizeof (src));
	if ((src.teredo.prefix != htonl (TEREDO_PREFIX))
	 || !IN6_MATCHES_TEREDO_CLIENT (&src, sock->GetClientIP (),
		 			sock->GetClientPort ()))
		return 0;
	syslog (LOG_DEBUG, "DEBUG: packet is valid and has %u byte(s) of payload\n",
			ntohs (ip6.ip6_plen));

	// Checks peers list
	struct peer *p = FindPeer (&src.ip6);
	/* 
	 * We are explicitly allowed to drop packet from unknown peers
	 * and it surely much safer.
	 */
	if (p == NULL)
	{
		syslog (LOG_DEBUG," DEBUG: peer is UNKNOWN!!\n");
		return 0;
	}
	syslog (LOG_DEBUG, "DEBUG: peer is known!\n");

	p->flags.flags.trusted = p->flags.flags.replied = 1;
	time (&p->last_rx);

	// Dequeues queued packets (TODO: dequeue more than one)
	if (p->queue != NULL)
	{
		syslog (LOG_DEBUG, "DEBUG: sending previously queued packet\n");
		sock->SendPacket (p->queue, p->queuelen, p->mapped_addr,
					p->mapped_port);
		delete p->queue;
		p->queue = NULL;
	}
	

	if (IsBubble (&ip6))
		return 0; // do not relay my own bubbles

	// TODO: check "range of IPv6 adresses served by the relay"
	// (which may for example be, at most, 2000::/3)
	syslog (LOG_DEBUG, "DEBUG: sending packet!\n");
	return tunnel->SendPacket (buf, length);
}


