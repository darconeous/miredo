/*
 * relay.cpp - Teredo relay core
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
#include <time.h>
#include <assert.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h> // ICMP6_DST_UNREACH_*
#include <syslog.h>

#include <libteredo/teredo.h>
#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include <libteredo/relay-udp.h>

#include "packets.h"
#include <libteredo/relay.h>
#include "peerlist.h"
#ifdef MIREDO_TEREDO_CLIENT
# include "security.h"
# include "maintain.h"
#endif

#define TEREDO_TIMEOUT 30 // seconds

// is_valid_teredo_prefix (PREFIX_UNSET) MUST return false
#define PREFIX_UNSET 0xffffffff


TeredoRelay::TeredoRelay (uint32_t pref, uint16_t port, uint32_t ipv4,
                          bool cone)
	:  allowCone (false)
{
	maintenance.state.addr.teredo.prefix = pref;
	maintenance.state.addr.teredo.server_ip = 0;
	if (cone)
	{
		maintenance.state.cone = true;
		maintenance.state.addr.teredo.flags = htons (TEREDO_FLAG_CONE);
	}
	else
	{
		maintenance.state.cone = false;
		maintenance.state.addr.teredo.flags = 0;
	}
	/* that doesn't really need to match our mapping - the address is only used
	 * to send Unreachable message */
	maintenance.state.addr.teredo.client_port = ~port;
	maintenance.state.addr.teredo.client_ip = ~ipv4;

	sock.ListenPort (port, ipv4);

	list.ptr = NULL;
	list.peerNumber = 0;

	maintenance.state.up = true;

#ifdef MIREDO_TEREDO_CLIENT
	server_ip2 = 0;
	maintenance.relay = NULL;
}


TeredoRelay::TeredoRelay (uint32_t ip, uint32_t ip2,
                          uint16_t port, uint32_t ipv4)
	: allowCone (false)
{
	/*syslog (LOG_DEBUG, "Peer size: %u bytes", sizeof (peer));*/
	if (!is_ipv4_global_unicast (ip) || !is_ipv4_global_unicast (ip2))
		syslog (LOG_WARNING, _("Server has a non global IPv4 address. "
		                       "It will most likely not work."));

	maintenance.state.mtu = 1280;
	maintenance.state.addr.teredo.prefix = PREFIX_UNSET;
	maintenance.state.addr.teredo.server_ip = ip;
	maintenance.state.addr.teredo.flags = htons (TEREDO_FLAG_CONE);
	maintenance.state.addr.teredo.client_ip = 0;
	maintenance.state.addr.teredo.client_port = 0;
	maintenance.state.up = false;

	server_ip2 = ip2;

	list.ptr = NULL;
	list.peerNumber = 0;

	maintenance.relay = NULL;
	if (sock.ListenPort (port, ipv4) == 0)
	{
		maintenance.relay = this;
		if (teredo_maintenance_start (&maintenance))
			maintenance.relay = NULL;
	}

#endif /* ifdef MIREDO_TEREDO_CLIENT */
}

/* Releases peers list entries */
TeredoRelay::~TeredoRelay (void)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (maintenance.relay != NULL)
		teredo_maintenance_stop (&maintenance);
#endif

	TeredoRelay::peer::DestroyList (list.ptr);
}


/*
 * Sends an ICMPv6 Destination Unreachable error to the IPv6 Internet.
 * Unfortunately, this will use a local-scope address as source, which is not
 * quite good.
 */
unsigned TeredoRelay::IcmpRateLimitMs = 100;

int
TeredoRelay::SendUnreach (int code, const void *in, size_t inlen)
{
	static struct
	{
		pthread_mutex_t lock;
		int count;
		time_t last;
	} ratelimit = { PTHREAD_MUTEX_INITIALIZER, 1, 0 };
	struct
	{
		struct ip6_hdr hdr;
		uint8_t fill[1280 - sizeof (struct ip6_hdr)];
	} buf;
	time_t now;

	/* ICMPv6 rate limit */
	time (&now);
	pthread_mutex_lock (&ratelimit.lock);
	if (memcmp (&now, &ratelimit.last, sizeof (now)))
	{
		memcpy (&ratelimit.last, &now, sizeof (now));
		ratelimit.count =
			IcmpRateLimitMs ? (int)(1000 / IcmpRateLimitMs) : -1;
	}

	if (ratelimit.count == 0)
	{
		/* rate limit exceeded */
		pthread_mutex_unlock (&ratelimit.lock);
		return 0;
	}
	if (ratelimit.count > 0)
		ratelimit.count--;
	pthread_mutex_unlock (&ratelimit.lock);

	size_t outlen = BuildICMPv6Error (&buf.hdr, &maintenance.state.addr.ip6,
	                                  ICMP6_DST_UNREACH, code, in, inlen);
	return outlen ? SendIPv6Packet (&buf, outlen) : 0;
}


#ifdef MIREDO_TEREDO_CLIENT
bool TeredoRelay::peer::CountPing (void)
{
	time_t now;
	bool res;

	time (&now);

	if (pings == 0)
		res = true;
	else if (pings == 3)
		res = false;
	else
	/*
	 * NOTE/FIXME:
	 * We hereby assume that expiry does not change.
	 * In practice, the value may increase. In that case,
	 * It will increase the delay of 2 seconds between pings
	 * to something longer, which is allowed (2 seconds is a
	 * minimum).
	 */
		res = ((unsigned)now > expiry - next_ping);

	if (res)
	{
		int next;

		next = expiry - (now + 2);
		pings ++;
		next_ping = next < 31 ? next : 30;
	}
	return res;
}


int
TeredoRelay::PingPeer (const struct in6_addr *a, peer *p) const
{
	if (p->CountPing ())
		return SendPing (sock, &maintenance.state.addr, a) ? 0 : -1;
	return -1;
}
#endif


/*
 * Returs true if the packet whose header is passed as a parameter looks
 * like a Teredo bubble.
 */
inline bool IsBubble (const struct ip6_hdr *hdr)
{
	return (hdr->ip6_plen == 0) && (hdr->ip6_nxt == IPPROTO_NONE);
}


bool TeredoRelay::peer::CountBubble (void)
{
	/* Same code as CountPing above */
	time_t now;
	bool res;

	time (&now);

	if (bubbles == 0)
		res = true;
	else if (bubbles == 3)
		res = false;
	else
		res = ((unsigned)now > expiry - next_bubble);

	if (res)
	{
		int next;

		next = expiry - (now + 2);
		bubbles ++;
		next_bubble = next < 31 ? next : 30;
	}
	return res;
}


/*
 * Handles a packet coming from the IPv6 Internet, toward a Teredo node
 * (as specified per paragraph 5.4.1). That's what the specification calls
 * "Packet transmission".
 *
 * It is assumed that the packet is valid (if not, it will be dropped by
 * the receiving Teredo peer). It is furthermore assumed that the packet
 * is at least 40 bytes long (room for the IPv6 header and that it is
 * properly aligned.
 *
 * The packet size should not exceed the MTU (1280 bytes by default).
 * In any case, sending will fail if the packets size exceeds 65507 bytes
 * (maximum size for a UDP packet's payload).
 *
 * Returns 0 on success, -1 on error.
 */
int TeredoRelay::SendPacket (const struct ip6_hdr *packet, size_t length)
{
	const union teredo_addr *dst = (union teredo_addr *)&packet->ip6_dst,
				*src = (union teredo_addr *)&packet->ip6_src;

	/* FIXME: race condition with maintenance procedure */
	uint32_t prefix = GetPrefix ();

	/* Drops multicast destination, we cannot handle these */
	if ((dst->ip6.s6_addr[0] == 0xff)
	/* Drops multicast source, these are invalid */
	 || (src->ip6.s6_addr[0] == 0xff))
		return 0;

	if (IsRelay ())
	{
		if (dst->teredo.prefix != prefix)
			/*
			 * If we are not a qualified client, ie. we have no server
			 * IPv4 address to contact for direct IPv6 connectivity, we
			 * cannot route packets toward non-Teredo IPv6 addresses, and
			 * we are not allowed to do it by the specification either.
			 *
			 * NOTE:
			 * The specification mandates silently ignoring such
			 * packets. However, this only happens in case of
			 * misconfiguration, so I believe it could be better to
			 * notify the user. An alternative is to send an ICMPv6 error
			 * back to the kernel.
			 */
				return SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
	}
#ifdef MIREDO_TEREDO_CLIENT
	else
	{
		if (prefix == PREFIX_UNSET) /* not qualified */
			return SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);

		if ((dst->teredo.prefix != prefix)
		 && (src->teredo.prefix != prefix))
			/*
			 * Routing packets not from a Teredo client,
			 * neither toward a Teredo client is NOT allowed through a
			 * Teredo tunnel. The Teredo server will reject the packet.
			 *
			 * We also drop link-local unicast and multicast packets as
			 * they can't be routed through Teredo properly.
			 */
			return SendUnreach (ICMP6_DST_UNREACH_ADMIN, packet, length);
	}
#endif

	peer *p = FindPeer (&dst->ip6);

	if (p != NULL)
	{
		/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
		if (p->trusted)
		{
			/* Already known -valid- peer */
			p->TouchTransmit ();
			return sock.SendPacket (packet, length, p->mapped_addr,
			                        p->mapped_port);
		}
	}

#ifdef MIREDO_TEREDO_CLIENT
	/* Unknown or untrusted peer */
	if (dst->teredo.prefix != prefix)
	{
		/* Unkown or untrusted non-Teredo node */
		assert (IsClient ());

		/* Client case 2: direct IPv6 connectivity test */
		// TODO: avoid code duplication
		if (p == NULL)
		{
			p = AllocatePeer (&dst->ip6);
			if (p == NULL)
				return -1; // memory error

			p->mapped_port = 0;
			p->mapped_addr = 0;
			p->trusted = p->replied = p->bubbles = p->pings = 0;
			p->TouchTransmit ();
		}

		p->QueueOutgoing (packet, length);
		if (PingPeer (&dst->ip6, p))
			SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
		return 0;
	}
#endif

	/* Unknown or untrusted Teredo client */

	// Ignores Teredo clients with incorrect server IPv4
	uint32_t peer_server = IN6_TEREDO_SERVER (dst);
	if (!is_ipv4_global_unicast (peer_server) || (peer_server == 0))
		return 0;

	/* Client case 3: TODO: implement local discovery */

	if (p == NULL)
	{
		/* Unknown Teredo clients */

		// Creates a new entry
		p = AllocatePeer (&dst->ip6);
		if (p == NULL)
			return -1; // insufficient memory

		p->SetMapping (IN6_TEREDO_IPV4 (dst), IN6_TEREDO_PORT (dst));
		p->trusted = p->replied = p->bubbles = p->pings = 0;

		// NOTE: we call TouchTransmit() but if the peer is non-cone, and
		// we are cone, we don't actually send a packet
		p->TouchTransmit ();

		/* Client case 4 & relay case 2: new cone peer */
		if (allowCone && IN6_IS_TEREDO_ADDR_CONE (dst))
		{
			p->trusted = 1;
			return sock.SendPacket (packet, length, p->mapped_addr,
			                        p->mapped_port);
		}
	}

	/* Client case 5 & relay case 3: untrusted non-cone peer */
	p->QueueOutgoing (packet, length);

	// Sends no more than one bubble every 2 seconds,
	// and 3 bubbles every 30 secondes
	if (p->CountBubble ())
	{
		/*
		 * Open the return path if we are behind a
		 * restricted NAT.
		 */
		if (!IsCone () && SendBubble (sock, &dst->ip6, false, false))
			return -1;

		return SendBubble (sock, &dst->ip6, IsCone ());
	}

	// Too many bubbles already sent
	SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
	return 0;
}


/*
 * Handles a packet coming from the Teredo tunnel
 * (as specified per paragraph 5.4.2). That's called "Packet reception".
 * Returns 0 on success, -1 on error.
 * FIXME: use a receive buffer
 */
int TeredoRelay::ReceivePacket (void)
{
	TeredoPacket packet;

	if (sock.ReceivePacket (packet))
		return -1;

	size_t length;
	const uint8_t *buf = packet.GetIPv6Packet (length);
	struct ip6_hdr ip6;

	// Checks packet
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0; // invalid packet

	memcpy (&ip6, buf, sizeof (ip6));
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6.ip6_plen) + sizeof (ip6)) != length))
		return 0; // malformatted IPv6 packet

#ifdef MIREDO_TEREDO_CLIENT
	/* FIXME race condition */
	if (IsClient () && !maintenance.state.up)
	{
		ProcessQualificationPacket (&packet);
		return 0;
	}

	/* Maintenance */
	/* FIXME race condition */
	if (IsClient () && IsServerPacket (&packet))
	{
		if (ProcessMaintenancePacket (&packet))
			return 0;

		const struct teredo_orig_ind *ind = packet.GetOrigInd ();
		if (ind != NULL)
		{
			SendBubble (sock, ~ind->orig_addr, ~ind->orig_port, &ip6.ip6_dst,
			            &ip6.ip6_src);
			if (IsBubble (&ip6))
				return 0; // don't pass bubble to kernel
		}
		else
		if (IsBubble (&ip6))
		{
			/*
			 * Some servers do not insert an origin indication.
			 * When the source IPv6 address is a Teredo address,
			 * we can guess the mapping. Otherwise, we're stuck.
			 */
		 	if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == GetPrefix ())
				SendBubble (sock, IN6_TEREDO_IPV4 (&ip6.ip6_src),
				            IN6_TEREDO_PORT (&ip6.ip6_src), &ip6.ip6_dst,
				            &ip6.ip6_src);
			else
			{
				syslog (LOG_WARNING, _("Ignoring invalid bubble: "
				        "your Teredo server is probably buggy."));
			}
			return 0; // don't pass bubble to kernel
		}

		/*
		 * Normal reception of packet must only occur if it does not
		 * come from the server, as specified. However, it is not
		 * unlikely that our server is a relay too. Hence, we must
		 * further process packets from it.
		 * At the moment, we only drop bubble (see above).
		 * (NOTE: besides, we don't sufficiently check that the packet
		 *  comes from the server, we only check the source port)
		 */
	}
#endif /* MIREDO_TEREDO_CLIENT */

	/*
	 * NOTE/TODO:
	 * In the client case, the spec says we should check that the
	 * destination is our Teredo IPv6 address. However, this library makes
	 * no difference between relay, host-specific relay and client
	 * (it very much sounds like market segmentation to me).
	 * We purposedly leave it up to the kernel to determine whether he
	 * should accept, route, or drop the packet, according to its
	 * configuration. That should be done now if we wanted to.
	 *
	 * In the relay case, it says we should accept packet toward the range
	 * of hosts for which we serve as a Teredo relay, and should otherwise
	 * drop it. That should be done just before sending the packet. That
	 * might be a run-time option.
	 *
	 * It should be noted that dropping packets with link-local
	 * destination here, before further processing, breaks connectivity
	 * with restricted Teredo clients: we send them Teredo bubbles with
	 * a link-local source, to which they reply with Teredo bubbles with
	 * a link-local destination. Indeed, the specification specifies that
	 * the relay MUST look up the peer in the list and update last
	 * reception date even if the destination is incorrect.
	 */
#if 0
	/*
	 * Ensures that the packet destination has an IPv6 Internet scope
	 * (ie 2000::/3). That should be done just before calling
	 * SendIPv6Packet(), but it so much easier to do it now.
	 */
	if ((ip6.ip6_dst.s6_addr[0] & 0xe0) != 0x20)
		return 0; // must be discarded, or ICMPv6 error (?)

	if ((ip6.ip6_dst.s6_addr[0] & 0xfe) == 0xfe)
		return 0;
#endif
	/*
	 * Packets with a link-local source address are purposedly dropped to
	 * prevent the kernel from receiving faked Router Advertisement which
	 * could break IPv6 routing completely. Router advertisements MUST
	 * have a link-local source address (RFC 2461).
	 *
	 * Note: only Linux defines convenient s6_addr16, so we don't use it.
	 *
	 * In no case are relays and clients supposed to receive and process
	 * such a packet *except* from their server (that processing is done
	 * in the "Maintenance" case above), or bubbles from other restricted
	 * clients/relays, which can safely be ignored (so long as the other
	 * bubble sent through the server is not ignored).
	 *
	 * This check is not part of the Teredo specification.
	 */
	if ((((uint16_t *)ip6.ip6_src.s6_addr)[0] & 0xfec0) == 0xfe80)
		return 0;

	/* Actual packet reception, either as a relay or a client */

	// Checks source IPv6 address / looks up peer in the list:
	peer *p = FindPeer (&ip6.ip6_src);

	if (p != NULL)
	{
		// Client case 1 (trusted node or (trusted) Teredo client):
		if (p->trusted
		 && (packet.GetClientIP () == p->mapped_addr)
		 && (packet.GetClientPort () == p->mapped_port))
		{
			p->TouchReceive ();
			return SendIPv6Packet (buf, length);
		}

#ifdef MIREDO_TEREDO_CLIENT
		// Client case 2 (untrusted non-Teredo node):
		if ((!p->trusted) && CheckPing (packet))
		{
			p->trusted = 1;

			p->SetMappingFromPacket (packet);
			p->TouchReceive ();
			p->Dequeue (this);
			return 0;
		}
#endif /* ifdef MIREDO_TEREDO_CLIENT */
	}

	/*
	 * At this point, we have either a trusted mapping mismatch,
	 * an unlisted peer, or an un-trusted client peer.
	 */
	if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == GetPrefix ())
	{
		// Client case 3 (unknown or untrusted matching Teredo client):
		if (IN6_MATCHES_TEREDO_CLIENT (&ip6.ip6_src,
						packet.GetClientIP (),
						packet.GetClientPort ()))
		{
			if (p == NULL)
			{
#ifdef MIREDO_TEREDO_CLIENT
				if (IsClient ())
				{
					// TODO: do not duplicate this code
					p = AllocatePeer (&ip6.ip6_src);
					if (p == NULL)
						return -1; // insufficient memory

					p->SetMapping (IN6_TEREDO_IPV4 (&ip6.ip6_src),
				    	           IN6_TEREDO_PORT (&ip6.ip6_src));
					p->trusted = p->replied = p->bubbles = p->pings = 0;
				}
				else
#endif
				/*
				 * Relays are explicitly allowed to drop packets from
				 * unknown peers. It prevents routing of packet through the
				 * wrong relay. If the peer is known, with the current
				 * libteredo implementation, it will be able to use a relay to
				 * reach any destination. Not too good (FIXME).
				 */
					return 0;

			}
			else
				p->Dequeue (this);

			p->trusted = 1;
			p->TouchReceive ();

			if (IsBubble (&ip6))
				return 0; // discard Teredo bubble
			return SendIPv6Packet (buf, length);
		}

		// TODO: remove this line if we implement local teredo
		return 0;
	}

#ifdef MIREDO_TEREDO_CLIENT
	// Relays only accept packets from Teredo clients;
	if (IsRelay ())
		return 0;

	// TODO: implement client cases 4 & 5 for local Teredo

	/*
	 * Default: Client case 6:
	 * (unknown non-Teredo node or Tereco client with incorrect mapping):
	 * We should be cautious when accepting packets there, all the
	 * more as we don't know if we are a really client or just a
	 * qualified relay (ie. whether the host's default route is
	 * actually the Teredo tunnel).
	 */

	// TODO: avoid code duplication (direct IPv6 connectivity test)
	if (p == NULL)
	{
		p = AllocatePeer (&ip6.ip6_src);
		if (p == NULL)
			return -1; // memory error

		p->mapped_port = 0;
		p->mapped_addr = 0;
		p->trusted = p->replied = p->bubbles = p->pings = 0;
	}
#if 0
	else
	if (p->trusted)
		/*
		 * Trusted node, but mismatch. That can only happen if:
		 *  - someone is spoofing the node,
		 *  - the node has changed relay (very unlikely),
		 *  - unfortunate node has multiple relay doing load-balancing
		 *    (that is not supposed to work with the Teredo protocol).
		 */
		return 0;
#endif

	p->QueueIncoming (buf, length);
	p->TouchReceive ();

	return PingPeer (&ip6.ip6_src, p);
#else /* ifdef MIREDO_TEREDO_CLIENT */
	return 0;
#endif
}
