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
#include <pthread.h>

#include "teredo.h"
#include "v4global.h" // is_ipv4_global_unicast()
#include "teredo-udp.h"

#include "packets.h"
#include "relay.h"
#include "peerlist.h"
#ifdef MIREDO_TEREDO_CLIENT
# include "security.h"
# include "maintain.h"
#endif

#define TEREDO_TIMEOUT 30 // seconds

// is_valid_teredo_prefix (PREFIX_UNSET) MUST return false
#define PREFIX_UNSET 0xffffffff

unsigned TeredoRelay::MaxPeers = 1024;


TeredoRelay::TeredoRelay (uint32_t pref, uint16_t port, uint32_t ipv4,
                          bool cone)
	:  allowCone (false)
{
	state.addr.teredo.prefix = pref;
	state.addr.teredo.server_ip = 0;
	if (cone)
	{
		state.cone = true;
		state.addr.teredo.flags = htons (TEREDO_FLAG_CONE);
	}
	else
	{
		state.cone = false;
		state.addr.teredo.flags = 0;
	}

	/* that doesn't really need to match our mapping -
	 * the address is only used to send Unreachable message... with the
	 * old method that is no longer supported (the one that involves
	 * building the IPv6 header as well as the ICMPv6 header) */
	state.addr.teredo.client_port = ~port;
	state.addr.teredo.client_ip = ~ipv4;

#ifdef MIREDO_TEREDO_CLIENT
	server_ip2 = 0;
	maintenance = NULL;
#endif

	state.up = true;

	fd = teredo_socket (ipv4, port);
	if (fd != -1)
	{
		list = teredo_list_create (MaxPeers);
		if (list != NULL)
			return; /* success */
		teredo_close (fd);
	}

	/* failure */
	throw new (void *)(NULL);
}


#ifdef MIREDO_TEREDO_CLIENT
TeredoRelay::TeredoRelay (uint32_t ip, uint32_t ip2,
                          uint16_t port, uint32_t ipv4)
	: allowCone (false), maintenance (NULL)
{

	/*syslog (LOG_DEBUG, "Peer size: %u bytes", sizeof (peer));*/
	if (!is_ipv4_global_unicast (ip) || !is_ipv4_global_unicast (ip2))
		syslog (LOG_WARNING, _("Server has a non global IPv4 address. "
		                       "It will most likely not work."));

	state.mtu = 1280;
	state.addr.teredo.prefix = PREFIX_UNSET;
	state.addr.teredo.server_ip = ip;
	state.addr.teredo.flags = htons (TEREDO_FLAG_CONE);
	state.addr.teredo.client_ip = 0;
	state.addr.teredo.client_port = 0;
	state.up = false;

	server_ip2 = ip2;

	fd = teredo_socket (ipv4, port);
	if (fd != -1)
	{
		list = teredo_list_create (MaxPeers);
		if (list != NULL)
		{
			maintenance = libteredo_maintenance_start (this, &state);
			if (maintenance != NULL)
				return; /* success */

			teredo_list_destroy (list);
		}
		teredo_close (fd);
	}

	/* failure */
	throw new (void *)(NULL);
}
#endif /* ifdef MIREDO_TEREDO_CLIENT */

/* Releases peers list entries */
TeredoRelay::~TeredoRelay (void)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (maintenance != NULL)
		libteredo_maintenance_stop (maintenance);
#endif

	teredo_close (fd);
	teredo_list_destroy (list);
}


/*
 * Sends an ICMPv6 Destination Unreachable error to the IPv6 Internet.
 * Unfortunately, this will use a local-scope address as source, which is not
 * quite good.
 */
unsigned TeredoRelay::IcmpRateLimitMs = 100;

void
TeredoRelay::SendUnreach (int code, const void *in, size_t len)
{
	/* FIXME: should probably not be static */
	static struct
	{
		pthread_mutex_t lock;
		int count;
		time_t last;
	} ratelimit = { PTHREAD_MUTEX_INITIALIZER, 1, 0 };
	struct
	{
		struct icmp6_hdr hdr;
		char fill[1280 - sizeof (struct ip6_hdr) - sizeof (struct icmp6_hdr)];
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
		return;
	}
	if (ratelimit.count > 0)
		ratelimit.count--;
	pthread_mutex_unlock (&ratelimit.lock);

	len = BuildICMPv6Error (&buf.hdr, ICMP6_DST_UNREACH, code, in, len);
	(void)EmitICMPv6Error (&buf.hdr, len,
	                       &((const struct ip6_hdr *)in)->ip6_src);
}

void
TeredoRelay::EmitICMPv6Error (const void *packet, size_t length,
							  const struct in6_addr *dst)
{
	/* TODO should be implemented with BuildIPv6Error() */
	/* that is currently dead code */
#if 0
	size_t outlen = BuildIPv6Error (&buf.hdr, &state.addr.ip6,
	                                ICMP6_DST_UNREACH, code, in, inlen);
	(void)SendIPv6Packet (&buf, outlen);
#endif
}


#ifdef MIREDO_TEREDO_CLIENT
/*
 * Returns 0 if a ping may be sent, -1 if no more ping may be sent,
 * 1 if a ping may be sent later.
 */
int teredo_peer::CountPing (void)
{
	time_t now;
	int res;

	time (&now);

	if (pings == 0)
		res = 0;
	else if (pings == 3)
		res = -1;
	else
	/*
	 * NOTE/FIXME:
	 * We hereby assume that expiry does not change.
	 * In practice, the value may increase. In that case,
	 * It will increase the delay of 2 seconds between pings
	 * to something longer, which is allowed (2 seconds is a
	 * minimum).
	 */
		res = ((unsigned)now > expiry - next_ping) ? 0 : 1;

	if (res == 0)
	{
		int next;

		next = expiry - (now + 2);
		pings ++;
		next_ping = next < 31 ? next : 30;
	}
	
	return res;
}


int
TeredoRelay::PingPeer (const struct in6_addr *a, teredo_peer *p) const
{
	int res = p->CountPing ();
	if (res == 0)
		return SendPing (fd, &state.addr, a);
	return res;
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


/*
 * Returns 0 if a bubble may be sent, -1 if no more bubble may be sent,
 * 1 if a bubble may be sent later.
 */
int teredo_peer::CountBubble (void)
{
	/* Pretty much the same code as CountPing above */
	time_t now;
	int res;

	time (&now);

	if (bubbles == 0)
		res = 0;
	else if (bubbles == 3)
		res = -1;
	else
		res = ((unsigned)now > expiry - next_bubble) ? 0 : 1;

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
		{
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
			SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
			return 0;
		}
	}
#ifdef MIREDO_TEREDO_CLIENT
	else
	{
		if (prefix == PREFIX_UNSET) /* not qualified */
		{
			SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
			return 0;
		}

		if ((dst->teredo.prefix != prefix)
		 && (src->teredo.prefix != prefix))
		{
			/*
			 * Routing packets not from a Teredo client,
			 * neither toward a Teredo client is NOT allowed through a
			 * Teredo tunnel. The Teredo server will reject the packet.
			 *
			 * We also drop link-local unicast and multicast packets as
			 * they can't be routed through Teredo properly.
			 */
			SendUnreach (ICMP6_DST_UNREACH_ADMIN, packet, length);
			return 0;
		}
	}
#endif

	if (dst->teredo.prefix == prefix)
	{
		/*
		 * Ignores Teredo clients with incorrect server IPv4.
		 * This check is only specified for client case 4 & 5.
		 * That said, it can never fail in the other client cases (either
		 * because the peer is already known which means it already passed
		 * this check, or because the peer is not a Teredo client.
		 * As for the relay, I consider the check should also be done, even if
		 * it wasn't specified (TBD: double check the spec).
		 * Doing the check earlier, while it has an additionnal cost, makes
		 * sure that the peer will be added to the list if it is not already
		 * in it, which avoids a double peer list lookup (failed lookup, then
		 * insertion), which is a big time saver under heavy load.
		 */
		uint32_t peer_server = IN6_TEREDO_SERVER (dst);
		if (!is_ipv4_global_unicast (peer_server) || (peer_server == 0))
			return 0;
	}

	bool created;
	teredo_peer *p = teredo_list_lookup (list, &dst->ip6, &created);
	if (p == NULL)
		return -1; /* error */

	if (!created)
	{
		/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
		if (p->trusted)
		{
			int res;

			/* Already known -valid- peer */
			p->TouchTransmit ();
			res = teredo_send (fd, packet, length, p->mapped_addr,
			                   p->mapped_port) == (int)length ? 0 : -1;
			teredo_list_release (list);
			return res;
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
		if (created)
		{
			p->mapped_port = 0;
			p->mapped_addr = 0;
			p->trusted = p->replied = p->bubbles = p->pings = 0;
			p->TouchTransmit ();
		}

		p->QueueOutgoing (packet, length);
		if (PingPeer (&dst->ip6, p) == -1)
			SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);

		teredo_list_release (list);
		return 0;
	}
#endif

	/* Unknown or untrusted Teredo client */

	/* Client case 3: TODO: implement local discovery */

	if (created)
	{
		/* Unknown Teredo clients */
		p->SetMapping (IN6_TEREDO_IPV4 (dst), IN6_TEREDO_PORT (dst));
		p->trusted = p->replied = p->bubbles = p->pings = 0;

		// NOTE: we call TouchTransmit() but if the peer is non-cone, and
		// we are cone, we don't actually send a packet
		p->TouchTransmit ();

		/* Client case 4 & relay case 2: new cone peer */
		if (allowCone && IN6_IS_TEREDO_ADDR_CONE (dst))
		{
			int res;

			p->trusted = 1;
			res = teredo_send (fd, packet, length, p->mapped_addr,
			                   p->mapped_port) == (int)length ? 0 : -1;
			teredo_list_release (list);
			return res;
		}
	}

	/* Client case 5 & relay case 3: untrusted non-cone peer */
	p->QueueOutgoing (packet, length);

	// Sends no more than one bubble every 2 seconds,
	// and 3 bubbles every 30 secondes
	switch (p->CountBubble ())
	{
		case 0:
		{
			/*
			* Open the return path if we are behind a
			* restricted NAT.
			*/
			if (!IsCone () && SendBubbleFromDst (fd, &dst->ip6, false, false))
			{
				teredo_list_release (list);
				return -1;
			}
	
			int res = SendBubbleFromDst (fd, &dst->ip6, IsCone (), true);
			teredo_list_release (list);
			return res;
		}

		case -1:
			// Too many bubbles already sent
			SendUnreach (ICMP6_DST_UNREACH_ADDR, packet, length);
		//case 1: -- between two bubbles -- nothing to do
	}

	teredo_list_release (list);
	return 0;
}


/*
 * Handles a packet coming from the Teredo tunnel
 * (as specified per paragraph 5.4.2). That's called "Packet reception".
 * Returns 0 on success, -1 on error.
 */
int TeredoRelay::ReceivePacket (void)
{
	struct teredo_packet packet;

	if (teredo_recv (fd, &packet))
		return -1;

	const uint8_t *buf = packet.ip6;
	size_t length = packet.ip6_len;
	struct ip6_hdr ip6;

	// Checks packet
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0; // invalid packet

	memcpy (&ip6, buf, sizeof (ip6));
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6.ip6_plen) + sizeof (ip6)) != length))
		return 0; // malformatted IPv6 packet

#ifdef MIREDO_TEREDO_CLIENT
	/* Maintenance */
	/* FIXME race condition */
	if (IsClient () && (packet.source_port == htons (IPPORT_TEREDO)))
	{
		if (packet.auth_nonce != NULL)
		{
			libteredo_maintenance_process (maintenance, &packet);
			return 0;
		}
		else
		if (!state.up)
		{
			/* Not qualified -> do not accept incoming packets */
			return 0;
		}
		else
		if (packet.source_ipv4 != GetServerIP ())
		{
			/* Not from primary server IPv4 address
			   -> force normal packet reception */
		}
		else
		if (packet.orig_ipv4)
		{
			SendBubble (fd, packet.orig_ipv4, packet.orig_port,
			            &ip6.ip6_dst, &ip6.ip6_src);
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
				/* FIXME: use SendBubbleFromDst if applicable */
				SendBubble (fd, IN6_TEREDO_IPV4 (&ip6.ip6_src),
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
		 */
	}
	else if (!state.up)
		/* Not qualified -> do not accept incoming packets */
		return 0;
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
	teredo_peer *p = teredo_list_lookup (list, &ip6.ip6_src, NULL);

	if (p != NULL)
	{
		// Client case 1 (trusted node or (trusted) Teredo client):
		if (p->trusted
		 && (packet.source_ipv4 == p->mapped_addr)
		 && (packet.source_port == p->mapped_port))
		{
			p->TouchReceive ();
			teredo_list_release (list);
			return SendIPv6Packet (buf, length);
		}

#ifdef MIREDO_TEREDO_CLIENT
		// Client case 2 (untrusted non-Teredo node):
		if ((!p->trusted) && (CheckPing (&packet) == 0))
		{
			p->trusted = 1;

			p->SetMappingFromPacket (&packet);
			p->TouchReceive ();
			p->Dequeue (this);
			teredo_list_release (list);
			return 0; /* don't pass ping to kernel */
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
		if (IN6_MATCHES_TEREDO_CLIENT (&ip6.ip6_src, packet.source_ipv4,
		                               packet.source_port))
		{
			if (p == NULL)
			{
#ifdef MIREDO_TEREDO_CLIENT
				if (IsClient ())
				{
					bool create;

					// TODO: do not duplicate this code
					p = teredo_list_lookup (list, &ip6.ip6_src, &create);
					/* FIXME: if they were multiple threads, we'd have a race
					 * condition whereby a peer would not be in the list at
					 * the time when teredo_list_lookup() returned NULL above,
					 * but would have been added since then. In that case, the
					 * peer will be partially overriden - make sure that is
					 * safe!
					 */
					/*if (!create) race_condition! */
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
				 * unknown peers. It makes it a little more difficult to route
				 * packets through the wrong relay. The specification leaves
				 * us a choice here. It is arguable whether accepting these
				 * packets would make it easier to DoS the peer list.
				 */
					return 0; // list not locked
			}
			else
				p->Dequeue (this);

			p->trusted = 1;
			p->TouchReceive ();
			teredo_list_release (list);

			if (IsBubble (&ip6))
				return 0; // discard Teredo bubble
			return SendIPv6Packet (buf, length);
		}

		// TODO: remove this line if we implement local teredo
		return 0;
	}

#ifdef MIREDO_TEREDO_CLIENT
	if (IsClient ())
	{
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
			bool create;

			// TODO: do not duplicate this code
			p = teredo_list_lookup (list, &ip6.ip6_src, &create);
			/* FIXME: if they were multiple threads, we'd have a race
			 * condition whereby a peer would not be in the list at
			 * the time when teredo_list_lookup() returned NULL above,
			 * but would have been added since then. In that case, the
			 * peer will be partially overriden - make sure that is
			 * safe!
			 */
			/*if (!create) race_condition! */
			if (p == NULL)
				return -1; // memory error
	
			p->mapped_port = 0;
			p->mapped_addr = 0;
			p->trusted = p->replied = p->bubbles = p->pings = 0;
		}
# if 0
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
# endif
	
		p->QueueIncoming (buf, length);
		p->TouchReceive ();
	
		int res = PingPeer (&ip6.ip6_src, p) ? -1 : 0;
		teredo_list_release (list);
		return res;
	}
#endif /* ifdef MIREDO_TEREDO_CLIENT */

	// Relays don't accept packets not from Teredo clients,
	// nor from mismatching packets
	assert (IsRelay ());
	
	if (p != NULL)
		teredo_list_release (list);

	return 0;
}

