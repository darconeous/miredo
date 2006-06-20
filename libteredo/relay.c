/*
 * relay.c - Teredo relay core
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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

#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdlib.h> // malloc()
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
#include "tunnel.h"
#include "maintain.h"
#include "peerlist.h"
#ifdef MIREDO_TEREDO_CLIENT
# include "security.h"
#endif
#include "debug.h"

struct teredo_tunnel
{
	struct teredo_peerlist *list;
	void *opaque;
#ifdef MIREDO_TEREDO_CLIENT
	struct teredo_maintenance *maintenance;
	
	teredo_state_up_cb up_cb;
	teredo_state_down_cb down_cb;
#endif
	teredo_recv_cb recv_cb;
	teredo_icmpv6_cb icmpv6_cb;

	teredo_state state;
	pthread_rwlock_t state_lock;

	// ICMPv6 rate limiting
	struct
	{
		pthread_mutex_t lock;
		int count;
		time_t last;
	} ratelimit;

	// Asynchronous packet reception
	struct
	{
		pthread_t thread;
		bool running;
	} recv;

	bool allow_cone;
	int fd;
	time_t now;
	pthread_t clock;
};

#ifdef HAVE_LIBJUDY
# define MAX_PEERS 1048576
#else
# define MAX_PEERS 1024
#endif
#define ICMP_RATE_LIMIT_MS 100

#if 0
static unsigned QualificationRetries; // maintain.c
static unsigned QualificationTimeOut; // maintain.c
static unsigned ServerNonceLifetime;  // maintain.c
static unsigned RestartDelay;         // maintain.c

static unsigned MaxQueueBytes;        // peerlist.c
static unsigned MaxPeers;             // here
static unsigned IcmpRateLimitMs;      // here
#endif

/**
 * Rate limiter around ICMPv6 unreachable error packet emission callback.
 *
 * @param code ICMPv6 unreachable error code.
 * @param in IPv6 packet that caused the error.
 * @param len byte length of the IPv6 packet at <in>.
 */
static void
teredo_send_unreach (teredo_tunnel *restrict tunnel, int code,
                     const void *restrict in, size_t len)
{
	struct
	{
		struct icmp6_hdr hdr;
		char fill[1280 - sizeof (struct ip6_hdr) - sizeof (struct icmp6_hdr)];
	} buf;

	/* ICMPv6 rate limit */
	pthread_mutex_lock (&tunnel->ratelimit.lock);
	if (tunnel->now != tunnel->ratelimit.last)
	{
		tunnel->ratelimit.last = tunnel->now;
		tunnel->ratelimit.count =
			ICMP_RATE_LIMIT_MS ? (int)(1000 / ICMP_RATE_LIMIT_MS) : -1;
	}

	if (tunnel->ratelimit.count == 0)
	{
		/* rate limit exceeded */
		pthread_mutex_unlock (&tunnel->ratelimit.lock);
		return;
	}
	if (tunnel->ratelimit.count > 0)
		tunnel->ratelimit.count--;
	pthread_mutex_unlock (&tunnel->ratelimit.lock);

	len = BuildICMPv6Error (&buf.hdr, ICMP6_DST_UNREACH, code, in, len);
	tunnel->icmpv6_cb (tunnel->opaque, &buf.hdr, len,
	                   &((const struct ip6_hdr *)in)->ip6_src);
}

#if 0
/*
 * Sends an ICMPv6 Destination Unreachable error to the IPv6 Internet.
 * Unfortunately, this will use a local-scope address as source, which is not
 * quite good.
 */
void
TeredoRelay::EmitICMPv6Error (const void *packet, size_t length,
							  const struct in6_addr *dst)
{
	/* TODO should be implemented with BuildIPv6Error() */
	/* that is currently dead code */

	/* F-I-X-M-E: using state implies locking */
	size_t outlen = BuildIPv6Error (&buf.hdr, &state.addr.ip6,
	                                ICMP6_DST_UNREACH, code, in, inlen);
	tunnel->recv_cb (tunnel->opaque, &buf, outlen);
}
#endif


#ifdef MIREDO_TEREDO_CLIENT
static void
teredo_state_change (const teredo_state *state, void *self)
{
	teredo_tunnel *tunnel = (teredo_tunnel *)self;

	pthread_rwlock_wrlock (&tunnel->state_lock);
	bool previously_up = tunnel->state.up;
	memcpy (&tunnel->state, state, sizeof (tunnel->state));

	if (tunnel->state.up)
	{
		/*
		 * NOTE: we get an hold on both state and peer list locks here.
		 * As such, in any case, attempting to acquire the state lock while
		 * the peer list is locked is STRICTLY FORBIDDEN to avoid an obvious
		 * inter-locking deadlock.
		 */
		teredo_list_reset (tunnel->list, MAX_PEERS);
		tunnel->up_cb (tunnel->opaque,
		               &tunnel->state.addr.ip6, tunnel->state.mtu);
	}
	else
	if (previously_up)
		tunnel->down_cb (tunnel->opaque);

	/*
	 * NOTE: the lock is retained until here to ensure notifications remain
	 * properly ordered. Unfortunately, we cannot be re-entrant from within
	* up_cb/down_cb.
	 */
	pthread_rwlock_unlock (&tunnel->state_lock);
}

/**
 * @return 0 if a ping may be sent. 1 if one was sent recently
 * -1 if the peer seems unreachable.
 */
static int CountPing (teredo_peer *peer, time_t now)
{
	int res;

	if (peer->pings == 0)
		res = 0;
	// don't test more than 4 times (once + 3 repeats)
	else if (peer->pings >= 4)
		res = -1;
	// test must be separated by at least 2 seconds
	else
	if (((now - peer->last_ping) & 0x1ff) <= 2)
		res = 1;
	else
		res = 0; // can test again!

	if (res == 0)
	{
		peer->last_ping = now;
		peer->pings++;
	}

	return res;
}


static inline bool IsClient (const teredo_tunnel *tunnel)
{
	return tunnel->maintenance != NULL;
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
static int CountBubble (teredo_peer *peer, time_t now)
{
	/* § 5.2.6 - sending bubbles */
	int res;

	if (peer->bubbles > 0)
	{
		if (peer->bubbles >= 4)
		{
			// don't send if 4 bubbles already sent within 300 seconds
			if ((now - peer->last_tx) <= 300)
				res = -1;
			else
			{
				// reset counter every 300 seconds
				peer->bubbles = 0;
				res = 0;
			}
		}
		else
		// don't send if last tx was 2 seconds ago or fewer
		if ((now - peer->last_tx) <= 2)
			res = 1;
		else
			res = 0;
	}
	else
		res = 0;

	if (res == 0)
	{
		peer->last_tx = now;
		peer->bubbles++;
	}

	return res;
}


static inline void SetMappingFromPacket (teredo_peer *peer,
                                         const struct teredo_packet *p)
{
	SetMapping (peer, p->source_ipv4, p->source_port);
}


/**
 * Transmits a packet coming from the IPv6 Internet, toward a Teredo node
 * (as specified per paragraph 5.4.1). That's what the specification calls
 * “Packet transmission”.
 *
 * It is assumed that the IPv6 packet is valid (if not, it will be dropped by
 * the receiving Teredo peer). It is furthermore assumed that the packet is at
 * least 40 bytes long (room for the IPv6 header and that it is properly
 * aligned.
 *
 * The packet size should not exceed the MTU (1280 bytes by default).
 * In any case, sending will fail if the packets size exceeds 65507 bytes
 * (maximum size for a UDP packet's payload).
 *
 * Thread-safety: This function is thread-safe.
 *
 * @return 0 on success, -1 on error.
 */
int teredo_transmit (teredo_tunnel *restrict tunnel,
                     const struct ip6_hdr *restrict packet, size_t length)
{
	assert (tunnel != NULL);

	const union teredo_addr *dst = (union teredo_addr *)&packet->ip6_dst;

	/* Drops multicast destination, we cannot handle these */
	if (dst->ip6.s6_addr[0] == 0xff)
		return 0;

	teredo_state s;
	pthread_rwlock_rdlock (&tunnel->state_lock);
	memcpy (&s, &tunnel->state, sizeof (s));
	/*
	 * We can afford to use a slightly outdated state, but we cannot afford to
	 * use an inconsistent state, hence this lock.
	*/
	pthread_rwlock_unlock (&tunnel->state_lock);

#ifdef MIREDO_TEREDO_CLIENT
	if (IsClient (tunnel))
	{
		if (!s.up) /* not qualified */
		{
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                        packet, length);
			return 0;
		}

		const union teredo_addr *src = (union teredo_addr *)&packet->ip6_src;
		if ((dst->teredo.prefix != s.addr.teredo.prefix)
		 && (src->teredo.prefix != s.addr.teredo.prefix))
		{
			/*
			 * Routing packets not from a Teredo client,
			 * neither toward a Teredo client is NOT allowed through a
			 * Teredo tunnel. The Teredo server will reject the packet.
			 */
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADMIN,
			                        packet, length);
			return 0;
		}
	}
	else
#endif
	{
		if (dst->teredo.prefix != s.addr.teredo.prefix)
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
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                        packet, length);
			return 0;
		}
	}

	if (dst->teredo.prefix == s.addr.teredo.prefix)
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
	time_t now = tunnel->now;
	struct teredo_peerlist *list = tunnel->list;

//	syslog (LOG_DEBUG, "packet to be sent");
	teredo_peer *p = teredo_list_lookup (list, now, &dst->ip6, &created);
	if (p == NULL)
		return -1; /* error */

	if (!created)
	{
//		syslog (LOG_DEBUG, " peer is %strusted", p->trusted ? "" : "NOT ");
//		syslog (LOG_DEBUG, " peer is %svalid", IsValid (p, now) ? "" : "NOT ");
//		syslog (LOG_DEBUG, " pings = %u, bubbles = %u", p->pings, p->bubbles);

		/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
		if (p->trusted && IsValid (p, now))
		{
			/* Already known -valid- peer */
			TouchTransmit (p, now);
			uint32_t ipv4 = p->mapped_addr;
			uint16_t port = p->mapped_port;
			teredo_list_release (list);

			return (teredo_send (tunnel->fd, packet, length, ipv4, port)
					== (int)length) ? 0 : -1;
		}
	}
 	else
	{
 		p->trusted = p->bubbles = p->pings = 0;
//		syslog (LOG_DEBUG, " peer unknown and created");
	}

	// Unknown, untrusted, or too old peer
	// (thereafter refered to as simply "untrusted")

#ifdef MIREDO_TEREDO_CLIENT
	/* Untrusted non-Teredo node */
	if (dst->teredo.prefix != s.addr.teredo.prefix)
	{
		int res;

		assert (IsClient (tunnel));

		/* Client case 2: direct IPv6 connectivity test */
		// TODO: avoid code duplication
		if (created)
		{
			p->mapped_port = 0;
			p->mapped_addr = 0;
		}

		teredo_enqueue_out (p, packet, length);
		res = CountPing (p, now);
		teredo_list_release (list);

		if (res == 0)
			res = SendPing (tunnel->fd, &s.addr, &dst->ip6);

		if (res == -1)
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                     packet, length);

//		syslog (LOG_DEBUG, " ping peer returned %d", res);
		return 0;
	}
#endif

	// Untrusted Teredo client

	/* Client case 3: TODO: implement local discovery */

	if (created)
		/* Unknown Teredo clients */
		SetMapping (p, IN6_TEREDO_IPV4 (dst), IN6_TEREDO_PORT (dst));

	/* Client case 4 & relay case 2: new cone peer */
	if (tunnel->allow_cone && IN6_IS_TEREDO_ADDR_CONE (dst))
	{
		p->trusted = 1;
		p->bubbles = /*p->pings -USELESS- =*/ 0;
		TouchTransmit (p, now);
		uint32_t ipv4 = p->mapped_addr;
		uint16_t port = p->mapped_port;
		teredo_list_release (list);
		return teredo_send (tunnel->fd, packet, length, ipv4, port)
				== (int)length ? 0 : -1;
	}

	/* Client case 5 & relay case 3: untrusted non-cone peer */
	teredo_enqueue_out (p, packet, length);

	// Sends bubble, if rate limit allows
	int res = CountBubble (p, now);
	teredo_list_release (list);
	switch (res)
	{
		case 0:
			/*
			 * Open the return path if we are behind a
			 * restricted NAT.
			 */
			if ((!s.cone)
			 && SendBubbleFromDst (tunnel->fd, &dst->ip6, false, false))
				return -1;

			return SendBubbleFromDst (tunnel->fd, &dst->ip6, s.cone, true);

		case -1: // Too many bubbles already sent
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                        packet, length);

		//case 1: -- between two bubbles -- nothing to do
	}

	return 0;
}


/**
 * Receives a packet coming from the Teredo tunnel (as specified per
 * paragraph 5.4.2). That's called “Packet reception”.
 *
 * This function will NOT block if no packet are pending processing; it
 * will return immediatly.
 *
 * Thread-safety: This function is thread-safe.
 */
static void
teredo_run_inner (teredo_tunnel *restrict tunnel,
                  const struct teredo_packet *restrict packet)
{
	assert (tunnel != NULL);
	assert (packet != NULL);

	const uint8_t *buf = packet->ip6;
	size_t length = packet->ip6_len;
	struct ip6_hdr ip6;

	// Checks packet
	if ((length < sizeof (ip6)) || (length > 65507))
		return; // invalid packet

	memcpy (&ip6, buf, sizeof (ip6));
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6.ip6_plen) + sizeof (ip6)) != length))
		return; // malformatted IPv6 packet

	teredo_state s;
	pthread_rwlock_rdlock (&tunnel->state_lock);
	memcpy (&s, &tunnel->state, sizeof (s));
	/*
	 * We can afford to use a slightly outdated state, but we cannot afford to
	 * use an inconsistent state, hence this lock. Also, we cannot call
	 * teredo_maintenance_process() while holding the lock, as that would
	 * cause a deadlock at StateChange().
	 */
	pthread_rwlock_unlock (&tunnel->state_lock);

#ifdef MIREDO_TEREDO_CLIENT
	/* Maintenance */
	if (IsClient (tunnel) && (packet->source_port == htons (IPPORT_TEREDO)))
	{
		if (packet->auth_nonce != NULL)
		{
			teredo_maintenance_process (tunnel->maintenance, packet);
			return;
		}
		else
		if (!s.up)
		{
			/* Not qualified -> do not accept incoming packets */
			return;
		}
		else
		if (packet->source_ipv4 != s.addr.teredo.server_ip)
		{
			/* Not from primary server IPv4 address
			   -> force normal packet reception */
// 			syslog (LOG_DEBUG, "packet from relay");
		}
		else
		if (packet->orig_ipv4)
		{
// 			syslog (LOG_DEBUG, "bubble from server (+reply)");
			/* TODO: record sending of bubble, create a peer, etc ? */
			SendBubble (tunnel->fd, packet->orig_ipv4, packet->orig_port,
			            &ip6.ip6_dst, &ip6.ip6_src);
			if (IsBubble (&ip6))
				return; // don't pass bubble to kernel
		}
		else
		if (IsBubble (&ip6))
		{
			/*
			 * Some servers do not insert an origin indication.
			 * When the source IPv6 address is a Teredo address,
			 * we can guess the mapping. Otherwise, we're stuck.
			 */
			if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == s.addr.teredo.prefix)
				/* TODO: record sending of bubble, create a peer, etc ? */
				SendBubble (tunnel->fd, IN6_TEREDO_IPV4 (&ip6.ip6_src),
				            IN6_TEREDO_PORT (&ip6.ip6_src), &ip6.ip6_dst,
				            &ip6.ip6_src);
			else
			{
				syslog (LOG_WARNING, _("Ignoring invalid bubble: "
				        "your Teredo server is probably buggy."));
			}
			return; // don't pass bubble to kernel
		}
		/*
		 * Normal reception of packet must only occur if it does not
		 * come from the server, as specified. However, it is not
		 * unlikely that our server is a relay too. Hence, we must
		 * further process packets from it.
		 * At the moment, we only drop bubble (see above).
		 */
	}
	else if (!s.up)
		/* Not qualified -> do not accept incoming packets */
		return;
#endif /* MIREDO_TEREDO_CLIENT */

	/*
	 * NOTE:
	 * In the client case, the spec says we should check that the
	 * destination is our Teredo IPv6 address. However, this library makes
	 * no difference between relay, host-specific relay and client
	 * (it very much sounds like market segmentation to me).
	 * We purposedly leave it up to the kernel to determine whether he
	 * should accept, route, or drop the packet, according to its
	 * configuration. It is expected that client will normally not have
	 * IPv6 forwarding enabled, so that the kernel will actually make said
	 * destination address check itself.
	 *
	 * In the relay case, it is said we should accept packet toward the range
	 * of hosts for which we serve as a Teredo relay, and should otherwise
	 * drop it. That should be done just before sending the packet. We leave
	 * it up to the network administrator to configure or not configure
	 * source address filtering on its Teredo relay/router, via standard
	 * firewalling (e.g. NetFilter/iptables on Linux).
	 *
	 * It should also be noted that dropping packets with link-local
	 * destination here, before further processing, breaks connectivity
	 * with restricted Teredo clients: we send them Teredo bubbles with
	 * a link-local source, to which they reply with Teredo bubbles with
	 * a link-local destination. Indeed, the specification specifies that
	 * the relay MUST look up the peer in the list and update last
	 * reception date even if the destination is incorrect.
	 *
	 * Therefore, we don't check that the destination in any case. However, we
	 * DO check source address quite a lot...
	 *
	 * Well, ok, we do still check that the destination is not multicast since
	 * this is not supposed to happen, even for hole punching, and there is no
	 * way to handle multicast over Teredo at the moment. This is a
	 * precautionary measure.
	 */
	if (ip6.ip6_dst.s6_addr[0] == 0xff)
		return;

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
	 * bubbles sent through the server are not ignored).
	 *
	 * This check is not part of the Teredo specification, but I really don't
	 * feel like letting link-local packets come in through the virtual
	 * network interface.
	 */
	if ((((uint16_t *)ip6.ip6_src.s6_addr)[0] & 0xffc0) == 0xfe80)
		return;

	/* Actual packet reception, either as a relay or a client */

	time_t now = tunnel->now;

	// Checks source IPv6 address / looks up peer in the list:
	struct teredo_peerlist *list = tunnel->list;
	teredo_peer *p = teredo_list_lookup (list, now, &ip6.ip6_src, NULL);

	if (p != NULL)
	{
//		syslog (LOG_DEBUG, " peer is %strusted", p->trusted ? "" : "NOT ");
//		syslog (LOG_DEBUG, " not checking validity");
//		syslog (LOG_DEBUG, " pings = %u, bubbles = %u", p->pings, p->bubbles);

		// Client case 1 (trusted node or (trusted) Teredo client):
		if (p->trusted
		 && (packet->source_ipv4 == p->mapped_addr)
		 && (packet->source_port == p->mapped_port))
		{
			TouchReceive (p, now);
			p->bubbles = p->pings = 0;
			teredo_queue *q = teredo_peer_queue_yield (p);
			teredo_list_release (list);

			if (q != NULL)
				teredo_queue_emit (q, tunnel->fd,
				                   packet->source_ipv4, packet->source_port,
				                   tunnel->recv_cb, tunnel->opaque);
			tunnel->recv_cb (tunnel->opaque, buf, length);
			return;
		}

#ifdef MIREDO_TEREDO_CLIENT
		// Client case 2 (untrusted non-Teredo node):
		if (IsClient (tunnel) && (!p->trusted) && (CheckPing (packet) == 0))
		{
			// FIXME: lots of duplicated code here (see case 1)
			p->trusted = 1;
			SetMappingFromPacket (p, packet);

			TouchReceive (p, now);
			p->bubbles = p->pings = 0;
			teredo_queue *q = teredo_peer_queue_yield (p);
			teredo_list_release (list);

			if (q != NULL)
				teredo_queue_emit (q, tunnel->fd,
				                   packet->source_ipv4, packet->source_port,
				                   tunnel->recv_cb, tunnel->opaque);
			return; /* don't pass ping to kernel */
		}
#endif /* ifdef MIREDO_TEREDO_CLIENT */
	}
//	else
//		syslog (LOG_DEBUG, " unknown peer");

	/*
	 * At this point, we have either a trusted mapping mismatch,
	 * an unlisted peer, or an un-trusted client peer.
	 */
	if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == s.addr.teredo.prefix)
	{
		// Client case 3 (unknown or untrusted matching Teredo client):
		if (IN6_MATCHES_TEREDO_CLIENT (&ip6.ip6_src, packet->source_ipv4,
		                               packet->source_port))
		{
			if (p == NULL)
			{
#ifdef MIREDO_TEREDO_CLIENT
				if (IsClient (tunnel))
				{
					bool create;

					// TODO: do not duplicate this code
					p = teredo_list_lookup (list, now, &ip6.ip6_src, &create);
					if (p == NULL)
						return; // insufficient memory

					/*
					 * This is useless:
					 * trusted and bubbles are set above, pings is never used
					 * for other Teredo clients.
					if (create)
						p->trusted = p->bubbles = p->pings = 0;
					else
						race condition: peer created by another thread
					 */
					SetMapping (p, IN6_TEREDO_IPV4 (&ip6.ip6_src),
					            IN6_TEREDO_PORT (&ip6.ip6_src));
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
					return; // list not locked (p = NULL)
			}

			p->trusted = 1;
			p->bubbles = /*p->pings -USELESS- =*/ 0;
			TouchReceive (p, now);
			teredo_queue *q = teredo_peer_queue_yield (p);
			teredo_list_release (list);

			if (q != NULL)
				teredo_queue_emit (q, tunnel->fd, IN6_TEREDO_IPV4 (&ip6.ip6_src),
				                   IN6_TEREDO_PORT (&ip6.ip6_src),
				                   tunnel->recv_cb, tunnel->opaque);

			if (!IsBubble (&ip6)) // discard Teredo bubble
				tunnel->recv_cb (tunnel->opaque, buf, length);
			return;
		}

		if (p != NULL)
			teredo_list_release (list);
		// TODO: remove this line if we implement local teredo
		return;
	}

	assert (IN6_TEREDO_PREFIX (&ip6.ip6_src) != s.addr.teredo.prefix);

#ifdef MIREDO_TEREDO_CLIENT
	if (IsClient (tunnel))
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
			p = teredo_list_lookup (list, now, &ip6.ip6_src, &create);
			if (p == NULL)
				return; // memory error

			if (create)
			{
				p->mapped_port = 0;
				p->mapped_addr = 0;
				p->trusted = p->bubbles = p->pings = 0;
			}
			//else race condition - peer already created by another thread
				// -> nothing to set in that case
//			syslog (LOG_DEBUG, " peer created");
		}

//		syslog (LOG_DEBUG, " packet queued pending Echo Reply");
		teredo_enqueue_in (p, buf, length,
		                   packet->source_ipv4, packet->source_port);
		TouchReceive (p, now);

		int res = CountPing (p, now);
		teredo_list_release (list);

		if (res == 0)
			SendPing (tunnel->fd, &s.addr, &ip6.ip6_src);

// 		syslog (LOG_DEBUG, " ping peer returned %d", res);
		return;
	}
#endif /* ifdef MIREDO_TEREDO_CLIENT */

	// Relays don't accept packets not from Teredo clients,
	// nor from mismatching packets
	if (p != NULL)
		teredo_list_release (list);
}



static void teredo_dummy_recv_cb (void *o, const void *p, size_t l)
{
	(void)o;
	(void)p;
	(void)l;
}


static void teredo_dummy_icmpv6_cb (void *o, const void *p, size_t l,
                                       const struct in6_addr *d)
{
	(void)o;
	(void)p;
	(void)l;
	(void)d;
}


#ifdef MIREDO_TEREDO_CLIENT
static void teredo_dummy_state_up_cb (void *o, const struct in6_addr *a,
                                         uint16_t m)
{
	(void)o;
	(void)a;
	(void)m;
}


static void teredo_dummy_state_down_cb (void *o)
{
	(void)o;
}
#endif


/**
 * Userland low-precision (1 Hz) clock
 *
 * This is way faster than calling time() for every packet transmitted or
 * received. The first implementation was using POSIX timers, but it might
 * be a bit overkill to spawn a thread every second to simply increment an
 * integer. Also, POSIX timers with thread event delivery has a terrible
 * portable at the time of writing (June 2006). Basically, recent
 * GNU/Linux have it, and that's about it... no uClibc support, only in
 * -current for FreeBSD...
 *
 * TODO:
 * - use monotonic clock if available (GC will need fixing)
 */
static void *teredo_clock (void *val)
{
	time_t *clock = (time_t *)val;

	for (;;)
	{
		struct timespec now;
		clock_gettime (CLOCK_REALTIME, &now);

		*clock = now.tv_sec;
		now.tv_sec++;
		now.tv_nsec = 0;

		clock_nanosleep (CLOCK_REALTIME, TIMER_ABSTIME, &now, NULL);
	}

	return NULL;
}


/**
 * Creates a teredo_tunnel instance. teredo_preinit() must have been
 * called first.
 *
 * Thread-safety: This function is thread-safe.
 *
 * @param ipv4 IPv4 (network byte order) to bind to, or 0 if unspecified.
 * @param port UDP/IPv4 port number (network byte order) or 0 if unspecified.
 * Note that some campus firewall drop certain UDP ports (typically those used
 * by some P2P application); in that case, you should use a fixed port so that
 * the kernel does not select a possibly blocked port. Also note that some
 * severely broken NAT devices might fail if multiple NAT-ed computers use the
 * same source UDP port number at the same time, so avoid you should
 * paradoxically avoid querying a fixed port.
 *
 * @return NULL in case of failure.
 */
teredo_tunnel *teredo_create (uint32_t ipv4, uint16_t port)
{
	teredo_tunnel *tunnel = (teredo_tunnel *)malloc (sizeof (*tunnel));
	if (tunnel == NULL)
		return NULL;

	memset (tunnel, 0, sizeof (*tunnel));
	tunnel->state.addr.teredo.prefix = htonl (TEREDO_PREFIX);

	/*
	 * That doesn't really need to match our mapping: the address is only
	 * used to send Unreachable message... with the old method that is no
	 * longer supported (the one that involves building the IPv6 header as
	 * well as the ICMPv6 header).
	 */
	tunnel->state.addr.teredo.client_port = ~port;
	tunnel->state.addr.teredo.client_ip = ~ipv4;

	tunnel->state.up = false;
	tunnel->ratelimit.count = 1;

	tunnel->recv_cb = teredo_dummy_recv_cb;
	tunnel->icmpv6_cb = teredo_dummy_icmpv6_cb;
#ifdef MIREDO_TEREDO_CLIENT
	tunnel->up_cb = teredo_dummy_state_up_cb;
	tunnel->down_cb = teredo_dummy_state_down_cb;
#endif

	time (&tunnel->now);

	if (pthread_create (&tunnel->clock, NULL, teredo_clock, &tunnel->now) == 0)
	{
		if ((tunnel->fd = teredo_socket (ipv4, port)) != -1)
		{
			if ((tunnel->list = teredo_list_create (MAX_PEERS, 30)) != NULL)
			{
				(void)pthread_rwlock_init (&tunnel->state_lock, NULL);
				(void)pthread_mutex_init (&tunnel->ratelimit.lock, NULL);
				return tunnel;
			}
			teredo_close (tunnel->fd);
		}
		pthread_cancel (tunnel->clock);
		pthread_join (tunnel->clock, NULL);
	}

	free (tunnel);
	return NULL;
}


/**
 * Releases all resources (sockets, memory chunks...) and terminates all
 * threads associated with a teredo_tunnel instance.
 *
 * Thread-safety: This function is thread-safe. However, you must obviously
 * not call it if any other thread (including the calling one) is still using
 * the specified tunnel in some way.
 *
 * @param t tunnel to be destroyed. No longer useable thereafter.
 *
 * @return nothing (always succeeds).
 */
void teredo_destroy (teredo_tunnel *t)
{
	assert (t != NULL);
	assert (t->fd != -1);
	assert (t->list != NULL);

#ifdef MIREDO_TEREDO_CLIENT
	/* NOTE: We must NOT lock the state r/w lock here,
	 * to avoid a potential deadlock, if the state callback is called by the
	 * maintenance thread. Anyway, if the user obey the specified constraints,
	 * we need not lock anyting in teredo_destroy(). */
	if (t->maintenance != NULL)
		teredo_maintenance_stop (t->maintenance);
#endif

	if (t->recv.running)
	{
		pthread_cancel (t->recv.thread);
		pthread_join (t->recv.thread, NULL);
	}

	teredo_list_destroy (t->list);
	pthread_rwlock_destroy (&t->state_lock);
	pthread_mutex_destroy (&t->ratelimit.lock);
	teredo_close (t->fd);
	pthread_cancel (t->clock);
	pthread_join (t->clock, NULL);
	free (t);
}


static void *teredo_recv_thread (void *t)
{
	teredo_tunnel *tunnel = (teredo_tunnel *)t;

	for (;;)
	{
		struct teredo_packet packet;

		if (teredo_wait_recv (tunnel->fd, &packet) == 0)
		{
			pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
			teredo_run_inner (tunnel, &packet);
			pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
		}
	}

	return NULL;
}

/**
 * Spawns a new thread to perform Teredo packet reception in the background.
 * The thread will be automatically terminated when the tunnel is destroyed.
 *
 * It is safe to call teredo_run_async multiple times for the same tunnel,
 * however all call will fail (safe) after the first succesful one.
 *
 * Thread-safety: teredo_run_async() is not re-entrant. Calling it from
 * multiple threads with the same teredo_tunnel objet simultanously is
 * undefined. It is safe to call teredo_run_async() from different threads
 * each with a different teredo_tunnel object.
 *
 * @return 0 on success, -1 on error.
 */
int teredo_run_async (teredo_tunnel *t)
{
	assert (t != NULL);

	/* already running */
	if (t->recv.running)
		return -1;

	if (pthread_create (&t->recv.thread, NULL, teredo_recv_thread, t))
		return -1;

	t->recv.running = true;
	return 0;
}

/**
 * Registers file descriptors in an fd_set for use with select().
 *
 * Thread-safety: This function is thread-safe.
 *
 * @return the "biggest" file descriptor registered (useful as the
 * first parameter to select()). -1 if any of the descriptors exceeded
 * FD_SETSIZE - 1.
 */
int teredo_register_readset (teredo_tunnel *t, fd_set *rdset)
{
	assert (t != NULL);
	assert (t->fd != -1);

	// FIXME: May be problematic once multicast local discovery gets
	// implemented.

	if (t->fd >= FD_SETSIZE)
		return -1;

	FD_SET (t->fd, rdset);
	return t->fd;

}


/**
 * Receives all pending packets coming from the Teredo tunnel. If you
 * don't use teredo_run_async(), you have to call this function as
 * often as possible. It is up to you to find the correct tradeoff
 * between busy waiting on this function for better response time of
 * the Teredo tunnel, and a long delay to not waste too much CPU
 * cycles. You should really consider using teredo_run_async() instead!
 * libteredo will spawn some threads even if you don't call
 * teredo_run_async() anyway...
 *
 * Thread-safety: This function is thread-safe.
 */
void teredo_run (teredo_tunnel *tunnel)
{
	assert (tunnel != NULL);

	struct teredo_packet packet;

	if (teredo_recv (tunnel->fd, &packet))
		return;

	teredo_run_inner (tunnel, &packet);
}


/**
 * Overrides the Teredo prefix of a Teredo relay. It is undefined if the
 * tunnel is configured as a Teredo client. teredo_set_prefix() is
 * undefined if teredo_set_cone_flag() was already invoked.
 *
 * Thread-safety: This function is thread-safe.
 *
 * @param prefix Teredo 32-bits (network byte order) prefix.
 *
 * @return 0 on success, -1 if the prefix is invalid (in which case the
 * teredo_tunnel instance is not modified).
 */
int teredo_set_prefix (teredo_tunnel *t, uint32_t prefix)
{
	assert (t != NULL);
#ifdef MIREDO_TEREDO_CLIENT
	assert (t->maintenance == NULL);
#endif

	if (!is_valid_teredo_prefix (prefix))
		return -1;

	pthread_rwlock_wrlock (&t->state_lock);
	t->state.addr.teredo.prefix = prefix;
	pthread_rwlock_unlock (&t->state_lock);
	return 0;
}


/**
 * Enables Teredo relay mode for a teredo_tunnel,
 * defines whether it will operate as a “cone” or “restricted” relay,
 * and starts processing of encapsulated IPv6 packets.
 * This is undefined if Teredo client mode was previously enabled.
 *
 * @param cone true if the cone flag should be enabled. This only works if the
 * relay runs from behind a cone NAT and has no stateful firewall for incoming
 * UDP packets. If there is a stateful firewall or a restricted-port NAT,
 * flag must be false.
 *
 * @return 0 if the initialization was succesful, -1 in case of error.
 * In case of error, the teredo_tunnel instance is not modifed.
 */
int teredo_set_cone_flag (teredo_tunnel *t, bool cone)
{
	assert (t != NULL);
#ifdef MIREDO_TEREDO_CLIENT
	assert (t->maintenance == NULL);
#endif

	pthread_rwlock_wrlock (&t->state_lock);
	if (cone)
	{
		t->state.addr.teredo.flags = htons (TEREDO_FLAG_CONE);
		t->state.cone = true;
	}
	t->state.up = true;
	pthread_rwlock_unlock (&t->state_lock);

	return 0;
}


/**
 * Enables Teredo client mode for a teredo_tunnel and starts the Teredo
 * client maintenance procedure in a separate thread. This is undefined if
 * either teredo_set_cone_flag(), teredo_set_prefix() were previously called
 * for this tunnel.
 *
 * NOTE: calling teredo_set_client_mode() multiple times on the same tunnel
 * is currently not supported, and will safely return an error. Future
 * versions might support this.
 *
 * Thread-safety: This function is thread-safe.
 *
 * @param s Teredo server's host name or “dotted quad” primary IPv4 address.
 * @param s2 Teredo server's secondary address (or host name), or NULL to
 * infer it from <s>.
 *
 * @return 0 on success, -1 in case of error.
 * In case of error, the teredo_tunnel instance is not modifed.
 */
int teredo_set_client_mode (teredo_tunnel *restrict t,
                            const char *s, const char *s2)
{
#ifdef MIREDO_TEREDO_CLIENT
	assert (t != NULL);

	pthread_rwlock_wrlock (&t->state_lock);
	if (t->maintenance != NULL)
	{
		pthread_rwlock_unlock (&t->state_lock);
		return -1;
	}

	struct teredo_maintenance *m;
	m = teredo_maintenance_start (t->fd, teredo_state_change, t, s, s2);
	t->maintenance = m;
	pthread_rwlock_unlock (&t->state_lock);

	if (m != NULL)
		return 0;

#else
	(void)t;
	(void)s;
	(void)s2;
#endif
	return -1;
}


/**
 * Enables/disables the processing of the cone flag found in other Teredo
 * client's IPv6 addresses. By default, the cone flag is ignored, because this
 * supposedly increase reliability of the Teredo tunneling mechanism.
 *
 * @param ignore true to enable processing, false to disable.
 */
void teredo_set_cone_ignore (teredo_tunnel *t, bool ignore)
{
	assert (t != NULL);
	t->allow_cone = !ignore;
}


/**
 * Thread-safety: FIXME.
 */
void *teredo_set_privdata (teredo_tunnel *t, void *opaque)
{
	assert (t != NULL);

	void *prev = t->opaque;
	t->opaque = opaque;
	return prev;
}


/**
 * Thread-safety: FIXME.
 */
void *teredo_get_privdata (const teredo_tunnel *t)
{
	assert (t != NULL);

	return t->opaque;
}


/**
 * Thread-safety: FIXME.
 */
void teredo_set_recv_callback (teredo_tunnel *restrict t, teredo_recv_cb cb)
{
	assert (t != NULL);
	t->recv_cb = (cb != NULL) ? cb : teredo_dummy_recv_cb;
}


/**
 * Thread-safety: FIXME.
 */
void teredo_set_icmpv6_callback (teredo_tunnel *restrict t,
                                 teredo_icmpv6_cb cb)
{
	assert (t != NULL);
	t->icmpv6_cb = (cb != NULL) ? cb : teredo_dummy_icmpv6_cb;
}


/**
 * Registers callbacks to be called when the Teredo client maintenance
 * procedure detects that the tunnel becomes usable (or has got a new IPv6
 * address, or a new MTU), or unusable respectively.
 * These callbacks are ignored for a Teredo relay tunnel.
 *
 * Any packet sent when the relay/client is down will be ignored.
 * The callbacks function might be called from a separate thread.
 *
 * Thread-safety: This function is thread-safe.
 *
 * If a callback is set to NULL, it is ignored.
 */
void teredo_set_state_cb (teredo_tunnel *restrict t, teredo_state_up_cb u,
                          teredo_state_down_cb d)
{
#ifdef MIREDO_TEREDO_CLIENT
	assert (t != NULL);

	pthread_rwlock_wrlock (&t->state_lock);
	t->up_cb = (u != NULL) ? u : teredo_dummy_state_up_cb;
	t->down_cb = (d != NULL) ? d : teredo_dummy_state_down_cb;
	pthread_rwlock_unlock (&t->state_lock);
#else
	(void)t;
	(void)u;
	(void)d;
#endif
}
