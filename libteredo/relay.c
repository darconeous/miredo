/*
 * relay.c - Teredo relay core
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

#include <gettext.h>

#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdlib.h> // malloc()
#include <assert.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h> // ICMP6_DST_UNREACH_*
#include <pthread.h>

#include "teredo.h"
#include "v4global.h" // is_ipv4_global_unicast()
#include "teredo-udp.h"

#include "packets.h"
#include "tunnel.h"
#include "maintain.h"
#include "clock.h"
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
		teredo_clock_t last;
	} ratelimit;

	// Asynchronous packet reception
	struct
	{
		pthread_t thread;
		bool running;
	} recv;

	int fd;
};

#ifdef HAVE_LIBJUDY
# define MAX_PEERS 1048576
#else
# define MAX_PEERS 1024
#endif
#define ICMP_RATE_LIMIT_MS 100

#ifndef NDEBUG
# include <syslog.h>
# include <stdarg.h>

static inline void debug (const char *str, ...)
{
	va_list ap;
	va_start (ap, str);
	vsyslog (LOG_DEBUG, str, ap);
	va_end (ap);
}
#else
#define debug( ... ) (void)0
#endif

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
teredo_send_unreach (teredo_tunnel *restrict tunnel, uint8_t code,
                     const struct ip6_hdr *restrict in, size_t len)
{
	struct
	{
		struct icmp6_hdr hdr;
		char fill[1280 - sizeof (struct ip6_hdr) - sizeof (struct icmp6_hdr)];
	} buf;
	teredo_clock_t now = teredo_clock ();

	/* ICMPv6 rate limit */
	pthread_mutex_lock (&tunnel->ratelimit.lock);
	if (now != tunnel->ratelimit.last)
	{
		tunnel->ratelimit.last = now;
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
	struct in6_addr dst;
	memcpy (&dst, &((const struct ip6_hdr *)in)->ip6_src, sizeof (dst));
	tunnel->icmpv6_cb (tunnel->opaque, &buf.hdr, len, &dst);
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
static int CountPing (teredo_peer *peer, teredo_clock_t now)
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
 * Returns 0 if a bubble may be sent, -1 if no more bubble may be sent,
 * 1 if a bubble may be sent later.
 */
static int CountBubble (teredo_peer *peer, teredo_clock_t now)
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
 * Encapsulates an IPv6 packet, forward it to a Teredo peer and release the
 * Teredo peers list. It is (obviously) assumed that the peers list lock is
 * held upon entry.
 *
 * @return 0 on success, -1 in case of UDP/IPv4 network error.
 */
static
int teredo_encap (teredo_tunnel *restrict tunnel, teredo_peer *restrict peer,
                  const void *restrict data, size_t len, teredo_clock_t now)
{
	uint32_t ipv4 = peer->mapped_addr;
	uint16_t port = peer->mapped_port;
	TouchTransmit (peer, now);
	teredo_list_release (tunnel->list);

	return (teredo_send (tunnel->fd,
	                     data, len, ipv4, port) == (int)len) ? 0 : -1;
}


int teredo_transmit (teredo_tunnel *restrict tunnel,
                     const struct ip6_hdr *restrict packet, size_t length)
{
	assert (tunnel != NULL);

	const union teredo_addr *dst =
		(const union teredo_addr *)&packet->ip6_dst;

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
	if (IsClient (tunnel) && !s.up)
	{
		/* Client not qualified */
		teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR, packet, length);
		return 0;
	}
#endif

	if (dst->teredo.prefix != s.addr.teredo.prefix)
	{
		/* Non-Teredo destination */
#ifdef MIREDO_TEREDO_CLIENT
		if (IsClient (tunnel))
		{
			const union teredo_addr *src =
				(const union teredo_addr *)&packet->ip6_src;

			if (src->teredo.prefix != s.addr.teredo.prefix)
			{
				// Teredo servers and relays would reject the packet
				// if it does not have a Teredo source.
				teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADMIN,
				                     packet, length);
				return 0;
			}
		}
		else
#endif
		{
			// Teredo relays only routes toward Teredo clients.
			// The routing table must be misconfigured.
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                     packet, length);
			return 0;
		}
	}
	else
	{
		/* Teredo destination */
		assert (dst->teredo.prefix == s.addr.teredo.prefix);
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
	teredo_clock_t now = teredo_clock ();
	struct teredo_peerlist *list = tunnel->list;

	debug ("packet to be sent");
	teredo_peer *p = teredo_list_lookup (list, &dst->ip6, &created);
	if (p == NULL)
		return -1; /* error */

	if (!created)
	{
		debug (" peer is %strusted", p->trusted ? "" : "NOT ");
		debug (" peer is %svalid", IsValid (p, now) ? "" : "NOT ");
		debug (" pings = %u, bubbles = %u", p->pings, p->bubbles);

		/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
		if (p->trusted && IsValid (p, now))
			/* Already known -valid- peer */
			return teredo_encap (tunnel, p, packet, length, now);
	}
 	else
	{
 		p->trusted = p->bubbles = p->pings = 0;
		debug (" peer unknown, created");
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

		debug (" peer: ping returned %d", res);
		return 0;
	}
#endif

	// Untrusted Teredo client

	/* Client case 3: TODO: implement local discovery */

	if (created)
		/* Unknown Teredo clients */
		SetMapping (p, IN6_TEREDO_IPV4 (dst), IN6_TEREDO_PORT (dst));

#ifdef LIBTEREDO_ALLOW_CONE
	/* Client case 4 & relay case 2: new cone peer */
	if (IN6_IS_TEREDO_ADDR_CONE (dst))
	{
		p->trusted = 1;
		p->bubbles = /*p->pings -USELESS- =*/ 0;
		return teredo_encap (tunnel, p, packet, length);
	}
#endif

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
			if (!(s.addr.teredo.flags & htons (TEREDO_FLAG_CONE))
			 && SendBubbleFromDst (tunnel->fd, &dst->ip6, false))
				return -1;

			return SendBubbleFromDst (tunnel->fd, &dst->ip6, true);

		case -1: // Too many bubbles already sent
			teredo_send_unreach (tunnel, ICMP6_DST_UNREACH_ADDR,
			                     packet, length);

		//case 1: -- between two bubbles -- nothing to do
	}

	return 0;
}


static
void teredo_predecap (teredo_tunnel *restrict tunnel,
                      teredo_peer *restrict peer, teredo_clock_t now)
{
	TouchReceive (peer, now);
	peer->bubbles = peer->pings = 0;
	teredo_queue *q = teredo_peer_queue_yield (peer);
	teredo_list_release (tunnel->list);

	if (q != NULL)
		teredo_queue_emit (q, tunnel->fd,
		                   peer->mapped_addr, peer->mapped_port,
		                   tunnel->recv_cb, tunnel->opaque);
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

	size_t length = packet->ip6_len;
	struct ip6_hdr *ip6 = packet->ip6;

	// Checks packet
	if ((length < sizeof (*ip6)) || (length > 65507))
		return; // invalid packet

	if (((ip6->ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6->ip6_plen) + sizeof (*ip6)) != length))
		return; // malformatted IPv6 packet
	debug ("packet received (%u bytes)", (unsigned)length);

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
	if (IsClient (tunnel))
	{
		if (teredo_maintenance_process (tunnel->maintenance, packet) == 0)
		{
			debug (" packet passed to maintenance procedure");
			return;
		}

		if (!s.up)
		{
			debug (" packet dropped because tunnel down");
			return; /* Not qualified -> do not accept incoming packets */
		}

		if ((packet->source_ipv4 == s.addr.teredo.server_ip)
		 && (packet->source_port == htons (IPPORT_TEREDO)))
		{
			uint32_t ipv4 = packet->orig_ipv4;
			uint16_t port = packet->orig_port;

			if ((ipv4 == 0) && IsBubble (ip6)
			 && (IN6_TEREDO_PREFIX (&ip6->ip6_src) == s.addr.teredo.prefix))
			{
				/*
				 * Some servers do not insert an origin indication.
				 * When the source IPv6 address is a Teredo address,
				 * we can guess the mapping. Otherwise, we're stuck.
				 */
				ipv4 = IN6_TEREDO_IPV4 (&ip6->ip6_src);
				port = IN6_TEREDO_PORT (&ip6->ip6_src);
			}

			if (ipv4)
			{
				/* TODO: record sending of bubble, create a peer, etc ? */
				teredo_reply_bubble (tunnel->fd, ipv4, port, ip6);
				debug (" bubble sent");
				if (IsBubble (ip6))
					return; // don't pass bubble to kernel
			}
		}

		/*
		 * Normal reception of packet must only occur if it does not
		 * come from the server, as specified. However, it is not
		 * unlikely that our server is a relay too. Hence, we must
		 * further process packets from it.
		 * At the moment, we only drop bubble (see above).
		 */

		/*
		 * Packets with a link-local source address are purposedly dropped to
		 * prevent the kernel from receiving faked Router Advertisement which
		 * could break IPv6 routing completely. Router advertisements MUST
		 * have a link-local source address (RFC 2461).
		 *
		 * This is not supposed to occur except from the Teredo server for
		 * Teredo maintenance (done above), and in hole punching packets
		 * (bubbles). Direct bubbles can safely be ignored, so long as the
		 * indirect ones are processed (and they are processed above).
		 *
		 * This check is not part of the Teredo specification, but I really
		 * don't feel like letting link-local packets come in through the
		 * virtual network interface.
		 *
		 * Only Linux defines s6_addr16, so we don't use it.
		 */
		if (ntohs ((*(uint16_t *)ip6->ip6_src.s6_addr) & 0xffc0) == 0xfe80)
			return;
	}
	else
#endif /* MIREDO_TEREDO_CLIENT */
	/* Relays only accept packets from Teredo clients */
	if (IN6_TEREDO_PREFIX (&ip6->ip6_src) != s.addr.teredo.prefix)
		return;

	/*
	 * NOTE:
	 * Clients are supposed to check that the destination is their Teredo IPv6
	 * address; this is done by the IPv6 stack. When IPv6 forwarding is enabled,
	 * Teredo clients behave like Teredo non-host-specific relays.
	 *
	 * Teredo relays are advised to accept only packets whose IPv6 destination
	 * is served by them (i.e. egress filtering from Teredo to native IPv6).
	 * The IPv6 stack firewall should be used to that end.
	 *
	 * Multicast destinations are not supposed to occur, not even for hole
	 * punching. We drop them as a precautionary measure.
	 *
	 * We purposedly don't drop packets on the basis of link-local destination
	 * as it breaks hole punching: we send Teredo bubbles with a link-local
	 * source, and get replies with a link-local destination. Indeed, the
	 * specification specifies that relays MUST look up the peer in the list
	 * and update last reception date regardless of the destination.
	 *
	 */
	if (ip6->ip6_dst.s6_addr[0] == 0xff)
		return;

	debug (" packet to be decapsulated");
	/* Actual packet reception, either as a relay or a client */

	teredo_clock_t now = teredo_clock ();

	// Checks source IPv6 address / looks up peer in the list:
	struct teredo_peerlist *list = tunnel->list;
	teredo_peer *p = teredo_list_lookup (list, &ip6->ip6_src, NULL);

	if (p != NULL)
	{
		debug (" peer is %strusted", p->trusted ? "" : "NOT ");
		debug (" pings = %u, bubbles = %u", p->pings, p->bubbles);

		// Client case 1 (trusted node or (trusted) Teredo client):
		if (p->trusted
		 && (packet->source_ipv4 == p->mapped_addr)
		 && (packet->source_port == p->mapped_port))
		{
			teredo_predecap (tunnel, p, now);
			tunnel->recv_cb (tunnel->opaque, ip6, length);
			return;
		}

#ifdef MIREDO_TEREDO_CLIENT
		/*
		 * Client case 2 (untrusted non-Teredo node):
		 * Mismatching trusted non-Teredo nodes are also accepted to recover
		 * faster from a Teredo relay change. This is legal (client case 6).
		 */
		if (IsClient (tunnel) && (CheckPing (packet) == 0))
		{
			p->trusted = 1;
			SetMappingFromPacket (p, packet);

			teredo_predecap (tunnel, p, now);
			return; /* don't pass ping to kernel */
		}
#endif /* ifdef MIREDO_TEREDO_CLIENT */
	}
	else
		debug (" peer unknown");

	/*
	 * At this point, we have either a trusted mapping mismatch,
	 * an unlisted peer, or an un-trusted client peer.
	 */
	if (IN6_TEREDO_PREFIX (&ip6->ip6_src) == s.addr.teredo.prefix)
	{
		// Client case 3 (unknown or untrusted matching Teredo client):
		if (IN6_MATCHES_TEREDO_CLIENT (&ip6->ip6_src, packet->source_ipv4,
		                               packet->source_port)
		// Extension: allow mismatch (i.e. clients behind symmetric NATs)
		 || (IsBubble (ip6) && (CheckBubble (packet) == 0)))
		{
#ifdef MIREDO_TEREDO_CLIENT
			if (IsClient (tunnel) && (p == NULL))
				p = teredo_list_lookup (list, &ip6->ip6_src, &(bool){ false });
#endif
			/*
			 * Relays are explicitly allowed to drop packets from
			 * unknown peers. It makes it a little more difficult to route
			 * packets through the wrong relay. The specification leaves
			 * us a choice here. It is arguable whether accepting these
			 * packets would make it easier to DoS the peer list.
			 */
			if (p == NULL)
				return; // list not locked (p = NULL)

			SetMappingFromPacket (p, packet);
			p->trusted = 1;
			teredo_predecap (tunnel, p, now);

			if (!IsBubble (ip6)) // discard Teredo bubble
				tunnel->recv_cb (tunnel->opaque, ip6, length);
			return;
		}

		// TODO: local Teredo
	}
#ifdef MIREDO_TEREDO_CLIENT
	else
	{
		assert (IN6_TEREDO_PREFIX (&ip6->ip6_src) != s.addr.teredo.prefix);
		assert (IsClient (tunnel));

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
			p = teredo_list_lookup (list, &ip6->ip6_src, &create);
			if (p == NULL)
				return; // memory error

			/*
			 * We have to check "create": there is a race condition whereby
			 * another thread could have created the peer in between the two
			 * lookups of this function, since we did not lock the list
			 * in between.
			 */
			if (create)
			{
				p->mapped_port = 0;
				p->mapped_addr = 0;
				p->trusted = p->bubbles = p->pings = 0;
			}
			debug (" peer created");
		}

		debug (" packet queued (pending Echo Reply)");
		teredo_enqueue_in (p, ip6, length,
		                   packet->source_ipv4, packet->source_port);
		TouchReceive (p, now);

		int res = CountPing (p, now);
		teredo_list_release (list);

		if (res == 0)
			SendPing (tunnel->fd, &s.addr, &ip6->ip6_src);

 		debug (" peer: ping returned %d", res);
		return;
	}
#endif /* ifdef MIREDO_TEREDO_CLIENT */

	// Rejected packet
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

	free (tunnel);
	return NULL;
}


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
	free (t);
}


static LIBTEREDO_NORETURN void *teredo_recv_thread (void *t)
{
	teredo_tunnel *tunnel = (teredo_tunnel *)t;

	for (;;)
	{
		struct teredo_packet packet;

		if (teredo_wait_recv (tunnel->fd, &packet) == 0)
		{
			pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
			teredo_run_inner (tunnel, &packet);
			pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
		}
	}
}


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


void teredo_run (teredo_tunnel *tunnel)
{
	assert (tunnel != NULL);

	struct teredo_packet packet;

	if (teredo_recv (tunnel->fd, &packet))
		return;

	teredo_run_inner (tunnel, &packet);
}


int teredo_set_prefix (teredo_tunnel *t, uint32_t prefix)
{
	assert (t != NULL);
	if (!is_valid_teredo_prefix (prefix))
		return -1;

	int retval = 0;

	pthread_rwlock_wrlock (&t->state_lock);

#ifdef MIREDO_TEREDO_CLIENT
	if (t->maintenance != NULL)
		retval = -1;
	else
#endif
		t->state.addr.teredo.prefix = prefix;

	pthread_rwlock_unlock (&t->state_lock);
	return retval;
}


int teredo_set_cone_flag (teredo_tunnel *t, bool cone)
{
	assert (t != NULL);

	int retval = 0;

	pthread_rwlock_wrlock (&t->state_lock);

#ifdef MIREDO_TEREDO_CLIENT
	if (t->maintenance != NULL)
		retval = -1;
	else
#endif
	if (cone)
		t->state.addr.teredo.flags |= htons (TEREDO_FLAG_CONE);
	else
		t->state.addr.teredo.flags &= ~htons (TEREDO_FLAG_CONE);

	pthread_rwlock_unlock (&t->state_lock);

	return retval;
}


int teredo_set_relay_mode (teredo_tunnel *t)
{
	int retval;

#ifdef MIREDO_TEREDO_CLIENT
	pthread_rwlock_wrlock (&t->state_lock);
	retval = (t->maintenance != NULL) ? -1 : 0;
	pthread_rwlock_unlock (&t->state_lock);
#else
	(void)t;
	retval = 0;
#endif

	return retval;
}


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
	m = teredo_maintenance_start (t->fd, teredo_state_change, t, s, s2,
	                              0, 0, 0, 0);
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
