/*
 * relay.cpp - Teredo relay peers list definition
 * $Id: relay.cpp,v 1.26 2004/08/27 16:42:19 rdenisc Exp $
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
#include <time.h> // TODO: use gettimeofday
#include <inttypes.h>

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h> // router solicication
#include <syslog.h>

#ifdef USE_OPENSSL
# include <openssl/rand.h>
# include <openssl/err.h>
#endif

#include "teredo.h"
#include <v4global.h> // is_ipv4_global_unicast()
#include "teredo-udp.h"

#include "relay.h"

#define TEREDO_TIMEOUT 30 // seconds

/*
 * Sends a Teredo Bubble to the server specified in Teredo address <dst>.
 * Returns 0 on success, -1 on error.
 */
static int 
SendBubble (const TeredoRelayUDP& sock, const struct in6_addr *d,
		bool cone, bool indirect = true)
{
	uint32_t ip;
	uint16_t port;
	const union teredo_addr *dst = (const union teredo_addr *)d;

	if (indirect)
	{
		ip = dst->teredo.server_ip;
		port = htons (IPPORT_TEREDO);
	}
	else
	{
		ip = ~dst->teredo.client_ip;
		port = ~dst->teredo.client_port;
	}

	if (ip && is_ipv4_global_unicast (ip))
	{
		struct ip6_hdr hdr;

		hdr.ip6_flow = htonl (0x60000000);
		hdr.ip6_plen = 0;
		hdr.ip6_nxt = IPPROTO_NONE;
		hdr.ip6_hlim = 255;
		memcpy (&hdr.ip6_src, cone ? &teredo_cone : &teredo_restrict,
				sizeof (hdr.ip6_src));
		memcpy (&hdr.ip6_dst, &dst->ip6, sizeof (hdr.ip6_dst));

		return sock.SendPacket (&hdr, sizeof (hdr), ip, port);
	}

	return 0;
}

/*
 * Sends a router solication with an Authentication header to the server.
 * If secondary is true, the packet will be sent to the server's secondary
 * IPv4 adress instead of the primary one.
 *
 * Returns 0 on success, -1 on error.
 */
static const struct in6_addr in6addr_allrouters =
        { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } };

static int 
SendRS (const TeredoRelayUDP& sock, uint32_t server_ip, unsigned char *nonce,
	bool cone, bool secondary)
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
#ifdef USE_OPENSSL
		if (!RAND_pseudo_bytes (nonce, 8))
		{
			char buf[120];

			syslog (LOG_WARNING, _("Possibly predictable RS: %s"),
				ERR_error_string (ERR_get_error (), buf));
		}
#else
		memset (nonce, 0, 8);
#endif
		memcpy (&auth->nonce, nonce, 8);
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
		rs.ip6.ip6_plen = htons (sizeof (rs));
		rs.ip6.ip6_nxt = IPPROTO_ICMPV6;
		rs.ip6.ip6_hlim = 255;
		memcpy (&rs.ip6.ip6_src, cone
			? &teredo_cone : &teredo_restrict,
			sizeof (rs.ip6.ip6_src));
		memcpy (&rs.ip6.ip6_dst, &in6addr_allrouters,
			sizeof (rs.ip6.ip6_dst));
	
		// avoids memory disclosure, and allows
		// precomputed checksum:
		memset (&rs.rs, 0, sizeof (rs.rs));

		rs.rs.nd_rs_type = ND_ROUTER_SOLICIT;
		rs.rs.nd_rs_code = 0;
		// Checksums are pre-computed
		rs.rs.nd_rs_cksum = htons (cone ? 0x114b : 0x914b);

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

	if (secondary)
		server_ip = htonl (ntohl (server_ip) + 1);

	return sock.SendPacket (packet, sizeof (packet), server_ip,
				htons (IPPORT_TEREDO));
}


#define EXPIRED( date, now ) ((((unsigned)now) - (unsigned)date) > 30)
#define ENTRY_EXPIRED( peer, now ) (peer->flags.flags.replied \
					? EXPIRED (peer->last_rx, now) \
					: EXPIRED (peer->last_xmit, now))

// is_valid_teredo_prefix (PREFIX_UNSET) MUST return false
# define PREFIX_UNSET 0xffffffff

struct __TeredoRelay_peer
{
	struct __TeredoRelay_peer *next;

	struct in6_addr addr;
	uint32_t mapped_addr;
	uint16_t mapped_port;
	union
	{
		struct
		{
			unsigned trusted:1;
			unsigned replied:1;
			unsigned bubbles:2;
		} flags;
		uint16_t all_flags;
	} flags;
	/* nonce: only for client */
	time_t last_rx;
	time_t last_xmit;

	uint8_t *queue;
	size_t queuelen;
};


TeredoRelay::TeredoRelay (uint32_t pref, uint16_t port, bool cone)
	: head (NULL)
{
	addr.teredo.prefix = pref;
	addr.teredo.server_ip = 0;
	addr.teredo.flags = cone ? htons (TEREDO_FLAGS_CONE) : 0;
	addr.teredo.client_ip = 0;
	addr.teredo.client_port = 0; 

	sock.ListenPort (port);
}


#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3

#define QUALIFIED	0

TeredoRelay::TeredoRelay (uint32_t server_ip, uint16_t port)
	: head (NULL)
{
	addr.teredo.prefix = PREFIX_UNSET;
	addr.teredo.server_ip = server_ip;
	addr.teredo.flags = htons (TEREDO_FLAGS_CONE);
	addr.teredo.client_ip = 0;
	addr.teredo.client_port = 0;

	if (sock.ListenPort (port) == 0)
	{
		probe.state = PROBE_CONE;
		probe.count = 0;
		Process ();
	}
}


/* Releases peers list entries */
TeredoRelay::~TeredoRelay (void)
{
	struct __TeredoRelay_peer *p = head;

	while (p != NULL)
	{
		struct __TeredoRelay_peer *buf = p->next;
		if (p->queue != NULL)
			delete p->queue;
		delete p;
		p = buf;
	}
}


int TeredoRelay::NotifyUp (const struct in6_addr *addr)
{
	return 0;
}


int TeredoRelay::NotifyDown (void)
{
	return 0;
}


/* 
 * Allocates a peer entry. It is up to the caller to fill informations
 * correctly.
 *
 * FIXME: number of entry should be bound
 */
struct __TeredoRelay_peer *TeredoRelay::AllocatePeer (void)
{
	time_t now;
	time (&now);

	/* Tries to recycle a timed-out peer entry */
	for (struct __TeredoRelay_peer *p = head; p != NULL; p = p->next)
		if (ENTRY_EXPIRED (p, now))
			return p;

	/* Otherwise allocates a new peer entry */
	struct __TeredoRelay_peer *p;
	try
	{
		p = new struct __TeredoRelay_peer;
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
struct __TeredoRelay_peer *TeredoRelay::FindPeer (const struct in6_addr *addr)
{
	time_t now;

	time(&now);

	for (struct __TeredoRelay_peer *p = head; p != NULL; p = p->next)
		if (memcmp (&p->addr, addr, sizeof (struct in6_addr)) == 0)
			if (!ENTRY_EXPIRED (p, now))
				return p; // found!
	
	return NULL;
}




/*
 * Returs true if the packet whose header is passed as a parameter looks
 * like a Teredo bubble.
 */
inline bool IsBubble (const struct ip6_hdr *hdr)
{
	return (hdr->ip6_plen == 0) && (hdr->ip6_nxt == IPPROTO_NONE);
}


/*
 * Handles a packet coming from the IPv6 Internet, toward a Teredo node
 * (as specified per paragraph 5.4.1). That's what the specification calls
 * "Packet transmission".
 * Returns 0 on success, -1 on error.
 */
int TeredoRelay::SendPacket (const void *packet, size_t length)
{
	/* Makes sure we are qualified properly */
	if (!IsRunning ())
		return -1; // TODO: send ICMPv6 error?

	struct ip6_hdr ip6;
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0;

	memcpy (&ip6, packet, sizeof (ip6_hdr));

	// Sanity check (should we trust the kernel?):
	// It's no use emitting such a broken packet because the other side
	// will drop it anyway.
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((sizeof (ip6) + ntohs (ip6.ip6_plen)) != length))
		return 0; // invalid IPv6 packet

	const union teredo_addr *dst = (union teredo_addr *)&ip6.ip6_dst,
				*src = (union teredo_addr *)&ip6.ip6_src;

	if (dst->teredo.prefix != GetPrefix ()
	 && src->teredo.prefix != GetPrefix ())
		/*
		 * Routing packets not from a Teredo client,
		 * neither toward a Teredo client is NOT allowed through a
		 * Teredo tunnel. The Teredo server will reject the packet.
		 *
		 * We also drop link-local unicast and multicast packets as
		 * they can't be routed through Teredo properly.
		 */
		// TODO: maybe, send a ICMP adminstrative error
		return 0;

	/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
	struct __TeredoRelay_peer *p = FindPeer (&ip6.ip6_dst);
#ifdef DEBUG
	{
		struct in_addr a;
		a.s_addr = ~addr.teredo.client_ip;
		syslog (LOG_DEBUG, "DEBUG: packet for %s:%hu\n", inet_ntoa (a),
				~addr.teredo.client_port);
	}
#endif

	if (p != NULL)
	{
		/* Already known -valid- peer */
		if (p->flags.flags.trusted)
		{
			time (&p->last_rx);
			return sock.SendPacket (packet, length,
						p->mapped_addr,
						p->mapped_port);
		}
	}
	
	/* Unknown, possibly invalid, peer */
	if (dst->teredo.prefix != GetPrefix ())
	{
		/*
		 * If we are not a qualified client, ie. we have no server
		 * IPv4 address to contact for direct IPv6 connectivity, we
		 * cannot route packets toward non-Teredo IPv6 addresses.
		 *
		 * TODO:
		 * The specification mandates silently ignoring such
		 * packets. However, this only happens in case of
		 * misconfiguration, so I believe it could be better to
		 * notify the user. An alternative might be to send an
		 * ICMPv6 error back to the kernel.
		 */
		if (IsRelay ())
			return 0;
			
		/* Client case 2: direct IPv6 connectivity test */
		// FIXME: implement that before next release
		syslog (LOG_WARNING, "DEBUG: FIXME: should send echo request");
		return 0;
	}

	// Ignores Teredo clients with incorrect server IPv4
	if (!is_ipv4_global_unicast (~dst->teredo.client_ip))
		return 0;
		
	/* Client case 3: TODO: implement local discovery */

	// Creates a new entry
	p = AllocatePeer ();
	if (p == NULL)
		return -1; // insufficient memory
	memcpy (&p->addr, &ip6.ip6_dst, sizeof (struct in6_addr));
	p->mapped_addr = ~dst->teredo.client_ip;
	p->mapped_port = ~dst->teredo.client_port;
	p->flags.all_flags = 0;
	time (&p->last_xmit);
	p->queue = NULL;
	
	/* Client case 4 & relay case 2: new cone peer */
	if (IN6_IS_TEREDO_ADDR_CONE (&ip6.ip6_dst))
	{
		p->flags.flags.trusted = 1;
		return sock.SendPacket (packet, length, p->mapped_addr,
					p->mapped_port);
	}

	/* Client case 5 & relay case 3: untrusted non-cone peer */
	/* TODO: enqueue more than one packet 
	 * (and do this in separate functions) */
	if (p->queue == NULL)
	{
		p->queue = new uint8_t[length];

		memcpy (p->queue, packet, length);
		p->queuelen = length;
	}
#ifdef DEBUG
	else
		syslog (LOG_DEBUG, _("FIXME: packet not queued\n"));
#endif

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

			/*
			 * Open the return path if we are behind a
			 * restricted NAT.
			 */
			if (!IsCone ()
			 && SendBubble (sock, &ip6.ip6_dst, IsCone (), false))
				return -1;

			return SendBubble (sock, &ip6.ip6_dst, IsCone ());
		}
	}

	// Too many bubbles already sent
	return 0;
}


/*
 * Handles a packet coming from the Teredo tunnel
 * (as specified per paragraph 5.4.2). That's called "Packet reception".
 * Returns 0 on success, -1 on error.
 */
int TeredoRelay::ReceivePacket (const fd_set *readset)
{
	TeredoPacket packet;

	if (sock.ReceivePacket (readset, packet))
		return -1;

	size_t length;
	const struct ip6_hdr *buf = packet.GetIPv6Header (length);
	struct ip6_hdr ip6;

	// Checks packet
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0; // invalid packet

	memcpy (&ip6, buf, sizeof (ip6));
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((ntohs (ip6.ip6_plen) + sizeof (ip6)) != length))
		return 0; // malformatted IPv6 packet

	if (!IsRunning ())
	{
		/* FIXME: handle server RA for Qualification */
		return 0;
	}

	/*
	 * The specification says we "should" check that the packet
	 * destination address is ours, if we are a client. The kernel
	 * will do this for us if we are a client. If we are a relay, we must
	 * absolutely NOT check that.
	 */

	if (IsClient () && (packet.GetClientIP () == GetServerIP ())
	 && (packet.GetClientPort () == htons (IPPORT_TEREDO)))
	{
		gettimeofday (&probe.serv, NULL);

		const struct teredo_orig_ind *ind = packet.GetOrigInd ();
		if (ind != NULL)
			/* FIXME: perform direct IPv6 connectivity test */;
	}

	// Only the server is allowed to send packet when not qualified
	if (!IsRunning ())
		return 0;

	const union teredo_addr *src =
		(const union teredo_addr *)&ip6.ip6_src;

	// Checks source IPv6 address
	if ((src->teredo.prefix != GetPrefix ())
	 || !IN6_MATCHES_TEREDO_CLIENT (src, packet.GetClientIP (),
		 			packet.GetClientPort ()))
		return 0;

	// Checks peers list
	struct __TeredoRelay_peer *p = FindPeer (&ip6.ip6_src);
	/* 
	 * We are explicitly allowed to drop packet from unknown peers
	 * and it is surely much safer.
	 */
	if (p == NULL)
		return 0;

	p->flags.flags.trusted = p->flags.flags.replied = 1;
	time (&p->last_rx);

	// Dequeues queued packets (TODO: dequeue more than one)
	if (p->queue != NULL)
	{
		sock.SendPacket (p->queue, p->queuelen, p->mapped_addr,
					p->mapped_port);
		delete p->queue;
		p->queue = NULL;
	}
	
	if (IsBubble (&ip6))
		return 0; // do not relay bubbles

	/*
	 * TODO: check "range of IPv6 adresses served by the relay"
	 * (that should be a run-time option)
	 * Ensures that the packet destination has a global scope
	 * (ie 2000::/3)
	if ((ip6.ip6_dst.s6_addr[0] & 0xe0) != 0x20)
		return 0; // must be discarded
	 */

	return SendIPv6Packet (buf, length);
}


int TeredoRelay::Process (void)
{
	struct timeval now;

	gettimeofday (&now, NULL);

	if (IsRelay ())
		return 0;

	/* Qualification or server refresh (only for client) */
	if (((signed)(now.tv_sec - probe.next.tv_sec) > 0)
	 || ((now.tv_sec == probe.next.tv_sec)
	  && ((signed)(now.tv_usec - probe.next.tv_usec) > 0)))
	{
		unsigned delay;

		if (probe.state == QUALIFIED)
		{
			// TODO: randomize refresh interval
			delay = 30;

			if (((signed)(now.tv_sec - probe.serv.tv_sec) > 0)
			 || ((now.tv_sec == probe.serv.tv_sec)
			  && ((signed)(now.tv_usec - probe.serv.tv_usec) > 0)))
			{
				// connectivity with server lost
				probe.count = 1;
				probe.state = IsCone () ? PROBE_CONE
							: PROBE_RESTRICT;
			}
		}
		else
		{
			delay = 4;

			if (probe.state == PROBE_CONE)
			{
				if (probe.count == 4) // already 4 attempts?
				{
					// Cone qualification failed
					probe.state = PROBE_RESTRICT;
					probe.count = 0;
				}
			}
			else
			{
				if (probe.state == PROBE_SYMMETRIC)
					/*
					 * Second half of restricted
					 * qualification failed: re-trying
					 * restricted qualifcation
					 */
					probe.state = PROBE_RESTRICT;

				if (probe.count == 4)
					/*
					 * Restricted qualification failed.
					 * Restarting from zero.
					 */
					probe.state = PROBE_CONE;
				else
				if (probe.count == 3)
					/*
					 * Last restricted qualification
					 * attempt before declaring failure.
					 * Defer new attempts for 30 seconds.
					 */
					delay = 30;
			}

			probe.count ++;
		}

		SendRS (sock, GetServerIP (), probe.nonce,
			probe.state == PROBE_CONE /* cone */,
			probe.state == PROBE_RESTRICT /* secondary */);

		gettimeofday (&state.next, NULL);
		probe.next.tv_sec += delay;
	}

	return 0;
}
