/*
 * relay.cpp - Teredo relay peers list definition
 * $Id$
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

#include <gettext.h>

#include <string.h>
#include <time.h> // TODO: use gettimeofday
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip6.h> // struct ip6_hdr
#include <syslog.h>

#include <libteredo/teredo.h>
#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include <libteredo/relay-udp.h>

#include "packets.h"
#include "security.h"
#include "queue.h"
#include <libteredo/relay.h>

#define TEREDO_TIMEOUT 30 // seconds


#define EXPIRED( date, now ) ((((unsigned)now) - (unsigned)date) > 30)
#define ENTRY_EXPIRED( peer, now ) (peer->flags.flags.replied \
					? EXPIRED (peer->last_rx, now) \
					: EXPIRED (peer->last_xmit, now))

// is_valid_teredo_prefix (PREFIX_UNSET) MUST return false
#define PREFIX_UNSET 0xffffffff


#define MAXQUEUE 1280 // bytes


/*
 * Queueng of packets from the IPv6 toward Teredo
 */
class TeredoRelay::OutQueue : public PacketsQueue
{
	private:
		TeredoRelayUDP *sock;
		uint32_t addr;
		uint16_t port;

		virtual int SendPacket (const void *p, size_t len)
		{
			return sock->SendPacket (p, len, addr, port);
		}

	public:
		OutQueue (TeredoRelayUDP *s) : PacketsQueue (MAXQUEUE),
					       sock (s)
		{
		}

		void SetMapping (uint32_t mapped_addr, uint16_t mapped_port)
		{
			addr = mapped_addr;
			port = mapped_port;
		}
};

/*
 * Queueing of packets from Teredo toward the IPv6
 */
class TeredoRelay::InQueue : public PacketsQueue
{
	private:
		TeredoRelay *relay;

		virtual int SendPacket (const void *p, size_t len)
		{
			return relay->SendIPv6Packet (p, len);
		}

	public:
		InQueue (TeredoRelay *r) : PacketsQueue (MAXQUEUE), relay (r)
		{
		}
};



struct TeredoRelay::peer
{
	peer (TeredoRelayUDP *sock, TeredoRelay *r)
		: outqueue (sock), inqueue (r)
	{
	}
		
	struct peer *next;

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
			unsigned nonce:1; // mapped_* unset, nonce set
		} flags;
		uint16_t all_flags;
	} flags;
	// TODO: nonce and mapped_* could be union-ed
	uint8_t nonce[8]; /* only for client toward non-client */
	time_t last_rx;
	time_t last_xmit;

	OutQueue outqueue;
	InQueue inqueue;
};

#define PROBE_CONE	1
#define PROBE_RESTRICT	2
#define PROBE_SYMMETRIC	3

#define QUALIFIED	0


TeredoRelay::TeredoRelay (uint32_t pref, uint16_t port, uint32_t ipv4,
				bool cone)
	: server_ip2 (0), head (NULL)
{
	addr.teredo.prefix = pref;
	addr.teredo.server_ip = 0;
	addr.teredo.flags = cone ? htons (TEREDO_FLAG_CONE) : 0;
	addr.teredo.client_ip = 0;
	addr.teredo.client_port = 0;
	probe.state = QUALIFIED;

	sock.ListenPort (port, ipv4);
}


#ifdef MIREDO_TEREDO_CLIENT
TeredoRelay::TeredoRelay (uint32_t server_ip, uint16_t port, uint32_t ipv4)
	: head (NULL)
{
	if (!is_ipv4_global_unicast (server_ip))
		syslog (LOG_WARNING,
			_("Server has a non global IPv4 address. "
			"It will most likely not work."));

	addr.teredo.prefix = PREFIX_UNSET;
	addr.teredo.server_ip = server_ip;
	addr.teredo.flags = htons (TEREDO_FLAG_CONE);
	addr.teredo.client_ip = 0;
	addr.teredo.client_port = 0;

	server_ip2 = htonl (ntohl (server_ip) + 1);

	if (GenerateNonce (probe.nonce, true)
	 && (sock.ListenPort (port, ipv4) == 0))
	{
		probe.state = PROBE_CONE;
		probe.count = 0;
		gettimeofday (&probe.next, NULL);
		Process ();
	}
}
#endif

/* Releases peers list entries */
TeredoRelay::~TeredoRelay (void)
{
	struct peer *p = head;

	while (p != NULL)
	{
		struct peer *buf = p->next;
		delete p;
		p = buf;
	}
}


int TeredoRelay::NotifyUp (const struct in6_addr *)
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
 * FIXME: move to another file
 */
struct TeredoRelay::peer *TeredoRelay::AllocatePeer (void)
{
	time_t now;
	time (&now);

	/* Tries to recycle a timed-out peer entry */
	for (struct peer *p = head; p != NULL; p = p->next)
		if (ENTRY_EXPIRED (p, now))
		{
			p->outqueue.Trash ();
			p->inqueue.Trash ();
			return p;
		}

	/* Otherwise allocates a new peer entry */
	struct peer *p;
	try
	{
		p = new struct peer (&sock, this);
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
struct TeredoRelay::peer *TeredoRelay::FindPeer (const struct in6_addr *addr)
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
 * Sends an ICMPv6 Destination Unreachable error to the IPv6 Internet.
 * Unfortunately, this will use a local-scope address as source, which is not
 * quite good.
 */
int
TeredoRelay::SendUnreach (int code, const void *in, size_t inlen)
{
	struct
	{
		struct ip6_hdr hdr;
		uint8_t fill[1280 - sizeof (struct ip6_hdr)];
	} buf;

	/* FIXME: implement ICMP rate limit */
	size_t outlen = BuildICMPv6Error (&buf.hdr, &teredo_cone, 1, code,
						in, inlen);
	return outlen ? SendIPv6Packet (&buf, outlen) : 0;
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
	struct ip6_hdr ip6;
	if ((length < sizeof (ip6)) || (length > 65507))
		return 0;

	memcpy (&ip6, packet, sizeof (ip6));

	// Sanity check (should we trust the kernel?):
	// It's no use emitting such a broken packet because the other side
	// will drop it anyway.
	if (((ip6.ip6_vfc >> 4) != 6)
	 || ((sizeof (ip6) + ntohs (ip6.ip6_plen)) != length))
		return 0; // invalid IPv6 packet

	/* Makes sure we are qualified properly */
	if (!IsRunning ())
		return SendUnreach (0, packet, length);

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
		return SendUnreach (1, packet, length);


	struct peer *p = FindPeer (&ip6.ip6_dst);

	if (p != NULL)
	{
		/* Case 1 (paragraphs 5.2.4 & 5.4.1): trusted peer */
		if (p->flags.flags.trusted)
		{
			/* Already known -valid- peer */
			time (&p->last_xmit);
			return sock.SendPacket (packet, length,
						p->mapped_addr,
						p->mapped_port);
		}
	}
	
	/* Unknown or untrusted peer */
	if (dst->teredo.prefix != GetPrefix ())
	{
		/* Unkown or untrusted non-Teredo node */

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
		if (IsRelay ())
			return SendUnreach (1, packet, length);

#ifdef MIREDO_TEREDO_CLIENT
		/* Client case 2: direct IPv6 connectivity test */
		// TODO: avoid code duplication
		if (p == NULL)
		{
			p = AllocatePeer ();
			if (p == NULL)
				return -1; // memory error
			memcpy (&p->addr, &ip6.ip6_dst, sizeof (struct in6_addr));
			p->mapped_port = 0;
			p->mapped_addr = 0;
			p->flags.all_flags = 0;
			time (&p->last_xmit);
		}

		// FIXME: re-send echo request later if no response

		p->outqueue.Queue (packet, length);

		if (!p->flags.flags.nonce)
		{
			if (!GenerateNonce (p->nonce))
				return 0;

			p->flags.flags.nonce = 1;
		}
		return SendPing (sock, &addr, &dst->ip6, p->nonce);
#endif
	}

	/* Unknown or untrusted Teredo client */

	// Ignores Teredo clients with incorrect server IPv4
	if (!is_ipv4_global_unicast (IN6_TEREDO_SERVER (&ip6.ip6_dst))
	 || (IN6_TEREDO_SERVER (&ip6.ip6_dst) == 0))
		return 0;

	/* Client case 3: TODO: implement local discovery */

	if (p == NULL)
	{
		/* Unknown Teredo clients */

		// Creates a new entry
		p = AllocatePeer ();
		if (p == NULL)
			return -1; // insufficient memory
		memcpy (&p->addr, &ip6.ip6_dst, sizeof (struct in6_addr));
		p->mapped_port = IN6_TEREDO_PORT (dst);
		p->mapped_addr = IN6_TEREDO_IPV4 (dst);
		p->outqueue.SetMapping (p->mapped_addr, p->mapped_port);
		p->flags.all_flags = 0;
		time (&p->last_xmit);

		/* Client case 4 & relay case 2: new cone peer */
		if (IN6_IS_TEREDO_ADDR_CONE (&ip6.ip6_dst))
		{
			p->flags.flags.trusted = 1;
			return sock.SendPacket (packet, length,
						p->mapped_addr,
						p->mapped_port);
		}
	}

	/* Client case 5 & relay case 3: untrusted non-cone peer */
	p->outqueue.Queue (packet, length);

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
			 && SendBubble (sock, &ip6.ip6_dst, false, false))
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
// seconds to wait before considering that we've lost contact with the server
#define SERVER_LOSS_DELAY 40
#define SERVER_PING_DELAY 30

unsigned TeredoRelay::QualificationTimeOut = 4; // seconds
unsigned TeredoRelay::QualificationRetries = 3;
unsigned TeredoRelay::RestartDelay = 300; // seconds

int TeredoRelay::ReceivePacket (const fd_set *readset)
{
	TeredoPacket packet;

	if (sock.ReceivePacket (readset, packet))
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
	if (!IsRunning ())
	{
		/* Handle router advertisement for qualification */
		/*
		 * We don't accept router advertisement without nonce.
		 * It is far too easy to spoof such packets.
		 *
		 * We don't check the source address (which may be the
		 * server's secondary address, nor the source port)
		 * TODO: Maybe we should check that too
		 */
		const uint8_t *s_nonce = packet.GetAuthNonce ();
		if ((s_nonce == NULL) || memcmp (s_nonce, probe.nonce, 8))
			return 0;
		if (packet.GetConfByte ())
		{
			syslog (LOG_ERR,
				_("Authentication refused by server."));
			return 0;
		}

		union teredo_addr newaddr;

		newaddr.teredo.server_ip = GetServerIP ();
		if (!ParseRA (packet, &newaddr, probe.state == PROBE_CONE))
			return 0;

		/* Correct router advertisement! */
		gettimeofday (&probe.serv, NULL);
		probe.serv.tv_sec += SERVER_LOSS_DELAY;

		if (probe.state == PROBE_RESTRICT)
		{
			probe.state = PROBE_SYMMETRIC;
			SendRS (sock, GetServerIP (), probe.nonce,
				false, false);

			gettimeofday (&probe.next, NULL);
			probe.next.tv_sec += QualificationTimeOut;
			memcpy (&addr, &newaddr, sizeof (addr));
		}
		else
		if ((probe.state == PROBE_SYMMETRIC)
		 && ((addr.teredo.client_port != newaddr.teredo.client_port)
		  || (addr.teredo.client_ip != newaddr.teredo.client_ip)))
		{
			syslog (LOG_ERR,
				_("Unsupported symmetric NAT detected."));

			/* Resets state, will retry in 5 minutes */
			addr.teredo.prefix = PREFIX_UNSET;
			probe.state = PROBE_CONE;
			probe.count = 0;
			gettimeofday (&probe.next, NULL);
			probe.next.tv_sec += RestartDelay;
			return 0;
		}
		else
		{
			syslog (LOG_INFO, _("Qualified (NAT type: %s)"),
				gettext (probe.state == PROBE_CONE
				? N_("cone") : N_("restricted")));
			probe.state = QUALIFIED;

			gettimeofday (&probe.next, NULL);
			probe.next.tv_sec += SERVER_PING_DELAY;

			// call memcpy before NotifyUp for re-entrancy
			memcpy (&addr, &newaddr, sizeof (addr));
			NotifyUp (&newaddr.ip6);
		}

		return 0;
	}

	/* Maintenance */
	if (IsClient () && (packet.GetClientPort () == htons (IPPORT_TEREDO)))
	{
		/*
		 * Server IP not checked because it might be the server's
		 * secondary IP. We use the authentication header instead.
		 */
		const uint8_t *s_nonce = packet.GetAuthNonce ();

		if ((s_nonce != NULL)
		 && (memcmp (s_nonce, probe.nonce, 8) == 0))
		{
			// TODO: refresh interval randomisation
			gettimeofday (&probe.serv, NULL);
			probe.serv.tv_sec += SERVER_LOSS_DELAY;

			// Checks if our Teredo address changed:
			union teredo_addr newaddr;
			newaddr.teredo.server_ip = GetServerIP ();

			if (ParseRA (packet, &newaddr, IsCone ())
			 && memcmp (&addr, &newaddr, sizeof (addr)))
			{
				memcpy (&addr, &newaddr, sizeof (addr));
				syslog (LOG_NOTICE,
					_("Teredo address changed"));
				NotifyUp (&newaddr.ip6);
			}

			/*
			 * Our server will not send a packet with auth header
			 * except a Router Advertisement (or it is broken and
			 * we'd better ignore it).
			 */
			return 0;
		}

		// FIXME check server IP!!!
		const struct teredo_orig_ind *ind = packet.GetOrigInd ();
		if (ind != NULL)
		{
			SendBubble (sock, ~ind->orig_addr, ~ind->orig_port,
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
				SendBubble (sock,
					IN6_TEREDO_IPV4 (&ip6.ip6_src),
					IN6_TEREDO_PORT (&ip6.ip6_src),
					&ip6.ip6_dst, &ip6.ip6_src);
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
	 * TODO:
	 * The specification says we "should" check that the packet
	 * destination address is ours, if we are a client. The kernel
	 * will do this for us if we are a client. Besides, in the case of
	 * packets from the server, the destination might not be our Teredo
	 * address.
	 *
	 * In the relay's case, we "should" check that the destination is in
	 * the "range of IPv6 adresses served by the relay", which may be a
	 * run-time option (?).
	 *
	 * NOTE:
	 * The specification specifies that the relay MUST look up the peer in
	 * the list and update last reception date even if the destination is
	 * incorrect.
	 */

#if 0
	/*
	 * Ensures that the packet destination has an IPv6 Internet scope
	 * (ie 2000::/3)
	 * That should be done just before calling SendIPv6Packet(), but it
	 * so much easier to do it now.
	 */
	if ((ip6.ip6_dst.s6_addr[0] & 0xe0) != 0x20)
		return 0; // must be discarded, or ICMPv6 error (?)
#else
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
	 */
	if ((((uint16_t *)ip6.ip6_src.s6_addr)[0] & 0xfec0) == 0xfe80)
		return 0;

	/* Actual packet reception, either as a relay or a client */

	// Checks source IPv6 address / looks up peer in the list:
	struct peer *p = FindPeer (&ip6.ip6_src);

	if (p != NULL)
	{
		// Client case 1 (trusted node or (trusted) Teredo client):
		if (p->flags.flags.trusted
		 && (packet.GetClientIP () == p->mapped_addr)
		 && (packet.GetClientPort () == p->mapped_port))
		{
			p->flags.flags.replied = 1;

			time (&p->last_rx);
			return SendIPv6Packet (buf, length);
		}

#ifdef MIREDO_TEREDO_CLIENT
		// Client case 2 (untrusted non-Teredo node):
		if ((!p->flags.flags.trusted) && p->flags.flags.nonce
		 && CheckPing (packet, p->nonce))
		{
			p->flags.flags.trusted = p->flags.flags.replied = 1;
			p->flags.flags.nonce = 0;

			p->mapped_port = packet.GetClientPort ();
			p->mapped_addr = packet.GetClientIP ();
			p->outqueue.SetMapping (p->mapped_addr,
						p->mapped_port);
			time (&p->last_rx);

			p->outqueue.Flush ();
			p->inqueue.Flush ();

			/*
			 * NOTE:
			 * This implies the kernel will see Echo replies sent
			 * for Teredo tunneling maintenance. It's not really
			 * an issue, as IPv6 stacks ignore them.
			 *
			 * FIXME: do not do this
			 */
			return SendIPv6Packet (buf, length);
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
				/*
				 * Relays are explicitly allowed to drop
				 * packets from unknown peers and it is surely
				 * much better. It prevents routing of packet
				 * through the wrong relay.
				 */
				if (IsRelay ())
					return 0;

#ifdef MIREDO_TEREDO_CLIENT
				// TODO: do not duplicate this code
				p = AllocatePeer ();
				if (p == NULL)
					return -1; // insufficient memory
				memcpy (&p->addr, &ip6.ip6_dst,
					sizeof (struct in6_addr));
				
				p->mapped_port =
					IN6_TEREDO_PORT (&ip6.ip6_dst);
				p->mapped_addr =
					IN6_TEREDO_IPV4 (&ip6.ip6_dst);
				p->outqueue.SetMapping (p->mapped_addr,
							p->mapped_port);
				p->flags.all_flags = 0;
#endif
			}
			else
			{
				p->outqueue.Flush ();
				/* p->inqueue.Flush (); -- always empty */
			}

			p->flags.flags.trusted = p->flags.flags.replied = 1;
			time (&p->last_rx);

			if (IsBubble (&ip6))
				return 0; // discard Teredo bubble
			return SendIPv6Packet (buf, length);
		}

		// TODO: remove this line if we implement local teredo
		return 0;
	}

#ifdef MIREDO_TEREDO_CLIENT
	// Relays only accept packet from Teredo clients;
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
		p = AllocatePeer ();
		if (p == NULL)
			return -1; // memory error
		memcpy (&p->addr, &ip6.ip6_src, sizeof (struct in6_addr));
		p->mapped_port = 0;
		p->mapped_addr = 0;
		p->flags.all_flags = 0;
		time (&p->last_rx);
	}

	p->inqueue.Queue (buf, length);

	// FIXME: re-send echo request later if no response
	if (!p->flags.flags.nonce)
	{
		if (!GenerateNonce (p->nonce))
			return -1;
		p->flags.flags.nonce = 1;
	}

	p->flags.flags.replied = 1;
	time (&p->last_xmit);
	return SendPing (sock, &addr, &ip6.ip6_src, p->nonce);
#else /* ifdef MIREDO_TEREDO_CLIENT */
	return 0;
#endif
}


int TeredoRelay::Process (void)
{
	if (!sock)
		return -1;

	struct timeval now;

	gettimeofday (&now, NULL);

	if (IsRelay ())
		return 0;

#ifdef MIREDO_TEREDO_CLIENT
	/* Qualification or server refresh (only for client) */
	if (((signed)(now.tv_sec - probe.next.tv_sec) > 0)
	 || ((now.tv_sec == probe.next.tv_sec)
	  && ((signed)(now.tv_usec - probe.next.tv_usec) > 0)))
	{
		unsigned delay;
		bool down = false;

		if (probe.state == QUALIFIED)
		{
			// TODO: randomize refresh interval
			delay = SERVER_PING_DELAY;
#if 0
			if (((signed)(now.tv_sec - probe.serv.tv_sec) > 0)
			 || ((now.tv_sec == probe.serv.tv_sec)
			  && ((signed)(now.tv_usec - probe.serv.tv_usec) > 0)))
			{
				// connectivity with server lost
				probe.count = 1;
				probe.state = IsCone () ? PROBE_CONE
							: PROBE_RESTRICT;
				down = true;
			}
#endif
		}
		else
		{
			delay = QualificationTimeOut;

			if (probe.state == PROBE_CONE)
			{
				if (probe.count >= QualificationRetries)
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

				if (probe.count >= QualificationRetries)
					/*
					 * Restricted qualification failed.
					 * Restarting from zero.
					 */
					probe.state = PROBE_CONE;
				else
				if ((probe.count + 1) == QualificationRetries)
					/*
					 * Last restricted qualification
					 * attempt before declaring failure.
					 * Defer new attempts for 300 seconds.
					 */
					delay = RestartDelay;
			}

			probe.count ++;
		}

		SendRS (sock, GetServerIP (), probe.nonce,
			probe.state == PROBE_CONE /* cone */,
			probe.state == PROBE_RESTRICT /* secondary */);

		gettimeofday (&probe.next, NULL);
		probe.next.tv_sec += delay;

		if (down)
		{
			syslog (LOG_NOTICE, _("Lost Teredo connectivity"));
			// do this at the end to allow re-entrancy
			NotifyDown ();
		}
	}
#endif /* ifdef MIREDO_TEREDO_CLIENT */

	return 0;
}
