/*
 * server.cpp - Handling of a single Teredo datagram (server-side).
 * $Id$
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

#include <stddef.h>
#include <string.h> /* memcpy(), memset() */
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <errno.h> // errno
#include <stdio.h> // snprintf()

#include <sys/types.h>
#include <unistd.h> // close()
#include <sys/socket.h>
#include <netinet/in.h> // struct in6_addr
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <pthread.h>

#include <libteredo/server-udp.h>
#include <libteredo/server.h>
#include "v4global.h"
#include "checksum.h"

/*
 * Sends a Teredo-encapsulated Router Advertisement.
 * Returns -1 on error, 0 on success.
 */
bool
TeredoServer::SendRA (const TeredoPacket& p, const struct in6_addr *dest_ip6,
                      bool use_secondary_ip) const
{
	uint8_t packet[13 + 8 + sizeof (struct ip6_hdr)
	                  + sizeof (struct nd_router_advert)
	                  + sizeof (struct nd_opt_prefix_info)];
	uint8_t *ptr = packet;

	// Authentification header
	// TODO: support for secure qualification
	const uint8_t *nonce = p.GetAuthNonce ();
	if (nonce != NULL)
	{
		// No particular alignment issue
		struct teredo_simple_auth *auth;

		auth = (struct teredo_simple_auth *)ptr;

		auth->hdr.hdr.zero = 0;
		auth->hdr.hdr.code = teredo_auth_hdr;
		auth->hdr.id_len = auth->hdr.au_len = 0;
		memcpy (&auth->nonce, nonce, 8);
		auth->confirmation = 0;

		ptr += 13;
	}

	// Origin indication header
	{
		struct teredo_orig_ind orig;

		orig.hdr.zero = 0;
		orig.hdr.code = teredo_orig_ind;
		orig.orig_port = ~p.GetClientPort (); // obfuscate
		orig.orig_addr = ~p.GetClientIP (); // obfuscate

		memcpy (ptr, &orig, 8);
		ptr += 8;
	}


	{
		struct
		{
			struct ip6_hdr            ip6;
			struct nd_router_advert   ra;
			struct nd_opt_prefix_info pi;
			struct nd_opt_mtu         mtu;
		} ra;

		// IPv6 header
		ra.ip6.ip6_flow = htonl (0x60000000);
		ra.ip6.ip6_plen = htons (sizeof (ra) - sizeof (ra.ip6));
		ra.ip6.ip6_nxt = IPPROTO_ICMPV6;
		ra.ip6.ip6_hlim = 255;

		{
			union teredo_addr src;
			src.teredo.prefix = htonl (0xfe800000);
			src.teredo.server_ip = 0;
			src.teredo.flags = htons (TEREDO_FLAG_CONE);
			src.teredo.client_port = htons (IPPORT_TEREDO);
			src.teredo.client_ip = ~GetServerIP ();

			memcpy (&ra.ip6.ip6_src, &src,
				sizeof (ra.ip6.ip6_src));
		}

		memcpy (&ra.ip6.ip6_dst, dest_ip6, sizeof (ra.ip6.ip6_dst));

		// ICMPv6: Router Advertisement
		ra.ra.nd_ra_type = ND_ROUTER_ADVERT;
		ra.ra.nd_ra_code = 0;
		ra.ra.nd_ra_cksum = 0;
		ra.ra.nd_ra_curhoplimit = 0;
		ra.ra.nd_ra_flags_reserved = 0;
		ra.ra.nd_ra_router_lifetime = 0;
		ra.ra.nd_ra_reachable = 0;
		ra.ra.nd_ra_retransmit = htonl (2000);

		// ICMPv6 option: Prefix information

		ra.pi.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
		ra.pi.nd_opt_pi_len = sizeof (ra.pi) >> 3;
		ra.pi.nd_opt_pi_prefix_len = 64;
		ra.pi.nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_AUTO;
		ra.pi.nd_opt_pi_valid_time = 0xffffffff;
		ra.pi.nd_opt_pi_preferred_time = 0xffffffff;
		{
			union teredo_addr pref;

			pref.teredo.prefix = prefix;
			pref.teredo.server_ip = GetServerIP ();
			memset (pref.ip6.s6_addr + 8, 0, 8);
			memcpy (&ra.pi.nd_opt_pi_prefix, &pref.ip6,
				sizeof (ra.pi.nd_opt_pi_prefix));
		}

		// ICMPv6 option : MTU
		ra.mtu.nd_opt_mtu_type = ND_OPT_MTU;
		ra.mtu.nd_opt_mtu_len = sizeof (ra.mtu) >> 3;
		ra.mtu.nd_opt_mtu_reserved = 0;
		ra.mtu.nd_opt_mtu_mtu = advLinkMTU;

		// ICMPv6 checksum computation
		ra.ra.nd_ra_cksum = icmp6_checksum (&ra.ip6,
				(struct icmp6_hdr *)&ra.ra);
		memcpy (ptr, &ra, sizeof (ra));
		ptr += sizeof (ra);
	}

	if (IN6_IS_TEREDO_ADDR_CONE (dest_ip6))
		use_secondary_ip = !use_secondary_ip;

	return sock.SendPacket (packet, ptr - packet, p.GetClientIP (),
	                        p.GetClientPort (), use_secondary_ip) == 0;
}

/*
 * Forwards a Teredo packet to a client
 */
static bool
ForwardUDPPacket (const TeredoServerUDP& sock, const TeredoPacket& packet,
                  bool insert_orig = true)
{
	size_t length;
	const struct ip6_hdr *p =
		(const struct ip6_hdr *)packet.GetIPv6Packet (length);
		/* might not be aligned */

	if ((p == NULL) || (length > 65507))
		return -1;

	union teredo_addr dst;
	memcpy (&dst, &p->ip6_dst, sizeof (dst));
	uint32_t dest_ip = ~dst.teredo.client_ip;

	if (!is_ipv4_global_unicast (dest_ip))
		return 0; // ignore invalid client IP

	uint8_t buf[65515];
	unsigned offset;

	// Origin indication header
	// if the Teredo server's address is ours
	// NOTE: I wonder in which legitimate case insert_orig might be
	// false... but the spec implies it could
	if (insert_orig)
	{
		struct teredo_orig_ind orig;
		offset = 8;

		orig.hdr.zero = 0;
		orig.hdr.code = teredo_orig_ind;
		orig.orig_port = ~packet.GetClientPort (); // obfuscate
		orig.orig_addr = ~packet.GetClientIP (); // obfuscate
		memcpy (buf, &orig, offset);
	}
	else
		offset = 0;

	memcpy (buf + offset, p, length);
	return sock.SendPacket (buf, length + offset, dest_ip,
	                        ~dst.teredo.client_port) == 0;
}


/*
 * Sends an IPv6 packet of *payload* length <plen> with a raw IPv6 socket.
 * Returns 0 on success, -1 on error.
 */
static bool
SendIPv6Packet (int fd, const void *p, size_t plen)
{
	struct sockaddr_in6 dst = { };
	int tries, res;

	dst.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	dst.sin6_len = sizeof (dst);
#endif
	memcpy (&dst.sin6_addr, &((const struct ip6_hdr *)p)->ip6_dst,
	        sizeof (dst.sin6_addr));
	plen += sizeof (struct ip6_hdr);

	for (tries = 0; tries < 10; tries++)
	{
		res = sendto (fd, p, plen, 0, (struct sockaddr *)&dst, sizeof (dst));
		if (res != -1)
			return res == (int)plen;

		switch (errno)
		{
			case ENETUNREACH: /* ICMPv6 unreach no route */
			case EACCES: /* ICMPv6 unreach administravely prohibited */
			case EHOSTUNREACH: /* ICMPv6 unreach addres unreachable */
				               /* ICMPv6 time exceeded */
			case ECONNREFUSED: /* ICMPv6 unreach port unreachable */
			case EMSGSIZE: /* ICMPv6 packet too big */
			case EPROTO: /* ICMPv6 param prob (and other errors) */
				break;

			default:
				return false;
		}
	}

	return false;
}


static const struct in6_addr in6addr_allrouters =
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2 } } };

/*
 * Checks and handles an Teredo-encapsulated packet.
 * Thread-safety note: Prefix and AdvLinkMTU might be changed by another
 * thread
 */
bool
TeredoServer::ProcessPacket (bool secondary)
{
	TeredoPacket packet;

	if (secondary ? sock.ReceivePacket2 (packet)
	              : sock.ReceivePacket (packet))
		return false;

	// Teredo server case number 3
	if (!is_ipv4_global_unicast (packet.GetClientIP ()))
		return true;

	// Check IPv6 packet (Teredo server check number 1)
	size_t ip6len;
	const uint8_t *buf = packet.GetIPv6Packet (ip6len);
	struct ip6_hdr ip6;
	
	if (ip6len < sizeof(ip6_hdr))
		return 0; // too small
	memcpy(&ip6, buf, sizeof (ip6));
	ip6len -= sizeof(ip6_hdr);

	if (((ip6.ip6_vfc >> 4) != 6)
	 || (ntohs (ip6.ip6_plen) != ip6len))
		return true; // not an IPv6 packet

	const uint8_t *upper = buf + sizeof (ip6);
	// NOTE: upper is not aligned, read single bytes only

	// Teredo server case number 2
	uint8_t proto = ip6.ip6_nxt;
	if ((proto != IPPROTO_NONE || ip6len > 0) // neither a bubble...
	 && proto != IPPROTO_ICMPV6) // nor an ICMPv6 message
		return true; // packet not allowed through server

	// Teredo server case number 4
	if (IN6_IS_ADDR_LINKLOCAL(&ip6.ip6_src)
	 && IN6_ARE_ADDR_EQUAL (&in6addr_allrouters, &ip6.ip6_dst)
	 && (proto == IPPROTO_ICMPV6)
	 && (ip6len > sizeof (nd_router_solicit))
	 && (((struct icmp6_hdr *)upper)->icmp6_type == ND_ROUTER_SOLICIT))
		// sends a Router Advertisement
		return SendRA (packet, &ip6.ip6_src, secondary);

	uint32_t myprefix = prefix;

	if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == myprefix)
	{
		// Source address is Teredo

		if (!IN6_MATCHES_TEREDO_CLIENT (&ip6.ip6_src,
						packet.GetClientIP (),
						packet.GetClientPort ()))
			return true; // case 7

		// Teredo server case number 5
		/*
		 * NOTE: Theoretically, we "should" accept ICMPv6 toward the
		 * server's own local-link address or the ip6-allrouters
		 * multicast address. In practice, it never happens.
		 */

		// Ensures that the packet destination has a global scope
		// (ie 2000::/3) - as specified.
		if ((ip6.ip6_dst.s6_addr[0] & 0xe0) != 0x20)
			return true; // must be discarded

		if (IN6_TEREDO_PREFIX(&ip6.ip6_dst) != myprefix)
			return SendIPv6Packet (fd, buf, ip6len);

		/*
		 * If the IPv6 destination is a Teredo address, the packet
		 * should be forwarded over UDP
		 */
	}
	else
	{
		// Source address is not Teredo
		if (IN6_TEREDO_PREFIX (&ip6.ip6_dst) != myprefix
		  || IN6_TEREDO_SERVER (&ip6.ip6_dst) != GetServerIP ())
			return true; // case 7

		// Teredo server case number 6
	}

	// forwards packet over Teredo:
	// (destination is a Teredo IPv6 address)
	return ForwardUDPPacket (sock, packet,
		IN6_TEREDO_SERVER (&ip6.ip6_dst) == GetServerIP ());
}


TeredoServer::TeredoServer (uint32_t ip1, uint32_t ip2)
	: server_ip (ip1), prefix (htonl (DEFAULT_TEREDO_PREFIX)),
	  advLinkMTU (htonl (1280))
{
	sock.ListenIP (ip1, ip2);

	fd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (fd != -1)
	{
		int flags = fcntl (fd, F_GETFL, 0);
		shutdown (fd, SHUT_RD);
		if (flags != -1)
			fcntl (fd, F_SETFL, O_NONBLOCK | flags);
	}
}


TeredoServer::~TeredoServer (void)
{
	if (fd != -1)
		close (fd);
}


bool
TeredoServer::CheckSystem (char *errmsg, size_t len)
{
	int fd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);

	if (fd >= 0)
	{
		close (fd);
		return true;
	}

	snprintf (errmsg, len, _("Raw IPv6 sockets not working: %s\n"),
	          strerror (errno));
	return false;
}


typedef struct server_thread_data
{
	TeredoServer *server;
	bool secondary;
	pthread_cond_t ready;
	pthread_mutex_t mutex;
};


void *
TeredoServer::Thread (void *o)
{
	struct server_thread_data *d = (struct server_thread_data *)o;

	TeredoServer *s = d->server;
	bool secondary = d->secondary;

	pthread_mutex_lock (&d->mutex);
	pthread_cond_signal (&d->ready);
	pthread_mutex_unlock (&d->mutex);

	while (1)
	{
		pthread_testcancel ();
		s->ProcessPacket (secondary);
	}

	/* unreachable */
}


bool
TeredoServer::Start (void)
{
	struct server_thread_data d;

	d.server = this;
	pthread_mutex_init (&d.mutex, NULL);
	pthread_cond_init (&d.ready, NULL);
	pthread_mutex_lock (&d.mutex);

	d.secondary = true;
	if (pthread_create (&t2, NULL, Thread, &d) == 0)
	{
		pthread_cond_wait (&d.ready, &d.mutex);

		d.secondary = false;
		if (pthread_create (&t1, NULL, Thread, &d) == 0)
		{
			pthread_cond_wait (&d.ready, &d.mutex);
			pthread_mutex_unlock (&d.mutex);
			pthread_cond_destroy (&d.ready);
			pthread_mutex_destroy (&d.mutex);
			return true;
		}

		pthread_cancel (t2);
		pthread_join (t2, NULL);
	}

	pthread_mutex_unlock (&d.mutex);
	pthread_cond_destroy (&d.ready);
	pthread_mutex_destroy (&d.mutex);

	return false;
}


void
TeredoServer::Stop (void)
{
	pthread_cancel (t1);
	pthread_cancel (t2);
	pthread_join (t1, NULL);
	pthread_join (t2, NULL);
}
