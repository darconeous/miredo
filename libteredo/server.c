/*
 * server.c - Handling of a single Teredo datagram (server-side).
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

#include <stdbool.h>
#include <errno.h> // errno
#include <stdio.h> // snprintf()
#include <stdlib.h>

#include <sys/types.h>
#include <unistd.h> // close()
#include <sys/socket.h>
#include <netinet/in.h> // struct in6_addr
#include <netinet/ip6.h> // struct ip6_hdr
#include <netinet/icmp6.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>

#include "server.h"
#include "v4global.h"
#include "checksum.h"
#include "teredo.h"
#include "teredo-udp.h"

static pthread_mutex_t raw_mutex = PTHREAD_MUTEX_INITIALIZER;
static int raw_fd; // raw IPv6 socket
static unsigned raw_users = 0;

struct libteredo_server
{
	pthread_t t1, t2;

	int fd_primary, fd_secondary; // UDP/IPv4 sockets

	/* These are all in network byte order (including MTU!!) */
	uint32_t server_ip, prefix, advLinkMTU;
};

/*
 * Sends a Teredo-encapsulated Router Advertisement.
 * Returns -1 on error, 0 on success.
 */
static bool
SendRA (const libteredo_server *s, const struct teredo_packet *p,
        const struct in6_addr *dest_ip6, bool secondary)
{
	const uint8_t *nonce;
	union teredo_addr *addr;
	struct iovec iov[3];
	struct teredo_simple_auth auth;
	struct teredo_orig_ind orig;
	struct
	{
		struct ip6_hdr            ip6;
		struct nd_router_advert   ra;
		struct nd_opt_prefix_info pi;
		struct nd_opt_mtu         mtu;
	} ra;

	// Authentification header
	// TODO: support for secure qualification
	iov[0].iov_base = &auth;

	nonce = p->nonce;
	if (nonce != NULL)
	{
		//memset (&auth, 0, sizeof (auth));
		auth.hdr.hdr.zero = 0;
		auth.hdr.hdr.code = teredo_auth_hdr;
		auth.hdr.id_len = auth.hdr.au_len = 0;
		memcpy (&auth.nonce, nonce, 8);
		auth.confirmation = 0;

		iov[0].iov_len = 13;
	}
	else
		iov[0].iov_len = 0;

	// Origin indication header
	//memset (&orig, 0, sizeof (orig));
	iov[1].iov_base = &orig;
	iov[1].iov_len = 8;
	orig.hdr.zero = 0;
	orig.hdr.code = teredo_orig_ind;
	orig.orig_port = ~p->source_port; // obfuscate
	orig.orig_addr = ~p->source_ipv4; // obfuscate

	// IPv6 header
	memset (&ra, 0, sizeof (ra));
	iov[2].iov_base = &ra;
	iov[2].iov_len = sizeof (ra);

	ra.ip6.ip6_flow = htonl (0x60000000);
	ra.ip6.ip6_plen = htons (sizeof (ra) - sizeof (ra.ip6));
	ra.ip6.ip6_nxt = IPPROTO_ICMPV6;
	ra.ip6.ip6_hlim = 255;

	addr = (union teredo_addr *)&ra.ip6.ip6_src;
	addr->teredo.prefix = htonl (0xfe800000);
	//addr->teredo.server_ip = 0;
	addr->teredo.flags = htons (TEREDO_FLAG_CONE);
	addr->teredo.client_port = htons (IPPORT_TEREDO);
	addr->teredo.client_ip = ~s->server_ip;

	memcpy (&ra.ip6.ip6_dst, dest_ip6, sizeof (ra.ip6.ip6_dst));

	// ICMPv6: Router Advertisement
	ra.ra.nd_ra_type = ND_ROUTER_ADVERT;
	//ra.ra.nd_ra_code = 0;
	//ra.ra.nd_ra_cksum = 0;
	//ra.ra.nd_ra_curhoplimit = 0;
	//ra.ra.nd_ra_flags_reserved = 0;
	//ra.ra.nd_ra_router_lifetime = 0;
	//ra.ra.nd_ra_reachable = 0;
	ra.ra.nd_ra_retransmit = htonl (2000);

	// ICMPv6 option: Prefix information
	ra.pi.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	ra.pi.nd_opt_pi_len = sizeof (ra.pi) >> 3;
	ra.pi.nd_opt_pi_prefix_len = 64;
	ra.pi.nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_AUTO;
	ra.pi.nd_opt_pi_valid_time = 0xffffffff;
	ra.pi.nd_opt_pi_preferred_time = 0xffffffff;
	addr = (union teredo_addr *)&ra.pi.nd_opt_pi_prefix;
	addr->teredo.prefix = s->prefix;
	addr->teredo.server_ip = s->server_ip;
	//memset (addr->ip6.s6_addr + 8, 0, 8);

	// ICMPv6 option : MTU
	ra.mtu.nd_opt_mtu_type = ND_OPT_MTU;
	ra.mtu.nd_opt_mtu_len = sizeof (ra.mtu) >> 3;
	//ra.mtu.nd_opt_mtu_reserved = 0;
	ra.mtu.nd_opt_mtu_mtu = s->advLinkMTU;

	// ICMPv6 checksum computation
	ra.ra.nd_ra_cksum = icmp6_checksum (&ra.ip6, (struct icmp6_hdr *)&ra.ra);

	if (IN6_IS_TEREDO_ADDR_CONE (dest_ip6))
		secondary = !secondary;

	return teredo_sendv (secondary ? s->fd_secondary : s->fd_primary,
	                     iov, 3, p->source_ipv4, p->source_port) > 0;
}

/*
 * Forwards a Teredo packet to a client
 */
static bool
libteredo_forward_udp (int fd, const struct teredo_packet *packet,
                       bool insert_orig)
{
	struct teredo_orig_ind orig;
	struct iovec iov[2];
	uint32_t dest_ipv4;
	uint16_t dest_port;

	/* extract the IPv4 destination directly from the Teredo IPv6 destination
	   within the IPv6 header */
	memcpy (&dest_ipv4, packet->ip6 + 24 + 12, 4);
	dest_ipv4 = ~dest_ipv4;

	if (!is_ipv4_global_unicast (dest_ipv4))
		return 0; // ignore invalid client IP

	memcpy (&dest_port, packet->ip6 + 24 + 10, 2);
	dest_port = ~dest_port;

	// Origin indication header
	// if the Teredo server's address is ours
	// NOTE: I wonder in which legitimate case insert_orig might be
	// false... but the spec implies it could
	iov[0].iov_base = &orig;
	if (insert_orig)
	{
		iov[0].iov_len = sizeof (orig);
		orig.hdr.zero = 0;
		orig.hdr.code = teredo_orig_ind;
		orig.orig_port = ~packet->source_port; // obfuscate
		orig.orig_addr = ~packet->source_ipv4; // obfuscate
	}
	else
		iov[0].iov_len = 0;

	iov[1].iov_base = packet->ip6;
	iov[1].iov_len = packet->ip6_len;

	return teredo_sendv (fd, iov, 2, dest_ipv4, dest_port) > 0;
}


/*
 * Sends an IPv6 packet of *payload* length <plen> with a raw IPv6 socket.
 * Returns 0 on success, -1 on error.
 */
static bool
libteredo_send_ipv6 (const void *p, size_t len)
{
	struct sockaddr_in6 dst = { };
	int tries, res;

	dst.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	dst.sin6_len = sizeof (dst);
#endif
	memcpy (&dst.sin6_addr, &((const struct ip6_hdr *)p)->ip6_dst,
	        sizeof (dst.sin6_addr));

	for (tries = 0; tries < 10; tries++)
	{
		res = sendto (raw_fd, p, len, 0,
		              (struct sockaddr *)&dst, sizeof (dst));
		if (res != -1)
			return res == (int)len;

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
 * Thread-safety note: prefix and advLinkMTU might be changed by another
 * thread
 */
static bool
libteredo_process_packet (const libteredo_server *s, bool sec)
{
	const uint8_t *ptr;
	struct teredo_packet packet;
	size_t ip6len;
	struct ip6_hdr ip6;
	uint32_t myprefix;
	uint8_t proto;

	if (teredo_wait_recv (sec ? s->fd_secondary : s->fd_primary, &packet))
		return false;

	// Teredo server case number 3
	if (!is_ipv4_global_unicast (packet.source_ipv4))
		return true;

	// Check IPv6 packet (Teredo server check number 1)
	ptr = packet.ip6;
	ip6len = packet.ip6_len;

	if (ip6len < sizeof (ip6))
		return 0; // too small

	memcpy (&ip6, ptr, sizeof (ip6));
	ip6len -= sizeof (ip6);
	ptr += sizeof (ip6);

	if (((ip6.ip6_vfc >> 4) != 6)
	 || (ntohs (ip6.ip6_plen) != ip6len))
		return true; // not an IPv6 packet

	// NOTE: ptr is not aligned => read single bytes only

	// Teredo server case number 2
	proto = ip6.ip6_nxt;
	if (((proto != IPPROTO_NONE) || (ip6len > 0)) // neither a bubble...
	 && (proto != IPPROTO_ICMPV6)) // nor an ICMPv6 message
		return true; // packet not allowed through server

	// Teredo server case number 4
	if (IN6_IS_ADDR_LINKLOCAL (&ip6.ip6_src)
	 && IN6_ARE_ADDR_EQUAL (&in6addr_allrouters, &ip6.ip6_dst)
	 && (proto == IPPROTO_ICMPV6)
	 && (ip6len > sizeof (struct nd_router_solicit))
	 && (((struct icmp6_hdr *)ptr)->icmp6_type == ND_ROUTER_SOLICIT))
		// sends a Router Advertisement
		return SendRA (s, &packet, &ip6.ip6_src, sec);

	myprefix = s->prefix;

	if (IN6_TEREDO_PREFIX (&ip6.ip6_src) == myprefix)
	{
		// Source address is Teredo

		if (!IN6_MATCHES_TEREDO_CLIENT (&ip6.ip6_src, packet.source_ipv4,
		                                packet.source_port))
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
			return libteredo_send_ipv6 (packet.ip6, packet.ip6_len);

		/*
		 * If the IPv6 destination is a Teredo address, the packet
		 * should be forwarded over UDP
		 */
	}
	else
	{
		// Source address is not Teredo
		if ((IN6_TEREDO_PREFIX (&ip6.ip6_dst) != myprefix)
		 || (IN6_TEREDO_SERVER (&ip6.ip6_dst) != s->server_ip))
			return true; // case 7

		// Teredo server case number 6
	}

	// forwards packet over Teredo:
	// (destination is a Teredo IPv6 address)
	return libteredo_forward_udp (s->fd_primary, &packet,
		IN6_TEREDO_SERVER (&ip6.ip6_dst) == s->server_ip);
}


int libteredo_server_check (char *errmsg, size_t len)
{
	int fd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);

	if (fd >= 0)
	{
		close (fd);
		return 0;
	}

	snprintf (errmsg, len, _("Raw IPv6 socket not working: %s"),
	          strerror (errno));
	return -1;
}


static void *thread_primary (void *data)
{
	libteredo_server *s = (libteredo_server *)data;

	for (;;)
	{
		pthread_testcancel ();
		libteredo_process_packet (s, false);
	}
}


static void *thread_secondary (void *data)
{
	libteredo_server *s = (libteredo_server *)data;

	for (;;)
	{
		pthread_testcancel ();
		libteredo_process_packet (s, true);
	}
}


/**
 * Creates a Teredo server handler. You should then drop your
 * privileges and call libteredo_server_start().
 *
 * @note Only one thread should use a given server handle at a time 
 *
 * @param ip1 server primary IPv4 address (network byte order),
 * @param ip2 server secondary IPv4 address (network byte order).
 *
 * @return NULL on error.
 */
libteredo_server *libteredo_server_create (uint32_t ip1, uint32_t ip2)
{
	libteredo_server *s;

	/* Initializes shared raw IPv6 socket */
	pthread_mutex_lock (&raw_mutex);
	if (raw_users == UINT_MAX) /* integer overflow */
	{
		/* piece of code that will probably never ever be executed */
		pthread_mutex_unlock (&raw_mutex);
		return NULL;
	}
	if (raw_users++ == 0)
	{
		raw_fd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (raw_fd != -1)
		{
			int flags = fcntl (raw_fd, F_GETFL, 0);
			//shutdown (fd, SHUT_RD); -- won't work
			fcntl (raw_fd, F_SETFL,
			       O_NONBLOCK | ((flags != -1) ? flags : 0));
		}
	}
	pthread_mutex_unlock (&raw_mutex);

	if (raw_fd == -1)
	{
		syslog (LOG_ERR, _("Raw IPv6 socket not working: %s"),
		        strerror (errno));
		return NULL;
	}

	/* Initializes exclusive UDP/IPv4 sockets */
	if (!is_ipv4_global_unicast (ip1) || !is_ipv4_global_unicast (ip2))
	{
		syslog (LOG_ERR, _("Teredo server UDP socket error: "
		        "Server IPv4 addresses must be global unicast."));
		return NULL;
	}

	s = (libteredo_server *)malloc (sizeof (*s));

	if (s != NULL)
	{
		int fd;

		memset (s, 0, sizeof (s));
		s->server_ip = ip1;
		s->prefix = htonl (DEFAULT_TEREDO_PREFIX);
		s->advLinkMTU = htonl (1280);

		fd = s->fd_primary = teredo_socket (ip1, htons (IPPORT_TEREDO));
		if (fd != -1)
		{
			fd = s->fd_secondary = teredo_socket (ip2, htons (IPPORT_TEREDO));
			if (fd != -1)
				return s;
			else
				syslog (LOG_ERR, _("Secondary socket: %m"));

			teredo_close (s->fd_primary);
		}
		else
			syslog (LOG_ERR, _("Primary socket: %m"));

		free (s);
	}
	return NULL;
}


/**
 * Changes the Teredo prefix to be advertised by a Teredo server.
 * If not set, the internal default will be used.
 *
 * @note The default Teredo prefix is expected to change in a future
 * version of this library, when IANA assigns a permanent Teredo prefix.
 *
 * @param s server handler as returned from libteredo_server_create(),
 * @param prefix 32-bits IPv6 address prefix (network byte order).
 *
 * @return 0 on success, -1 if the prefix is not acceptable.
 */
int libteredo_server_set_prefix (libteredo_server *s, uint32_t prefix)
{
	if (is_valid_teredo_prefix (prefix))
	{
		s->prefix = prefix;
		return 0;
	}
	return -1;
}


/**
 * Returns the Teredo prefix currently advertised by the server (in network
 * byte order).
 *
 * @param s server handler as returned from libteredo_server_create(),
 */
uint32_t libteredo_server_get_prefix (const libteredo_server *s)
{
	return s->prefix;
}

/**
 * Changes the link MTU advertised by the Teredo server.
 * If not set, the internal default will be used (currently 1280 bytes).
 *
 * @param s server handler as returned from libteredo_server_create(),
 * @param prefix MTU (in bytes) (host byte order).
 *
 * @return 0 on success, -1 if the MTU is not acceptable.
 */
int libteredo_server_set_MTU (libteredo_server *s, uint16_t mtu)
{
	if (mtu < 1280)
		return -1;

	s->advLinkMTU = htonl (mtu);
	return 0;
}


/**
 * Returns the link MTU currently advertised by the server in host byte order.
 *
 * @param s server handler as returned from libteredo_server_create(),
 */
uint16_t libteredo_server_get_MTU (const libteredo_server *s)
{
	return ntohl (s->advLinkMTU);
}


/**
 * Starts a Teredo server processing.
 *
 * @param s server handler as returned from libteredo_server_create(),
 *
 * @return 0 on success, -1 on error.
 */
int libteredo_server_start (libteredo_server *s)
{
	if (pthread_create (&s->t1, NULL, thread_primary, s) == 0)
	{
		if (pthread_create (&s->t2, NULL, thread_secondary, s) == 0)
			return 0;
		pthread_cancel (s->t1);
		pthread_join (s->t1, NULL);
	}

	return -1;
}


/**
 * Stops a Teredo server. Behavior is not defined if it was not started first.
 *
 * @param s server handler as returned from libteredo_server_create(),
 */
void libteredo_server_stop (libteredo_server *s)
{
	pthread_cancel (s->t1);
	pthread_cancel (s->t2);
	pthread_join (s->t1, NULL);
	pthread_join (s->t2, NULL);
}


/**
 * Destroys a Teredo server handle. Behavior is not defined if the associated
 * server is currently running - you must stop it with libteredo_server_stop()
 * first, if it is running.
 *
 * @param s server handler as returned from libteredo_server_create(),
 */
void libteredo_server_destroy (libteredo_server *s)
{
	teredo_close (s->fd_primary);
	teredo_close (s->fd_secondary);
	free (s);

	pthread_mutex_lock (&raw_mutex);
	if (--raw_users == 0)
		close (raw_fd);
	pthread_mutex_unlock (&raw_mutex);
}
