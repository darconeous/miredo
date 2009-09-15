/*
 * discovery.c - Teredo local client discovery procedure
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2009 Jérémie Koenig.                                   *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h> // malloc()
#include <string.h> // mem???()

#include <netinet/in.h> // struct in6_addr
#include <netinet/ip6.h> // struct ip6_hdr (for packets.h)
#include <arpa/inet.h> // inet_ntop()
#include <pthread.h>
#include <ifaddrs.h> // getifaddrs()
#include <net/if.h> // IFF_MULTICAST

#include "teredo.h"
#include "teredo-udp.h"
#include "packets.h"
#include "v4global.h"
#include "security.h"
#include "clock.h"
#include "debug.h"
#include "iothread.h"
#include "discovery.h"


struct teredo_discovery
{
	struct teredo_discovery_interface
	{
		uint32_t addr;
		uint32_t mask;
	} *ifaces;
	struct in6_addr src;
	teredo_iothread *recv;
	teredo_iothread *send;
};


static const struct in6_addr in6addr_allnodes =
{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } } };


bool is_ipv4_discovered (teredo_discovery *d, uint32_t ip)
{
	int i;

	for (i = 0; d->ifaces[i].addr; i++)
		if (((ip ^ d->ifaces[i].addr) & d->ifaces[i].mask) == 0)
			return true;

	return false;
}


void SendDiscoveryBubble (teredo_discovery *d, int fd)
{
	struct ip_mreqn mreq;
	int i, r;

	for (i = 0; d->ifaces[i].addr; i++)
	{
		memset (&mreq, 0, sizeof mreq);
		mreq.imr_multiaddr.s_addr = htonl (TEREDO_DISCOVERY_IPV4);
		mreq.imr_address.s_addr = d->ifaces[i].addr;
		r = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
		                   &mreq, sizeof mreq);
		if (r < 0)
		{
			debug ("Could not set multicast interface");
			continue;
		}

		teredo_send_bubble_anyway (fd, htonl (TEREDO_DISCOVERY_IPV4),
		                               htons (IPPORT_TEREDO),
		                               &d->src, &in6addr_allnodes);
	}

	debug ("discovery bubble sent");
}


bool IsDiscoveryBubble (const teredo_packet *restrict packet)
{
	return IsBubble(packet->ip6)
	 && packet->dest_ipv4 == htonl (TEREDO_DISCOVERY_IPV4)
	 && memcmp(&packet->ip6->ip6_dst, &in6addr_allnodes, 16) == 0;
}


// 5.2.8  Optional Local Client Discovery Procedure
static LIBTEREDO_NORETURN void *teredo_sendmcast_thread (void *opaque, int fd)
{
	teredo_discovery *d = (teredo_discovery *)opaque;

	for (;;)
	{
		SendDiscoveryBubble (d, fd);

		int interval = 200 + teredo_get_flbits (teredo_clock ()) % 100;
		struct timespec delay = { .tv_sec = interval };
		while (clock_nanosleep (CLOCK_REALTIME, 0, &delay, &delay));
	}
}


/* Join the Teredo local discovery multicast group on a given interface */
static void teredo_discovery_joinmcast(int sk, uint32_t ifaddr)
{
	struct ip_mreqn mreq;
	int r;
	char addr[20];

	memset (&mreq, 0, sizeof mreq);
	mreq.imr_address.s_addr = ifaddr;
	mreq.imr_multiaddr.s_addr = htonl (TEREDO_DISCOVERY_IPV4);
	r = setsockopt (sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq);

	debug (r < 0 ? "Could not join the Teredo local discovery "
	               "multicast group on interface %.20s"
	             : "Listening for Teredo local discovery bubbles "
	               "on interface %.20s",
	       inet_ntop(AF_INET, &ifaddr, addr, sizeof addr));
}


teredo_discovery *
teredo_discovery_start (int fd, const struct in6_addr *src,
                        teredo_iothread_proc proc, void *opaque)
{
	struct ifaddrs *ifaddrs, *ifa;
	int r, ifno;

	teredo_discovery *d = malloc (sizeof (teredo_discovery));
	if (d == NULL)
	{
		return NULL;
	}

	/* Get a list of the suitable interfaces */

	r = getifaddrs(&ifaddrs);
	if (r < 0)
	{
		debug ("Could not enumerate interfaces for local discovery");
		free (d);
		return NULL;
	}

	d->ifaces = NULL;
	ifno = 0;

	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next)
	{
		struct teredo_discovery_interface *list = d->ifaces;
		struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
		struct sockaddr_in *ma = (struct sockaddr_in *) ifa->ifa_netmask;

		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (!(ifa->ifa_flags & IFF_MULTICAST))
			continue;
		if (is_ipv4_global_unicast (sa->sin_addr.s_addr))
			continue;

		list = realloc (list, (ifno + 2) * sizeof (*d->ifaces));
		if(list == NULL)
		{
			debug ("Out of memory.");
			break; // memory error
		}

		d->ifaces = list;
		d->ifaces[ifno].addr = sa->sin_addr.s_addr;
		d->ifaces[ifno].mask = ma->sin_addr.s_addr;
		ifno++;
	}

	freeifaddrs(ifaddrs);

	if (d->ifaces == NULL)
	{
		debug ("No suitable interfaces found for local discovery");
		free (d);
		return NULL;
	}
	d->ifaces[ifno].addr = 0;

	/* Setup the multicast-receiving socket */

	int sk = teredo_socket (0, htons (IPPORT_TEREDO));
	if (sk < 0)
	{
		debug ("Could not create the local discovery socket");
		free (d->ifaces);
		free (d);
		return NULL;
	}

	for (ifno = 0; d->ifaces[ifno].addr; ifno++)
		teredo_discovery_joinmcast (sk, d->ifaces[ifno].addr);

	d->recv = teredo_iothread_start (proc, opaque, sk);

	/* Start the discovery procedure thread */

	memcpy (&d->src, src, sizeof d->src);
	setsockopt (fd, IPPROTO_IP, IP_MULTICAST_LOOP, &(int){0}, sizeof (int));

	d->send = teredo_iothread_start (teredo_sendmcast_thread, d, fd);

	return d;
}


void teredo_discovery_stop (teredo_discovery *d)
{
	if (d->send)
		teredo_iothread_stop (d->send, false);
	if (d->recv)
		teredo_iothread_stop (d->recv, true);

	free (d->ifaces);
	free (d);
}


