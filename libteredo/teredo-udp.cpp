/*
 * teredo-udp.cpp - UDP sockets class definition
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

#include <inttypes.h>
#include <string.h> // memset()

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h> // close()
#include <sys/select.h>
#include <netinet/in.h>

#include <syslog.h> // syslog()

#include <libteredo/v4global.h> // is_ipv4_global_unicast()
#include "teredo-udp.h"

/*
 * Opens a Teredo UDP/IPv4 socket.
 */
static int
OpenTeredoSocket (uint32_t bind_ip, uint16_t port)
{
	struct sockaddr_in myaddr;
	memset (&myaddr, 0, sizeof (myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_port = port;
	myaddr.sin_addr.s_addr = bind_ip;
#ifdef HAVE_SA_LEN
	myaddr.sin_len = sizeof (myaddr);
#endif

	int fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
	{
		syslog (LOG_ALERT, _("Fatal socket error: %m"));
		return -1; // failure
	}

	if (bind (fd, (struct sockaddr *)&myaddr, sizeof (myaddr)))
	{
		syslog (LOG_ALERT, _("Fatal bind error: %m"));
		return -1;
	}

	int t = 1;
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof (t));
#ifdef IP_PMTUDISC_DONT
	/* 
	 * This tells the (Linux) kernel not to set the Don't Fragment flags
	 * on UDP packets we send. This is recommended by the Teredo
	 * specifiation.
	 */
	t = IP_PMTUDISC_DONT;
	setsockopt (fd, SOL_IP, IP_MTU_DISCOVER, &t, sizeof (t));
#endif
	/*
	 * Teredo multicast packets always have a TTL of 1.
	 */
	setsockopt (fd, SOL_IP, IP_MULTICAST_TTL, &t, sizeof (t));
	return fd;
}


static int
SendUDPPacket (int fd, const void *packet, size_t plen,
		uint32_t dest_ip, uint16_t dest_port)
{
	if (plen > 65507)
		return -1;

	struct sockaddr_in nat_addr;
	memset (&nat_addr, 0, sizeof (nat_addr));
	nat_addr.sin_family = AF_INET;
	nat_addr.sin_port = dest_port;
	nat_addr.sin_addr.s_addr = dest_ip;
#ifdef HAVE_SA_LEN
	nat_addr.sin_len = sizeof (nat_addr);
#endif

	return sendto (fd, packet, plen, 0, (struct sockaddr *)&nat_addr,
			sizeof (nat_addr)) == (int)plen ? 0 : -1;
}


/*** TeredoPacket implementation ***/

/*
 * Parses a Teredo packet header. Blocking function.
 */
int
TeredoPacket::Receive (int fd)
{
	int length;

	// Receive a UDP packet
	{
		struct sockaddr_in ad;
		socklen_t alen = sizeof (ad);

		length = recvfrom (fd, buf, sizeof (buf), 0,
					(struct sockaddr *)&ad, &alen);

		if (length < 0)
			return -1;

		last_ip = ad.sin_addr.s_addr;
		last_port = ad.sin_port;
	}

	// Check type of Teredo header:
	uint8_t *ptr = buf;
	orig = NULL;
	nonce = NULL;

	// Parse Teredo headers
	if (length < 2)
		return -1; // too small

	// Teredo Authentication header
	if ((ptr[0] == 0) && (ptr[1] == teredo_auth_hdr))
	{
		ptr += 2;
		/* ID and Auth */
		length -= 4;
		if (length < 0)
			return -1; // too small

		uint8_t id_len = *ptr;
		ptr++;
		uint8_t au_len = *ptr;
		ptr++;

		length -= id_len + au_len;
		/* TODO: secure qualification */
		ptr += id_len + au_len;

		/* Nonce + confirmation byte */
		length -= 9;
		if (length < 0)
			return -1;

		nonce = ptr;
		ptr += 9;
	}

	// Teredo Origin Indication
	if ((ptr[0] == 0) && (ptr[1] == teredo_orig_ind))
	{
		length -= sizeof (orig_buf);
		if (length < 0)
			return -1; // too small

		memcpy (&orig_buf, ptr, sizeof (orig_buf));
		orig = &orig_buf;
		ptr += sizeof (orig_buf);
	}

	if (length < 0)
		return -1;

	// length <= 65507 = sizeof(buf)
	ip6len = length;
	ip6 = ptr;

	return 0;
}



/*** TeredoRelayUDP implementation ***/
TeredoRelayUDP::~TeredoRelayUDP (void)
{
	if (fd != -1)
		close (fd);
}


int TeredoRelayUDP::ListenPort (uint16_t port, uint32_t ipv4)
{
	// Closes former socket:
	if (fd != -1)
		close (fd);

	fd = OpenTeredoSocket (ipv4, port);
	return fd != -1 ? 0 : -1;
}


int
TeredoRelayUDP::RegisterReadSet (fd_set *readset) const
{
	if (fd != -1)
		FD_SET (fd, readset);
	return fd;
}


int
TeredoRelayUDP::ReceivePacket (const fd_set *readset,
				TeredoPacket& packet) const
{
	return ((fd != -1) && FD_ISSET (fd, readset))
		? packet.Receive (fd) : -1;
}


int
TeredoRelayUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const
{
	return (fd != -1)
		? SendUDPPacket (fd, packet, len, dest_ip, dest_port)
		: -1;
}


/*** TeredoServerUDP implementation ***/
#ifdef MIREDO_TEREDO_SERVER
TeredoServerUDP::~TeredoServerUDP ()
{
	if (fd_primary != -1)
		close (fd_primary);
	if (fd_secondary != -1)
		close (fd_secondary);
}


int TeredoServerUDP::ListenIP (uint32_t ip1, uint32_t ip2)
{
	if (!is_ipv4_global_unicast (ip1)
	 || !is_ipv4_global_unicast (ip2))
	{
		syslog (LOG_ERR, _("Teredo server UDP socket error: "
			"Server IPv4 addresses must be global unicast."));
		return -1;
	}

	if (ip1 == INADDR_ANY || ip2 == INADDR_ANY)
	{
		syslog (LOG_ERR, _("Teredo server UDP socket error: "
			"Server IPv4 addresses must not be wildcard."));
		return -1;
	}

	if (fd_primary != -1)
		close (fd_primary);
	fd_primary = OpenTeredoSocket (ip1, htons (IPPORT_TEREDO));
	if (fd_primary == -1)
		return -1;

	if (fd_secondary != -1)
		close (fd_secondary);
	fd_secondary = OpenTeredoSocket (ip2, htons (IPPORT_TEREDO));
	if (fd_secondary == -1)
	{
		close (fd_primary);
		fd_primary = -1;
		return -1;
	}

	return 0;
}


int TeredoServerUDP::RegisterReadSet (fd_set *readset) const
{
	int maxfd = -1;
	if (fd_primary != -1)
	{
		FD_SET (fd_primary, readset);
		if (fd_primary > maxfd)
			maxfd = fd_primary;
	}
	
	if (fd_secondary != -1)
	{
		FD_SET (fd_secondary, readset);
		if (fd_secondary > maxfd)
			maxfd = fd_secondary;
	}
	return maxfd;
}


int
TeredoServerUDP::ReceivePacket (const fd_set *set, TeredoPacket& packet,
				bool *was_secondary)
{
	int fd = -1;

	/* Is there a packet on any of the UDP sockets? */
	if ((fd_primary != -1) && FD_ISSET (fd_primary, set))
	{
		fd = fd_primary;
		*was_secondary = false;
	}
	else
	if ((fd_secondary != -1) && FD_ISSET (fd_secondary, set))
	{
		fd = fd_secondary;
		*was_secondary = true;
	}
	
	return (fd != -1) ? packet.Receive (fd) : -1;
}


int
TeredoServerUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port,
				bool use_secondary_ip) const
{
	int fd = use_secondary_ip ? fd_secondary : fd_primary;

	return (fd != -1)
		? SendUDPPacket (fd, packet, len, dest_ip, dest_port)
		: -1;
}
#endif /* MIREDO_TEREDO_SERVER */
