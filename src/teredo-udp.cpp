/*
 * teredo-udp.cpp - UDP sockets class definition
 * $Id: teredo-udp.cpp,v 1.3 2004/06/15 16:09:22 rdenisc Exp $
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

#include <string.h> // memset()

#include "teredo-udp.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h> // close()
#include <sys/select.h>
#include <netinet/in.h>

#include <syslog.h> // syslog()

/*** MiredoCommonUDP implementation ***/
MiredoCommonUDP::~MiredoCommonUDP (void)
{
}

/*
 * Opens the Teredo server's UDP/IPv4 socket.
 */
int
MiredoCommonUDP::OpenTeredoSocket (uint32_t bind_ip, uint16_t port)
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
		syslog (LOG_ALERT, _("Fatal socket error: %m\n"));
		return -1; // failure
	}

	if (bind (fd, (struct sockaddr *)&myaddr, sizeof (myaddr)))
	{
		syslog (LOG_ALERT, _("Fatal bind error: %m\n"));
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
	return fd;
}


int
MiredoCommonUDP::ReceivePacket (int fd)
{
	// Receive a UDP packet
	struct sockaddr_in ad;
	size_t alen;
	int check = recvfrom (fd, pbuf, sizeof (pbuf), 0,
				(struct sockaddr *)&ad, &alen);

	if (check == -1)
	{
		syslog (LOG_WARNING, _("Error receiving UDP packet: %m\n"));
		return -1;
	}

	ip6len = check;
	last_ip = ad.sin_addr.s_addr;
	last_port = ad.sin_port;

	// Check type of Teredo header:
	uint8_t *buf = pbuf;
	orig = NULL;
	nonce = NULL;
	ip6 = NULL;

	if (ip6len < 1)
		return -1; // bogus empty packet

	// Parse Teredo headers
	while (*buf == 0)
	{
		buf++;
		ip6len--;

		if (ip6len < 1)
			return -1; // too small

		uint8_t code = *buf;
		buf++;
		ip6len--;

		switch (code)
		{
			// Teredo Authentication header
			case teredo_auth_hdr:
			{
				if (ip6len < 11)
					return -1; // too small
				uint8_t id_len = *(buf++);
				uint8_t au_len = *(buf++);
				ip6len -= 11;

				if (ip6len < (size_t)(id_len + au_len))
					return -1;
				buf += id_len + au_len;
				ip6len -= id_len + au_len;
				nonce = buf;
				buf += 8;
				if (/* confirmation = */ *buf)
					return -1;
						// confirmation byte MUST be 0
				buf++;
				break;
			}

			// Teredo Origin Indication
			case teredo_orig_ind:
			{
				if (ip6len < 6)
					return -1; // too small
				orig = (struct teredo_orig_ind *)(buf - 2);
				ip6len -= 6;
				buf += 6;
				break;
			}

			// Unknown Teredo header
			default:
				return -1; // malformatted packet
		}
	}

	ip6 = (struct ip6_hdr *)buf;

	return 0;
}


int
MiredoCommonUDP::SendPacket (int fd, const void *packet, size_t plen,
				uint32_t dest_ip, uint16_t dest_port)
{
	struct sockaddr_in nat_addr;
	memset (&nat_addr, 0, sizeof (nat_addr));
	nat_addr.sin_family = AF_INET;
	nat_addr.sin_port = dest_port;
	nat_addr.sin_addr.s_addr = dest_ip;
#ifdef HAVE_SA_LEN
	nat_addr.sin_len = sizeof (nat_addr);
#endif

	int check = sendto (fd, packet, plen, 0, (struct sockaddr *)&nat_addr,
				sizeof (nat_addr));
	if (check == -1)
	{
		syslog (LOG_WARNING, _("Couldn't send UDP packet: %m\n"));
		return -1;
	}
	else if ((size_t)check < plen)
	{
		syslog (LOG_WARNING, _("UDP packet shortened: sent %d bytes "
				"instead of %u\n"), check, plen);
		return -1;
	}
	return 0;
}


/*** MiredoRelayUDP implementation ***/
MiredoRelayUDP::~MiredoRelayUDP (void)
{
	if (fd != -1)
		close (fd);
}


int MiredoRelayUDP::ListenPort (uint16_t port)
{
	// Closes former socket:
	if (fd != -1)
		close (fd);

	fd = OpenTeredoSocket (INADDR_ANY, port);
	return fd != -1 ? 0 : -1;
}


int
MiredoRelayUDP::RegisterReadSet (fd_set *readset) const
{
	if (fd != -1)
		FD_SET (fd, readset);
	return fd;
}


int
MiredoRelayUDP::ReceivePacket (const fd_set *readset)
{
	return ((fd != -1) && FD_ISSET (fd, readset))
		? MiredoCommonUDP::ReceivePacket (fd) : -1;
}


int
MiredoRelayUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t dest_port) const
{
	return MiredoCommonUDP::SendPacket (fd, packet, len, dest_ip,
						dest_port);
}


/*** MiredoServerUDP implementation ***/

MiredoServerUDP::~MiredoServerUDP ()
{
	if (fd_primary != -1)
		close (fd_primary);
	if (fd_secondary != -1)
		close (fd_secondary);
}


int MiredoServerUDP::ListenIP (uint32_t ip1, uint32_t ip2)
{
	if (fd_primary != -1)
		close (fd_primary);
	fd_primary = OpenTeredoSocket (ip1, htons (IPPORT_TEREDO));
	if (fd_primary == -1)
		return -1;

	if (fd_secondary != -1)
		close (fd_secondary);
	fd_secondary = OpenTeredoSocket (ip2, htons (IPPORT_TEREDO));
	if (fd_secondary == -1)
		return -1;

	return 0;
}


int MiredoServerUDP::RegisterReadSet (fd_set *readset) const
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
MiredoServerUDP::ReceivePacket (const fd_set *readset)
{
	/* Is there a packet on any of the UDP socket? */
	int fd = -1;

	if ((fd_primary != -1) && FD_ISSET (fd_primary, readset))
	{
		fd = fd_primary;
		was_secondary = false;
	}
	else
	if ((fd_secondary != -1) && FD_ISSET (fd_secondary, readset))
	{
		fd = fd_secondary;
		was_secondary = true;
	}
	
	return (fd == -1) ? -1 : MiredoCommonUDP::ReceivePacket (fd);
}


int
MiredoServerUDP::SendPacket (const void *packet, size_t len,
				uint32_t dest_ip, uint16_t port) const
{
	return SendPacket (packet, len, dest_ip, port, false);
}


