/*
 * ipv6-tunnel.cpp - IPv6 interface class definition
 * $Id: ipv6-tunnel.cpp,v 1.2 2004/06/14 21:52:32 rdenisc Exp $
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include "ipv6-tunnel.h"

#if HAVE_LINUX_IF_TUN_H
# include <linux/if_tun.h> // TUNSETIFF
#endif
#include <net/if.h> // struct ifreq
#include <sys/socket.h> // socket(PF_INET6, SOCK_DGRAM, 0)
#if HAVE_LINUX_IPV6_H
# include <linux/ipv6.h> // strict in6_ifreq
#endif

/* 
 * NOTE:
 * This has to be done by hand rather than through htons(),
 * not for optimisation, but because <netinet/in.h> conflicts with
 * <linux/ipv6.h> on my system.
 */
#ifdef WORDS_BIGENDIAN
# define L2_PROTO_IPV6 0x86dd
#else
# define L2_PROTO_IPV6 0xdd86
#endif

inline void
secure_strncpy (char *tgt, const char *src, size_t len)
{
	strncpy (tgt, src, len);
	tgt[len - 1] = '\0';
}



IPv6Tunnel::IPv6Tunnel (const char *req_name, const char *tundev)
{
	extern uid_t unpriv_uid;
	if (tundev == NULL)
		tundev = "/dev/net/tun";

	fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m\n"),
			tundev);
		return;
	}
	
	int reqfd = socket (PF_INET6, SOCK_DGRAM, 0);
	if (reqfd == -1)
	{
		syslog (LOG_ERR, _("IPv6 stack not available: %m\n"));
		goto abort;
	}

	struct ifreq req;

	// Allocates the tunneling virtual network interface
	memset (&req, 0, sizeof (req));
	if (req_name != NULL)
		req.ifr_flags = IFF_TUN;
	secure_strncpy (req.ifr_name, req_name, IFNAMSIZ);

	if (ioctl (fd, TUNSETIFF, (void *)&req))
	{
		syslog (LOG_ERR, _("Tunneling interface failure: %m\n"));
		goto abort;
	}

	secure_strncpy (ifname, req.ifr_name, IFNAMSIZ);
		
	// Sets up the interface
	//secure_strncpy (req.ifr_name, ifname, IFNAMSIZ); // already set
	if (ioctl (reqfd, SIOCGIFFLAGS, &req))
	{
		syslog (LOG_ERR, _("Tunnel setup failure: %m\n"));
		goto abort;
	}

	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	// settings we want:
	req.ifr_flags |= IFF_UP | IFF_POINTOPOINT | IFF_NOARP;
	// settings we don't want:
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);
	if (ioctl (reqfd, SIOCSIFFLAGS, &req))
	{
		syslog (LOG_ERR, _("Tunnel setup failure: %m\n"));
		goto abort;
	}
	
	close (reqfd);
	syslog (LOG_INFO, _("Tunneling interface %s created.\n"), ifname);

	return;

abort:
	close (fd);
	fd = -1;
	if (reqfd != -1)
		close (reqfd);
}


IPv6Tunnel::~IPv6Tunnel ()
{
	if (fd != -1)
	{
		syslog (LOG_INFO, _("Tunneling interface %s removed.\n"),
			ifname);
		close (fd);
	}
}

#if 0
int
IPv6Tunnel::AddPrefix (const struct in6_addr *addr, int prefix_len) const
{
	int reqfd = socket (PF_INET6, SOCK_DGRAM, 0);
	if (reqfd == -1)
	{
		syslog (LOG_ERR, _("IPv6 socket failure: %m\n"));
		return -1;
	}

	// Gets interface flags
	struct ifreq req;
	memset (&req, 0, sizeof (req));
	secure_strncpy (req.ifr_name, ifname);

	
}
#endif

int
IPv6Tunnel::RegisterReadSet (fd_set *readset) const
{
	if (fd != -1)
		FD_SET (fd, readset);
	return fd;
}


int
IPv6Tunnel::ReceivePacket (const fd_set *readset)
{
	if ((fd == -1) || !FD_ISSET (fd, readset))
		return -1;

	int len = read (fd, pbuf, sizeof (pbuf));
	if (len == -1)
		return -1;

	plen = len;
	uint16_t flags, proto;
	memcpy (&flags, pbuf, 2);
	memcpy (&proto, pbuf + 2, 2);
	if (proto != L2_PROTO_IPV6)
		return -1; // only accept IPv6 packets

	return 0;
}


int
IPv6Tunnel::SendPacket (const void *packet, size_t len) const
{
	if ((fd != -1) && (len <= 65535))
	{
		uint8_t buf[65535 + 4];
		const uint16_t flags = 0, proto = L2_PROTO_IPV6;

		memcpy (buf, &flags, 2);
		memcpy (buf + 2, &proto, 2);
		memcpy (buf + 4, packet, len);

		len += 4;

		if (write (fd, buf, len) == len)
			return 0;
		if (len == -1)
			syslog (LOG_ERR,
				_("Cannot send packet to tunnel: %m"));
		else
			syslog (LOG_ERR,
				_("Packet truncated to %u byte(s)\n"), len);
	}
	return -1;
}

