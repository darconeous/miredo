/*
 * ipv6-tunnel.cpp - IPv6 interface class definition
 * $Id$
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
#include <netinet/in.h> // htons()
#include <syslog.h>
#include "ipv6-tunnel.h"

# include <linux/if_tun.h> // FIXME: not portable
# include <net/if.h>

IPv6Tunnel::IPv6Tunnel (const char *ifname, const char *tundev)
{
	fd = open (tundev, O_RDWR);
	if (fd != -1)
	{
		struct ifreq req;

		memset (&req, 0, sizeof (req));
		req.ifr_flags = IFF_TUN;
		strncpy (req.ifr_name, ifname, IFNAMSIZ);

		if (ioctl (fd, TUNSETIFF, (void *)&req))
		{
			syslog (LOG_ERR,
				_("Teredo interface creation failed: %m\n"));
			close (fd);
			fd = -1;
		}
		else
			syslog (LOG_INFO,
				_("Teredo tunneling interface %s created.\n"),
				req.ifr_name);
	}
	else
		syslog (LOG_ERR, _("Cannot open %s: %m\n"), tundev);
}


IPv6Tunnel::~IPv6Tunnel ()
{
	if (fd != -1)
		close (fd);
}


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
	if (proto != htons (0x86dd))
		return -1; // only accept IPv6 packets

	return 0;
}


int
IPv6Tunnel::SendPacket (const void *packet, size_t len) const
{
	if ((fd != -1) && (len <= 65535))
	{
		uint8_t buf[65535 + 4];
		uint16_t flags = 0, proto = htons (0x86dd);

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

