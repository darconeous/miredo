/*
 * ipv6-tunnel.cpp - IPv6 interface class definition
 * $Id: ipv6-tunnel.cpp,v 1.9 2004/06/22 16:20:25 rdenisc Exp $
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
#include <stdlib.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>

#include <sys/socket.h> // socket(PF_INET6, SOCK_DGRAM, 0)
#include <netinet/in.h> // htons()
#include <net/if.h> // struct ifreq
#include <arpa/inet.h> // inet_ntop()

#ifndef ETH_P_IPV6
# define ETH_P_IPV6 0x86DD
#endif

#if HAVE_LINUX_IF_TUN_H
# include <linux/if_tun.h> // TUNSETIFF
#endif


#if HAVE_NETINET6_IN6_VAR_H
# include <net/if_var.h>
# include <netinet6/in6_var.h>
#elif HAVE_LINUX_IPV6_H
/*
 * <linux/ipv6.h> conflicts with <netinet/in.h> and <arpa/inet.h>,
 * so we've got to declare this structure by hand.
 */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	int ifr6_ifindex;
};

# include <net/route.h> // struct in6_rtmsg
#endif

#include "ipv6-tunnel.h"

static int
socket_udp6 (void)
{
	int fd = socket (PF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
                syslog (LOG_ERR, _("IPv6 stack not available: %m\n"));
	return fd;
}


inline void
secure_strncpy (char *tgt, const char *src, size_t len)
{
	strncpy (tgt, src, len);
	tgt[len - 1] = '\0';
}


/*
 * Allocates a tunnel network interface from the kernel
 */
IPv6Tunnel::IPv6Tunnel (const char *req_name)
{
	const char *tundev = "/dev/net/tun";

	fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m\n"),
			tundev);
		return;
	}

	// Allocates the tunneling virtual network interface
	struct ifreq req;
	memset (&req, 0, sizeof (req));
	if (req_name != NULL)
		secure_strncpy (req.ifr_name, req_name, IFNAMSIZ);
	req.ifr_flags = IFF_TUN;

	if (ioctl (fd, TUNSETIFF, (void *)&req))
	{
		syslog (LOG_ERR, _("Tunnel error (TUNSETIFF): %m\n"));
		close (fd);
		fd = -1;
	}

	ifname = strdup (req.ifr_name);
	if (ifname == NULL)
	{
		syslog (LOG_ERR, _("Tunnel error: %m\n"));
		close (fd);
		fd = -1;
	}
	syslog (LOG_INFO, _("Tunneling interface %s created\n"), ifname);
}


/*
 * Removes the tunnel interface
 */
IPv6Tunnel::~IPv6Tunnel ()
{
	if (fd != -1)
	{
		SetState (false);
		syslog (LOG_INFO, _("Tunneling interface %s removed\n"),
			ifname);
		close (fd);
		free (ifname);
	}
}


/*
 * Unless otherwise stated, all the methods thereafter should return -1 on
 * error, and 0 on success. Similarly, they should require root privileges.
 */

/*
 * Brings the tunnel interface up or down.
 */
int
IPv6Tunnel::SetState (bool up) const
{
	int reqfd = socket_udp6 ();
	if (reqfd == -1)
		return -1;

	// Sets up the interface
	struct ifreq req;
	memset (&req, 0, sizeof (req));	
	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	if (ioctl (reqfd, SIOCGIFFLAGS, &req))
	{
		syslog (LOG_ERR, _("Tunnel error (SIOCGIFFLAGS): %m\n"));
		close (reqfd);
		return -1;
	}

	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	// settings we want/don't want:
	req.ifr_flags |= IFF_NOARP;
	if (up)
		req.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		req.ifr_flags &= ~IFF_UP | IFF_RUNNING;
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST | IFF_POINTOPOINT);

	if (ioctl (reqfd, SIOCSIFFLAGS, &req))
	{
		syslog (LOG_ERR, _("%s tunnel error (SIOCSIFFLAGS): %m\n"),
			ifname);
		close (reqfd);
		return -1;
	}

	close (reqfd);
	return 0;
}


/*
 * Adds or removes an address and a prefix to the tunnel interface.
 */
static int
_linux_addr (const char *ifname, bool add,
		const struct in6_addr *addr, int prefix_len)
{
	if (prefix_len < 0)
		return -1;

	if (prefix_len > 128)
	{
		syslog (LOG_ERR, _("IPv6 prefix length too long: %d\n"),
			prefix_len);
		return -1;
	}

	int reqfd = socket_udp6 ();
	if (reqfd == -1)
		return -1;

	// Gets kernel's interface index
	struct ifreq req;
	memset (&req, 0, sizeof (req));
	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	if (ioctl (reqfd, SIOCGIFINDEX, &req) == 0)
	{
		// Sets interface address
		struct in6_ifreq req6;

		memset (&req6, 0, sizeof (req6));
		req6.ifr6_ifindex = req.ifr_ifindex;
		memcpy (&req6.ifr6_addr, addr, sizeof (struct in6_addr));
		req6.ifr6_prefixlen = prefix_len;

		if (!ioctl (reqfd, add ? SIOCSIFADDR : SIOCDIFADDR , &req6))
		{
			char str[INET6_ADDRSTRLEN];

			if (inet_ntop (AF_INET6, addr, str, sizeof (str))
								!= NULL)
				syslog (LOG_DEBUG,
					_("%s tunnel address set to %s/%d\n"),
					ifname, str, prefix_len);
			close (reqfd);
			return 0;
		}
	}

	close (reqfd);
	return -1;
}


/*
 * Adds or removes a route to the tunnel interface from the kernel routing
 * table.
 */
static int
_linux_route (const char *ifname, bool add,
		const struct in6_addr *addr, int prefix_len)
{
	if (prefix_len < 0)
		return -1;

	if (prefix_len > 128)
	{
		syslog (LOG_ERR, _("IPv6 prefix length too long: %d\n"),
			prefix_len);
		return -1;
	}

	int reqfd = socket_udp6 ();
	if (reqfd == -1)
		return -1;

	// Gets kernel's interface index
	struct ifreq req;
	memset (&req, 0, sizeof (req));
	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	if (ioctl (reqfd, SIOCGIFINDEX, &req) == 0)
	{
		// Adds/deletes route
		struct in6_rtmsg req6;

		memset (&req6, 0, sizeof (req6));
		req6.rtmsg_flags = RTF_UP;
		req6.rtmsg_ifindex = req.ifr_ifindex;
		memcpy (&req6.rtmsg_dst, addr, sizeof (struct in6_addr));
		req6.rtmsg_dst_len = prefix_len;
		req6.rtmsg_metric = 1;
		if (prefix_len == 128)
			req6.rtmsg_flags |= RTF_HOST;
		// no gateway

		if (ioctl (reqfd, add ? SIOCADDRT : SIOCDELRT, &req6) == 0)
		{
			char str[INET6_ADDRSTRLEN];

			if (inet_ntop (AF_INET6, addr, str, sizeof (str))
								!= NULL)
				syslog (LOG_DEBUG,
					_("%s tunnel route added: %s/%d\n"),
					ifname, str, prefix_len);
			close (reqfd);
			return 0;
		}
	}

	close (reqfd);
	return -1;
}


int
IPv6Tunnel::AddAddress (const struct in6_addr *addr, int prefix_len) const
{
	return _linux_addr (ifname, true, addr, prefix_len);
}


int
IPv6Tunnel::DelAddress (const struct in6_addr *addr, int prefix_len) const
{
	return _linux_addr (ifname, false, addr, prefix_len);
}


int
IPv6Tunnel::AddRoute (const struct in6_addr *addr, int prefix_len) const
{
	return _linux_route (ifname, true, addr, prefix_len);
}


int
IPv6Tunnel::DelRoute (const struct in6_addr *addr, int prefix_len) const
{
	return _linux_route (ifname, false, addr, prefix_len);
}


/*
 * Defines the tunnel interface Max Transmission Unit (bytes).
 */
int
IPv6Tunnel::SetMTU (int mtu) const
{
	if (mtu < 1280)
	{
		syslog (LOG_ERR, _("IPv6 MTU too small (<1280): %d\n"), mtu);
		return -1;
	}
	if (mtu > 65535)
	{
		syslog (LOG_ERR, _("IPv6 MTU too big (>65535): %d\n"), mtu);
		return -1;
	}

	int reqfd = socket_udp6 ();
	if (reqfd == -1)
		return -1;

	struct ifreq req;
	memset (&req, 0, sizeof (req));
	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	req.ifr_mtu = mtu;

	if (ioctl (reqfd, SIOCSIFMTU, &req))
	{
		syslog (LOG_ERR, _("%s tunnel MTU error (SIOCSIFMTU): %m\n"),
			ifname);
		close (reqfd);
		return -1;
	}

	syslog (LOG_DEBUG, _("%s tunnel MTU set to %d\n"), ifname, mtu);
	return 0;
}



/*
 * These functions do not require root privileges:
 */

/*
 * Registers the tunnel file descriptor for select().
 * When selects return, you should call ReceivePacket() with the same fd_set.
 */
int
IPv6Tunnel::RegisterReadSet (fd_set *readset) const
{
	if (fd != -1)
		FD_SET (fd, readset);
	return fd;
}


/*
 * Tries to receive a packet from the kernel networking stack.
 * Fails if fd is not in the readset. Call this function when select()
 * returns.
 */
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
	if (proto != htons (ETH_P_IPV6))
		return -1; // only accept IPv6 packets

	return 0;
}


/*
 * Sends a packet from userland to the kernel's networking stack.
 */
int
IPv6Tunnel::SendPacket (const void *packet, size_t len) const
{
	if ((fd != -1) && (len <= 65535))
	{
		uint8_t buf[65535 + 4];
		uint16_t word;

		word = 0;
		memcpy (buf, &word, 2);

		word = htons (ETH_P_IPV6);
		memcpy (buf + 2, &word, 2);

		memcpy (buf + 4, packet, len);
		len += 4;

		if (write (fd, buf, len) == (int)len)
			return 0;
		if ((int)len == -1)
			syslog (LOG_ERR,
				_("Cannot send packet to tunnel: %m"));
		else
			syslog (LOG_ERR,
				_("Packet truncated to %u byte(s)\n"), len);
	}
	return -1;
}

