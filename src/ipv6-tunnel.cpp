/*
 * ipv6-tunnel.cpp - IPv6 interface class definition
 * $Id: ipv6-tunnel.cpp,v 1.14 2004/06/26 15:24:26 rdenisc Exp $
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

#if HAVE_LINUX_IF_TUN_H
/* Linux includes */
# include <linux/if_tun.h> // TUNSETIFF - Linux tunnel driver
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
#elif HAVE_NETINET6_IN6_VAR_H
/* FreeBSD includes */
# include <net/if_var.h>
# include <netinet6/in6_var.h> // struct in6_aliasreq, struct in6_ifreq
/*
 * Unless you have a very recent KAME implementation <netinet6/nd6.h> is
 * not usable in a C++ program.
 * cf: http://www.atm.tut.fi/list-archive/snap-users/msg03004.html
 */
//# include <netinet6/nd6.h> // ND6_INFINITE_LIFETIME
# define ND6_INFINITE_LIFETIME 0xffffffff

# include <net/if_tun.h> // TUNSIFHEAD - FreeBSD tunnel driver
# include <stdio.h> // asprintf(), snprintf()
#endif

#include <arpa/inet.h> // inet_ntop()

#ifndef ETH_P_IPV6
# define ETH_P_IPV6 0x86DD
#endif

#include "ipv6-tunnel.h"

static int
socket_udp6 (void)
{
	int fd = socket (PF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
                syslog (LOG_ERR, _("IPv6 stack not available: %m"));
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
IPv6Tunnel::IPv6Tunnel (const char *req_name) : fd (-1)
{
#if defined (TUNSETIFF)
	/*
	 * TUNTAP (Linux) tunnel driver initialization
	 */
	const char *const tundev = "/dev/net/tun";

	fd = open (tundev, O_RDWR);
	if (fd == -1)
	{
		syslog (LOG_ERR, _("Tunneling driver error (%s): %m"),
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
		syslog (LOG_ERR, _("Tunnel error (TUNSETIFF): %m"));
		close (fd);
		fd = -1;
	}

	ifname = strdup (req.ifr_name);
#elif defined (TUNSIFHEAD)
	/*
	 * FreeBSD tunnel driver initialization
	 */
	char tundev[12];
	int reqfd = socket_udp6 ();

	if (reqfd != -1)
	{
		for (unsigned i = 0; (i < 256) && (fd == -1); i++)
		{
			snprintf (tundev, sizeof (tundev), "/dev/tun%u", i);
			tundev[sizeof (tundev) - 1] = '\0';

			fd = open (tundev, O_RDWR);
			if (fd == -1)
				continue;

# if defined (SIOCSIFNAME)
			// Overrides the interface name
			struct ifreq req;
			memset (&req, 0, sizeof (req));
			ifname = strdup (req_name);
			req.ifr_data = ifname;

			if (ioctl (reqfd, SIOCSIFNAME, &req))
			{
				syslog (LOG_ERR,
					_("Tunnel error (SIOCSIFNAME): %m"));
				close (fd);
				fd = -1;
			}
# else
			ifname = strdup (tundev + 5); // strlen ("/dev/") == 5
# endif
			// Enables TUNSIFHEAD
			const int dummy = 1;
			if (ioctl (fd, TUNSIFHEAD, &dummy))
			{
				syslog (LOG_ERR,
					_("%s tunnel error (TUNSIFHEAD): %m"),
					ifname);
				close (fd);
				fd = -1;
			}
		}

		close (reqfd);
	}
#else
# error No tunneling driver implemented on your platform!
#endif

	if (fd != -1)
		syslog (LOG_INFO, _("Tunneling interface %s created"),
			ifname);
	else
		syslog (LOG_ERR, _("Tunneling interface creation failure"));
}


/*
 * Removes the tunnel interface
 */
IPv6Tunnel::~IPv6Tunnel ()
{
	if (fd != -1)
	{
		SetState (false);
		syslog (LOG_INFO, _("Tunneling interface %s removed"),
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
		syslog (LOG_ERR, _("Tunnel error (SIOCGIFFLAGS): %m"));
		close (reqfd);
		return -1;
	}

	secure_strncpy (req.ifr_name, ifname, IFNAMSIZ);
	// settings we want/don't want:
	req.ifr_flags |= IFF_NOARP | IFF_POINTOPOINT;
	if (up)
		req.ifr_flags |= IFF_UP | IFF_RUNNING;
	else
		req.ifr_flags &= ~IFF_UP | IFF_RUNNING;
	req.ifr_flags &= ~(IFF_MULTICAST | IFF_BROADCAST);

	if (ioctl (reqfd, SIOCSIFFLAGS, &req) == 0)
	{
		close (reqfd);
		syslog (LOG_DEBUG, "%s tunnel brought %s", ifname,
			up ? "up" : "down");
		return 0;
	}

	syslog (LOG_ERR, _("%s tunnel error (SIOCSIFFLAGS): %m"), ifname);
	close (reqfd);
	return -1;

}


#ifdef SIOCAIFADDR_IN6
/*
 * Converts a prefix length to a netmask.
 */
static void
plen_to_mask (unsigned plen, struct in6_addr *mask)
{
	memset (&mask->s6_addr, 0x00, 16);

	div_t d = div (plen, 8);
	int i;

	for (i = 0; i < d.quot; i ++)
		mask->s6_addr[i] = 0xff;

	if (d.rem)
		mask->s6_addr[i] = 0xff << (8 - d.rem);
}
#endif

/*
 * Adds or removes an address and a prefix to the tunnel interface.
 */
static int
_iface_addr (const char *ifname, bool add,
		const struct in6_addr *addr, unsigned prefix_len)
{
	if (prefix_len > 128)
	{
		syslog (LOG_ERR, _("IPv6 prefix length too long: %d"),
			prefix_len);
		return -1;
	}

	int reqfd = socket_udp6 ();
	if (reqfd == -1)
		return -1;

	long cmd = 0;
	void *req = NULL;

#if defined (SIOCGIFINDEX)
	/*
	 * Linux ioctl interface
	 */
	// Gets kernel's interface index
	union
	{
		struct ifreq req;
		struct in6_ifreq req6;
	} r;

	memset (&r.req, 0, sizeof (r.req));
	secure_strncpy (r.req.ifr_name, ifname, IFNAMSIZ);
	if (ioctl (reqfd, SIOCGIFINDEX, &r.req) == 0)
	{
		// Sets interface address
		int ifindex = r.req.ifr_ifindex;

		memset (&r.req6, 0, sizeof (r.req6));
		r.req6.ifr6_ifindex = ifindex;
		memcpy (&r.req6.ifr6_addr, addr,
			sizeof (r.req6.ifr6_addr));
		r.req6.ifr6_prefixlen = prefix_len;

		cmd = add ? SIOCSIFADDR : SIOCDIFADDR;
		req = &r.req6;
	}
#elif defined (SIOCAIFADDR_IN6)
	/*
	 * FreeBSD ioctl interface
	 */
	// Sets interface address
	union
	{
		struct in6_aliasreq addreq6;
		struct in6_ifreq delreq6;
	} r;
	
	if (add)
	{
		memset (&r.addreq6, 0, sizeof (r.addreq6));
		secure_strncpy (r.addreq6.ifra_name, ifname, IFNAMSIZ);
		r.addreq6.ifra_addr.sin6_family = AF_INET6;
		r.addreq6.ifra_addr.sin6_len = sizeof (r.addreq6.ifra_addr);
		memcpy (&r.addreq6.ifra_addr.sin6_addr, addr,
			sizeof (r.addreq6.ifra_addr.sin6_addr));

		r.addreq6.ifra_prefixmask.sin6_family = AF_INET6;
		r.addreq6.ifra_prefixmask.sin6_len =
					sizeof (r.addreq6.ifra_prefixmask);
		plen_to_mask (prefix_len,
				&r.addreq6.ifra_prefixmask.sin6_addr);

		r.addreq6.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
		r.addreq6.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

		cmd = SIOCAIFADDR_IN6;
		req = &r.addreq6;
	}
	else
	{
		memset (&r.delreq6, 0, sizeof (r.delreq6));
		secure_strncpy (r.delreq6.ifr_name, ifname, IFNAMSIZ);
		r.delreq6.ifr_addr.sin6_family = AF_INET6;
		r.delreq6.ifr_addr.sin6_len = sizeof (r.delreq6.ifr_addr);
		memcpy (&r.delreq6.ifr_addr.sin6_addr, addr,
			sizeof (r.delreq6.ifr_addr.sin6_addr));

		cmd = SIOCDIFADDR_IN6;
		req = &r.delreq6;
	}
#else
	syslog (LOG_WARN, _("%s tunnel address setup not supported.\n"
				"Please do it manually."), ifname);
	return 0;
#endif
	int retval = -1;

	if ((cmd != 0) && (req != NULL) && (ioctl (reqfd, cmd, req) == 0))
		retval = 0;
	close (reqfd);

	char str[INET6_ADDRSTRLEN];
	if (inet_ntop (AF_INET6, addr, str, sizeof (str)) == NULL)
		secure_strncpy (str, _("[unknown_address]"), sizeof (str));
	
	int level;
	const char *msg;

	if (retval)
	{
		level = LOG_ERR;

		if (add)
			msg = N_("%s tunnel address %s/%u setup error: %m");
		else
			msg = N_("%s tunnel address %s/%u removal error: %m");
	}
	else
	{
		level = LOG_DEBUG;

		if (add)
			msg = N_("%s tunnel address added: %s/%u");
		else
			msg = N_("%s tunnel address deleted: %s/%u");
	}

	syslog (level, gettext (msg), ifname, str, prefix_len);

	return retval;
}


/*
 * Adds or removes a route to the tunnel interface from the kernel routing
 * table.
 */
static int
_iface_route (const char *ifname, bool add,
		const struct in6_addr *addr, unsigned prefix_len)
{
	if (prefix_len < 0)
		return -1;

	if (prefix_len > 128)
	{
		syslog (LOG_ERR, _("IPv6 prefix length too long: %d"),
			prefix_len);
		return -1;
	}

	int retval = -1;

#if defined (SIOCGIFINDEX)
	/*
	 * Linux ioctl interface
	 */
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
			retval = 0;
	}
	close (reqfd);
#elif defined (RTM_ADD)
	/*
	 * BSD routing socket interface
	 */
	int sock = socket (PF_ROUTE, SOCKET_DGRAM, 0);
	
	close (sock);
#else
	syslog (LOG_WARN, _("%s tunnel route setup not supported.\n"
				"Please do it manually."), ifname);
	return 0;
#endif

	char str[INET6_ADDRSTRLEN];
	if (inet_ntop (AF_INET6, addr, str, sizeof (str)) == NULL)
		secure_strncpy (str, _("[unknown_route]"), sizeof (str));
	
	int level;
	const char *msg;

	if (retval)
	{
		level = LOG_ERR;

		if (add)
			msg = N_("%s tunnel route %s/%u setup error: %m");
		else
			msg = N_("%s tunnel route %s/%u removal error: %m");
	}
	else
	{
		level = LOG_DEBUG;

		if (add)
			msg = N_("%s tunnel route set: %s/%u");
		else
			msg = N_("%s tunnel route removed: %s/%u");
	}

	syslog (level, gettext (msg), ifname, str, prefix_len);

	return retval;
}


int
IPv6Tunnel::AddAddress (const struct in6_addr *addr, unsigned prefixlen) const
{
	return _iface_addr (ifname, true, addr, prefixlen);
}


int
IPv6Tunnel::DelAddress (const struct in6_addr *addr, unsigned prefixlen) const
{
	return _iface_addr (ifname, false, addr, prefixlen);
}


int
IPv6Tunnel::AddRoute (const struct in6_addr *addr, unsigned prefix_len) const
{
	return _iface_route (ifname, true, addr, prefix_len);
}


int
IPv6Tunnel::DelRoute (const struct in6_addr *addr, unsigned prefix_len) const
{
	return _iface_route (ifname, false, addr, prefix_len);
}


/*
 * Defines the tunnel interface Max Transmission Unit (bytes).
 */
int
IPv6Tunnel::SetMTU (unsigned mtu) const
{
	if (mtu < 1280)
	{
		syslog (LOG_ERR, _("IPv6 MTU too small (<1280): %u"), mtu);
		return -1;
	}
	if (mtu > 65535)
	{
		syslog (LOG_ERR, _("IPv6 MTU too big (>65535): %u"), mtu);
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
		syslog (LOG_ERR, _("%s tunnel MTU error (SIOCSIFMTU): %m"),
			ifname);
		close (reqfd);
		return -1;
	}

	syslog (LOG_DEBUG, _("%s tunnel MTU set to %u"), ifname, mtu);
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

#if defined (TUNSETIFF)
	/* TUNTAP driver */
	uint16_t flags, proto;
	memcpy (&flags, pbuf, 2);
	memcpy (&proto, pbuf + 2, 2);
	if (proto != htons (ETH_P_IPV6))
		return -1; // only accept IPv6 packets

#elif defined (TUNSIFHEAD)
	/* FreeBSD driver */
	uint32_t af;
	memcpy (&af, pbuf, 4);
	if (af != AF_INET6)
	{
		// FIXME: remove this:
		syslog (LOG_DEBUG, "Not an IPv6 packet (%08x instead of %08x)",
			af, AF_INET6);
		return -1;
	}
	
#endif

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

#if defined (TUNSETIFF)
		/* TUNTAP driver */
		uint16_t word;

		word = 0;
		memcpy (buf, &word, 2);

		word = htons (ETH_P_IPV6);
		memcpy (buf + 2, &word, 2);

#elif defined (TUNSIFHEAD)
		/* FreeBSD tunnel driver */
		uint32_t af = AF_INET6; // FIXME: is it htonl (AF_INET6) ?

		memcpy (buf, &af, 4);

#endif

		memcpy (buf + 4, packet, len);
		len += 4;

		if (write (fd, buf, len) == (int)len)
			return 0;
		if ((int)len == -1)
			syslog (LOG_ERR,
				_("Cannot send packet to tunnel: %m"));
		else
			syslog (LOG_ERR,
				_("Packet truncated to %u byte(s)"), len);
	}

	return -1;
}

