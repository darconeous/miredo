/*
 * isatap.c - basic ISATAP implementation
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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

#include <assert.h>
#include <gettext.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <stdlib.h> // free()
#include <stdio.h>
#include <sys/types.h>
#include <string.h> // strerror()
#include <errno.h>
#include <unistd.h> // close()
#include <fcntl.h>
#include <sys/wait.h> // wait()
#include <sys/select.h> // pselect()
#include <signal.h> // sigemptyset()
#include <compat/pselect.h>
#include <syslog.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h> // NI_MAXHOST
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libtun6/tun6.h>

#include "miredo.h"
#include "conf.h"

const char *const miredo_name = "isatapd";
const char *const miredo_pidfile = LOCALSTATEDIR"/run/isatap.pid";

#ifdef HAVE_LIBCAP
static const cap_value_t capv[] =
{
	CAP_NET_ADMIN, /* required by libtun6 */
	CAP_NET_RAW /* required for raw ICMPv6 socket */
};

const cap_value_t *miredo_capv = capv;
const int miredo_capc = sizeof (capv) / sizeof (capv[0]);
#endif


extern int
miredo_diagnose (void)
{
	char errbuf[LIBTUN6_ERRBUF_SIZE];
	if (tun6_driver_diagnose (errbuf))
	{
		fputs (errbuf, stderr);
		return -1;
	}

	int fd = socket (AF_INET, SOCK_RAW, IPPROTO_IPV6);
	if (fd == -1)
	{
		perror (_("Raw IPv6 socket not working: %s"));
		return -1;
	}
	close (fd);

	return 0;
}


static bool is_ipv4_unique (uint32_t ipv4)
{
	ipv4 = ntohl (ipv4);

	// See RFC3330 for reference.

	// 0.0.0.0/8 is “this”
	if (ipv4 < 0x01000000)
		return false;
	// 1.0.0.0 - 9.255.255.255 are global
	if (ipv4 < 0x0a000000)
		return true;
	// 10.0.0.0/8 are private
	if (ipv4 < 0x0b000000)
		return false;
	// 11.0.0.0 - 126.255.255.255 are global
	if (ipv4 < 0x7f000000)
		return true;
	// 127.0.0.0/8 are local host
	if (ipv4 < 0x80000000)
		return false;
	// 128.0.0.0 - 169.253.255.255 are global
	if (ipv4 < 0xa9fe0000)
		return true;
	// 169.254.0.0/16 are link-local
	if (ipv4 < 0xa9ff0000)
		return false;
	// 169.255.0.0 - 172.15.255.255 are global
	if (ipv4 < 0xac100000)
		return true;
	// 172.16.0.0/12 are private
	if (ipv4 < 0xac200000)
		return false;
	// 172.32.0.0 - 192.167.255.255 are global
	if (ipv4 < 0xc0a80000)
		return true;
	// 192.168.0.0/16 are private
	if (ipv4 < 0xc0a90000)
		return false;
	// 192.169.0.0 - 198.17.255.255 are global
	if (ipv4 < 0xc6120000)
		return true;
	// 198.18.0.0/15 are not global
	if (ipv4 < 0xc6140000)
		return false;
	// 198.20.0.0 - 223.255.255.255 are global
	if (ipv4 < 0xe0000000)
		return true;
	// other are multicast or reserved
	return false;
}


static tun6 *
create_static_tunnel (const char *ifname, uint32_t ipv4)
{
	tun6 *tunnel = tun6_create (ifname);

	if (tunnel == NULL)
		return NULL;

	struct in6_addr addr;
	static const uint8_t pref12[] =
		"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x5e\xfe";
	memcpy (addr.s6_addr, pref12, 12);
	if (is_ipv4_unique (ipv4))
		addr.s6_addr[8] |= 2; /* unique bit */
	memcpy (addr.s6_addr + 12, &ipv4, 4);

	// FIXME: MTU should probably be 1280
	if (tun6_setMTU (tunnel, 1480) || tun6_bringUp (tunnel)
	 || tun6_addAddress (tunnel, &addr, 64))
	{
		tun6_destroy (tunnel);
		return NULL;
	}
	return tunnel;
}



/**
 * Miredo main daemon function, with UDP datagrams and IPv6 packets
 * receive loop.
 */
static int
run_tunnel (int ipv6fd, tun6 *tunnel)
{
	fd_set refset;

	FD_ZERO (&refset);
	int maxfd = tun6_registerReadSet (tunnel, &refset);

	if ((maxfd == -1) || (ipv6fd >= FD_SETSIZE))
		return -1;

	FD_SET (ipv6fd, &refset);
	if (ipv6fd > maxfd)
		maxfd = ipv6fd;

	maxfd++;
	sigset_t set;
	sigemptyset (&set);

	/* Main loop */
	for (;;)
	{
		fd_set readset;
		memcpy (&readset, &refset, sizeof (readset));

		/* Wait until one of them is ready for read */
		int val = pselect (maxfd, &readset, NULL, NULL, NULL, &set);
		if (val < 0)
			return 0;
		if (val == 0)
			continue;

		/* Handle incoming data */
		union
		{
			struct ip6_hdr ip6;
			struct ip ip4;
			uint8_t fill[65535];
		} buf;

		val = tun6_recv (tunnel, &readset, &buf.ip6, sizeof (buf));
		do
		{
			if (val < 40)
				break;

			uint32_t v;
			memcpy (&v, buf.ip6.ip6_dst.s6_addr + 8, sizeof (v));
			if ((ntohl (v) & 0xfcffffff) != 0x00005efe)
				break; // TODO: send to default router instead

			memcpy (&v, buf.ip6.ip6_dst.s6_addr + 8, sizeof (v));
			// Make sure the destination is not multicast
			if ((ntohl (v) >> 28) == 14)
				break;

			struct sockaddr_in dst;
			memset (&dst, 0, sizeof (dst));
			dst.sin_family = AF_INET;
			dst.sin_addr.s_addr = v;
			sendto (ipv6fd, &buf, val, 0,
			        (struct sockaddr *)&dst, sizeof (dst));
		}
		while (0);

		do
		{
			if (!FD_ISSET (ipv6fd, &readset))
				break;

			val = recv (ipv6fd, &buf, sizeof (buf), 0);

			if ((val < (int)sizeof (struct ip))
			 || (ntohs (buf.ip4.ip_len) != val))
				break;

			val -= buf.ip4.ip_hl << 2;
			if (val < (int)sizeof (struct ip6_hdr))
				break; // no room for IPv6 header

			const struct ip6_hdr *ip6 =
				(const struct ip6_hdr *)(buf.fill + (buf.ip4.ip_hl << 2));

			if (((ip6->ip6_vfc >> 4) != 6)
			 || (ntohs (ip6->ip6_plen) != val))
				break; // invalid IPv6 header

			uint32_t v;
			memcpy (&v, ip6->ip6_src.s6_addr + 8, sizeof (v));
			if ((ntohl (v) & 0xfcffffff) != 0x00005efe)
				break; // TODO: check if it comes from the router

			if (memcmp (ip6->ip6_src.s6_addr + 12, &buf.ip4.ip_src, 4))
				break;

			tun6_send (tunnel, ip6, val);
		}
		while (0);
	}
}


extern int
miredo_run (miredo_conf *conf, const char *server_name)
{
	/*
	 * CONFIGURATION
	 */
#ifdef MIREDO_TEREDO_CLIENT
	char namebuf[NI_MAXHOST];

	if (server_name == NULL)
	{
		char *name = miredo_conf_get (conf, "ServerAddress", NULL);
		if (name == NULL)
		{
			syslog (LOG_ALERT, _("Server address not specified"));
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}
		strlcpy (namebuf, name, sizeof (namebuf));
		free (name);
		server_name = namebuf;
	}
#endif

	uint32_t bind_ip = INADDR_ANY;

	if (!miredo_conf_parse_IPv4 (conf, "BindAddress", &bind_ip))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	if (bind_ip == INADDR_ANY)
	{
		syslog (LOG_ALERT, "IPv4 bind address must be set explicitly!");
		return -2;
	}

	char *ifname = miredo_conf_get (conf, "InterfaceName", NULL);

	miredo_conf_clear (conf, 5);

	/*
	 * SETUP
	 */

	// Tunneling interface initialization
	tun6 *tunnel = create_static_tunnel (ifname, bind_ip);

	if (ifname != NULL)
		free (ifname);

	int retval = -1;

	if (tunnel == NULL)
	{
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("Cannot create IPv6 tunnel"));
		return -1;
	}

	int ipv6_fd = socket (AF_INET, SOCK_RAW, IPPROTO_IPV6);
	if (ipv6_fd != -1)
	{
		miredo_setup_nonblock_fd (ipv6_fd);

		struct sockaddr_in a;
		memset (&a, 0, sizeof (a));
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = bind_ip;
		if (bind (ipv6_fd, (struct sockaddr *)&a, sizeof (a)))
		{
			close (ipv6_fd);
			ipv6_fd = -1;
		}
	}

	if (ipv6_fd == -1)
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        strerror (errno));
	else
	{
		if (drop_privileges () == 0)
		{
			/*
			 * RUN
			 */
			retval = run_tunnel (ipv6_fd, tunnel);
		}

		close (ipv6_fd);
	}

	tun6_destroy (tunnel);
	return retval;
}


extern
void miredo_setup_fd (int fd)
{
	(void) fcntl (fd, F_SETFD, FD_CLOEXEC);
}


extern
void miredo_setup_nonblock_fd (int fd)
{
	int flags = fcntl (fd, F_GETFL);
	if (flags == -1)
		flags = 0;
	(void) fcntl (fd, F_SETFL, O_NONBLOCK | flags);
	miredo_setup_fd (fd);
}
