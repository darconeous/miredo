/*
 * isatap.cpp - proof of concept ISATAP implementation
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h> // NI_MAXHOST
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libtun6/tun6.h>

#include "conf.h"
#include "miredo.h"

const char *const miredo_name = "miredo-isatap";
const char *const miredo_pidfile = LOCALSTATEDIR"/run/miredo-isatap.pid";

#ifdef HAVE_LIBCAP
static const cap_value_t capv[] =
{
	CAP_NET_ADMIN, /* required by libtun6 */
	CAP_NET_RAW /* required for raw ICMPv6 socket */
};

const cap_value_t *miredo_capv = capv;
const int miredo_capc = sizeof (capv) / sizeof (capv[0]);
#endif


extern "C" int
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


static tun6 *
create_static_tunnel (const char *ifname, uint32_t ipv4)
{
	tun6 *tunnel = tun6_create (ifname);

	if (tunnel == NULL)
		return NULL;

	struct in6_addr addr;
	memcpy (addr.s6_addr, "\xfe\x80\x00\x00\x00\x00\x00\x00", 8);
	// FIXME: set the global bit when ipv4 is global
	memcpy (addr.s6_addr + 8, "\x00\x00\x5e\xfe", 4);
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

	FD_SET (ipv6fd, &refset);
	if (ipv6fd > maxfd)
		maxfd = ipv6fd;

	maxfd++;
	sigset_t sigset;
	sigemptyset (&sigset);

	/* Main loop */
	for (;;)
	{
		fd_set readset;
		memcpy (&readset, &refset, sizeof (readset));

		/* Wait until one of them is ready for read */
		int val = pselect (maxfd, &readset, NULL, NULL, NULL, &sigset);
		if (val < 0)
			return 0;
		if (val == 0)
			continue;

		/* Handle incoming data */
		union
		{
			struct ip6_hdr ip6;
			struct iphdr ip4;
			uint8_t fill[65535];
		} buf;

		val = tun6_recv (tunnel, &readset, &buf.ip6, sizeof (buf));
		if ((val >= 40)
				   // FIXME: check global bit properly
				// FIXME: check that embedded IPv4 address is unicast
		 && !memcmp (buf.ip6.ip6_dst.s6_addr + 8, "\x00\x00\x5e\xfe", 4))
		{
			struct sockaddr_in dst;
			memset (&dst, 0, sizeof (dst));
			dst.sin_family = AF_INET;
			memcpy (&dst.sin_addr, buf.ip6.ip6_dst.s6_addr + 12, 4);
			sendto (ipv6fd, &buf, val, 0,
			        (struct sockaddr *)&dst, sizeof (dst));
		}

		if (FD_ISSET (ipv6fd, &readset))
		{
			struct sockaddr_in src;
			socklen_t srclen = sizeof (src);
			val = recvfrom (ipv6fd, &buf, sizeof (buf), 0,
			                (struct sockaddr *)&src, &srclen);

			if ((val < (int)sizeof (struct iphdr))
			 || (ntohs (buf.ip4.tot_len) != val))
				continue;

			val -= buf.ip4.ihl << 2;
			if (val < (int)sizeof (struct ip6_hdr))
				continue;

			const struct ip6_hdr *ip6 =
				(const struct ip6_hdr *)(buf.fill + (buf.ip4.ihl << 2));

			if (((ip6->ip6_vfc >> 4) != 6)
			 || (ntohs (ip6->ip6_plen) != val)
			 || memcmp (ip6->ip6_src.s6_addr + 8, "\x00\x00\x5e\xfe", 4)
			 || memcmp (ip6->ip6_src.s6_addr + 12, &src.sin_addr, 4))
				tun6_send (tunnel, ip6, val);
		}
	}
}


extern int
miredo_run (MiredoConf& conf, const char *server_name)
{
	/*
	 * CONFIGURATION
	 */
#ifdef MIREDO_TEREDO_CLIENT
	char namebuf[NI_MAXHOST];

	if (server_name == NULL)
	{
		char *name = conf.GetRawValue ("ServerAddress");
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

	if (!ParseIPv4 (conf, "BindAddress", &bind_ip))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	if (bind_ip == INADDR_ANY)
	{
		syslog (LOG_ALERT, "IPv4 bind address must be set explicitly!");
		return -2;
	}

	char *ifname = conf.GetRawValue ("InterfaceName");

	conf.Clear (5);

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


extern "C"
void miredo_setup_fd (int fd)
{
	(void) fcntl (fd, F_SETFD, FD_CLOEXEC);
}


extern "C"
void miredo_setup_nonblock_fd (int fd)
{
	int flags = fcntl (fd, F_GETFL);
	if (flags == -1)
		flags = 0;
	(void) fcntl (fd, F_SETFL, O_NONBLOCK | flags);
	miredo_setup_fd (fd);
}
