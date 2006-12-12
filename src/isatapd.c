/*
 * isatapd.c - basic ISATAP daemon implementation
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <gettext.h>

#include <inttypes.h>

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
#include <pthread.h>

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


static int
isatap_diagnose (void)
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


#ifdef MIREDO_TEREDO_CLIENT
/**
 * Perform a non-blocking (UDP) connect to a host to find out a suitable
 * source address to use when communicating with it.
 *
 * @param conn_ipv4 IPv4 of the host to connect to (network byte order)
 * @param bind_ipv4 [out] where to store the source address
 *
 * @return 0 on success, -1 on error.
 */
static int get_bind_ipv4 (uint32_t conn_ipv4, uint32_t *bind_ipv4)
{
	int fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;

	struct sockaddr_in addr =
	{
		.sin_family = AF_INET,
#ifdef HAVE_SA_LEN
		.sin_len = sizeof (struct sockaddr_in),
#endif
		.sin_addr.s_addr = conn_ipv4
	};
	socklen_t addrlen = sizeof (addr);

	if (connect (fd, (struct sockaddr *)&addr, sizeof (addr))
	 || getsockname (fd, (struct sockaddr *)&addr, &addrlen)
	 || addrlen < sizeof (addr))
	{
		close (fd);
		return -1;
	}
	close (fd);

	*bind_ipv4 = addr.sin_addr.s_addr;
	return bind_ipv4 ? 0 : -1;
}
#endif /* MIREDO_TEREDO_CLIENT */



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


typedef struct
{
	tun6 *tunnel;
	int fd;
	uint32_t router_ipv4;
} isatapd_t;


static LIBTEREDO_NORETURN void *encap_thread (void *data)
{
	isatapd_t conf = *((isatapd_t *)data);
	struct sockaddr_in dst =
	{
		.sin_family = AF_INET,
#ifdef HAVE_SA_LEN
		.sin_len = sizeof (struct sockaddr_in),
#endif
	};

	for (;;)
	{
		union
		{
			struct ip6_hdr ip6;
			uint8_t fill[65535];
		} buf;

		int val = tun6_wait_recv (conf.tunnel, &buf.ip6, sizeof (buf));
		if (val < (int)sizeof (buf.ip6))
			continue;

		dst.sin_addr.s_addr = conf.router_ipv4;

		/*
		 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
		 *
		 * This is not just an ugly piece of code, this is also severely
		 * _broken_. It will (sometime) send packet to the ISATAP router
		 * instead of an other on-link node. This typically happends when an
		 * application binds manually to an address, instead of letting the
		 * IPv6 stack use the longest-prefix match rule.
		 *
		 * A more proper solution would consists of reading the local
		 * addresses assigned to the tunnel interface, though this is a
		 * little “racy”. Ultimately, the correct solutions are:
		 *  - a next-hop hint from the tunnel driver
		 *    (not supported on Linux, might be IPv4-only on BSD),
		 *  - better yet, use a fully in-kernel ISATAP client tunnel.
		 */
		if (memcmp (buf.ip6.ip6_src.s6_addr, buf.ip6.ip6_dst.s6_addr, 8) == 0)
		{
			uint32_t v;
			memcpy (&v, buf.ip6.ip6_dst.s6_addr + 8, sizeof (v));

			if ((ntohl (v) & 0xfcffffff) == 0x00005efe)
				memcpy (&dst.sin_addr, buf.ip6.ip6_dst.s6_addr + 12, 4);
			/*else
			 * If we knew that the destination was actually on-link, we ought
			 * to send an ICMPv6 unreachable error back here.
			 */
		}

		// Make sure the IPv4 destination is valid
		if ((dst.sin_addr.s_addr == INADDR_ANY)
		 || IN_MULTICAST (ntohl (dst.sin_addr.s_addr)))
			continue; // drop packet

		sendto (conf.fd, &buf, val, 0,
		        (struct sockaddr *)&dst, sizeof (dst));
	}
}


static LIBTEREDO_NORETURN void *decap_thread (void *data)
{
	isatapd_t conf = *((isatapd_t *)data);

	for (;;)
	{
		union
		{
			struct ip ip4;
			uint8_t fill[65535];
		} buf;


		int val = recv (conf.fd, &buf, sizeof (buf), 0);
		if ((val < (int)sizeof (struct ip))
		 || (ntohs (buf.ip4.ip_len) != val))
			continue;

		val -= buf.ip4.ip_hl << 2;
		if (val < (int)sizeof (struct ip6_hdr))
			continue; // no room for IPv6 header

		const struct ip6_hdr *ip6 =
			(const struct ip6_hdr *)(buf.fill + (buf.ip4.ip_hl << 2));

		if (((ip6->ip6_vfc >> 4) != 6)
		 || (ntohs (ip6->ip6_plen) != val))
			continue; // invalid IPv6 header

#if 0
		uint32_t v;
		memcpy (&v, ip6->ip6_src.s6_addr + 8, sizeof (v));
		if ((ntohl (v) & 0xfcffffff) != 0x00005efe)
			break; // TODO: check if it comes from the router

		if (memcmp (ip6->ip6_src.s6_addr + 12, &buf.ip4.ip_src, 4))
			break;
#endif

		tun6_send (conf.tunnel, ip6, val);
	}
}


/**
 * Miredo main daemon function, with UDP datagrams and IPv6 packets
 * receive loop.
 */
static int
run_tunnel (int ipv6fd, tun6 *tunnel, uint32_t router_ipv4)
{
	isatapd_t t = { tunnel, ipv6fd, router_ipv4 };
	pthread_t deth, enth;

	int retval = -1;

	if (pthread_create (&deth, NULL, decap_thread, &t) == 0)
	{
		if (pthread_create (&enth, NULL, encap_thread, &t) == 0)
		{
			sigset_t dummyset, set;

			/* changes nothing, only gets the current mask */
			sigemptyset (&dummyset);
			pthread_sigmask (SIG_BLOCK, &dummyset, &set);

			/* wait for fatal signal */
			while (sigwait (&set, &(int) { 0 }) != 0);

			retval = 0;

			pthread_cancel (enth);
			pthread_join (enth, NULL);
		}

		pthread_cancel (deth);
		pthread_join (deth, NULL);
	}

	return retval;
}


static int
isatap_run (miredo_conf *conf, const char *server_name)
{
	/*
	 * CONFIGURATION
	 */
	uint32_t router_ip = INADDR_ANY, bind_ip = INADDR_ANY;

#ifdef MIREDO_TEREDO_CLIENT
	if ((server_name == NULL)
		? !miredo_conf_parse_IPv4 (conf, "ServerAddress", &router_ip)
		: GetIPv4ByName (server_name, &router_ip))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}
#else
	(void)server_name;
#endif

	if (!miredo_conf_parse_IPv4 (conf, "BindAddress", &bind_ip))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	if (bind_ip == INADDR_ANY)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (router_ip != INADDR_ANY)
		{
			if (get_bind_ipv4 (router_ip, &bind_ip)
			 || IN_MULTICAST (ntohl (router_ip)))
			{
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return -2;
			}
		}
		else
#endif
		{
			syslog (LOG_ALERT,
			        "ISATAP router requires an explicit IPv4 bind address!");
			return -2;
		}
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
		miredo_setup_fd (ipv6_fd);

		struct sockaddr_in a =
		{
			.sin_family = AF_INET,
#ifdef HAVE_SA_LEN
			.sin_len = sizeof (struct sockaddr_in),
#endif
			.sin_addr.s_addr = bind_ip
		};
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
			retval = run_tunnel (ipv6_fd, tunnel, router_ip);
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


int main (int argc, char *argv[])
{
#ifdef HAVE_LIBCAP
	static const cap_value_t capv[] =
	{
		CAP_NET_ADMIN, /* required by libtun6 */
		CAP_NET_RAW /* required for raw ICMPv6 socket */
	};

	miredo_capv = capv;
	miredo_capc = sizeof (capv) / sizeof (capv[0]);
#endif

	miredo_name = "isatapd";
	miredo_diagnose = isatap_diagnose;
	miredo_run = isatap_run;

	return miredo_main (argc, argv);
}

