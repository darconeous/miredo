/*
 * relay.cpp - Unix Teredo relay implementation core functions
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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
#include <sys/wait.h> // wait()
#include <sys/select.h> // pselect()
#include <signal.h> // sigemptyset()
#include <syslog.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h> // inet_ntop()
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#ifndef SOL_IPV6
# define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef SOL_ICMPV6
# define SOL_ICMPV6 IPPROTO_ICMPV6
#endif

#include <libtun6/tun6.h>

#include <libteredo/teredo.h> /* FIXME should not be needed */
#include <libteredo/relay.h>

#include "privproc.h"
#include "addrwatch.h"
#include "conf.h"
#include "miredo.h"

const char *const miredo_name = "miredo";
const char *const miredo_pidfile = LOCALSTATEDIR"/run/miredo.pid";

#ifdef HAVE_LIBCAP
static const cap_value_t capv[] =
{
	CAP_KILL, /* required by the signal handler */
	CAP_SETUID,
	CAP_SYS_CHROOT,
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
	
	return 0;
}


class MiredoRelay : public TeredoRelay
{
	private:
		const tun6 *tunnel;
		int priv_fd;
		static int icmp6_fd;

		virtual int SendIPv6Packet (const void *packet, size_t length)
		{
			return tun6_send (tunnel, packet, length);
		}

		virtual void EmitICMPv6Error (const void *packet, size_t length,
		                              const struct in6_addr *dst)
		{
			if (icmp6_fd == -1)
				return;

			struct sockaddr_in6 addr;

			memset (&addr, 0, sizeof (addr));
			/* TODO: use sendmsg and don't memcpy in BuildICMPv6Error */
			addr.sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
			addr.sin6_len = sizeof (addr);
#endif
			memcpy (&addr.sin6_addr, dst, sizeof (addr.sin6_addr));
			sendto (icmp6_fd, packet, length, 0,
					(struct sockaddr *)&addr, sizeof (addr));
		}

	public:
		MiredoRelay (const tun6 *tun, uint32_t prefix,
		             uint16_t port = 0, uint32_t ipv4 = 0,
		             bool cone = true)
			: TeredoRelay (prefix, port, ipv4, cone), tunnel (tun),
			  priv_fd (-1)
		{
		}

		static int GlobalInit (void);
		static void GlobalDeinit (void);

		//virtual void ~MiredoRelay (void);

#ifdef MIREDO_TEREDO_CLIENT
		MiredoRelay (int fd, const tun6 *tun,
		             const char *server_ip, const char *server_ip2,
		             uint16_t port = 0, uint32_t ipv4 = 0)
			: TeredoRelay (server_ip, server_ip2, port, ipv4), tunnel (tun),
			  priv_fd (fd)
		{
		}

	private:
		virtual void NotifyUp (const struct in6_addr *addr,
		                      uint16_t mtu = 1280)
		{
			char str[INET6_ADDRSTRLEN];

			syslog (LOG_NOTICE, _("Teredo pseudo-tunnel started"));
			if (inet_ntop (AF_INET6, addr, str, sizeof (str)) != NULL)
				syslog (LOG_INFO, _(" (address: %s, MTU: %u)"),
				        str, (unsigned)mtu);
			miredo_configure_tunnel (priv_fd, addr, mtu);
		}

		virtual void NotifyDown (void)
		{
			miredo_configure_tunnel (priv_fd, &in6addr_any, 1280);
			syslog (LOG_NOTICE, _("Teredo pseudo-tunnel stopped"));
		}
#endif /* ifdef MIREDO_TEREDO_CLIENT */
};


int MiredoRelay::icmp6_fd = -1;

int MiredoRelay::GlobalInit (void)
{
	struct icmp6_filter filt;
	int val;

	icmp6_fd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (icmp6_fd == -1)
		return -1;

	val = 2;
	setsockopt (icmp6_fd, SOL_IPV6, IPV6_CHECKSUM, &val, sizeof (val));

	/* We don't use the socket for receive -> block all */
	ICMP6_FILTER_SETBLOCKALL (&filt);
	setsockopt (icmp6_fd, SOL_ICMPV6, ICMP6_FILTER, &filt, sizeof (filt));
	return 0;
}

void MiredoRelay::GlobalDeinit (void)
{
	if (icmp6_fd != -1)
		close (icmp6_fd);
}

/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_relay (tun6 *tunnel, TeredoRelay *relay = NULL)
{
	fd_set refset;

	FD_ZERO (&refset);
	int maxfd = tun6_registerReadSet (tunnel, &refset);

	int val = relay->RegisterReadSet (&refset);
	if (val > maxfd)
		maxfd = val;

	maxfd++;

	sigset_t sigset;
	sigemptyset (&sigset);

	/* Main loop */
	while (1)
	{
		fd_set readset;
		memcpy (&readset, &refset, sizeof (readset));

		/* Wait until one of them is ready for read */
		val = pselect (maxfd, &readset, NULL, NULL, NULL, &sigset);
		if (val < 0)
		{
			assert (errno == EINTR);
			break;
		}

		/* Handle incoming data */
		union
		{
			struct ip6_hdr ip6;
			uint8_t fill[65507];
		} pbuf;

		/* Forwards IPv6 packet to Teredo
		 * (Packet transmission) */
		val = tun6_recv (tunnel, &readset, &pbuf.ip6, sizeof (pbuf));
		if (val >= 40)
			relay->SendPacket (&pbuf.ip6, val);

		/* Forwards Teredo packet to IPv6
		 * (Packet reception) */
		relay->ReceivePacket ();
	}
}


#define TEREDO_CLIENT   1
#define TEREDO_RELAY    2
#define TEREDO_CONE     2
#define TEREDO_RESTRICT 3

static bool
ParseRelayType (MiredoConf& conf, const char *name, int *type)
{
	unsigned line;
	char *val = conf.GetRawValue (name, &line);

	if (val == NULL)
		return true;

	if (strcasecmp (val, "client") == 0)
		*type = TEREDO_CLIENT;
	else if (strcasecmp (val, "cone") == 0)
		*type = TEREDO_CONE;
	else if (strcasecmp (val, "restricted") == 0)
		*type = TEREDO_RESTRICT;
	else
	{
		syslog (LOG_ERR, _("Invalid relay type \"%s\" at line %u"),
		        val, line);
		free (val);
		return false;
	}
	free (val);
	return true;
}


#ifdef MIREDO_TEREDO_CLIENT
/* FIXME: default_route is probably useless nowadays */
static tun6 *
create_dynamic_tunnel (const char *ifname, int *fd, bool default_route)
{
	tun6 *tunnel = tun6_create (ifname);

	if (tunnel == NULL)
		return NULL;

	/* FIXME: we leak all heap-allocated settings in the child process */
	int res = miredo_privileged_process (tunnel, default_route);
	if (res == -1)
	{
		tun6_destroy (tunnel);
		return NULL;
	}
	*fd = res;
	return tunnel;
}


static int
miredo_client (tun6 *tunnel, int fd, const char *server, const char *server2,
               uint32_t bind_ip, uint16_t bind_port, bool ignore_cone)
{
	try
	{
		MiredoRelay client (fd, tunnel, server, server2, bind_port, bind_ip);
		client.SetConeIgnore (ignore_cone);

		// Processing...
		teredo_relay (tunnel, &client);
	}
	catch (...)
	{
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("libteredo cannot be initialized"));
		return -1;
	}

	return 0;
}
#else
# define create_dynamic_tunnel( a, b, c ) NULL
# define miredo_client( a, b, c, d, e, f, g ) (-1)
#endif


static tun6 *
create_static_tunnel (const char *ifname, const struct in6_addr *prefix,
					  uint16_t mtu, bool cone)
{
	tun6 *tunnel = tun6_create (ifname);

	if (tunnel == NULL)
		return NULL;

	if (tun6_setMTU (tunnel, mtu) || tun6_bringUp (tunnel)
		   || tun6_addAddress (tunnel, cone ? &teredo_cone : &teredo_restrict, 64)
		   || tun6_addRoute (tunnel, prefix, 32, 0))
	{
		tun6_destroy (tunnel);
		return NULL;
	}
	return tunnel;
}



static int
miredo_relay (tun6 *tunnel, uint32_t prefix, bool cone,
              uint32_t bind_ip, uint16_t bind_port, bool ignore_cone)
{
	try
	{
		MiredoRelay relay (tunnel, prefix, bind_port, bind_ip, cone);
		relay.SetConeIgnore (ignore_cone);

		// Processing...
		teredo_relay (tunnel, &relay);
	}
	catch (...)
	{
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("libteredo cannot be initialized"));
		return -1;
	}

	return 0;
}


extern int
miredo_run (MiredoConf& conf, const char *cmd_server_name)
{
	/*
	 * CONFIGURATION
	 */
	union teredo_addr prefix;
	memset (&prefix, 0, sizeof (prefix));
	prefix.teredo.prefix = htonl (TEREDO_PREFIX);

	int mode = TEREDO_CLIENT;
	if (!ParseRelayType (conf, "RelayType", &mode))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

#ifdef MIREDO_TEREDO_CLIENT
	char *server_name = NULL, *server_name2 = NULL;
	bool default_route = true;
#endif
	uint16_t mtu = 1280;

	if (mode == TEREDO_CLIENT)
	{
#ifdef MIREDO_TEREDO_CLIENT
		if (!conf.GetBoolean ("DefaultRoute", &default_route))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}

		if (cmd_server_name != NULL)
		{
			server_name = strdup (cmd_server_name);
			if (server_name == NULL)
				return -1;
		}
		else
		{
			server_name = conf.GetRawValue ("ServerAddress");
			if (server_name == NULL)
			{
				syslog (LOG_ALERT, _("Server address not specified"));
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return -2;
			}

			server_name2 = conf.GetRawValue ("ServerAddress2");
		}
#else
		(void)cmd_server_name;
		syslog (LOG_ALERT, _("Unsupported Teredo client mode"));
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
#endif
	}
	else
	{
		mtu = 1280;

		if (!ParseIPv6 (conf, "Prefix", &prefix.ip6)
		 || !conf.GetInt16 ("InterfaceMTU", &mtu))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}
	}

	uint32_t bind_ip = INADDR_ANY;
	uint16_t bind_port = 
#if 0
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
		IPPORT_TEREDO + 1;
#else
		0;
#endif
	bool ignore_cone = true;

	if (!ParseIPv4 (conf, "BindAddress", &bind_ip)
	 || !conf.GetInt16 ("BindPort", &bind_port)
	 || !conf.GetBoolean ("IgnoreConeBit", &ignore_cone))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
#ifdef MIREDO_TEREDO_CLIENT
		if (server_name != NULL)
			free (server_name);
		if (server_name2 != NULL)
			free (server_name2);
#endif
		return -2;
	}

	bind_port = htons (bind_port);

	char *ifname = conf.GetRawValue ("InterfaceName");

	conf.Clear (5);

	/*
	 * SETUP
	 */

	/*
	 * Tunneling interface initialization
	 *
	 * NOTE: The Linux kernel does not allow setting up an address
	 * before the interface is up, and it tends to complain about its
	 * inability to set a link-scope address for the interface, as it
	 * lacks an hardware layer address.
	 */
	int fd;
	tun6 *tunnel = (mode == TEREDO_CLIENT)
		? create_dynamic_tunnel (ifname, &fd, default_route)
		: create_static_tunnel (ifname, &prefix.ip6, mtu, mode == TEREDO_CONE);

	if (ifname != NULL)
		free (ifname);

	int retval = -1;

	if (tunnel == NULL)
	{
		syslog (LOG_ALERT, _("Miredo setup failure: %s"),
		        _("Cannot create IPv6 tunnel"));
	}
	else
	{
		if (libteredo_preinit (mode == TEREDO_CLIENT))
			syslog (LOG_ALERT, _("Miredo setup failure: %s"),
			        _("libteredo cannot be initialized"));
		else
		{
			MiredoRelay::GlobalInit ();

/*#ifdef MIREDO_TEREDO_CLIENT
			miredo_addrwatch *watch;
			if (mode == TEREDO_CLIENT)
				watch = miredo_addrwatch_start (tun6_getId (tunnel));
			else
				watch = NULL;
#endif*/

			if (drop_privileges () == 0)
			{
				retval = (mode == TEREDO_CLIENT)
					? miredo_client (tunnel, fd, server_name,
					                 server_name2, bind_ip, bind_port,
					                 ignore_cone)
					: miredo_relay (tunnel, prefix.teredo.prefix, bind_ip,
					                bind_port, mode == TEREDO_CONE,
					                ignore_cone);
			}

/*#ifdef MIREDO_TEREDO_CLIENT
			if (watch != NULL)
				miredo_addrwatch_stop (watch);
#endif*/
			MiredoRelay::GlobalDeinit ();
			libteredo_terminate (mode == TEREDO_CLIENT);
		}

		if (mode == TEREDO_CLIENT)
		{
			close (fd);
			wait (NULL); // wait for privsep process
		}
		tun6_destroy (tunnel);
	}

#ifdef MIREDO_TEREDO_CLIENT
	if (server_name != NULL)
		free (server_name);
	if (server_name2 != NULL)
		free (server_name2);
#endif

	return retval;
}
