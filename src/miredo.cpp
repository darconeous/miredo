/*
 * miredo.cpp - Unix Teredo server & relay implementation
 *              core functions
 * $Id: miredo.cpp,v 1.1 2004/06/14 21:52:32 rdenisc Exp $
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h> // struct sockaddr_in
#include <syslog.h>
#include <unistd.h> // uid

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include "miredo.h"
#include "teredo-udp.h"
#include "ipv6-tunnel.h"
#include "server_pkt.h"
#include "relay.h"


struct miredo_setup conf;


/*
 * Main server function, with UDP datagrams receive loop.
 * TODO:
 * * should be able to be relay-only
 * * use an application class instead
 */
static int
teredo_server_relay (void)
{
	MiredoRelay relay;

	if (conf.relay_udp != NULL)
	{
		relay.SetSocket (conf.relay_udp);
		relay.SetTunnel (conf.tunnel);
		relay.SetLocalAddress (&conf.addr.ip6);
	}

	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		FD_ZERO (&readset);

		int maxfd = -1;

		if (conf.server_udp != NULL)
		{
			int val = conf.server_udp->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}

		if (conf.relay_udp != NULL)
		{
			int val = conf.tunnel->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;

			val = conf.relay_udp->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if (maxfd <= 0)
			continue;

		/* Handle incoming data */
		if (conf.server_udp != NULL)
		{
			if (conf.server_udp->ReceivePacket (&readset) == 0)
				handle_server_packet (conf.server_udp);
		}
		
		if (conf.relay_udp != NULL)
		{
			if (conf.tunnel->ReceivePacket (&readset) == 0)
				relay.TransmitPacket ();
			if (conf.relay_udp->ReceivePacket (&readset) == 0)
				relay.ReceivePacket ();
		}
	}

	/* Termination */
	return 0;
}



/*
 * Returns an IPv4 address (network byte order) associated with hostname
 * <name>. Returns 0 on error.
 */
static uint32_t
getipbyname (const char *name)
{
	struct addrinfo help, *res;
	uint32_t ipv4;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (name, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname `%s': %s\n"),
			name, gai_strerror (check));
		closelog ();
		return 0;
	}

	ipv4 = ((const struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo (res);
	return ipv4;
}


/*
 * NOTES:
 * It would be much better to find this out automatically, and not to require
 * the user to specify a static, possibly wrong, value.
 *
 * When running as a client (which is far from being supported), this HAS to
 * be found out through qualification. When running as a server, this is
 * entirely useless. When running as a relay, this should really be a
 * non-Teredo public IPv6 address that we own (if we don't have one, we should
 * be a client rather than a relay).
 *
 * Additionnaly, it would be good to not require relay IPv4 address manual
 * configuration either.
 */
static int
get_relay_ipv6 (const char *name)
{
	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET6;

	int check = getaddrinfo (name, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname '%s': %s\n"),
			name, gai_strerror (check));
		closelog ();
		return -1;
	}

	memcpy (&conf.addr.ip6,
		&((const struct sockaddr_in6*)(res->ai_addr))->sin6_addr,
		sizeof (conf.addr));

	freeaddrinfo (res);
	return 0;
}


/*
 * Initialization stuff
 */
extern uid_t unpriv_uid = 0;
 
extern "C" int
miredo_run (const char *ipv6_name,
	const char *relay_name, const char *server_name,
	const char *prefix_name, const char *ifname, const char *tundev_name)
{
	seteuid (unpriv_uid);
	int retval = -1;

	/* default values */
	if (ifname == NULL)
		ifname = "ter%d";
	if (prefix_name == NULL) // TODO: parse prefix_name
		prefix_name = TEREDO_PREFIX_STR":";

	openlog ("miredo", LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);
	
	if (seteuid (0))
		syslog (LOG_WARNING, _("SetUID to root failed: %m\n"));

	IPv6Tunnel tunnel (ifname, tundev_name); // must be root

	// Definitely drops privileges
	if (setuid (unpriv_uid))
	{
		syslog (LOG_ALERT, _("setuid failed: %m\n"));
		return -1;
	}

	conf.tunnel = &tunnel;
	conf.server_udp = NULL;
	conf.relay_udp = NULL;

	if (!tunnel)
	{
		syslog (LOG_ALERT, _("Teredo tunnel allocation failed."
					" You should be root to do that."));
		goto abort;
	}
	
	// Sets up server sockets
	if (server_name != NULL)
	{
		uint32_t ipv4 = getipbyname (server_name);
		if (!ipv4)
		{
			syslog (LOG_ALERT, _("Fatal configuration error\n"));
			goto abort;
		}
		
		try
		{
			conf.server_udp = new MiredoServerUDP;
		}
		catch (...)
		{
			conf.server_udp = NULL;
			goto abort;
		}
		
		conf.server_ip = ipv4;
		/*
		 * NOTE:
		 * While it is nowhere in the draft Teredo
		 * specification, it really seems that the secondary
		 * server IPv4 address has to be the one just after
		 * the primary server IPv4 address.
		 */
		conf.server_ip2 = htonl (ntohl (ipv4) + 1);

		if (conf.server_udp->ListenIP (ipv4, conf.server_ip2))
		{
			syslog (LOG_ALERT, _("Teredo UDP port failure\n"));
			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running.\n"));
			goto abort;
		}
	}

	// Sets up relay socket
	if (relay_name != NULL)
	{
		uint32_t ipv4 = getipbyname (relay_name);
		if (!ipv4)
		{	// an error message has already been logged
			syslog (LOG_ALERT, _("Fatal configuration error\n"));
			goto abort;
		}
		
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
		uint16_t port = htons (IPPORT_TEREDO + 1);

		try
		{
			conf.relay_udp = new MiredoRelayUDP;
		}
		catch (...)
		{
			conf.relay_udp = NULL;
			goto abort;
		}
		

		if (conf.relay_udp->ListenIP (ipv4, port))
		{
			syslog (LOG_ALERT,
				_("Teredo service port failure\n"));
			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running.\n"));
			goto abort;
		}
	}

	retval = teredo_server_relay ();
	
abort:
	if (conf.relay_udp != NULL)
		delete conf.relay_udp;
	if (conf.server_udp != NULL)
		delete conf.server_udp;

	closelog ();
	return retval;
}
