/*
 * miredo.cpp - Unix Teredo server & relay implementation
 *              core functions
 * $Id: miredo.cpp,v 1.13 2004/06/26 15:24:26 rdenisc Exp $
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
#include <stdlib.h> // daemon() on FreeBSD
#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h> // struct sockaddr_in
#include <syslog.h>
#include <unistd.h> // uid_t

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include "miredo.h" // FIXME: remove conf
#include "teredo.h" // FIXME: move AddRoute to <relay.cpp>
#include "teredo-udp.h"
#include "ipv6-tunnel.h"
#include "server_pkt.h"
#include "common_pkt.h" // is_ipv4_global_unicast() -- FIXME: code clean up
#include "relay.h"


struct miredo_setup conf;

static MiredoRelayUDP *relay_udp = NULL;
static MiredoServerUDP *server_udp = NULL;
static IPv6Tunnel *ipv6_tunnel = NULL;

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

	if (relay_udp != NULL)
	{
		relay.SetSocket (relay_udp);
		relay.SetTunnel (ipv6_tunnel);
	}

	/* Main loop */
	int exitcode = 0;
	while (exitcode == 0)
	{
		/* Registers file descriptors */
		fd_set readset;
		FD_ZERO (&readset);

		int maxfd = -1;

		if (server_udp != NULL)
		{
			int val = server_udp->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}

		if (relay_udp != NULL)
		{
			int val = ipv6_tunnel->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;

			val = relay_udp->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if (maxfd <= 0)
			continue;

		/* Handle incoming data */
		if (server_udp != NULL)
		{
			if (server_udp->ReceivePacket (&readset) == 0)
				handle_server_packet (server_udp);
		}
		
		if (relay_udp != NULL)
		{
			if (ipv6_tunnel->ReceivePacket (&readset) == 0)
				relay.TransmitPacket ();
			if (relay_udp->ReceivePacket (&readset) == 0)
				relay.ReceivePacket ();
		}
	}

	/* Termination */
	return 0;
}



/*
 * Returns an IPv4 address (network byte order) associated with hostname
 * <name>. Returns -1 on error.
 */
static int
getipv4byname (const char *name, uint32_t *ipv4)
{
	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (name, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname `%s': %s"),
			name, gai_strerror (check));
		closelog ();
		return -1;
	}

	*ipv4 = ((const struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
	freeaddrinfo (res);
	return 0;
}


static int
getipv6byname (const char *name, struct in6_addr *ipv6)
{
	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = PF_INET6;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (name, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname '%s': %s"),
			name, gai_strerror (check));
		closelog ();
		return -1;
	}

	memcpy (ipv6,
		&((const struct sockaddr_in6*)(res->ai_addr))->sin6_addr,
		sizeof (struct in6_addr));

	freeaddrinfo (res);
	return 0;
}


/*
 * Initialization stuff
 * (client_port is is host byte order)
 */
uid_t unpriv_uid = 0;
 
extern "C" int
miredo_run (uint16_t client_port, const char *server_name,
		const char *prefix_name, const char *ifname)
{
	seteuid (unpriv_uid);

	/* default values */
	if (client_port == 0)
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
		client_port = IPPORT_TEREDO + 1;

	if (ifname == NULL)
		ifname = "teredo";
	if (prefix_name == NULL)
		prefix_name = TEREDO_PREFIX_STR":";

	openlog ("miredo", LOG_PERROR|LOG_PID, LOG_DAEMON);

	struct in6_addr prefix;
	if (getipv6byname (prefix_name, &prefix))
	{
		syslog (LOG_ALERT,
			_("Teredo IPv6 prefix not properly set."));
		closelog ();
		return -1;
	}


	if (seteuid (0))
		syslog (LOG_WARNING, _("SetUID to root failed: %m"));

	/* Tunneling interface initialization */
	// must likely be root:
	IPv6Tunnel tunnel (ifname);
	// must be root:
	int retval = !tunnel
		|| tunnel.SetMTU (1280)
		|| tunnel.BringUp ()
	// FIXME: should be done later (not OK if we are a client)
	// FIXME: should be done by TeredoRelay
	// FIXME: but we need root, and later we are not root
	// FIXME: should set cone flag as appropriate
		|| tunnel.AddAddress (&teredo_restrict, 64)
		|| tunnel.AddRoute (&prefix, 32);

	// Definitely drops privileges
	if (setuid (unpriv_uid))
	{
		syslog (LOG_ALERT, _("setuid failed: %m"));
		goto abort;
	}

	if (retval)
	{
		syslog (LOG_ALERT, _("Teredo tunnel setup failed."
					" You should be root to do that."));
		goto abort;
	}

	conf.tunnel = (ipv6_tunnel = &tunnel);

	// Sets up server sockets
	if (server_name != NULL)
	{
		uint32_t ipv4;
		 
		if (getipv4byname (server_name, &ipv4))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			goto abort;
		}

		if ((ipv4 == 0) || !is_ipv4_global_unicast (ipv4))
		{
			syslog (LOG_ALERT,
				_("Server IPv4 must be global unicast. "
								"Exiting."));
			goto abort;
		}

		server_udp = new MiredoServerUDP;
		conf.server_ip = ipv4;
		/*
		 * NOTE:
		 * While it is nowhere in the draft Teredo
		 * specification, it really seems that the secondary
		 * server IPv4 address has to be the one just after
		 * the primary server IPv4 address.
		 */
		conf.server_ip2 = htonl (ntohl (ipv4) + 1);

		if (server_udp->ListenIP (ipv4, conf.server_ip2))
		{
			syslog (LOG_ALERT, _("Teredo UDP port failure"));
			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running."));
			goto abort;
		}
	}

	// Sets up relay socket
	relay_udp = new MiredoRelayUDP;

	if (relay_udp->ListenPort (htons (client_port)))
	{
		syslog (LOG_ALERT,
			_("Teredo service port failure: "
			"cannot open UDP port %u\n"), (unsigned)client_port);
		syslog (LOG_NOTICE, _("Make sure another instance "
			"of the program is not already running."));
		goto abort;
	}

	if (daemon (0, 0))
	{
		syslog (LOG_ALERT,
			_("Background mode error (fork): %m"));
		return -1;
	}

	retval = teredo_server_relay ();

abort:
	if (relay_udp != NULL)
		delete relay_udp;
	if (server_udp != NULL)
		delete server_udp;

	closelog ();
	return retval;
}
