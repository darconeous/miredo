/*
 * main.cpp - Unix Teredo server & relay implementation
 *            command line handling and core functions
 * $Id: main.cpp,v 1.1 2004/06/14 14:45:58 rdenisc Exp $
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
#include <stdio.h> // printf()

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h> // struct sockaddr_in, struct sockaddr_in6
#include <syslog.h>
#include <unistd.h> // uid

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include "conf.h"
#include "teredo-udp.h"
#include "ipv6-tunnel.h"
#include "server_pkt.h"
#include "relay.h"

/*
 * Main server function, with UDP datagrams receive loop.
 * TODO: should be able to be relay-only
 */
static int
teredo_server_relay (void)
{
	MiredoRelay relay;

	relay.SetSocket (conf.relay_udp);
	relay.SetTunnel (conf.tunnel);
	relay.SetLocalAddress (&conf.addr);

	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		FD_ZERO (&readset);
		int maxfd = conf.server_udp->RegisterReadSet (&readset);
		int val = conf.tunnel->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;
		val = conf.relay_udp->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		/* Wait until one of them is ready for read */
		val = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if (val <= 0)
			continue;

		/* Handle incoming data */
		if (conf.server_udp->ReceivePacket (&readset) == 0)
			handle_server_packet (conf.server_udp);
		if (conf.tunnel->ReceivePacket (&readset) == 0)
			relay.TransmitPacket ();
		if (conf.relay_udp->ReceivePacket (&readset) == 0)
			relay.ReceivePacket ();
	}

	/* Termination */
	return 0;
}



struct miredo_configuration conf;


static int
get_server_ip (const char *name)
{
	struct addrinfo help, *res;

	memset (&help, 0, sizeof (help));
	help.ai_family = AF_INET;
	help.ai_socktype = SOCK_DGRAM;
	help.ai_protocol = IPPROTO_UDP;

	int check = getaddrinfo (name, NULL, &help, &res);

	if (check)
	{
		syslog (LOG_ERR, _("Invalid hostname '%s': %s\n"),
			name, gai_strerror (check));
		closelog ();
		return -1;
	}

	conf.server_ip = ((const struct sockaddr_in*)res->ai_addr)
			->sin_addr.s_addr;
	conf.server_ip2 = htonl (ntohl (conf.server_ip) + 1);

	freeaddrinfo (res);
	return 0;
}


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

	memcpy (&conf.addr,
		&((const struct sockaddr_in6*)(res->ai_addr))->sin6_addr,
		sizeof (conf.addr));

	freeaddrinfo (res);
	return 0;
}

	
static int
teredo (const char *server_name, const char *relay_name)
{
	uid_t uid = getuid ();
	seteuid (uid);
	int retval = -1;

	openlog ("miredo", LOG_PERROR|LOG_PID|LOG_CONS, LOG_DAEMON);

	seteuid (0);
	IPv6Tunnel tunnel ("ter%d");
	/* FIXME: this is very bad for security (and very buggy too):
	 * TODO: do it with netlink or something similar */
	//system ("/sbin/ip -6 link set teredo up");
	//system ("/sbin/ip -6 address add "TEREDO_PREFIX_STR":1/32 dev teredo");
	/* Definitely drops privileges */
	setuid (uid);

	conf.tunnel = &tunnel;

	if (!tunnel)
	{
		syslog (LOG_ALERT, _("Teredo tunnel allocation failed\n"));
		syslog (LOG_INFO, _("Make sure you have read/write access to "
			"/dev/net/tun (char dev: 10 200)"));
	}
	else
	{
		/* 
		 * TODO:
		 * - ability to only be a server or a relay
		 * - separate relay and server address
		 */
		MiredoServerUDP serversock;
		conf.server_udp = &serversock;

		MiredoRelayUDP relaysock;
		conf.relay_udp = &relaysock;

		if (get_server_ip (server_name)
		 || serversock.ListenIP (conf.server_ip, conf.server_ip2))
			syslog (LOG_ALERT,
				_("Teredo UDP port allocation failed\n"));
		else
		if (relaysock.ListenIP (conf.server_ip))
			syslog (LOG_ALERT,
				_("Teredo service port allocation failed\n"));
		else
		if (get_relay_ipv6 (relay_name))
			syslog (LOG_ALERT,
				_("Teredo relay IPv6 address undefined\n"));
		else
			retval = teredo_server_relay ();
	}
	
	closelog ();
	return retval;
}


static int
usage (const char *path)
{
	printf (_("Usage: %s <primary server IPv4> <relay IPv6>\n"), path);
	return 1;
}


int
main (int argc, char *argv[])
{
	return (argc != 3) ? usage (argv[0]) : teredo (argv[1], argv[2]);
}

