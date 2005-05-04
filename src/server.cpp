/*
 * server.cpp - Unix Teredo server implementation core functions
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2004-2005 Remi Denis-Courmont.                       *
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

#include <gettext.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <sys/select.h>
#include <syslog.h>
#include <netdb.h> // gai_strerror()

#include <libteredo/teredo.h>

#include "conf.h"
#include "miredo.h"

#include <libteredo/server.h>

extern "C" const char *const miredo_conf_filename = "/miredo-server.conf";
extern "C" const char *const pidfile = MIREDO_PIDFILEDIR"/miredo-server.pid";

/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_server (TeredoServer *server)
{
	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		FD_ZERO (&readset);

		int maxfd = signalfd[0];
		FD_SET(signalfd[0], &readset);

		int val = server->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, NULL);
		if ((maxfd < 0)
		 || ((maxfd >= 1) && FD_ISSET (signalfd[0], &readset)))
			// interrupted by signal
			break;

		/* Handle incoming data */
		server->ProcessPacket (&readset);
	}
}


extern int
miredo_run (MiredoConf& conf, const char *server_name)
{
	union teredo_addr prefix = { 0 };
	uint32_t server_ip = INADDR_ANY, server_ip2 = INADDR_ANY;
	uint16_t mtu = 1280;

	prefix.teredo.prefix = htonl (DEFAULT_TEREDO_PREFIX);

	if (server_name != NULL)
	{
		int check = GetIPv4ByName (server_name, &server_ip);
		if (check)
		{
			syslog (LOG_ALERT, _("Invalid server hostname \"%s\": %s"),
			        server_name, gai_strerror (check));
			return -2;
		}
	}
	else
	{
		if (!ParseIPv4 (conf, "ServerBindAddress", &server_ip)
		 || !ParseIPv4 (conf, "ServerBindAddress2", &server_ip2))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return -2;
		}
	}

	if (server_ip == INADDR_ANY)
	{
		syslog (LOG_ALERT, _("Server address not specified"));
		return -2;
	}

	/*
	 * NOTE:
	 * While it is not specified in the draft Teredo
	 * specification, it really seems that the secondary
	 * server IPv4 address has to be the one just after
	 * the primary server IPv4 address.
	 */
	if (server_ip2 == INADDR_ANY)
		server_ip2 = htonl (ntohl (server_ip) + 1);

	if (!ParseIPv6 (conf, "Prefix", &prefix.ip6)
	 || !conf.GetInt16 ("InterfaceMTU", &mtu))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	conf.Clear (5);

	TeredoServer *server;

	// Sets up server (needs privileges to create raw socket)
	try
	{
		server = new TeredoServer (server_ip, server_ip2);
	}
	catch (...)
	{
		syslog (LOG_ALERT, _("Teredo server failure"));
		return -1;
	}

	int retval = -1;

	if (!*server)
	{
		syslog (LOG_ALERT, _("Teredo UDP port failure"));
		syslog (LOG_NOTICE, _("Make sure another instance "
		        "of the program is not already running."));
		goto abort;
	}

	server->SetPrefix (&prefix);
	server->SetAdvLinkMTU (mtu);

	if (drop_privileges ())
		goto abort;

	retval = 0;
	teredo_server (server);

abort:
	delete server;
	return retval;
}
