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
#include <string.h> // memset()

#include <sys/types.h>
#include <sys/select.h>
#include <syslog.h>
#include <netdb.h> // gai_strerror()
#include <unistd.h> // for broken libc which don't know about sys/select.h

#include <libteredo/teredo.h>

#include "conf.h"
#include "miredo.h"

#include <libteredo/server.h>

const char *const miredo_conffile =
		SYSCONFDIR"/miredo-server.conf";
const char *const miredo_pidfile =
		LOCALSTATEDIR"/run/miredo-server.pid";

extern "C" int
miredo_diagnose (void)
{
	char buf[1024];
	int check = libteredo_server_check (buf, sizeof (buf));
	if (check)
	{
		buf[sizeof (buf) - 1] = '\0';
		fputs (buf, stderr);
	}
	return check;
}


extern int
miredo_run (int fd, MiredoConf& conf, const char *server_name)
{
	libteredo_server *server;
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
		syslog (LOG_ALERT, _("Fatal configuration error"));
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

	// Sets up server (needs privileges to create raw socket)
	server = libteredo_server_create (server_ip, server_ip2);

	if (drop_privileges ())
		return -1;

	if (server != NULL)
	{
		if ((libteredo_server_set_prefix (server, *(uint32_t *)&prefix) == 0)
		 && (libteredo_server_set_MTU (server, mtu) == 0)
		 && (libteredo_server_start (server) == 0))
		{
			int dummy;
	
			while (read (fd, &dummy, sizeof (dummy)) < 0);

			libteredo_server_stop (server);
			libteredo_server_destroy (server);

			// parent's been signaled or died
			return 0;
		}
		libteredo_server_destroy (server);
	}

	syslog (LOG_ALERT, _("Teredo server fatal error"));
	syslog (LOG_NOTICE, _("Make sure another instance "
	        "of the program is not already running."));
	return -1;
}
