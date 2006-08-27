/*
 * server.c - Unix Teredo server implementation daemon
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

#include <gettext.h>

#include <inttypes.h>
#include <string.h> // memset()
#include <stdbool.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/select.h>
#include <syslog.h>
#include <signal.h> // sigemptyset()
#include <pthread.h> // pthread_sigmask()
#include <netdb.h> // gai_strerror()
#include <unistd.h> // for broken libc which don't know about sys/select.h
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#include <signal.h> // sigwait()

#include <netinet/in.h>
#include <libteredo/teredo.h>

#include "miredo.h"
#include "conf.h"

#include <libteredo/server.h>


static int
server_diagnose (void)
{
	char buf[1024];
	int check = teredo_server_check (buf, sizeof (buf));
	if (check)
	{
		buf[sizeof (buf) - 1] = '\0';
		fprintf (stderr, "%s\n", buf);
	}
	return check;
}


static int
server_run (miredo_conf *conf, const char *server_name)
{
	teredo_server *server;
	union teredo_addr prefix;
	uint32_t server_ip = INADDR_ANY, server_ip2 = INADDR_ANY;
	uint16_t mtu = 1280;

	memset (&prefix, 0, sizeof (prefix));
	prefix.teredo.prefix = htonl (TEREDO_PREFIX);

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
		if (!miredo_conf_parse_IPv4 (conf, "ServerBindAddress", &server_ip)
		 || !miredo_conf_parse_IPv4 (conf, "ServerBindAddress2", &server_ip2))
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
	 * While it is not specified in the Teredo RFC,
	 * it really seems that the secondary
	 * server IPv4 address has to be the one just after
	 * the primary server IPv4 address.
	 */
	if (server_ip2 == INADDR_ANY)
		server_ip2 = htonl (ntohl (server_ip) + 1);

	if (!miredo_conf_parse_teredo_prefix (conf, "Prefix",
	                                      &prefix.teredo.prefix)
	 || !miredo_conf_get_int16 (conf, "InterfaceMTU", &mtu, NULL))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return -2;
	}

	miredo_conf_clear (conf, 5);

	// Sets up server (needs privileges to create raw socket)
	server = teredo_server_create (server_ip, server_ip2);

	if (drop_privileges ())
		return -1;

	if (server != NULL)
	{
		if ((teredo_server_set_prefix (server, prefix.teredo.prefix) == 0)
		 && (teredo_server_set_MTU (server, mtu) == 0)
		 && (teredo_server_start (server) == 0))
		{
			sigset_t dummyset, set;
			int dummy;

			/* changes nothing, only gets the current mask */
			sigemptyset (&dummyset);
			pthread_sigmask (SIG_BLOCK, &dummyset, &set);

			/* wait for fatal signal */
			while (sigwait (&set, &dummy) != 0);

			teredo_server_stop (server);
			teredo_server_destroy (server);

			// parent's been signaled or died
			return 0;
		}
		teredo_server_destroy (server);
	}

	syslog (LOG_ALERT, _("Teredo server fatal error"));
	syslog (LOG_NOTICE, _("Make sure another instance "
	        "of the program is not already running."));
	return -1;
}


int main (int argc, char *argv[])
{
#ifdef HAVE_LIBCAP
	static const cap_value_t capv[] =
	{
		CAP_NET_RAW /* required by teredo_server */
	};

	miredo_capv = capv;
	miredo_capc = sizeof (capv) / sizeof (capv[0]);
#endif

	miredo_name = "miredo-server";
	miredo_diagnose = server_diagnose;
	miredo_run = server_run;

	return miredo_main (argc, argv);
}

