/*
 * miredo.cpp - Unix Teredo server & relay implementation
 *              core functions
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

#include <libteredo/teredo.h>

#include "conf.h"
#include "miredo.h"


#include <libteredo/server.h>

/* FIXME: this file needs a lot of cleanup */

/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_server (TeredoServer *server = NULL)
{
	/* Main loop */
	while (1)
	{
		/* Registers file descriptors */
		fd_set readset;
		struct timeval tv;
		FD_ZERO (&readset);

		int maxfd = signalfd[0];
		FD_SET(signalfd[0], &readset);

		int val = server->RegisterReadSet (&readset);
		if (val > maxfd)
			maxfd = val;

		/*
		 * Short time-out to call relay->Proces () quite often.
		 */
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, &tv);
		if ((maxfd < 0)
		 || ((maxfd >= 1) && FD_ISSET (signalfd[0], &readset)))
			// interrupted by signal
			break;

		/* Handle incoming data */
		server->ProcessPacket (&readset);
	}
}


extern int
miredo_run (const struct miredo_conf *conf)
{
	TeredoServer *server;

	// Sets up server (needs privileges to create raw socket)
	try
	{
		server = new TeredoServer (conf->server_ip, conf->server_ip2);
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

	server->SetPrefix (&conf->prefix);
	server->SetAdvLinkMTU (conf->adv_mtu);

	if (drop_privileges ())
		goto abort;

	retval = 0;
	teredo_server (server);

abort:
	delete server;
	return retval;
}
