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

#include <string.h> // memset(), strsignal()
#include <stdlib.h> // daemon() on FreeBSD
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <signal.h> // sigaction()

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h> // struct sockaddr_in
#include <syslog.h>
#include <unistd.h> // uid_t
#include <sys/wait.h> // wait()

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include "miredo.h"

#include <libtun6/ipv6-tunnel.h>

#include <libteredo/teredo.h>

#include "conf.h"

#ifdef MIREDO_TEREDO_SERVER
# include "server.h"
#else
# define teredo_server_relay( t, r, s ) teredo_relay( t, r )
#endif

#ifdef MIREDO_TEREDO_RELAY
# include "relay.h"
# ifdef MIREDO_TEREDO_CLIENT
#  include <privproc.h>
#  include <libteredo/security.h> // FIXME: dirty
# endif
#else
# define teredo_server_relay(t, r, s ) teredo_server( t, s )
#endif

/* FIXME: this file needs a lot of cleanup */

/*
 * Signal handlers
 *
 * We block all signals when one of those we catch is being handled.
 * SECURITY NOTE: these signal handlers might be called as root or not,
 * in the context of the privileged child process or in that of the main
 * unprivileged worker process. They must not compromise the child's security.
 */
static int should_exit;
static int should_reload;

/* 
 * The value of rootpid is defined to the PID of the permanent parent process
 * that reads the configuration before any signal handler is set.
 */
static pid_t rootpid;

/*
 * Pipe file descriptors (the right way to interrupt select() on Linux
 * from a signal handler, as pselect() is not supported).
 */
static int signalfd[2];

static void
exit_handler (int signum)
{
	if (should_exit)
		return; // avoid infinite signal loop

	if (rootpid == getpid ())
		/* Signal handler run from the parent that loads configuration
		 * and respawns miredo */
		kill (0, signum);
	else
		write(signalfd[1], &signum, sizeof (signum));

	should_exit = signum;
}


static void
reload_handler (int signum)
{
	if (should_reload)
		return; // avoid infinite signal loop

	if (rootpid == getpid ())
		/* Signal handler run from the parent that loads configuration
		 * and respawns miredo */
		kill (0, signum);

	should_reload = signum;
}


/*
 * Main server function, with UDP datagrams receive loop.
 */
static int
teredo_server_relay (IPv6Tunnel& tunnel, TeredoRelay *relay = NULL,
			TeredoServer *server = NULL)
{
	/* Main loop */
	while (!should_exit && !should_reload)
	{
		/* Registers file descriptors */
		fd_set readset;
		struct timeval tv;
		FD_ZERO (&readset);

		int maxfd = signalfd[0];
		FD_SET(signalfd[0], &readset);

#ifdef MIREDO_TEREDO_SERVER
		if (server != NULL)
		{
			int val = server->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}
#endif

#ifdef MIREDO_TEREDO_RELAY
		if (relay != NULL)
		{
			int val = tunnel.RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;

			val = relay->RegisterReadSet (&readset);
			if (val > maxfd)
				maxfd = val;
		}
#endif

		/*
		 * Short time-out to call relay->Proces () quite often.
		 */
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		/* Wait until one of them is ready for read */
		maxfd = select (maxfd + 1, &readset, NULL, NULL, &tv);
		if ((maxfd < 0)
		 || ((maxfd >= 1) && FD_ISSET(signalfd[0], &readset)))
			// interrupted by signal
			continue;

		/* Handle incoming data */
#ifdef MIREDO_TEREDO_SERVER
		if (server != NULL)
			server->ProcessPacket (&readset);
#endif

#ifdef MIREDO_TEREDO_RELAY
		if (relay != NULL)
		{
			char pbuf[65535];
			int len;

			relay->Process ();

			/* Forwards IPv6 packet to Teredo
			 * (Packet transmission) */
			len = tunnel.ReceivePacket (&readset, pbuf,
							sizeof (pbuf));
			if (len > 0)
				relay->SendPacket (pbuf, len);

			/* Forwards Teredo packet to IPv6
			 * (Packet reception) */
			relay->ReceivePacket (&readset);
		}
#endif
	}

	/* Termination */
	if (should_reload)
		return -2;
	return 0;
}



/*
 * Initialization stuff
 * (bind_port is in host byte order)
 */
uid_t unpriv_uid = 0;


static int
miredo_run (int mode, const char *ifname,
		uint16_t bind_port, uint32_t bind_ip,
		uint32_t server_ip, union teredo_addr *prefix,
		bool default_route)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
		InitNonceGenerator ();
#endif

	if (seteuid (0))
		syslog (LOG_WARNING, _("SetUID to root failed: %m"));

	/*
	 * Tunneling interface initialization
	 *
	 * NOTE: The Linux kernel does not allow setting up an address
	 * before the interface is up, and it tends to complain about its
	 * inability to set a link-scope address for the interface, as it
	 * lacks an hardware layer address.
	 */

	/*
	 * Must likely be root (unless the user was granted access to the
	 * device file).
	 */
	IPv6Tunnel tunnel (ifname);

#ifdef MIREDO_CHROOT_PATH
	if (chroot (MIREDO_CHROOT_PATH) || chdir ("/"))
		syslog (LOG_WARNING, "chroot to %s failed: %m",
			MIREDO_CHROOT_PATH);
#endif

	/*
	 * Must be root to do that.
	 * TODO: move SetMTU() to privsep, as it may be overriden by the
	 * server if we're a client
	 */
	if (!tunnel || tunnel.SetMTU (1280))
	{
		syslog (LOG_ALERT, _("Teredo tunnel setup failed:\n %s"),
				_("You should be root to do that."));
		return -1;
	}

#ifdef MIREDO_TEREDO_RELAY
	MiredoRelay *relay = NULL;
#endif
#ifdef MIREDO_TEREDO_SERVER
	MiredoServer *server = NULL;
#endif
	int fd = -1, retval = -1;


#ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
	{
		fd = miredo_privileged_process (tunnel, unpriv_uid,
						default_route);
		if (fd == -1)
		{
			syslog (LOG_ALERT,
				_("Privileged process setup failed: %m"));
			goto abort;
		}
	}
	else
#endif
	{
		if (tunnel.BringUp ()
		 || tunnel.AddAddress (mode == TEREDO_RESTRICT
		 			? &teredo_restrict : &teredo_cone)
		 || (mode && tunnel.AddRoute (&prefix->ip6, 32)))
		{
			syslog (LOG_ALERT, _("Teredo routing failed:\n %s"),
				_("You should be root to do that."));
			goto abort;
		}
	}

	// Definitely drops privileges
	//if (setuid (unpriv_uid)) -- won't set saved UID
	if (setreuid (unpriv_uid, unpriv_uid))
	{
		syslog (LOG_ALERT, _("Setting UID failed: %m"));
		goto abort;
	}

#ifdef MIREDO_TEREDO_SERVER
	// Sets up server sockets
	if ((mode != TEREDO_CLIENT) && server_ip)
	{
		try
		{
			server = new MiredoServer (server_ip, htonl (ntohl (
							server_ip) + 1));
		}
		catch (...)
		{
			server = NULL;
			syslog (LOG_ALERT, _("Teredo server failure"));
			goto abort;
		}

		/*
		 * NOTE:
		 * While it is nowhere in the draft Teredo
		 * specification, it really seems that the secondary
		 * server IPv4 address has to be the one just after
		 * the primary server IPv4 address.
		 */
		if (!*server)
		{
			syslog (LOG_ALERT, _("Teredo UDP port failure"));
			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running."));
			goto abort;
		}

		// FIXME: read union teredo_addr instead of prefix ?
		server->SetPrefix (prefix->teredo.prefix);
		server->SetTunnel (&tunnel);
	}
#endif

	// Sets up relay or client

#ifdef MIREDO_TEREDO_RELAY
# ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
	{
		// Sets up client
		try
		{
			relay = new MiredoRelay (fd, &tunnel, server_ip,
						 bind_port, bind_ip);
		}
		catch (...)
		{
			relay = NULL;
		}
	}
	else
# endif /* ifdef MIREDO_TEREDO_CLIENT */
	if (mode != TEREDO_DISABLED)
	{
		// Sets up relay
		try
		{
			// FIXME: read union teredo_addr instead of prefix ?
			relay = new MiredoRelay (&tunnel,
						 prefix->teredo.prefix,
						 bind_port, bind_ip,
						 mode == TEREDO_CONE);
		}
		catch (...)
		{
			relay = NULL;
		}
	}

	if (relay == NULL)
	{
		syslog (LOG_ALERT, _("Teredo service failure"));
		goto abort;
	}

	if (!*relay)
	{
		if (bind_port)
			syslog (LOG_ALERT,
				_("Teredo service port failure: "
				"cannot open UDP port %u"),
				(unsigned int)ntohs (bind_port));
		else
			syslog (LOG_ALERT,
				_("Teredo service port failure: "
				"cannot open an UDP port"));

		syslog (LOG_NOTICE, _("Make sure another instance "
			"of the program is not already running."));
		goto abort;
	}
#endif /* ifdef MIREDO_TEREDO_RELAY */

	retval = teredo_server_relay (tunnel, relay, server);

abort:
	if (fd != -1)
		close (fd);
#ifdef MIREDO_TEREDO_RELAY
	if (relay != NULL)
		delete relay;
# ifdef MIREDO_TEREDO_CLIENT
	if (mode == TEREDO_CLIENT)
		DeinitNonceGenerator ();
# endif
#endif
#ifdef MIREDO_TEREDO_SERVER
	if (server != NULL)
		delete server;
#endif

	if (fd != -1)
		wait (NULL); // wait for privsep process

	return retval;
}


// Defines signal handlers
static int
init_signals (void)
{
	struct sigaction sa;

	rootpid = getpid ();
	if (pipe (signalfd))
	{
		syslog (LOG_ALERT, _("pipe failed: %m"));
		return -1;
	}
	should_exit = 0;
	should_reload = 0;

	memset (&sa, 0, sizeof (sa));
	sigemptyset (&sa.sa_mask); // -- can that really fail ?!?

	sa.sa_handler = exit_handler;
	sigaction (SIGINT, &sa, NULL);
	sigaction (SIGQUIT, &sa, NULL);
	sigaction (SIGTERM, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	// We check for EPIPE in errno instead:
	sigaction (SIGPIPE, &sa, NULL);
	// might use these for other purpose in later versions:
	sigaction (SIGUSR1, &sa, NULL);
	sigaction (SIGUSR2, &sa, NULL);
	
	sa.sa_handler = reload_handler;
	sigaction (SIGHUP, &sa, NULL);

	return 0;
}


/*
 * Configuration and respawning stuff
 */
static const char *const ident = "miredo";

extern "C" int
miredo (const char *confpath)
{
	int facility = LOG_DAEMON;
	openlog (ident, LOG_PID, facility);

	int retval = init_signals () ?: 2;

	while (retval == 2)
	{
		retval = 1;

		MiredoConf cnf;
		if (!cnf.ReadFile (confpath))
		{
			syslog (LOG_ALERT,
				_("Loading configuration from %s failed"),
				confpath);
			continue;
		}

		/* Default settings */
		int mode = TEREDO_CLIENT;
		bool default_route = true;
		char *ifname = NULL;
		uint32_t bind_ip = INADDR_ANY, server_ip = 0;
		int newfacility = LOG_DAEMON;
		union teredo_addr prefix;
		memset (&prefix, 0, sizeof (prefix));
		prefix.teredo.prefix = htonl (DEFAULT_TEREDO_PREFIX);
#if 0
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
		uint16_t bind_port = IPPORT_TEREDO + 1;
#else
		uint16_t bind_port = 0;
#endif

		/* FIXME: newfacility */
		// Apply syslog facility change if needed
		if (newfacility != facility)
		{
			closelog ();
			facility = newfacility;
			openlog (ident, LOG_PID, facility);
		}

		if (!ParseRelayType (cnf, "RelayType", &mode))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			continue;
		}

		if (mode == TEREDO_CLIENT)
		{
			if (!ParseIPv4 (cnf, "ServerAddress", &server_ip)
			 || !cnf.GetBoolean ("DefaultRoute", &default_route))
			{
				syslog (LOG_ALERT,
					_("Fatal configuration error"));
				continue;
			}
		}
		else
		{
			if (!ParseIPv4 (cnf, "ServerBindAddress", &server_ip)
			 || !ParseIPv6 (cnf, "Prefix", &prefix.ip6))
			{
				syslog (LOG_ALERT,
					_("Fatal configuration error"));
				continue;
			}
		}

		if (mode != TEREDO_DISABLED)
		{
			if (!ParseIPv4 (cnf, "BindAddress", &bind_ip))
			{
				syslog (LOG_ALERT,
					_("Fatal bind IPv4 address error"));
				continue;
			}

			if (!cnf.GetInt16 ("BindPort", &bind_port))
			{
				syslog (LOG_ALERT,
					_("Fatal bind UDP port error"));
				continue;
			}
			bind_port = htons (bind_port);
		}

		if (!cnf.GetString ("InterfaceName", &ifname))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			continue;
		}

		cnf.~MiredoConf ();

		// Starts the main miredo process
		pid_t pid = fork ();

		switch (pid)
		{
			case -1:
				syslog (LOG_ALERT, _("fork failed: %m"));
				continue;

			case 0:
				retval = miredo_run (mode, ifname != NULL
							? ifname : ident,
							bind_port, bind_ip,
							server_ip, &prefix,
							default_route);
				if (ifname != NULL)
					free (ifname);
				closelog ();
				exit (-retval);
		}

		if (ifname != NULL)
			free (ifname);

		// Waits until the miredo process terminates
		while (waitpid (pid, &retval, 0) == -1);
		
		if (should_exit)
		{
			syslog (LOG_NOTICE, _("Exiting on signal %d (%s)"),
				should_exit, strsignal (should_exit));

			should_exit = 0;
			retval = 0;
		}
		else
		if (should_reload)
		{
			syslog (LOG_NOTICE, _(
				"Reloading configuration on signal %d (%s)"),
				should_reload, strsignal (should_reload));

			should_reload = 0;
			retval = 2;
		}
		else
		if (WIFEXITED (retval))
		{
			retval = WEXITSTATUS (retval);
			syslog (LOG_NOTICE, _(
				"Terminated (exit code: %d)"), retval);
			retval = retval != 0;
		}
		else
		if (WIFSIGNALED (retval))
		{
			retval = WTERMSIG (retval);
			syslog (LOG_INFO, _(
				"Child %d killed by signal %d (%s)"),
				(int)pid, retval, strsignal (retval));
			retval = 2;
		}
	}

	closelog ();
	return -retval;
}
