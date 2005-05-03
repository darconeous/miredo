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
# include <libteredo/server.h>
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
# define teredo_server_relay(t, r, s ) teredo_server( s )
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
 * Pipe file descriptors (the right way to interrupt select() on Linux
 * from a signal handler, as pselect() is not supported).
 */
static int signalfd[2];

static void
exit_handler (int signum)
{
	if (should_exit || signalfd[1] == -1)
		return;

	write (signalfd[1], &signum, sizeof (signum));
	should_exit = signum;
}


static void
reload_handler (int signum)
{
	if (should_reload || signalfd[1] == -1)
		return;

	write (signalfd[1], &signum, sizeof (signum));
	should_reload = signum;
}


/*
 * Main server function, with UDP datagrams receive loop.
 */
static void
teredo_server_relay (IPv6Tunnel& tunnel, TeredoRelay *relay = NULL,
                     TeredoServer *server = NULL)
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
		 || ((maxfd >= 1) && FD_ISSET (signalfd[0], &readset)))
			// interrupted by signal
			break;

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

#ifdef MIREDO_TEREDO_CLIENT
			relay->Process ();
#endif

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
}


/*
 * Initialization stuff
 * (bind_port is in host byte order)
 */
uid_t unpriv_uid = 0;

struct miredo_conf
{
	int mode;
	char *ifname;
	union teredo_addr prefix;
	uint32_t server_ip, server_ip2;
	uint32_t bind_ip;
	uint16_t bind_port;
	union
	{
		struct
		{
			bool default_route;
		} client;
		struct
		{
			uint16_t adv_mtu;
		} relay;
	} u;
#define default_route u.client.default_route
#define adv_mtu       u.relay.adv_mtu
};


static int
miredo_run (const struct miredo_conf *conf)
{
#ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
		InitNonceGenerator ();
#endif

#ifdef MIREDO_TEREDO_RELAY
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
	IPv6Tunnel tunnel (conf->ifname);

	if (!tunnel)
	{
		syslog (LOG_ALERT, _("Teredo tunnel setup failed:\n %s"),
				_("You should be root to do that."));
		return -1;
	}

	MiredoRelay *relay = NULL;
#endif
#ifdef MIREDO_TEREDO_SERVER
	TeredoServer *server = NULL;
#endif
	int fd = -1, retval = -1;


	/*
	 * Must be root to do that.
	 */
#ifdef MIREDO_TEREDO_RELAY
#ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
	{
		fd = miredo_privileged_process (tunnel, conf->default_route);
		if (fd == -1)
		{
			syslog (LOG_ALERT,
				_("Privileged process setup failed: %m"));
			goto abort;
		}
	}
	else
#endif
	if (conf->mode != TEREDO_DISABLED)
	{
		if (tunnel.SetMTU (conf->adv_mtu) || tunnel.BringUp ()
		 || tunnel.AddAddress (conf->mode == TEREDO_RESTRICT
		 			? &teredo_restrict : &teredo_cone)
		 || (conf->mode != TEREDO_DISABLED
		  && tunnel.AddRoute (&conf->prefix.ip6, 32)))
		{
			syslog (LOG_ALERT, _("Teredo routing failed:\n %s"),
				_("You should be root to do that."));
			goto abort;
		}
	}
#endif

#ifdef MIREDO_TEREDO_SERVER
	// Sets up server (needs privileges to create raw socket)
	if ((conf->mode != TEREDO_CLIENT) && (conf->server_ip != INADDR_ANY))
	{
		try
		{
			server = new TeredoServer (conf->server_ip, conf->server_ip2);
		}
		catch (...)
		{
			server = NULL;
			syslog (LOG_ALERT, _("Teredo server failure"));
			goto abort;
		}

		if (!*server)
		{
			syslog (LOG_ALERT, _("Teredo UDP port failure"));
			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running."));
			goto abort;
		}

		server->SetPrefix (&conf->prefix);
		server->SetAdvLinkMTU (conf->adv_mtu);
	}
#endif

#ifdef MIREDO_CHROOT
	/*
	 * We could chroot earlier, but we do it know to keep compatibility with
	 * grsecurity Linux kernel patch that automatically removes capabilities
	 * when chrooted.
	 */
	if (chroot (MIREDO_CHROOT) || chdir ("/"))
		syslog (LOG_WARNING, "chroot to %s failed: %m",
			MIREDO_CHROOT);
#endif

	// Definitely drops privileges
	if (setuid (unpriv_uid))
	{
		syslog (LOG_ALERT, _("Setting UID failed: %m"));
		goto abort;
	}

	// Sets up relay or client

#ifdef MIREDO_TEREDO_RELAY
# ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
	{
		// Sets up client
		try
		{
			relay = new MiredoRelay (fd, &tunnel,
			                         conf->server_ip, conf->server_ip2,
			                         conf->bind_port, conf->bind_ip);
		}
		catch (...)
		{
			relay = NULL;
		}
	}
	else
# endif /* ifdef MIREDO_TEREDO_CLIENT */
	if (conf->mode != TEREDO_DISABLED)
	{
		// Sets up relay
		try
		{
			// FIXME: read union teredo_addr instead of prefix ?
			relay = new MiredoRelay (&tunnel, conf->prefix.teredo.prefix,
			                         conf->bind_port, conf->bind_ip,
			                         conf->mode == TEREDO_CONE);
		}
		catch (...)
		{
			relay = NULL;
		}
	}

	if (conf->mode != TEREDO_DISABLED)
	{
		if (relay == NULL)
		{
			syslog (LOG_ALERT, _("Teredo service failure"));
			goto abort;
		}

		if (!*relay)
		{
			if (conf->bind_port)
				syslog (LOG_ALERT,
					_("Teredo service port failure: "
					"cannot open UDP port %u"),
					(unsigned int)ntohs (conf->bind_port));
			else
				syslog (LOG_ALERT,
					_("Teredo service port failure: "
					"cannot open an UDP port"));

			syslog (LOG_NOTICE, _("Make sure another instance "
				"of the program is not already running."));
			goto abort;
		}
	}
#endif /* ifdef MIREDO_TEREDO_RELAY */

	retval = 0;
	teredo_server_relay (tunnel, relay, server);

abort:
	if (fd != -1)
		close (fd);
#ifdef MIREDO_TEREDO_RELAY
	if (relay != NULL)
		delete relay;
# ifdef MIREDO_TEREDO_CLIENT
	if (conf->mode == TEREDO_CLIENT)
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
static bool
InitSignals (void)
{
	struct sigaction sa;

	if (pipe (signalfd))
	{
		syslog (LOG_ALERT, _("pipe failed: %m"));
		return false;
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

	return true;
}


static void
asyncsafe_close (int& fd)
{
	int buf_fd = fd;

	// Prevents the signal handler from trying to write to a closed pipe
	fd = -1;
	(void)close (buf_fd);
}


static void
DeinitSignals (void)
{
	asyncsafe_close (signalfd[1]);

	// Keeps read fd open until now to prevent SIGPIPE if the
	// child process crashes and we receive a signal.
	(void)close (signalfd[0]);
}




static bool
ParseConf (const char *path, int *newfac, struct miredo_conf *conf,
           const char *server_name)
{
	MiredoConf cnf;
	if (!cnf.ReadFile (path))
	{
		syslog (LOG_ALERT, _("Loading configuration from %s failed"),
			path);
		return false;
	}

	// TODO: support for disabling logging completely
	(void)ParseSyslogFacility (cnf, "SyslogFacility", newfac);

	if (!ParseRelayType (cnf, "RelayType", &conf->mode))
	{
		syslog (LOG_ALERT, _("Fatal configuration error"));
		return false;
	}

	if (conf->mode == TEREDO_CLIENT)
	{
		conf->default_route = true;

		if (!cnf.GetBoolean ("DefaultRoute", &conf->default_route))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return false;
		}

		char *dummy = cnf.GetRawValue ("ServerAddress");

		if (server_name == NULL)
			server_name = dummy;

		if (server_name == NULL)
		{
			syslog (LOG_ALERT, _("Server address not specified"));
			return false;
		}

		/*
		 * We must resolve the server host name before chroot is called.
		 */
		struct addrinfo help, *res;

		memset (&help, 0, sizeof (help));
		help.ai_family = AF_INET;
		help.ai_socktype = SOCK_DGRAM;
		help.ai_protocol = IPPROTO_UDP;

		int check = getaddrinfo (server_name, NULL, &help, &res);

		if (check)
		{
			syslog (LOG_ALERT, _("Invalid server hostname \"%s\": %s"),
			        server_name, gai_strerror (check));
			if (dummy != NULL)
				free (dummy);
			return false;
		}

		conf->server_ip =
			((const struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
		freeaddrinfo (res);
		if (dummy != NULL)
			free (dummy);

		if (!ParseIPv4 (cnf, "ServerAddress2", &conf->server_ip2))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return false;
		}
	}
	else
	{
		conf->adv_mtu = 1280;

		if (!ParseIPv4 (cnf, "ServerBindAddress", &conf->server_ip)
		 || !ParseIPv6 (cnf, "Prefix", &conf->prefix.ip6)
		 || !cnf.GetInt16 ("InterfaceMTU", &conf->adv_mtu))
		{
			syslog (LOG_ALERT, _("Fatal configuration error"));
			return false;
		}

		if (conf->server_ip != INADDR_ANY)
		{
			if (!ParseIPv4 (cnf, "ServerBindAddress2", &conf->server_ip2))
			{
				syslog (LOG_ALERT, _("Fatal configuration error"));
				return false;
			}
		}
	}

	/*
	 * NOTE:
	 * While it is not specified in the draft Teredo
	 * specification, it really seems that the secondary
	 * server IPv4 address has to be the one just after
	 * the primary server IPv4 address.
	 */
	if ((conf->server_ip != INADDR_ANY) && (conf->server_ip2 == INADDR_ANY))
		conf->server_ip2 = htonl (ntohl (conf->server_ip) + 1);

	if (conf->mode != TEREDO_DISABLED)
	{
		if (!ParseIPv4 (cnf, "BindAddress", &conf->bind_ip))
		{
			syslog (LOG_ALERT, _("Fatal bind IPv4 address error"));
			return false;
		}

		uint16_t port = htons (conf->bind_port);
		if (!cnf.GetInt16 ("BindPort", &port))
		{
			syslog (LOG_ALERT, _("Fatal bind UDP port error"));
			return false;
		}
		conf->bind_port = htons (port);
	}

	conf->ifname = cnf.GetRawValue ("InterfaceName");

	cnf.Clear (5);
	return true;
}


/*
 * Configuration and respawning stuff
 */
static const char *const ident = "miredo";

extern "C" int
miredo (const char *confpath, const char *server_name)
{
	int facility = LOG_DAEMON, retval;
	openlog (ident, LOG_PID | LOG_PERROR, facility);

	do
	{
		retval = 1;

		if (!InitSignals ())
			continue;

		/* Default settings */
		int newfac = LOG_DAEMON;
		struct miredo_conf conf =
		{
			TEREDO_CLIENT,	// mode
			NULL,		// ifname
			{ 0 },		// prefix
			INADDR_ANY, INADDR_ANY, // server_ip{,2}
			INADDR_ANY,	// bind_ip
#if 0
		/*
		 * We use 3545 as a Teredo service port.
		 * It is better to use a fixed port number for the
		 * purpose of firewalling, rather than a pseudo-random
		 * one (all the more as it might be a "dangerous"
		 * often firewalled port, such as 1214 as it happened
		 * to me once).
		 */
			htons (IPPORT_TEREDO + 1),
#else
			0		// bind_port
#endif
		};
		conf.prefix.teredo.prefix = htonl (DEFAULT_TEREDO_PREFIX);

		if (!ParseConf (confpath, &newfac, &conf, server_name))
			continue;

		// Apply syslog facility change if needed
		if (newfac != facility)
		{
			closelog ();
			facility = newfac;
			openlog (ident, LOG_PID, facility);
		}

		// Starts the main miredo process
		pid_t pid = fork ();

		switch (pid)
		{
			case -1:
				syslog (LOG_ALERT, _("fork failed: %m"));
				break;

			case 0:
				asyncsafe_close (signalfd[1]);
				retval = miredo_run (&conf);
		}

		if (conf.ifname != NULL)
			free (conf.ifname);

		if (pid == 0)
		{
			closelog ();
			exit (-retval);
		}

		// Waits until the miredo process terminates
		if (pid != -1)
			while (waitpid (pid, &retval, 0) == -1);

		DeinitSignals ();

		if (pid == -1)
		{
		}
		else
		if (should_exit)
		{
			syslog (LOG_NOTICE, _("Exiting on signal %d (%s)"),
				should_exit, strsignal (should_exit));
			retval = 0;
		}
		else
		if (should_reload)
		{
			syslog (LOG_NOTICE, _(
				"Reloading configuration on signal %d (%s)"),
				should_reload, strsignal (should_reload));
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
	while (retval == 2);

	if (retval)
		syslog (LOG_INFO, _("Terminated with error(s)."));
	else
		syslog (LOG_INFO, _("Terminated with no error."));

	closelog ();
	return -retval;
}
