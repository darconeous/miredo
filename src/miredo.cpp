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
#include <netdb.h>
#include <netinet/in.h> // struct sockaddr_in
#include <syslog.h>
#include <unistd.h> // uid_t
#include <sys/wait.h> // waitpid()

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include <libtun6/ipv6-tunnel.h>

#include <libteredo/teredo.h>

#include "miredo.h"
#include "conf.h"

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
int signalfd[2]; /* FIXME: extern ?? */

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


/* FIXME: move this to main.c, and add a detach function */
uid_t unpriv_uid = 0;

extern "C" int
drop_privileges (void)
{
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
		return -1;
	}
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

extern int miredo_run (const struct miredo_conf *conf);


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
