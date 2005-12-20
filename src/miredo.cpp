/*
 * miredo.cpp - Miredo common daemon functions
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
#include <stdlib.h> // exit()
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#include <signal.h> // sigaction()

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h> // uid_t
#include <sys/wait.h> // waitpid()
#if HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#ifndef LOG_PERROR
# define LOG_PERROR 0
#endif

#include "conf.h"
#include "miredo.h"

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
		syslog (LOG_WARNING, _("Error (%s): %s\n"),
				"chroot(\""MIREDO_CHROOT"\")", strerror (errno));
#endif

	// Definitely drops privileges
	if (setuid (unpriv_uid))
	{
		syslog (LOG_ALERT, _("Error (%s): %s\n"), "setuid", strerror (errno));
		return -1;
	}

#ifdef HAVE_LIBCAP
	cap_t s = cap_init ();
	if (s != NULL)
	{
		cap_set_proc (s);
		cap_free (s);
	}
#endif
	return 0;
}


// Defines signal handlers
static bool
InitSignals (void)
{
	struct sigaction sa;

	if (pipe (signalfd))
	{
		syslog (LOG_ALERT, _("Error (%s): %s\n"), "pipe", strerror (errno));
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
	// or maybe not, GNU/kFreeBSD use these for pthread
	//sigaction (SIGUSR1, &sa, NULL);
	//sigaction (SIGUSR2, &sa, NULL);
	
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


/*
 * Configuration and respawning stuff
 */
static const char *const ident = "miredo";


extern "C" int
miredo (const char *confpath, const char *server_name, int pidfd)
{
	int facility = LOG_DAEMON, retval;
	openlog (ident, LOG_PID | LOG_PERROR, facility);

	do
	{
		retval = 1;

		if (!InitSignals ())
			continue;

		MiredoConf cnf;
		if (!cnf.ReadFile (confpath))
		{
			syslog (LOG_WARNING, _("Loading configuration from %s failed"),
			        confpath);
		}

		int newfac = LOG_DAEMON;
		(void)ParseSyslogFacility (cnf, "SyslogFacility", &newfac);

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
				syslog (LOG_ALERT, _("Error (%s): %s\n"), "fork",
				        strerror (errno));
				break;

			case 0:
				close (pidfd);
				asyncsafe_close (signalfd[1]);
				retval = miredo_run (signalfd[0], cnf, server_name);
		}

		cnf.Clear (0);

		if (pid == 0)
		{
			closelog ();
			exit (-retval);
		}

		if (pid != -1)
		{
			// Waits until the miredo process terminates
			while (waitpid (pid, &retval, 0) == -1);

			if (should_exit)
			{
				syslog (LOG_NOTICE, _("Exiting on signal %d (%s)"),
				        should_exit, strsignal (should_exit));
				retval = 0;
			}
			else
			if (should_reload)
			{
				syslog (LOG_NOTICE,
				        _("Reloading configuration on signal %d (%s)"),
				        should_reload, strsignal (should_reload));
				retval = 2;
			}
			else
			if (WIFEXITED (retval))
			{
				retval = WEXITSTATUS (retval);
				syslog (LOG_NOTICE, _("Terminated (exit code: %d)"),
				        retval);
				retval = retval != 0;
			}
			else
			if (WIFSIGNALED (retval))
			{
				retval = WTERMSIG (retval);
				syslog (LOG_INFO, _("Child %d killed by signal %d (%s)"),
				        (int)pid, retval, strsignal (retval));
				retval = 2;
			}
		}

		DeinitSignals ();
	}
	while (retval == 2);

	if (retval)
		syslog (LOG_INFO, _("Terminated with error(s)."));
	else
		syslog (LOG_INFO, _("Terminated with no error."));

	closelog ();
	return -retval;
}
