/*
 * miredo.cpp - Miredo common daemon functions
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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
#include <pthread.h> // pthread_sigmask()
#include <signal.h> // sigaction()
#include <stdarg.h>

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
static volatile int should_exit;
static volatile int should_reload;

static void
exit_handler (int signum)
{
	if (should_exit)
		return;

	should_exit = signum;
	kill (0, signum);
}


static void
reload_handler (int signum)
{
	if (should_reload)
		return;

	should_reload = signum;
	kill (0, signum);
}


uid_t unpriv_uid = 0;
const char *miredo_chrootdir = NULL;

extern "C" int
drop_privileges (void)
{
	/*
	 * We could chroot earlier, but we do it know to keep compatibility with
	 * grsecurity Linux kernel patch that automatically removes capabilities
	 * when chrooted.
	 */
	if ((miredo_chrootdir != NULL)
	 && (chroot (miredo_chrootdir) || chdir ("/")))
	{
		syslog (LOG_ALERT, _("Error (%s): %s\n"),
				"chroot", strerror (errno));
		return -1;
	}

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


/**
 * Defines signal handlers.
 */
static void
InitSignals (void)
{
	struct sigaction sa;
	sigset_t set;

	should_exit = 0;
	should_reload = 0;

	memset (&sa, 0, sizeof (sa));
	sigemptyset (&sa.sa_mask); // -- can that really fail ?!?
	sigemptyset (&set);

	/* Signals that trigger a clean exit */
	sa.sa_handler = exit_handler;

	sigaction (SIGINT, &sa, NULL);
	sigaddset (&set, SIGINT);

	sigaction (SIGQUIT, &sa, NULL);
	sigaddset (&set, SIGQUIT);

	sigaction (SIGTERM, &sa, NULL);
	sigaddset (&set, SIGTERM);

	/* Signals that are ignored */
	sa.sa_handler = SIG_IGN;

	sigaction (SIGPIPE, &sa, NULL); // We check errno == EPIPE instead
	sigaddset (&set, SIGPIPE);

#if 0
	// might use these for other purpose in later versions:
	// or maybe not, GNU/kFreeBSD use these for pthread
	sigaction (SIGUSR1, &sa, NULL);
	sigaddset (&set, SIGUSR1);

	sigaction (SIGUSR2, &sa, NULL);
	sigaddset (&set, SIGUSR2);
#endif

	/* Signals that trigger a configuration reload */
	sa.sa_handler = reload_handler;

	sigaction (SIGHUP, &sa, NULL);
	sigaddset (&set, SIGHUP);

	/* Block all handled signals */
	pthread_sigmask (SIG_BLOCK, &set, NULL);
}


/*
 * Configuration and respawning stuff
 */
class MiredoSyslogConf : public MiredoConf
{
	protected:
		virtual void Log (bool error, const char *fmt, va_list ap)
		{
			vsyslog (error ? LOG_ERR : LOG_WARNING, fmt, ap);
		}
};


extern "C" int
miredo (const char *confpath, const char *server_name, int pidfd)
{
	int facility = LOG_DAEMON, retval;
	openlog (miredo_name, LOG_PID | LOG_PERROR, facility);

	do
	{
		retval = 1;

		InitSignals ();

		MiredoSyslogConf cnf;
		if (!miredo_conf_read_file (cnf, confpath))
		{
			syslog (LOG_WARNING, _("Loading configuration from %s failed"),
			        confpath);
		}

		int newfac = LOG_DAEMON;
		miredo_conf_parse_syslog_facility (cnf, "SyslogFacility", &newfac);

		// Apply syslog facility change if needed
		if (newfac != facility)
		{
			closelog ();
			facility = newfac;
			openlog (miredo_name, LOG_PID, facility);
		}
		syslog (LOG_INFO, _("Starting..."));

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
				retval = miredo_run (cnf, server_name);
		}

		cnf.Clear (0);

		switch (pid)
		{
			case -1:
				continue;

			case 0:
				closelog ();
				exit (-retval);
		}

		sigset_t set, saved_set;
		sigemptyset (&set);
		pthread_sigmask (SIG_SETMASK, &set, &saved_set);

		// Waits until the miredo process terminates
		while (waitpid (pid, &retval, 0) == -1);

		pthread_sigmask (SIG_SETMASK, &saved_set, NULL);

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
	while (retval == 2);

	if (retval)
		syslog (LOG_INFO, _("Terminated with error(s)."));
	else
		syslog (LOG_INFO, _("Terminated with no error."));

	closelog ();
	return -retval;
}
