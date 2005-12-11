/*
 * main.c - Unix Teredo server & relay implementation
 *          command line handling and core functions
 * $Id$
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
#include "prefix.h"

#include <stdio.h>
#include <stdlib.h> /* strtoul(), clearenv() */
#include <string.h> /* strerrno() */

#include <locale.h>

#include <sys/types.h>
#include <sys/time.h> /* for <sys/resource.h> */
#include <sys/resource.h> /* getrlimit() */
#include <sys/stat.h> /* fstat(), mkdir */
#include <unistd.h>
#include <errno.h> /* errno */
#include <fcntl.h> /* O_RDONLY */
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <pwd.h> /* getpwnam() */
#include <grp.h> /* setgroups() */

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#include "miredo.h"

/*
 * RETURN VALUES:
 * 0: ok
 * 1: I/O error
 * 2: command line syntax error
 */

static int
quick_usage (const char *path)
{
	fprintf (stderr, _("Try \"%s -h | more\" for more information.\n"),
	         path);
	return 2;
}


static int
usage (const char *path)
{
	printf (_(
"Usage: %s [OPTIONS] [SERVER_NAME]\n"
"Creates a Teredo tunneling interface for encapsulation of IPv6 over UDP.\n"
"\n"
"  -c, --config     specify an configuration file\n"
"  -f, --foreground run in the foreground\n"
"  -h, --help       display this help and exit\n"
"  -p, --pidfile    override the location of the PID file\n"
"  -u, --user       override the user to set UID to\n"
"  -V, --version    display program version and exit\n"), path);
	return 0;
}


static int
version (void)
{
#ifndef VERSION
# define VERSION "unknown version"
#endif
	printf (_("Miredo: Teredo IPv6 tunneling software %s (%s)\n"
	          " built %s on %s (%s)\n"),
	        VERSION, PACKAGE_HOST, __DATE__,
	        PACKAGE_BUILD_HOSTNAME, PACKAGE_BUILD);
	printf (_("Configured with: %s\n"), PACKAGE_CONFIGURE_INVOCATION);
	puts (_("Written by Remi Denis-Courmont.\n"));

	puts (_("Copyright (C) 2004-2005 Remi Denis-Courmont\n"
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE."));
        return 0;
}


static int
error_dup (int opt, const char *already, const char *additionnal)
{
	fprintf (stderr, _(
"Duplicate parameter \"%s\" for option -%c\n"
"would override previous value \"%s\".\n"),
		 additionnal, opt, already);
	return 2;
}


#if 0
static int
error_qty (int opt, const char *qty)
{
	fprintf (stderr, _(
"Invalid number (or capacity exceeded) \"%s\" for option -%c\n"), qty, opt);
	return 2;
}
#endif


static int
error_extra (const char *extra)
{
	fprintf (stderr, _("%s: unexpected extra parameter\n"), extra);
	return 2;
}


#if 0
static int
error_missing (void)
{
	fputs (_("Error: missing command line parameter\n"), stderr);
	return 2;
}
#endif


/*
 * Creates a Process-ID file.
 */
static int
open_pidfile (const char *path)
{
	int fd;

	fd = open (path, O_WRONLY|O_CREAT, 0644);
	if (fd != -1)
	{
		struct stat s;

		if ((fstat (fd, &s) == 0)
		 && S_ISREG(s.st_mode)
		 && (lockf (fd, F_TLOCK, 0) == 0))
			return fd;

		close (fd);
	}
	return -1;
}


static int
write_pid (int fd)
{
	char buf[20]; // enough for > 2^64
	size_t len;

	(void)snprintf (buf, sizeof (buf), "%d", (int)getpid ());
	buf[sizeof (buf) - 1] = '\0';
	len = strlen (buf);
	return write (fd, buf, len) == (int)len ? 0 : -1;
}


static void
close_pidfile (int fd)
{
	(void)lockf (fd, F_ULOCK, 0);
	(void)close (fd);
}


#ifndef HAVE_CLEARENV
extern char **environ;

static int
clearenv (void)
{
	environ = NULL;
	return 0;
}
#endif


static void
setuid_notice (void)
{
	fputs (_(
"That is usually an indication that you are trying to start\n"
"the program as an user with insufficient system privileges.\n"
"This program should normally be started by root.\n"), stderr);
}


/*
 * Initialize daemon context.
 */
static int
init_daemon (const char *username, const char *pidfile, int nodetach)
{
	struct passwd *pw;
	struct rlimit lim;
	int fd;

	/* Clears environment */
	(void)clearenv ();

	/* Sets sensible umask */
	umask (022);

	/*
	 * We close all file handles, except 0, 1 and 2.
	 * Those last 3 handles will be opened as /dev/null
	 * by later daemon().
	 */
	if (getrlimit (RLIMIT_NOFILE, &lim))
		return -1;

	for (fd = 3; (unsigned)fd < lim.rlim_cur; fd++)
		(void)close (fd);

	/*
	 * Make sure 0, 1 and 2 are open.
	 */
#ifndef HAVE_OPENBSD
	/* OpenBugs^H^H^HSD won't return 3 which is obviously wrong! */
	if (dup (2) != 3)
		return -1;
	close (3);
#endif

	/* Determines unpriviledged user */
	errno = 0;
	pw = getpwnam (username);
	if (pw == NULL)
	{
		fprintf (stderr, "User %s: %s\n",
				username, errno ? strerror (errno)
					: _("User not found"));
		fprintf (stderr,
			_("Error: This program was asked to run in the\n"
			"security context of system user \"%s\", but it\n"
			"does not seem to exist on your system.\n"
			"\n"
			"Use command line option \"-u <username>\" to run\n"
			"this program in the security context of another\n"
			"user.\n"
			), username);
		return -1;
	}

#ifdef MIREDO_DEFAULT_USERNAME
	if (pw->pw_uid == 0)
	{
		fputs (_("Error: This program is not supposed to keep root\n"
			"privileges. That is potentially very dangerous\n"
			"(all the more as it is beta quality code that has\n"
			"never been audited for security vulnerabilities).\n"),
			stderr);
		return -1;
	}
#else
# define MIREDO_DEFAULT_USERNAME "root"
#endif

	unpriv_uid = pw->pw_uid;

	/* Unpriviledged group */
	errno = 0;
	if (setgid (pw->pw_gid))
	{
		fprintf (stderr, _("SetGID to group ID %u: %s\n"),
				(unsigned)pw->pw_gid, strerror (errno));
		fputs (_("Error: This program tried to change its system\n"
			"group(s) security context but it failed.\n"),
			stderr);
		setuid_notice ();
		return -1;
	}

	/* Leaves other group privileges.
	 * This fails if the user is not root. */
	(void)setgroups (0, NULL);

	/* Ensure we have root privilege before initialization */
	if (seteuid (0))
	{
		perror (_("SetUID to root: %s\n"));
		setuid_notice ();
		return -1;
	}

	/* POSIX.1e capabilities support */
#ifdef HAVE_LIBCAP
	{
		cap_t s;
		/* TODO: keep CAP_NET_ADMIN in miredo only */
		cap_value_t v[] =
		{
			CAP_SYS_CHROOT,
			CAP_SETUID,
			CAP_NET_ADMIN,
			CAP_NET_RAW
		};

		s = cap_init ();
		if (s == NULL)
		{
			/* Unlikely */
			perror (_("Fatal error"));
			return -1;
		}

		if (cap_set_flag (s, CAP_PERMITTED, sizeof(v)/sizeof(*v), v, CAP_SET)
		 || cap_set_flag (s, CAP_EFFECTIVE, sizeof(v)/sizeof(*v), v, CAP_SET))
		{
			/* Unlikely */
			perror (_("Fatal error"));
			cap_free (s);
			return -1;
		}

		if (cap_set_proc (s))
		{
			perror (_("Getting required capabilities"));
			cap_free (s);
			fputs (_("Error: This program tried to obtain "
				"required system administration\n"
				"privileges but it failed.\n"), stderr);
			setuid_notice ();
			return -1;
		}
		cap_free (s);
	}
#endif

	/* Opens pidfile */
	fd = open_pidfile (pidfile);
	if (fd == -1)
	{
		fprintf (stderr, _("Cannot create PID file %s:\n %s\n"),
		         pidfile, strerror (errno));
		if (errno == EAGAIN)
			fprintf (stderr, "%s\n",
			         _("Make sure another instance of the program is not "
			           "already running."));
		return -1;
	}

	/* 
	 * Detaches. While not security-related, it fits well here.
	 */
	if (!nodetach && daemon (0, 0))
	{
		perror (_("Error (daemon)"));
		return -1;
	}

	(void)write_pid (fd);

	return fd;
}


int
main (int argc, char *argv[])
{
	const char *username = NULL, *conffile = NULL, *servername = NULL,
	           *pidfile = NULL;
	struct
	{
		unsigned foreground:1; /* Run in the foreground */
	} flags;

	const struct option opts[] =
	{
		{ "conf",       required_argument, NULL, 'c' },
		{ "config",     required_argument, NULL, 'c' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "user",       required_argument, NULL, 'u' },
		{ "pidfile",    required_argument, NULL, 'p' },
		{ "version",    no_argument,       NULL, 'V' },
		{ NULL,         no_argument,       NULL, '\0'}
	};

	int c, fd;

	(void)setlocale (LC_ALL, "");
	(void)bindtextdomain (PACKAGE, LOCALEDIR);
	(void)textdomain (PACKAGE);

#define ONETIME_SETTING( setting ) \
	if (setting != NULL) \
		return error_dup (c, optarg, setting); \
	else \
		setting = optarg;

	memset (&flags, 0, sizeof (flags));

	while ((c = getopt_long (argc, argv, "c:fhp:u:V", opts,
					NULL)) != -1)
		switch (c)
		{
			case '?':
				return quick_usage (argv[0]);

			case 'c':
				ONETIME_SETTING (conffile);
				break;

			case 'f':
				flags.foreground = 1;
				break;

			case 'h':
				return usage (argv[0]);

			case 'p':
				ONETIME_SETTING (pidfile);
				break;

			case 'u':
				ONETIME_SETTING (username);
				break;

			case 'V':
				return version ();

			default:
				fprintf (stderr, _(
"Read unknown option -%c:\n"
"That is probably a bug. Please report it.\n"), c);
				return 1;
		}

	if (optind < argc)
		servername = argv[optind++];

	if (optind < argc)
		return error_extra (argv[optind]);

	if (username == NULL)
		username = MIREDO_DEFAULT_USERNAME;

	if (conffile == NULL)
		conffile = miredo_conffile;

	/* Check if config file and chroot dir are present */
	if ((servername == NULL) && access (conffile, R_OK))
	{
		fprintf (stderr, _("Reading configuration from %s: %s\n"),
				conffile, strerror (errno));
		return 1;
	}
#ifdef MIREDO_CHROOT
	else
	{
		struct stat s;
		const char path[] = MIREDO_CHROOT;

		errno = 0;

		if (stat (path, &s) || !S_ISDIR(s.st_mode)
		 || access (path, X_OK))
		{
			if (errno == 0)
				errno = ENOTDIR;

			fprintf (stderr,
				_("Chroot directory %s: %s\n"),
				path, strerror (errno));
			return 1;
		}
	}
#endif

	if (pidfile == NULL)
		pidfile = miredo_pidfile;

	if (miredo_diagnose ())
		return 1;
	fd = init_daemon (username, pidfile, flags.foreground);
	if (fd == -1)
		return 1;

	/*
	 * Run
	 */
	c = miredo (conffile, servername, fd);

	close_pidfile (fd);
	(void)unlink (pidfile);

	return c ? 1 : 0;
}

