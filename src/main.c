/*
 * main.c - Unix Teredo server & relay implementation
 *          command line handling and core functions
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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
#include "binreloc.h"

#include <stdio.h>
#include <stdlib.h> /* strtoul(), clearenv() */
#include <string.h> /* strerror() */

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

#ifdef HAVE_GETOPT_H
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


extern int
miredo_version (void)
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

	printf (_("Copyright (C) 2004-%u Remi Denis-Courmont\n"
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"), 2006);
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


static int
error_errno (const char *str)
{
	fprintf (stderr, _("Error (%s): %s\n"), str, strerror (errno));
	return -1;
}


/**
 * Creates a Process-ID file.
 */
#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif
static int
open_pidfile (const char *path)
{
	int fd;

	fd = open (path, O_WRONLY|O_CREAT|O_NOFOLLOW, 0644);
	if (fd != -1)
	{
		struct stat s;

		errno = 0;
		/* We only check the lock. The actual locking occurs
		 * after (possibly) calling daemon(). */
		if ((fstat (fd, &s) == 0)
		 && S_ISREG(s.st_mode)
		 && (lockf (fd, F_TEST, 0) == 0))
			return fd;

		if (errno == 0) /* !S_ISREG */
			errno = EACCES;

		(void)close (fd);
	}
	return -1;
}


static int
write_pid (int fd)
{
	char buf[20]; // enough for > 2^64

	/* Actually lock the file */
	if (lockf (fd, F_TLOCK, 0))
		return -1;

	(void)snprintf (buf, sizeof (buf), "%d", (int)getpid ());
	buf[sizeof (buf) - 1] = '\0';
	size_t len = strlen (buf);

	if (ftruncate (fd, 0)
	 || (write (fd, buf, len) != (ssize_t)len)
	 || fdatasync (fd))
		return -1;
	return 0;
}


static int
close_pidfile (int fd)
{
	if (lockf (fd, F_ULOCK, 0))
		return -1;
	if (close (fd))
		return -1;
	return 0;
}


#ifdef MIREDO_DEFAULT_USERNAME
static void
setuid_notice (void)
{
	fputs (_(
"That is usually an indication that you are trying to start\n"
"the program as an user with insufficient system privileges.\n"
"This program should normally be started by root.\n"), stderr);
}
#endif


/**
 * Initialize daemon context.
 */
static int
init_security (const char *username)
{
	int val;

	/* Sets sensible umask */
	(void)umask (022);

	/*
	 * We close all file handles, except 0, 1 and 2.
	 * This ensures that select() fd_set won't overflow.
	 *
	 * Those last 3 handles will be opened as /dev/null
	 * by later daemon().
	 */
	errno = 0;
	if (closefrom (3) && (errno != EBADF))
		return -1;

	/*
	 * Make sure 0, 1 and 2 are open.
	 */
	val = dup (2);
	if (val < 3)
		return -1;
	close (val);

	/* Clears environment */
	(void)clearenv ();

#ifdef MIREDO_DEFAULT_USERNAME
	/* Determines unpriviledged user */
	errno = 0;
	struct passwd *pw = getpwnam (username);
	if (pw == NULL)
	{
		fprintf (stderr, _("User \"%s\": %s\n"), username,
		         errno ? strerror (errno) : _("User not found"));
		return -1;
	}

	if (pw->pw_uid == 0)
	{
		fputs (_("Error: This program is not supposed to keep root\n"
			"privileges. That is potentially very dangerous\n"
			"(all the more as it has never been externally audited).\n"),
			stderr);
		return -1;
	}
	unpriv_uid = pw->pw_uid;

	/* Ensure we have root privilege before initialization */
	if (seteuid (0))
	{
		fprintf (stderr, _("SetUID to root: %s\n"), strerror (errno));
		setuid_notice ();
		return -1;
	}

	/* Unpriviledged group */
	(void)setgid (pw->pw_gid);
	(void)initgroups (username, pw->pw_gid);
#else
	(void)username;
#endif /* MIREDO_DEFAULT_USERNAME */


#ifdef HAVE_LIBCAP
	/* POSIX.1e capabilities support */
	cap_t s = cap_init ();
	if (s == NULL)
		return error_errno ("cap_init"); // unlikely

	static cap_value_t caps[] =
	{
		CAP_KILL, // required by the signal handler
		CAP_SETUID
	};
	cap_set_flag (s, CAP_PERMITTED, 3, caps, CAP_SET);
	cap_set_flag (s, CAP_EFFECTIVE, 3, caps, CAP_SET);

	if (miredo_chrootdir != NULL)
	{
		static cap_value_t chroot_cap[] = { CAP_SYS_CHROOT };
		cap_set_flag (s, CAP_PERMITTED, 1, chroot_cap, CAP_SET);
		cap_set_flag (s, CAP_EFFECTIVE, 1, chroot_cap, CAP_SET);
	}

	cap_set_flag (s, CAP_PERMITTED, miredo_capc,
	              (cap_value_t *)miredo_capv, CAP_SET);
	cap_set_flag (s, CAP_EFFECTIVE, miredo_capc,
	              (cap_value_t *)miredo_capv, CAP_SET);

	val = cap_set_proc (s);
	cap_free (s);

	if (val)
	{
		error_errno ("cap_set_proc");
		setuid_notice ();
		return -1;
	}
#endif

	return 0;
}


static void init_locale (void)
{
	(void)br_init (NULL);
	(void)setlocale (LC_ALL, "");
	char *path = br_find_locale_dir (LOCALEDIR);
	(void)bindtextdomain (PACKAGE, path);
	free (path);
	(void)textdomain (PACKAGE);
}


int miredo_main (int argc, char *argv[])
{
	const char *username = NULL, *conffile = NULL, *servername = NULL,
	           *pidfile = NULL, *chrootdir = NULL;
	struct
	{
		unsigned foreground:1; /* Run in the foreground */
	} flags;

	static const struct option opts[] =
	{
		{ "conf",       required_argument, NULL, 'c' },
		{ "config",     required_argument, NULL, 'c' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "pidfile",    required_argument, NULL, 'p' },
		{ "chroot",     required_argument, NULL, 't' },
		{ "chrootdir",  required_argument, NULL, 't' },
		{ "user",       required_argument, NULL, 'u' },
		{ "username",   required_argument, NULL, 'u' },
		{ "version",    no_argument,       NULL, 'V' },
		{ NULL,         no_argument,       NULL, '\0'}
	};

	init_locale ();

#define ONETIME_SETTING( setting ) \
	if (setting != NULL) \
		return error_dup (c, optarg, setting); \
	else \
		setting = optarg;

	memset (&flags, 0, sizeof (flags));

	int c;
	while ((c = getopt_long (argc, argv, "c:fhp:t:u:V", opts, NULL)) != -1)
		switch (c)
		{

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

			case 't':
				ONETIME_SETTING (chrootdir);
				break;

			case 'V':
				return miredo_version ();

			case '?':
			default:
				return quick_usage (argv[0]);
		}

	if (optind < argc)
		servername = argv[optind++];

	if (optind < argc)
		return error_extra (argv[optind]);

#ifdef MIREDO_DEFAULT_USERNAME
	if (username == NULL)
		username = MIREDO_DEFAULT_USERNAME;
#else
	if (username != NULL)
		return error_extra (username);
#endif

	size_t str_len = 0;
	char *path = NULL;
	if (conffile == NULL)
	{
		path = br_find_etc_dir (SYSCONFDIR);
		str_len = strlen (path) + strlen (miredo_name)
		                        + sizeof ("/miredo/.conf");
	}

	char conffile_buf[str_len];
	if (conffile == NULL)
	{
		snprintf (conffile_buf, str_len, "%s/miredo/%s.conf", path,
		          miredo_name);
		free (path);
		conffile = conffile_buf;
	}

	/* Check if config file and chroot dir are present */
	if ((servername == NULL) && access (conffile, R_OK))
	{
		fprintf (stderr, _("Reading configuration from %s: %s\n"),
				conffile, strerror (errno));
		return 1;
	}

	if (chrootdir != NULL)
	{
		struct stat s;
		errno = 0;

		if (stat (chrootdir, &s) || !S_ISDIR(s.st_mode)
		 || access (chrootdir, X_OK))
		{
			if (errno == 0)
				errno = ENOTDIR;

			error_errno (chrootdir);
			return 1;
		}
	}
	miredo_chrootdir = chrootdir;

	if (pidfile == NULL)
		str_len = sizeof (LOCALSTATEDIR"/run/" ".pid") + strlen (miredo_name);
	else
		str_len = 0;

	char pidfile_buf[str_len];
	if (pidfile == NULL)
	{
		snprintf (pidfile_buf, str_len, LOCALSTATEDIR"/run/%s.pid",
		          miredo_name);
		pidfile = pidfile_buf;
	}

	if (init_security (username))
		return 1;

	if (miredo_diagnose ())
		return 1;

	/* Opens pidfile */
	int fd = open_pidfile (pidfile);
	if (fd == -1)
	{
		fprintf (stderr, _("Cannot create PID file %s:\n %s\n"),
		         pidfile, strerror (errno));
		if ((errno == EAGAIN) || (errno == EACCES))
			fprintf (stderr, "%s\n",
			         _("Please make sure another instance of the program is "
				   "not already running."));
		return -1;
	}

	/* Detaches */
	if (!flags.foreground && daemon (0, 0))
	{
		fprintf (stderr, _("Error (%s): %s\n"), "daemon", strerror (errno));
		return -1;
	}

	if (write_pid (fd))
	{
		close (fd);
		return -1;
	}

	/*
	 * Run
	 */
	c = miredo (conffile, servername, fd);

	close_pidfile (fd);
	(void)unlink (pidfile);

	return c ? 1 : 0;
}

