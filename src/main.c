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

#include <stdio.h>
#include <stdlib.h> /* strtoul(), clearenv() */
#include <string.h> /* strerrno() */
#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <locale.h>

#include <sys/types.h>
#include <sys/time.h> /* for <sys/resource.h> */
#include <sys/resource.h> /* getrlimit() */
#include <sys/stat.h> /* fstat() */
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
#include <libteredo/teredo.h>
#include <libtun6/ipv6-tunnel.h>

/*#include "host.h"*/

/*
 * RETURN VALUES:
 * 0: ok
 * 1: I/O error
 * 2: command line syntax error
 */

static int
quick_usage (void)
{
	fputs (_("Try \"miredo -h | more\" for more information.\n"), stderr);
	return 2;
}


static int
usage (void)
{
	puts (_(
"Usage: miredo [OPTIONS]\n"
"Creates a Teredo tunneling interface for encapsulation of IPv6 over UDP.\n"
"\n"
"  -f, --foreground run in the foreground\n"
"  -h, --help       display this help and exit\n"
"  -p, --pidfile    override the pidfile path\n"
"  -u, --user       override the user to set UID to\n"
"  -V, --version    display program version and exit\n"));
	return 0;
}


static int
version (void)
{
#ifndef VERSION
# define VERSION "unknown version"
#endif
 	puts (
"Miredo : Teredo IPv6 tunneling software "VERSION/*" ("PACKAGE_HOST")"*/"\n"
" built "__DATE__" on "PACKAGE_BUILD_HOSTNAME/*" ("PACKAGE_BUILD")"*/"\n"
"Copyright (C) 2004 Remi Denis-Courmont");
	puts (_(
"This is free software; see the source for copying conditions.\n"
"There is NO warranty; not even for MERCHANTABILITY or\n"
"FITNESS FOR A PARTICULAR PURPOSE.\n"));
	printf (_("Written by %s.\nConfigured with: %s\n"),
		"Remi Denis-Courmont", PACKAGE_CONFIGURE_INVOCATION);
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


static FILE *
safe_fopen_w (const char *path)
{
	int fd;

	unlink (path);
	fd = open (path, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (fd != -1)
	{
		struct stat s;

		if (fstat (fd, &s) == 0)
		{
			if (S_ISREG(s.st_mode))
			{
				FILE *stream;

				stream = fdopen (fd, "w");
				if (stream != NULL)
					return stream;
			}
		}
		close (fd);
	}
	return NULL;
}


/*
 * Creates a Process-ID file.
 */
static int
create_pidfile (const char *path)
{
	FILE *stream;
	int retval = -1;

	stream = safe_fopen_w (path);
	if (stream != NULL)
	{
		if (fprintf (stream, "%d", (int)getpid ()) >= 0)
			retval = 0;

		fclose (stream);
	}
	return retval;
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
 * Initialize daemon security settings.
 */
static int
init_security (const char *username, int nodetach)
{
	struct passwd *pw;
	struct rlimit lim;
	int fd;

	/* Clears environment */
	(void)clearenv ();

	/*
	 * We close all file handles, except 0, 1 and 2.
	 * Those last 3 handles will be opened as /dev/null
	 * by later daemon().
	 */
	if (getrlimit (RLIMIT_NOFILE, &lim))
		return -1;

	for (fd = 3; fd < lim.rlim_cur; fd++)
		(void)close (fd);

	/*
	 * Make sure that 0, 1 and 2 are opened.
	 */
	fd = open ("/dev/null", O_RDWR);
	if (fd == -1)
		return -1;
	
	while (fd <= 2)
	{
		fd = dup (fd);
		if (fd == -1)
			return -1;
	}

	(void)close (fd); // fd > 2

	/* From then on, it is safe to write to stderr */

	/* Unpriviledged user (step 1) */
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

	if (pw->pw_uid == 0)
	{
		fputs (_("Error: This program is not supposed to keep root\n"
			"privileges. That is potentially very dangerous\n"
			"(all the more as it is beta quality code that has\n"
			"never been audited for security vulnerabilities).\n"
			"Besides, it does not even work properly when root\n"
			"privileges are kept.\n"), stderr);
		return -1;
	}

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
	setgroups (0, NULL);

	/* Unpriviledged user (step 2) */
	if (setreuid (unpriv_uid, -1) || seteuid (unpriv_uid))
	{
		fprintf (stderr, _("SetUID to user ID %u: %s\n"),
				(unsigned)unpriv_uid, strerror (errno));
		fputs (_("Error: This program tried to change its system\n"
			"user security context but it failed.\n"), stderr);
		setuid_notice ();
		return -1;
	}
	/* Real and effective UIDs are set; only saved UID is 0. */

	/* POSIX.1e capabilities support */
#ifdef HAVE_LIBCAP
	{
		cap_t s;
		cap_value_t v[] =
		{
			CAP_SYS_CHROOT,
			CAP_SETUID,
			CAP_NET_ADMIN
		};

		s = cap_init ();
		if (s == NULL)
		{
			/* Unlikely */
			perror (_("Fatal error"));
			return -1;
		}

		if (cap_set_flag (s, CAP_PERMITTED, 3, v, CAP_SET))
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

	/* 
	 * Detaches. This is not really a security thing, but it is simpler to
	 * do it now.
	 */
	if (!nodetach && daemon (0, 0))
	{
		perror (_("Error (daemon)"));
		return -1;
	}

	return 0;
}


static int
check_libtun6 (void)
{
	char errbuf[LIBTUN6_ERRBUF_SIZE];
	if (libtun6_driver_diagnose (errbuf))
	{
		fputs (errbuf, stderr);
		return -1;
	}

	return 0;
}



#ifndef MIREDO_DEFAULT_CONFFILE
# define MIREDO_DEFAULT_CONFFILE SYSCONFDIR "/miredo.conf"
#endif
#ifndef MIREDO_DEFAULT_USERNAME
# define MIREDO_DEFAULT_USERNAME "nobody"
#endif


int
main (int argc, char *argv[])
{
	const char *username = NULL, *conffile = NULL, *pidfile = NULL;
	struct
	{
		unsigned foreground:1; /* Run in the foreground */
	} flags;

	const struct option opts[] =
	{
		{ "conf",	required_argument,	NULL, 'c' },
		{ "config",	required_argument,	NULL, 'c' },
		{ "foreground",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "pidfile",	required_argument,	NULL, 'p' },
		{ "user",	required_argument,	NULL, 'u' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL,		no_argument,		NULL, '\0'}
	};

	int c;

        setlocale (LC_ALL, "");
        bindtextdomain (PACKAGE, LOCALEDIR);
        textdomain (PACKAGE);

#define ONETIME_SETTING( setting ) \
	if (setting != NULL) \
		return error_dup (c, optarg, setting); \
	else \
		setting = optarg;

	memset (&flags, 0, sizeof (flags));

	while ((c = getopt_long (argc, argv, "c:fhp:t:u:Vv", opts,
					NULL)) != -1)
		switch (c)
		{
			case '?':
				return quick_usage ();

			case 'c':
				ONETIME_SETTING (conffile);
				break;

			case 'f':
				flags.foreground = 1;
				break;

			/*TODO: case 'g' as in BIND */

			case 'h':
				return usage ();

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
"Read unknown option -%c :\n"
"That is probably a bug. Please report it.\n"), c);
				return 1;
		}

	if (optind < argc)
		return error_extra (argv[optind]);

	if (username == NULL)
		username = MIREDO_DEFAULT_USERNAME;

	if (conffile == NULL)
		conffile = MIREDO_DEFAULT_CONFFILE;

	if (access (conffile, R_OK))
	{
		fprintf (stderr, _("Reading configuration from %s: %s\n"),
				conffile, strerror (errno));
		return 1;
	}

	if (check_libtun6 () || init_security (username, flags.foreground))
		return 1;

#ifdef MIREDO_DEFAULT_PIDFILE
	if (pidfile == NULL)
		pidfile = MIREDO_DEFAULT_PIDFILE;
#endif

	if (pidfile != NULL)
	{
		seteuid (0);
		/*
		 * I purposedly don't check create_pidfile for error.
		 * If the sysadmin fails to setup a directory properly for the
		 * pidfile, I'd rather make its initscript's stop function
		 * fail than deny the service completely.
		 */
		create_pidfile (pidfile);
		seteuid (unpriv_uid);
	}

	/*
	 * Run
	 */
	c = miredo (conffile);

	if (pidfile != NULL)
	{
		seteuid (0);
		unlink (pidfile);
		seteuid (unpriv_uid);
	}


	return c ? 1 : 0;
}

