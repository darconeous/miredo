/*
 * main.c - Unix Teredo server & relay implementation
 *          command line handling and core functions
 * $Id: main.c,v 1.11 2004/07/10 17:51:20 rdenisc Exp $
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright (C) 2004 Remi Denis-Courmont.                            *
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

#include <stdio.h>
#include <stdlib.h> /* strtoul(), clearenv(), daemon() on FreeBSD */
#include <inttypes.h>

#include <sys/types.h>
#include <sys/time.h> /* for <sys/resource.h> */
#include <sys/resource.h> /* getrlimit() */
#include <unistd.h>
#include <errno.h> /* errno */
#include <fcntl.h> /* O_RDONLY */

#include <pwd.h> /* getpwnam() */
#include <grp.h> /* setgroups() */

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#include "miredo.h"
#include "teredo.h"

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
	fputs (_("Try `miredo -h | more' for more information.\n"), stderr);
	return 2;
}


static int
usage (void)
{
        puts (_(
"Usage: miredo [OPTION]...\n"
"Creates a Teredo tunneling interface for encapsulation of IPv6.\n"
"\n"
"  -f, --foreground run in the foreground\n"
"  -h, --help       display this help and exit\n"
"  -i, --iface      define the Teredo tunneling interface name\n"
"  -p, --port       define the UDP port to be used by relay/client\n"
"  -P, --prefix     define the Teredo prefix to be used\n"
"  -s, --server     enable Teredo server,\n"
"                   and specify primary server IPv4 address\n"
"  -t, --chroot     override the chroot directory\n"
"  -u, --user       override the user to set UID to\n"
"  -V, --version    display program version and exit\n"));

	printf (_("Default Teredo prefix: %s:/32\n"),
		DEFAULT_TEREDO_PREFIX_STR);
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
"Duplicate parameter `%s' for option -%c\n"
"would override previous value `%s'.\n"),
		 additionnal, opt, already);
	return 2;
}


static int
error_qty (int opt, const char *qty)
{
	fprintf (stderr, _(
"Invalid number (or capacity exceeded) `%s' for option -%c\n"), qty, opt);
	return 2;
}


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
 * Initialize daemon security settings.
 *
 * We can't setuid to non-root yet. That's done later.
 */
static int
init_security (const char *username, const char *rootdir, int nodetach)
{
	struct passwd *pw;
	struct rlimit lim;
	int fd;

	if (username == NULL)
		username = "miredo"; // default user name

	/* Clears environment */
	clearenv ();

	/*
	 * We close all file handles, except 0, 1 and 2.
	 * Those last 3 handles will be opened as /dev/null
	 * by later daemon().
	 */
	if (getrlimit (RLIMIT_NOFILE, &lim))
		return -1;

	for (fd = 3; fd < lim.rlim_cur; fd++)
		close (fd);

	/*
	 * Make sure that 0, 1 and 2 are opened.
	 * If it were not the case, we'd have daemon() close our internal
	 * handles, which we definitely don't want.
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

	close (fd); // fd > 2

	/* Unpriviledged user (step 1) */
	errno = 0;
	pw = getpwnam (username);
	if (pw == NULL)
	{
		if (errno)
			perror ("getpwnam");
		else
			fprintf (stderr, _("User not found: %s\n"),
					username);
		return -1;
	}

	/* Unpriviledged group */
	errno = 0;
	if (setgid  (pw->pw_gid) || setgroups (0, NULL))
	{
		perror (_("SetGID to unpriviledged group"));
		return -1;
	}

	/* Changes root directory */
	if (rootdir == NULL)
		rootdir = pw->pw_dir;
	if (chroot (rootdir))
	{
		perror (_("Root directory jail"));
		return -1;
	}

	/* 
	 * Sets current directory to '/' in the chroot
	 * and re-open 0, 1 and 2 from the chroot, so fchdir cannot break the
	 * jail.
	 */
	if (!nodetach && daemon (0, 0))
	{
		perror (_("Switching to background mode"));
		return -1;
	}

	/* Unpriviledged user (step 2) */
	if (seteuid (pw->pw_uid))
	{
		perror (_("SetUID to unpriviledged user"));
		return -1;
	}

	unpriv_uid = pw->pw_uid;

	return 0;
}


int
main (int argc, char *argv[])
{
	const char *server = NULL, *prefix = NULL, *ifname = NULL,
			*username = NULL, *rootdir = NULL;
	uint16_t client_port = 0;
	int foreground = 0;
	
	const struct option opts[] =
	{
		//{ "config",	required_argument,	NULL, 'c' },
		{ "foreground",	no_argument,		NULL, 'f' },
		{ "help",	no_argument,		NULL, 'h' },
		{ "iface",	required_argument,	NULL, 'i' },
		{ "interface",	required_argument,	NULL, 'i' },
		{ "port",	required_argument,	NULL, 'p' },
		{ "prefix",	required_argument,	NULL, 'P' },
		{ "server",	required_argument,	NULL, 's' },
		{ "chroot",	required_argument,	NULL, 't' },
		{ "user",	required_argument,	NULL, 'u' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL,		no_argument,		NULL, '\0'}
	};

	int c;

#define ONETIME_SETTING( setting ) \
	if (setting != NULL) \
		return error_dup (c, optarg, setting); \
	else \
		setting = optarg;

	while ((c = getopt_long (argc, argv, "fhi:p:P:r:s:t:u:V", opts, NULL))
			!= -1)
		switch (c)
		{
			case '?':
				return quick_usage ();

			case 'f':
				foreground = 1;
				break;

			case 'h':
				return usage ();

			case 'i':
				ONETIME_SETTING (ifname);
				break;

			case 'p':
			{
				unsigned long l;
				char *end;

				l = strtoul (optarg, &end, 0);
				if ((*end != '\0') || (l == 0)
				 || (l > 65535))
					return error_qty (c, optarg);
				if (client_port != 0)
				{
					char buf[6];
					snprintf (buf, 6, "%u",
						  (unsigned)client_port);
					buf[5] = 0;
					return error_dup (c,  optarg, buf);
				}
				client_port = (uint16_t)l;
			}
				break;
				
			case 'P':
				ONETIME_SETTING (prefix);
				break;

			case 's':
				ONETIME_SETTING (server);
				break;

			case 't':
				ONETIME_SETTING (rootdir);
				break;

			case 'u':
				ONETIME_SETTING (username);
				break;

			case 'V':
				return version ();

			default:
				fprintf (stderr, _(
"Returned unknown option -%c :\n"
"That is probably a bug. Please report it.\n"), c);
				return 1;
		}

	if (optind < argc)
		return error_extra (argv[optind]);

	if (init_security (username, rootdir, foreground))
		return 1;

	if (miredo (client_port, server, prefix, ifname))
		return 1;
	else
		return 0;
}

