/*
 * main.c - Unix Teredo server & relay implementation
 *          command line handling and core functions
 * $Id: main.c,v 1.1 2004/06/14 21:52:32 rdenisc Exp $
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

#include <sys/types.h>
#include <sys/resource.h> /* getrlimit() */
#include <unistd.h>
#include <errno.h> /* errno */
#include <pwd.h> /* getpwnam() */
#include <grp.h> /* getgrnam() */

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
"Usage: miredo [OPTION]... <IPv6 address/hostname>\n"
"Creates a Teredo tunneling interface for encapsulation of IPv6.\n"
"\n"
"  -h, --help     display this help and exit\n"
"  -i, --iface    define the Teredo tunneling interface name\n"
"  -P, --prefix   define the Teredo prefix to be used\n"
"  -r, --relay    enable Teredo relay,\n"
"                  and specify relay IPv4 address\n"
"  -s, --server   enable Teredo server,\n"
"                  and specify primary server IPv4 address\n"
"  -T, --tundev   override tunnel device file\n"
"  -V, --version  display program version and exit\n"));

	printf (_("Default Teredo prefix: %s\n"), TEREDO_PREFIX_STR);
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
error_dup (char opt, const char *already, const char *additionnal)
{
	fprintf (stderr, _(
"Duplicate parameter `%s' for option -%c\n"
"would override previous value `%s'.\n"),
		 additionnal, opt, already);
	return 2;
}


static int
error_extra (const char *extra)
{
	fprintf (stderr, _("%s: unexpected extra parameter\n"), extra);
	return 2;
}


static int
error_missing (void)
{
	fputs (_("Error: missing command line parameter\n"), stderr);
	return 2;
}


int init_security (void)
{
	struct passwd *pw;
	struct group *grp;
	struct rlimit lim;
	int i;
	extern uid_t unpriv_uid;

	/*
	 * We close all file handles except 0, 1 and 2, which we use
	 * before calling daemon(), and which daemon will re-open as
	 * /dev/null later.
	 */
	if (getrlimit (RLIMIT_NOFILE, &lim))
	{
		perror ("getrlimit(RLIMIT_NOFILE)");
		return -1;
	}
	
	for (i = 3; i < lim.rlim_cur; i++)
		close (i);

#ifdef MIREDO_UNPRIV_GROUP
	/* Unpriviledged group */
	errno = 0;
	grp = getgrnam (MIREDO_UNPRIV_GROUP);
	if (grp == NULL)
	{
		if (errno)
			perror ("getgrnam(\""MIREDO_UNPRIV_GROUP"\")");
		else
			fprintf (stderr, _("Group not found: %s\n"),
					MIREDO_UNPRIV_GROUP);

		return -1;
	}
	
	if (setgid  (grp->gr_gid))
	{
		perror (_("SetGID to unpriviledged group"));
		return -1;
	}
#endif

#ifdef MIREDO_UNPRIV_USER
	/* Unpriviledged user */
	errno = 0;
	pw = getpwnam (MIREDO_UNPRIV_USER);
	if (pw == NULL)
	{
		if (errno)
			perror ("getpwnam(\""MIREDO_UNPRIV_USER"\")");
		else
			fprintf (stderr, _("User not found: %s\n"),
					MIREDO_UNPRIV_USER);
		return -1;
	}
	
	if (seteuid (pw->pw_uid))
	{
		perror (_("SetUID to unpriviledged user"));
		return -1;
	}

	unpriv_uid = pw->pw_uid;
#else
	unpriv_uid = getuid ();
	seteuid (unpriv_uid);
#endif

	return 0;
}


int
main (int argc, char *argv[])
{
	const char *server = NULL, *relay = NULL,
		*prefix = NULL, *ifname = NULL, *tundev = NULL;
	const char *ipv6;
	
	const struct option longopts[] =
	{
		{ "help",	no_argument,		NULL, 'h' },
		{ "iface",	required_argument,	NULL, 'i' },
		{ "interface",	required_argument,	NULL, 'i' },
		//{ "port",	required_argument,	NULL, 'p' },
		{ "prefix",	required_argument,	NULL, 'P' },
		{ "relay",	required_argument,	NULL, 'r' },
		{ "server",	required_argument,	NULL, 's' },
		{ "tundev",	required_argument,	NULL, 'T' },
		{ "version",	no_argument,		NULL, 'V' },
		{ NULL,		no_argument,		NULL, '\0'}
	};

	int c;
	
	if (init_security ())
		return 1;

#define ONETIME_SETTING( setting ) \
	if (setting != NULL) \
		return error_dup (c, optarg, setting); \
	else \
		setting = optarg;

	while ((c = getopt_long (argc, argv, "hi:P:r:s:T:V", longopts, NULL))
			!= -1)
		switch (c)
		{
			case '?':
				return quick_usage ();

			case 'h':
				return usage ();

			case 'i':
				ONETIME_SETTING (ifname);
				break;

			case 'P': /* FIXME: */
				fputs ("-P option is NOT SUPPORTED YET\n", stderr);
				ONETIME_SETTING (prefix);
				break;

			case 'r':
				ONETIME_SETTING (relay);
				break;

			case 's':
				ONETIME_SETTING (server);
				break;

			case 'T':
				ONETIME_SETTING (tundev);
				break;

			case 'V':
				return version ();

			default:
				fprintf (stderr, _(
"Returned unknown option -%c :\n"
"That is probably a bug. Please report it.\n"), c);
				return 1;
		}

	if (optind >= argc) /* no more arguments ! */
		return error_missing ();
	else
		ipv6 = argv[optind++];

	if (optind < argc)
		return error_extra (argv[optind]);

	
	return miredo_run (ipv6, relay, server, prefix, ifname, tundev)
		? 1
		: 0;
}
