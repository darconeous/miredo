/*
 * diag.c - IPv6 tunnel diagnostic functions
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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

#include <assert.h>

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h> // socket(AF_INET6, SOCK_DGRAM, 0)
#include <libtun6/tun6.h>

extern const char os_driver[];

/**
 * Checks if libtun6 should be able to tun on system.
 *
 * @param errbuf a buffer of at least LIBTUN6_ERRBUF_SIZE bytes
 * to hold an error message suitable for the user attention.
 * Also set on success.
 *
 * @return 0 on success, -1 if the system seems inadequate.
 */
int tun6_driver_diagnose (char *errbuf)
{
	(void)bindtextdomain (PACKAGE_NAME, LOCALEDIR);

	int fd = socket (AF_INET6, SOCK_DGRAM, 0);
	if (fd == -1)
	{
		strlcpy (errbuf, "Error: IPv6 stack not available.\n",
		         LIBTUN6_ERRBUF_SIZE - 1);
		errbuf[LIBTUN6_ERRBUF_SIZE - 1] = '\0';
		return -1;
	}
	(void)close (fd);

#if defined (__linux__)
	const char tundev[] = "/dev/net/tun";

	fd = open (tundev, O_RDWR);
	if (fd != -1)
	{
		(void)close (fd);
		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
		          "%s tunneling driver found.", os_driver);
		return 0;
	}

	switch (errno)
	{
		case ENOENT:
			snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
			          _("Error: %s character device "
			            "not found or unavailable.\n%s"), tundev,
			          _("You might try to run this command to load it:\n"
			            "$ modprobe tun\n"
			            "(you must be root to do that).\n"));
			return -1;
		case ENXIO:
		case ENODEV: /* Linux returns ENODEV instead of ENXIO */
			snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
			          _("Error: your operating system does not "
			            "seem to provide a network tunneling\n"
			            "device driver, which is required.\n%s"),
			          _("Make sure your Linux kernel includes "
			            "the \"Universal TUNTAP driver\"\n"
			            "(CONFIG_TUN option), possibly as a module.\n"));
			return -1;
	}
#else
	const char tundev[] = "/dev/tun0";
	struct stat st;

	if (stat (tundev, &st) == 0)
	{
		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
		          "%s tunneling driver found.", os_driver);
		return 0;
	}

	if (errno == ENOENT)
	{
		const char *specific;

# if defined (__APPLE__)
		specific = N_("You can obtain a tunnel driver for the "
			"Darwin kernel (Mac OS X) from:\n"
			"http://www-user.rhrk.uni-kl.de/~nissler/tuntap/\n");
# elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
		specific = N_("You might try to run this command to load it:\n"
			"$ kldload if_tun\n"
			"(you must be root to do that).\n");
# else
		specific = NULL;
# endif

		snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
			_("Error: %s character device "
			"not found or unavailable.\n%s"), tundev,
			specific != NULL ? dgettext (PACKAGE_NAME, specific) : "");
		return -1;
	}
#endif

	/* FIXME: use strerror_l() instead? */
	char buf[256]; /* Hopefully big enough... :-/ */
	strerror_r (errno, buf, sizeof (buf));
	snprintf (errbuf, LIBTUN6_ERRBUF_SIZE,
		_("Error: cannot open device file %s (%s)\n"
		"IPv6 tunneling will not work.\n"), tundev, buf);
	return -1;
}
