/*
 * security.cpp - helpers for security-related stuff
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

#include <string.h>

#include <sys/types.h>
#include <fcntl.h> // open()
#include <unistd.h> // read(), close()
#include <syslog.h>

#include "security.h"

#ifndef HAVE_OPENBSD
static const char *randfile = "/dev/random";
#else
static const char *randfile = "/dev/srandom";
#endif
static const char *urandfile = "/dev/urandom";
static int devfd[2] = { -1, -1 };

static int
random_open (bool critical)
{
	int fd = open (critical ? randfile : urandfile, 0);
	if (fd == -1)
		syslog (LOG_ERR, _("Error opening %s: %m"),
			critical ? randfile : urandfile);

	return fd;
}


void
InitNonceGenerator (void)
{
	if (devfd[0] == -1)
		devfd[0] = random_open (true);
	if (devfd[1] == -1)
		devfd[1] = random_open (false);
}


void
DeinitNonceGenerator (void)
{
	if (devfd[0] != -1)
		(void)close (devfd[0]);

	if (devfd[1] != -1)
		(void)close (devfd[1]);
}


/*
 * Generates a random nonce value (8 bytes).
 * Thread-safe. Returns true on success, false on error
 */
bool
GenerateNonce (unsigned char *b, bool critical)
{
	int fd = devfd[critical ? 0 : 1];

	memset (b, 0, 8);
	if (fd != -1)
	{
		ssize_t tot = 0, val;

		do
		{
			val = read (fd, b + tot, 8 - tot);
			if (val <= 0)
				syslog (LOG_ERR, _("Error reading random data: %m"));
			else
				tot += val;
		}
		while ((tot < 8) && (val > 0));

		return tot == 8;
	}

	return false;
}

