/*
 * security.cpp - helpers for security-related stuff
 * $Id: packets.h 137 2004-08-30 12:07:43Z remi $
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

#include <gettext.h>

#include <sys/types.h>
#include <fcntl.h> // open()
#include <unistd.h> // read(), close()
#include <syslog.h>

#include "security.h"

/*
 * Generates a random nonce value (8 bytes).
 * Thread-safe. Returns true on success, false on error
 */
bool GenerateNonce (unsigned char *b, bool critical)
{
	const char *dev = critical ? "/dev/random" : "/dev/urandom";

	int fd = open (dev, 0);
	if (fd != -1)
	{
		ssize_t tot = 0, val;

		do
		{
			val = read (fd, b + tot, 8 - tot);
			if (val <= 0)
				syslog (LOG_ERR, _("Error reading %s: %m"),
					dev);
			else
				tot += val;
		}
		while ((tot < 8) && (val > 0));

		close (fd);

		return tot == 8;
	}
	syslog (LOG_ERR, _("Error opening %s: %m"), dev);

	return false;
}

