/*
 * privproc.cpp - Privileged process for Miredo
 * $Id: privproc.cpp,v 1.4 2004/08/26 10:20:48 rdenisc Exp $
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

#include <string.h>
#include <stdlib.h> // exit()

#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>

#include <libtun6/ipv6-tunnel.h>
#include <libteredo/teredo.h>


int
miredo_privileged_process (IPv6Tunnel& tunnel,
				const struct in6_addr *initial_addr)
{
	uid_t unpriv = geteuid ();

	int fd[2];
	if (pipe (fd))
		return -1;

	switch (fork ())
	{
		case -1:
			close (fd[0]);
			close (fd[1]);
			return -1;

		case 0:
			close (fd[1]);
			break;

		default:
			close (fd[0]);
			return fd[1];
	}

	struct in6_addr oldter, oldloc;
	memcpy (&oldloc, &teredo_cone, sizeof (oldloc));
	/*
	 * TODO: fix this is a dirty kludge.
	 * But, it makes my life easier, and works on FreeBSD
	 * (which won't accept my routes through libtun6).
	 */
	memcpy (&oldter, initial_addr, sizeof (oldter));

	seteuid (0);
	tunnel.AddAddress (&oldloc, 64);
	tunnel.AddAddress (&oldter, 32);
	seteuid (unpriv);

	while (1)
	{
		struct in6_addr newter;

		if (read (fd[0], &newter, sizeof (newter)) != sizeof (newter))
			break;

		const struct in6_addr *p_newloc =
				IN6_IS_TEREDO_ADDR_CONE (&newter)
					? &teredo_cone : &teredo_restrict;

		if (memcmp (&oldloc, p_newloc, sizeof (oldloc)))
		{
			seteuid (0);
			tunnel.DelAddress (&oldloc, 64);
			tunnel.AddAddress (p_newloc, 64);
			seteuid (unpriv);

			memcpy (&oldloc, p_newloc, sizeof (oldloc));
		}

		if (memcmp (&oldter, &newter, sizeof (oldter)))
		{
			// TODO: create a default route for client?
			seteuid (0);
			if (memcmp (&oldter, &in6addr_any, sizeof (oldter)))
				tunnel.DelAddress (&oldter, 32);
			if (memcpy (&newter, &in6addr_any, sizeof (newter)))
				tunnel.AddAddress (&newter, 32);
			seteuid (unpriv);

			memcpy (&oldter, &newter, sizeof (oldter));
		}
	}

	seteuid (0);
	setuid (unpriv);

	close (fd[0]);
	// Release the tunnel device automatically:
	exit (0);
}

