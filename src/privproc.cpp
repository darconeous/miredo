/*
 * privproc.cpp - Privileged process for Miredo
 * $Id: privproc.cpp,v 1.6 2004/08/28 12:07:23 rdenisc Exp $
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

	struct in6_addr oldter, newter;
	const struct in6_addr *p_oldloc, *p_newloc = &teredo_cone;

	/*
	 * TODO: fix this is a dirty kludge.
	 * But, it makes my life easier, and works on FreeBSD
	 * (which won't accept my routes through libtun6).
	 */
	memcpy (&newter, initial_addr, 16);
	seteuid (0);

	while (1)
	{
		tunnel.AddAddress (p_newloc, 64);
		if (memcmp (&newter, &in6addr_any, 16))
			tunnel.AddAddress (&newter, 32);
		// TODO: create a default route for client?
		seteuid (unpriv);

		p_oldloc = p_newloc;
		memcpy (&oldter, &newter, 16);

		do
			if (read (fd[0], &newter, 16) != 16)
				goto die;
		while (memcmp (&newter, &oldter, 16) == 0);

		p_newloc = IN6_IS_TEREDO_ADDR_CONE (&newter)
				? &teredo_cone : &teredo_restrict;

		seteuid (0);
		tunnel.DelAddress (p_oldloc, 64);
		if (memcmp (&oldter, &in6addr_any, 16))
			tunnel.DelAddress (&oldter, 32);
	}

die:
	seteuid (0);
	setuid (unpriv);

	close (fd[0]);
	// Release the tunnel device automatically:
	exit (0);
}

