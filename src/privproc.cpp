/*
 * privproc.cpp - Privileged process for Miredo
 * $Id$
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
#if HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libtun6/ipv6-tunnel.h>
#include <libteredo/teredo.h>


int
miredo_privileged_process (IPv6Tunnel& tunnel, bool default_route)
{
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

#ifdef HAVE_LIBCAP
	{
		cap_t s;
		cap_value_t v = CAP_NET_ADMIN;

		s = cap_init ();
		if (s == NULL)
			exit (1);

		if (cap_set_flag (s, CAP_PERMITTED, 1, &v, CAP_SET)
		 || cap_set_flag (s, CAP_EFFECTIVE, 1, &v, CAP_SET)
		 || cap_set_proc (s))
		{
			cap_free (s);
			exit (1);
		}
		cap_free (s);
	}
#endif

	struct in6_addr oldter;
	const struct in6_addr *p_oldloc = NULL;

	memcpy (&oldter, &in6addr_any, 16);

	while (1)
	{
		struct in6_addr newter;
		const struct in6_addr *p_newloc;

		do
			if (read (fd[0], &newter, 16) != 16)
				goto die;
		while (memcmp (&newter, &oldter, 16) == 0);

		p_newloc = IN6_IS_TEREDO_ADDR_CONE (&newter)
				? &teredo_cone : &teredo_restrict;

		if (memcmp (&oldter, &in6addr_any, 16))
		{
			if (default_route)
				tunnel.DelRoute (&in6addr_any, 0);
			tunnel.DelAddress (&oldter, 32);
			tunnel.DelAddress (p_oldloc, 64);
		}
		else
			tunnel.BringUp ();

		if (memcmp (&newter, &in6addr_any, 16))
		{
			tunnel.AddAddress (p_newloc, 64);
			tunnel.AddAddress (&newter, 32);
			if (default_route)
				tunnel.AddRoute (&in6addr_any, 0);
		}
		else
			tunnel.BringDown ();

		p_oldloc = p_newloc;
		memcpy (&oldter, &newter, 16);
	}

die:
	close (fd[0]);
	tunnel.CleanUp ();
	exit (0);
}

