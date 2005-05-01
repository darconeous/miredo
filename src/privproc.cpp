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
#include <errno.h>

#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#if HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libtun6/ipv6-tunnel.h>
#include <libteredo/teredo.h>


struct miredo_tunnel_settings
{
	struct in6_addr addr;
	uint16_t mtu;
};

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

	struct miredo_tunnel_settings oldcfg;
	const struct in6_addr *p_oldloc = NULL;

	memcpy (&oldcfg.addr, &in6addr_any, sizeof (oldcfg.addr));
	oldcfg.mtu = 0;

	tunnel.BringUp ();

	while (1)
	{
		struct miredo_tunnel_settings newcfg;
		const struct in6_addr *p_newloc;

		/* Waits until new (changed) settings arrive */
		do
			if (read (fd[0], &newcfg, sizeof (newcfg)) != sizeof (newcfg))
				goto die;
		while (memcmp (&newcfg, &oldcfg, sizeof (newcfg)) == 0);

		/* Unapplies old settings */
		if (memcmp (&oldcfg.addr, &in6addr_any, 16))
		{
			if (default_route)
				tunnel.DelRoute (&in6addr_any, 0);
			tunnel.DelAddress (&oldcfg.addr, 32);
		}

		/* Applies new settings */
		if (memcmp (&newcfg.addr, &in6addr_any, 16))
		{
			/* Updates MTU if needed */
			if (oldcfg.mtu != newcfg.mtu)
				tunnel.SetMTU (oldcfg.mtu = newcfg.mtu);

			/* Adds new addresses */
			p_newloc = IN6_IS_TEREDO_ADDR_CONE (&newcfg.addr)
					? &teredo_cone : &teredo_restrict;

			if (p_newloc != p_oldloc)
			{
				if (p_oldloc != NULL)
					tunnel.DelAddress (p_oldloc, 64);
				tunnel.AddAddress (p_newloc, 64);
				p_oldloc = p_newloc;
			}

			tunnel.AddAddress (&newcfg.addr, 32);
			if (default_route)
				tunnel.AddRoute (&in6addr_any, 0);

			/* Saves address */
			memcpy (&oldcfg.addr, &newcfg.addr, sizeof (oldcfg.addr));
		}
	}

die:
	close (fd[0]);
	tunnel.BringDown ();
	tunnel.CleanUp ();
	exit (0);
}


int
miredo_configure_tunnel (int fd, const struct in6_addr *addr, unsigned mtu)
{
	struct miredo_tunnel_settings s;

	if (mtu > 65535)
	{
		errno = EINVAL;
		return -1;
	}

	memcpy (&s.addr, addr, sizeof (s.addr));
	s.mtu = mtu;

	return write (fd, &s, sizeof (s)) == sizeof (s) ? 0 : -1;
}
