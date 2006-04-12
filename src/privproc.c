/*
 * privproc.cpp - Privileged process for Miredo
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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
#include <stdlib.h> /* exit() */
#include <errno.h>

#if HAVE_STDINT_H
# include <stdint.h>
#elif HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h> // fcntl()
#if HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#include <libtun6/tun6.h>
#include <libteredo/teredo.h>

#include "privproc.h"

struct miredo_tunnel_settings
{
	struct in6_addr addr;
	uint16_t mtu;
};


int
miredo_privileged_process (struct tun6 *tunnel)
{
	int fd[2];
	if (socketpair (AF_LOCAL, SOCK_STREAM, 0, fd))
		return -1;

	fcntl (fd[0], F_SETFD, FD_CLOEXEC);
	fcntl (fd[1], F_SETFD, FD_CLOEXEC);

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

	tun6_bringUp (tunnel);

	for (;;)
	{
		struct miredo_tunnel_settings newcfg;
		int res = 0;

		/* Waits until new (changed) settings arrive */
		if (recv (fd[0], &newcfg, sizeof (newcfg), 0) != sizeof (newcfg))
			break;

		if (memcmp (&oldcfg.addr, &newcfg.addr, 16))
		{
			/* Removes old addresses */
			if (memcmp (&oldcfg.addr, &in6addr_any, 16))
			{
				tun6_delRoute (tunnel, &in6addr_any, 0, +5);
				tun6_delAddress (tunnel, &oldcfg.addr, 32);
			}

			/* Adds new addresses */
			if (memcmp (&newcfg.addr, &in6addr_any, 16))
			{
				const struct in6_addr *p_newloc;

				/* Only change link-local if needed */
				p_newloc = IN6_IS_TEREDO_ADDR_CONE (&newcfg.addr)
						? &teredo_cone : &teredo_restrict;
	
				if (p_newloc != p_oldloc)
				{
					if (p_oldloc != NULL)
						tun6_delAddress (tunnel, p_oldloc, 64);
					if (tun6_addAddress (tunnel, p_newloc, 64))
						res = -1;
					p_oldloc = p_newloc;
				}
	
				if (tun6_addAddress (tunnel, &newcfg.addr, 32)
				 || tun6_addRoute (tunnel, &in6addr_any, 0, +5))
					res = -1;
			}

			/* Saves address */
			memcpy (&oldcfg.addr, &newcfg.addr, sizeof (oldcfg.addr));
		}

		/* Updates MTU if needed */
		if (oldcfg.mtu != newcfg.mtu)
			tun6_setMTU (tunnel, oldcfg.mtu = newcfg.mtu);

		if (send (fd[0], &res, sizeof (res), 0) != sizeof (res))
			break;
	}

	close (fd[0]);

	/* Removes old addresses */
	if (memcmp (&oldcfg.addr, &in6addr_any, 16))
	{
		tun6_delRoute (tunnel, &in6addr_any, 0, +5);
		tun6_delAddress (tunnel, &oldcfg.addr, 32);
	}

	if (p_oldloc != NULL)
		tun6_delAddress (tunnel, p_oldloc, 64);

	tun6_bringDown (tunnel);
	tun6_destroy (tunnel);
	exit (0);
}


int
miredo_configure_tunnel (int fd, const struct in6_addr *addr, unsigned mtu)
{
	struct miredo_tunnel_settings s;
	int res;

	if (mtu > 65535)
	{
		errno = EINVAL;
		return -1;
	}

	memset (&s, 0, sizeof (s));
	memcpy (&s.addr, addr, sizeof (s.addr));
	s.mtu = (uint16_t)mtu;

	if ((send (fd, &s, sizeof (s), 0) != sizeof (s))
	 || (recv (fd, &res, sizeof (res), 0) != sizeof (res)))
		return -1;

	return res;
}
