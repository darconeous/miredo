/*
 * privproc.cpp - Privileged process for Miredo
 * $Id: privproc.cpp,v 1.1 2004/07/31 20:15:07 rdenisc Exp $
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

#include <string.h> // memcpy(), memcmp()
#include <stdlib.h> // exit()

#include <sys/types.h>
#include <unistd.h> // read(), close()

#include <libtun6/ipv6-tunnel.h>
#include <libteredo/teredo.h>

void
miredo_privileged_process (int fd, IPv6Tunnel& tunnel, uid_t unpriv)
{
	union teredo_addr ter_addr, loc_addr;

	while (1)
	{
		union teredo_addr newaddr;

		seteuid (unpriv);
		if (read (fd, &newaddr, sizeof (newaddr)) != sizeof (newaddr))
			break;

		if (!memcmp (&ter_addr, &newaddr, sizeof (ter_addr)))
			continue;

		seteuid (0);
		tunnel.DelAddress (&ter_addr.ip6);
		tunnel.DelAddress (&loc_addr.ip6);

		memcpy (&ter_addr, &newaddr, sizeof (ter_addr));
		memcpy (&loc_addr,
			in6_is_teredo_addr_cone (&newaddr)
			? &teredo_cone : &teredo_restrict, sizeof (loc_addr));

		tunnel.AddAddress (&loc_addr.ip6);
		if (newaddr.teredo.prefix)
			tunnel.AddAddress (&ter_addr.ip6);
	}

	close (fd);
	exit (0);
}

