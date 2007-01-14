/*
 * privproc.c - Privileged process and IPC for Miredo
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <string.h>
#include <stdlib.h> /* exit() */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h> /* waitpid() */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* if_indextoname() */
#ifndef IFNAMESIZE
# define IFNAMESIZE IFNAMSIZ
#endif
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#ifndef AF_LOCAL
# define AF_LOCAL AF_UNIX
#endif

#include <libtun6/tun6.h>
#include <libteredo/teredo.h>

#include "miredo.h"
#include "privproc.h"

struct miredo_tunnel_settings
{
	struct in6_addr addr;
	uint16_t mtu;
};


static const char script_path[] = SYSCONFDIR"/miredo/client-hook";

/**
 * Runs the hook script.
 * @return the script exit status, or -1 in case of error.
 */
static int run_script (void)
{
	pid_t pid = fork ();

	switch (pid)
	{
		case -1:
			return -1;

		case 0:
			execl (script_path, script_path, (char *)NULL);
			exit (1);
	}

	int res;
	while (waitpid (pid, &res, 0) == -1);

	if (WIFEXITED (res))
		return WEXITSTATUS (res);

	return -1;
}


int
miredo_privileged_process (unsigned ifindex,
                           void (*clean_cb) (void *), void *opaque)
{
	char intbuf[21];
	if ((size_t)snprintf (intbuf, sizeof (intbuf), "%u", ifindex)
	             >= sizeof (intbuf))
		return -1;

	int fd[2];
	if (socketpair (AF_LOCAL, SOCK_SEQPACKET, 0, fd)
	 && socketpair (AF_LOCAL, SOCK_DGRAM, 0, fd))
		return -1;

	miredo_setup_fd (fd[0]);
	miredo_setup_fd (fd[1]);

	switch (fork ())
	{
		case -1:
			close (fd[0]);
			close (fd[1]);
			return -1;

		case 0:
			clean_cb (opaque);
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

	setenv ("IFINDEX", intbuf, 1);

	setenv ("OLD_STATE", "down", 1);
	unsetenv ("OLD_ADDRESS");
	unsetenv ("OLD_LLADDRESS");
	unsetenv ("OLD_MTU");

	for (;;)
	{
		struct miredo_tunnel_settings cfg;
		int res = -1;

		/* Waits until new (changed) settings arrive */
		if (recv (fd[0], &cfg, sizeof (cfg), 0) != sizeof (cfg))
			break;

		/* Prepare environment for hook script */
		char addr[INET6_ADDRSTRLEN], lladdr[INET6_ADDRSTRLEN];
		if (memcmp (&cfg.addr, &in6addr_any, sizeof (in6addr_any)))
		{
			setenv ("STATE", "up", 1);
			inet_ntop (AF_INET6, &cfg.addr, addr, sizeof (addr));
			setenv ("ADDRESS", addr, 1);

			inet_ntop (AF_INET6, IN6_IS_TEREDO_ADDR_CONE (&cfg.addr)
			            ? &teredo_cone : &teredo_restrict,
			           lladdr, sizeof (lladdr));
			setenv ("LLADDRESS", lladdr, 1);

			snprintf (intbuf, sizeof (intbuf), "%u", (unsigned)cfg.mtu);
			setenv ("MTU", intbuf, 1);
		}
		else
		{
			setenv ("STATE", "down", 1);
			unsetenv ("ADDRESS");
			unsetenv ("LLADDRESS");
			unsetenv ("MTU");
		}

		char iface[IFNAMESIZE];
		if (if_indextoname (ifindex, iface) == NULL)
			goto error;
		setenv ("IFACE", iface, 1);

		/* Run hook script */

		res = run_script ();

		/* Notify main process of completion */
	error:
		if (send (fd[0], &res, sizeof (res), 0) != sizeof (res))
			break;

		/* Prepend "OLD_" to variables names for next script invocation */
		if (memcmp (&cfg.addr, &in6addr_any, sizeof (in6addr_any)))
		{
			setenv ("OLD_STATE", "up", 1);
			setenv ("OLD_ADDRESS", addr, 1);
			setenv ("OLD_LLADDRESS", lladdr, 1);
			setenv ("OLD_MTU", intbuf, 1);
		}
		else
		{
			setenv ("OLD_STATE", "down", 1);
			unsetenv ("OLD_ADDRESS");
			unsetenv ("OLD_LLADDRESS");
			unsetenv ("OLD_MTU");
		}
	}

	close (fd[0]);

	/* Run script for the last time */
	char iface[IFNAMESIZE];
	if (if_indextoname (ifindex, iface) != NULL)
	{
		setenv ("STATE", "down", 1);
		unsetenv ("ADDRESS");
		unsetenv ("LLADDRESS");
		unsetenv ("MTU");
		setenv ("IFACE", iface, 1);

		run_script ();
	}

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
