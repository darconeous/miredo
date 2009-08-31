/*
 * privproc.c - Privileged process and IPC for Miredo
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
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

#include <string.h>
#include <stdlib.h> /* exit() */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <syslog.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h> /* waitpid() */
#include <arpa/inet.h> /* inet_ntop() */
#include <net/if.h> /* if_indextoname() */
#include <signal.h> /* sigemptyset() */
#include <pthread.h> /* pthread_sigmask() */
#include <netinet/in.h> /* needed by teredo.h */
#ifndef IFNAMESIZE
# define IFNAMESIZE IFNAMSIZ
#endif
#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif
#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0 /* Uho */
#endif

#include <libteredo/teredo.h>

#include "miredo.h"
#include "privproc.h"

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
		{
			sigset_t emptyset;
			sigemptyset (&emptyset);
			pthread_sigmask (SIG_SETMASK, &emptyset, NULL);

			if (dup2 (2, 0) == 0 && dup2 (2, 1) == 1)
				execl (script_path, script_path, (char *)NULL);

			syslog (LOG_ERR, "Could not execute %s: %s",
			        script_path, strerror (errno));
			exit (1);
		}
	}

	int res;
	while (waitpid (pid, &res, 0) == -1);

	if (WIFEXITED (res))
		return WEXITSTATUS (res);

	return -1;
}


int main (int argc, char *argv[])
{
	openlog ("miredo-privproc", LOG_PID | LOG_PERROR, LOG_DAEMON);

	if (argc != 2)
		exit (1);

	unsigned ifindex = strtoul (argv[1], NULL, 0x10);
	if (ifindex == 0)
		exit (1);

	char intbuf[21];
	if ((size_t)snprintf (intbuf, sizeof (intbuf), "%u", ifindex)
	             >= sizeof (intbuf))
		exit (1);

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
		if (recv (0, &cfg, sizeof (cfg), MSG_WAITALL) != sizeof (cfg))
			break;

		/* Sanity checks */
		if ((cfg.addr.s6_addr[0] == 0xff) || (cfg.mtu < 1280))
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

			snprintf (intbuf, sizeof (intbuf), "%"PRIu16, cfg.mtu);
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
		if (send (1, &res, sizeof (res), MSG_NOSIGNAL) != sizeof (res))
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

	/* Run scripts for the last time */
	char iface[IFNAMESIZE];
	if (if_indextoname (ifindex, iface) != NULL)
	{
		setenv ("STATE", "down", 1);
		unsetenv ("ADDRESS");
		unsetenv ("LLADDRESS");
		unsetenv ("MTU");
		setenv ("IFACE", iface, 1);
		run_script ();

		setenv ("STATE", "destroy", 1);
		run_script ();
	}

	exit (0);
}
