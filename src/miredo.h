/*
 * miredo.h - header for miredo.cpp
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#ifndef MIREDO_MIREDO_H
# define MIREDO_MIREDO_H

# ifdef __cplusplus
/* FIXME: relying on main.c being not C++ sucks big times */

struct miredo_conf
{
	int mode;
	char *ifname;
	union teredo_addr prefix;
	uint32_t server_ip, server_ip2;
	uint32_t bind_ip;
	uint16_t bind_port;
	union
	{
		struct
		{
			bool default_route;
		} client;
		struct
		{
			uint16_t adv_mtu;
		} relay;
	} u;
#define default_route u.client.default_route
#define adv_mtu       u.relay.adv_mtu
};

extern int signalfd[2];

extern "C"
{
# endif

# include <sys/types.h> // uid_t

int miredo (const char *conffile, const char *server_name);
int drop_privileges (void);

# ifdef __cplusplus
}
# endif

extern uid_t unpriv_uid;

#endif /* ifndef MIREDO_CONF_H */

