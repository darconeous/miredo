/*
 * miredo.h - header for miredo.cpp
 * $Id: miredo.h,v 1.10 2004/07/11 10:08:13 rdenisc Exp $
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
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

#ifndef MIREDO_MIREDO_H
# define MIREDO_MIREDO_H

# ifdef __cplusplus
#  include "teredo.h" // union teredo_addr

class IPv6Tunnel;
class MiredoServerUDP;
class MiredoRelayUDP;

// TODO: move that to mireco.cpp/get rid of it
struct miredo_setup
{
	uint32_t server_ip, server_ip2, prefix;
};

extern struct miredo_setup conf;

extern "C"
# endif

# include <inttypes.h> // uint16_t
# include <sys/types.h> // uid_t

int miredo (uint16_t client_port, const char *server_name,
		const char *prefix_name, const char *ifname);
extern uid_t unpriv_uid;

#endif /* ifndef MIREDO_CONF_H */

