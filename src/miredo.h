/*
 * miredo.h - header for miredo.cpp
 * $Id: miredo.h,v 1.5 2004/06/20 17:48:07 rdenisc Exp $
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

// TODO: get rid of that:
struct miredo_setup
{
	uint32_t server_ip, server_ip2;
	IPv6Tunnel *tunnel;
	MiredoServerUDP *server_udp;
	MiredoRelayUDP *relay_udp;
	union teredo_addr addr;
};

extern struct miredo_setup conf;

extern "C"
# endif

# include <inttypes.h> // uint16_t

int miredo_run (uint16_t client_port, const char *server_name,
		const char *prefix_name, const char *ifname);

#endif /* ifndef MIREDO_CONF_H */

