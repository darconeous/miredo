/*
 * conf.h - Configuration structure declaration
 * $Id: conf.h,v 1.1 2004/06/14 14:45:58 rdenisc Exp $
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

#ifndef MIREDO_CONF_H
# define MIREDO_CONF_H

# include <netinet/in.h> // struct in6_addr

class IPv6Tunnel;
class MiredoServerUDP;
class MiredoRelayUDP;

struct miredo_configuration
{
	uint32_t server_ip, server_ip2;
	IPv6Tunnel *tunnel;
	MiredoServerUDP *server_udp;
	MiredoRelayUDP *relay_udp;
	struct in6_addr addr;
};

extern struct miredo_configuration conf;

#endif /* ifndef MIREDO_CONF_H */

