/*
 * common_pkt.h - Declarations for common_pkt.cpp
 * $Id$
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

#ifndef MIREDO_COMMON_PKT_H
# define MIREDO_COMMON_PKT_H

class MiredoCommonUDP;
class IPv6Tunnel;

/*
 * Forwards a Teredo-encapsulated packet on IPv6 tunnel.
 */
int ForwardPacket (const MiredoCommonUDP *from, const IPv6Tunnel *to);

bool is_ipv4_global_unicast (u_long ip);

#endif /* ifndef MIREDO_COMMON_PKT_H */

