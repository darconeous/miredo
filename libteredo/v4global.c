/*
 * v4global.c - Check whether an IPv4 address is global
 * $Id: v4global.c,v 1.1 2004/07/22 17:38:29 rdenisc Exp $
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

#include "v4global.h"

#include <inttypes.h>
#include <netinet/in.h> // ntohl()

/*
 * Checks that ip is a global unicast IPv4 address
 * (Values shoud maybe not be hardcoded that way).
 */
int
is_ipv4_global_unicast (uint32_t ip)
{
	ip = ntohl (ip);
	return
		// Check for class A private range 10.0.0.0/24
		((ip & 0xff000000) != 0x0a000000) &&
		// Check for class A loopback range 127.0.0.0/8
		((ip & 0xff000000) != 0x7f000000) &&
		// Check for "Microsoft" private range 169.254.0.0/16
		((ip & 0xffff0000) != 0xa9fe0000) &&
		// Check for class B private range 172.16.0.0/12
		 ((ip & 0xfff00000) != 0xac100000) &&
		// Check for class C private range 192.168.0.0/16
		((ip & 0xffff0000) != 0xc0a80000) &&
		// Class D (Multicast), E, bad classes:
		((ip & 0xe0000000) != 0xe0000000);
}

