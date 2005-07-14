/*
 * teredo.c - Common Teredo helper functions
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

#if HAVE_CONFIG_H
# include <config.h>
#endif

#if HAVE_STDINT_H
# include <stdint.h> /* Mac OS X needs that */
#endif
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <fcntl.h>
#include <sys/socket.h>

#ifndef SOL_IP
# define SOL_IP IPPROTO_IP
#endif

#include <libteredo/teredo.h>

/*
 * Teredo addresses
 */
const struct in6_addr teredo_restrict =
	{ { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		    0, 0, 'T', 'E', 'R', 'E', 'D', 'O' } } };
const struct in6_addr teredo_cone =
	{ { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		    0x80, 0, 'T', 'E', 'R', 'E', 'D', 'O' } } };

/*
 * Opens a Teredo UDP/IPv4 socket.
 */
int teredo_socket (uint32_t bind_ip, uint16_t port)
{
	struct sockaddr_in myaddr = { };
	int fd, flags;

	myaddr.sin_family = AF_INET;
	myaddr.sin_port = port;
	myaddr.sin_addr.s_addr = bind_ip;
#ifdef HAVE_SA_LEN
	myaddr.sin_len = sizeof (myaddr);
#endif

	fd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == -1)
		return -1; // failure

	flags = fcntl (fd, F_GETFL, 0);
	if (flags != -1)
		fcntl (fd, F_SETFL, O_NONBLOCK | flags);

	if (bind (fd, (struct sockaddr *)&myaddr, sizeof (myaddr)))
		return -1;

	flags = 1;
	setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof (flags));
#ifdef IP_PMTUDISC_DONT
	/* 
	 * This tells the (Linux) kernel not to set the Don't Fragment flags
	 * on UDP packets we send. This is recommended by the Teredo
	 * specifiation.
	 */
	flags = IP_PMTUDISC_DONT;
	setsockopt (fd, SOL_IP, IP_MTU_DISCOVER, &flags, sizeof (flags));
#endif
	/*
	 * Teredo multicast packets always have a TTL of 1.
	 */
	setsockopt (fd, SOL_IP, IP_MULTICAST_TTL, &flags, sizeof (flags));
	return fd;
}


int teredo_send (int fd, const void *packet, size_t plen,
                 uint32_t dest_ip, uint16_t dest_port)
{
	struct sockaddr_in nat_addr;

	nat_addr.sin_family = AF_INET;
	nat_addr.sin_port = dest_port;
	nat_addr.sin_addr.s_addr = dest_ip;
#ifdef HAVE_SA_LEN
	nat_addr.sin_len = sizeof (nat_addr);
#endif

	return sendto (fd, packet, plen, 0, (struct sockaddr *)&nat_addr,
			sizeof (nat_addr)) == (int)plen ? 0 : -1;
}
