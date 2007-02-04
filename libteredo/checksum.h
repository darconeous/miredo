/*
 * checksum.h - ICMPv6 checksumming
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2005 Rémi Denis-Courmont.                         *
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

#ifndef LIBTEREDO_TEREDO_CHECKSUM_H
# define LIBTEREDO_TEREDO_CHECKSUM_H

# include <sys/types.h>
# include <netinet/in.h>

/*
 * Computes an ICMPv6 over IPv6 packet checksum.
 * Jumbo datagrams not supported (but you don't care, do you?).
 */
static inline uint16_t
icmp6_checksum (const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6)
{
	struct iovec iov = { (void *)icmp6, ntohs (ip6->ip6_plen) };
	return teredo_cksum (&ip6->ip6_src, &ip6->ip6_dst, IPPROTO_ICMPV6, &iov, 1);
}

#endif

