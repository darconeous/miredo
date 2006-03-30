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

static inline uint16_t
sum16 (const uint16_t *data, size_t length, uint32_t sum32)
{
	for (; length >= 2; length -= 2)
		sum32 += *data++;

	if (length) // trailing byte if length is odd
		sum32 += ntohs((*(const uint8_t *)data) << 8);

	while (sum32 > 0xffff)
		sum32 = (sum32 & 0xffff) + (sum32 >> 16);
	
	return sum32;
}

/*
 * Computes an IPv6 Pseudo-header 16-bits checksum
 */
static inline uint16_t 
ipv6_sum (const struct ip6_hdr *ip6)
{
	uint32_t sum32 = 0;
	size_t i;

	/* Pseudo-header sum */
	for (i = 0; i < 16; i += 2)
		sum32 += *(uint16_t *)(&ip6->ip6_src.s6_addr[i]);
	for (i = 0; i < 16; i += 2)
		sum32 += *(uint16_t *)(&ip6->ip6_dst.s6_addr[i]);

	sum32 += ip6->ip6_plen + ntohs (ip6->ip6_nxt);

	while (sum32 > 0xffff)
		sum32 = (sum32 & 0xffff) + (sum32 >> 16);

	return sum32;
}

/*
 * Computes an ICMPv6 over IPv6 packet checksum
 */
static inline uint16_t
icmp6_checksum (const struct ip6_hdr *ip6, const struct icmp6_hdr *icmp6)
{
	return ~sum16 ((uint16_t *)icmp6, ntohs (ip6->ip6_plen),
			ipv6_sum (ip6));
}

#endif

