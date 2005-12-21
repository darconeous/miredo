/*
 * packets.h - helpers to send Teredo packet
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

#ifndef LIBTEREDO_TEREDO_PACKETS_H
# define LIBTEREDO_TEREDO_PACKETS_H

struct in6_addr;
struct ip6_hdr;


# ifdef __cplusplus
extern "C" {
#endif

int ParseRA (const teredo_packet *packet, union teredo_addr *newaddr,
             bool cone, uint16_t *mtu);

int CheckPing (const teredo_packet *packet);


int SendBubbleFromDst (int fd, const struct in6_addr *dst, bool cone,
                       bool indirect = true);

int SendBubble (int fd, uint32_t ip, uint16_t port,
                const struct in6_addr *src, const struct in6_addr *dst);

int SendRS (int fd, uint32_t server_ip,
            const unsigned char *nonce, bool cone);

int SendPing (int fd, const union teredo_addr *src,
              const struct in6_addr *dst);

int BuildICMPv6Error (struct icmp6_hdr *out, uint8_t type, uint8_t code,
                      const void *in, uint16_t inlen);

int BuildIPv6Error (struct ip6_hdr *out, const struct in6_addr *src,
                    uint8_t type, uint8_t code, const void *in, uint16_t len);

# ifdef __cplusplus
}
#endif


#endif
