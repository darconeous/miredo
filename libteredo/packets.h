/**
 * @file packets.h
 * @brief helpers to send Teredo packets
 *
 * $Id$
 */

/***********************************************************************
 *  Copyright © 2004-2007 Rémi Denis-Courmont.                         *
 *  This program is free software; you can redistribute and/or modify  *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; version 2 of the license, or (at  *
 *  your option) any later version.                                    *
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
struct icmp6_hdr;

# ifdef __cplusplus
extern "C" {
#endif


/**
 * Checks that the packet is an ICMPv6 Echo reply and authenticates it.
 *
 * @return 0 if that is the case, -1 otherwise.
 */
int CheckPing (const teredo_packet *packet);
int CheckBubble (const teredo_packet *packet);


/**
 * Returs true if the packet whose header is passed as a parameter looks
 * like a Teredo bubble.
 */
static inline bool IsBubble (const struct ip6_hdr *hdr)
{
	return (hdr->ip6_plen == 0) && (hdr->ip6_nxt == IPPROTO_NONE);
}


/**
 * Sends a Teredo Bubble.
 *
 * @param dst Teredo destination address.
 * @param indirect determines whether the bubble is sent to the server (true)
 * or the client (if indirect is false) - as determined from dst.
 *
 * @return 0 on success, -1 on error.
 */
int SendBubbleFromDst (int fd, const struct in6_addr *dst, bool indirect);

/**
 * Sends a Teredo Bubble.
 *
 * @param ip destination IPv4
 * @param port destination UDP port
 * @param src pointer to source IPv6 address
 * @param dst pointer to destination IPv6 address
 *
 * @return 0 on success, -1 on error.
 */
int teredo_send_bubble (int fd, uint32_t ip, uint16_t port,
                        const struct in6_addr *src,
                        const struct in6_addr *dst);

static inline int teredo_reply_bubble (int fd, uint32_t ip, uint16_t port,
                                       const struct ip6_hdr *req)
{
	return teredo_send_bubble (fd, ip, port, &req->ip6_dst, &req->ip6_src);
}

/**
 * Sends a router solication with an Authentication header.
 *
 * @param fd socket through which the RS will be sent
 * @param server_ip server IPv4 address toward which the solicitation should
 * be encapsulated (network byte order)
 * @param nonce pointer to the 8-bytes authentication nonce
 * @param cone whether to send a Teredo “cone” solicitation
 *
 * @return 0 on success, -1 on error.
 */
int teredo_send_rs (int fd, uint32_t server_ip,
                    const unsigned char *nonce, bool cone);

/**
 * Validates a router advertisement from the Teredo server.
 * The RA must be of type cone if and only if cone is true.
 * Prefix, flags, mapped port and IP are returned through newaddr.
 * If there is a MTU option in the packet, the specified MTU value will
 * be returned at mtu. If not, the value pointed to by mtu will not be
 * modified.
 *
 * Assumption:
 * The IPv6 header is valid (ie. version 6, plen matches packet's length, and
 * the full packet is at least 40 bytes long).
 *
 * @param packet Teredo packet to be checked
 * @param newaddr upon succesful return, the  inferred Teredo client address
 * (_not_ including any randomized flags).
 * @param cone whether the RA should be a reply to “cone” RS
 * @param mtu [out] MTU parameter found in the RA, not modified if the RA
 * had no MTU option. Undefined on error.
 *
 * @return 0 on success, -1 on error.
 */
int teredo_parse_ra (const teredo_packet *restrict packet,
                     union teredo_addr *restrict newaddr,
                     bool cone, uint16_t *restrict mtu);

/**
 * Sends an ICMPv6 Echo request toward an IPv6 node through the Teredo server.
 */
int SendPing (int fd, const union teredo_addr *src,
              const struct in6_addr *dst);

/**
 * Builds an ICMPv6 error message with specified type and code from an IPv6
 * packet. The output buffer must be at least 1240 bytes long and have
 * adequate IPv6 packet alignment. The ICMPv6 checksum is not set as they are
 * not enough information for its computation.
 *
 * @param out output buffer
 * @param type ICMPv6 error type
 * @param code ICMPv6 error code
 * @param in original IPv6 packet
 * @param inlen original IPv6 packet length (including IPv6 header)
 *
 * @return the actual size of the generated error message, or zero if no
 * ICMPv6 packet should be generated. Never fails.
 */
int BuildICMPv6Error (struct icmp6_hdr *restrict out,
                      uint8_t type, uint8_t code,
                      const struct ip6_hdr *restrict in, size_t inlen);

# if 0
/**
 * Builds an ICMPv6/IPv6 error message with specified type and code from an
 * IPv6 packet. The output buffer must be at least 1280 bytes long and have
 * adequate IPv6 packet alignment.
 *
 * @param out output buffer
 * @param type ICMPv6 error type
 * @param code ICMPv6 error code
 * @param src source IPv6 address for ICMPv6 message
 * @param in original IPv6 packet
 * @param len original IPv6 packet length (including IPv6 header)
 *
 * @return the actual size of the generated error message, or zero if no
 * ICMPv6/IPv6 packet should be sent. Never fails.
 */
int BuildIPv6Error (struct ip6_hdr *out, const struct in6_addr *src,
                    uint8_t type, uint8_t code, const void *in, uint16_t len);
#endif

# ifdef __cplusplus
}
#endif


#endif
