/*
 * ipv6-tunnel.h - IPv6 interface class declaration
 * $Id: ipv6-tunnel.h,v 1.3 2004/08/17 17:31:14 rdenisc Exp $
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

#ifndef MIREDO_IPV6_TUNNEL_H
# define MIREDO_IPV6_TUNNEL_H

# ifndef __cplusplus
#  error C++ only header
# endif

# include <stddef.h>
# include <inttypes.h>

# include <sys/types.h>
# include <sys/select.h>

struct ip6_hdr;

/*
 * All methods, except the constructors and the destructor, are thread-safe.
 */

class IPv6Tunnel
{
	private:
		int fd;
		char *ifname;

	public:
		IPv6Tunnel (const char *req_name = NULL);
		~IPv6Tunnel ();

		int operator! (void)
		{
			return (fd == -1) || (ifname == NULL);
		}

		int SetState (bool up) const;

		int BringUp (void) const
		{
			return SetState (true);
		}

		int BringDown (void) const
		{
			return SetState (false);
		}

		int AddAddress (const struct in6_addr *addr,
				unsigned prefix_len = 64) const;
		int DelAddress (const struct in6_addr *addr,
				unsigned prefix_len = 64) const;

		int SetMTU (unsigned mtu) const;

		int AddRoute (const struct in6_addr *addr,
				unsigned prefix_len) const;
		int DelRoute (const struct in6_addr *addr,
				unsigned prefix_len) const;

		/*
		 * Registers file descriptors in an fd_set for use with
		 * select(). Returns the "biggest" file descriptor
		 * registered (useful as the first parameter to selcet()).
		 */
		int RegisterReadSet (fd_set *readset) const;

		/*
		 * Checks an fd_set, receives a packet and puts the result in
		 * <buffer>. <maxlen>, which is the length of the buffer in
		 * bytes, should be 65535.
		 *
		 * Returns the packet length on success,
		 * -1 if no packet were to be received.
		 */
		int ReceivePacket (const fd_set *readset, void *buffer,
					size_t maxlen);

		/*
		 * Sends an IPv6 packet at <packet>, of length <len>.
		 */
		int SendPacket (const void *packet, size_t len) const;
};


#endif /* ifndef MIREDO_IPV6TUNNEL_H */

