/*
 * ipv6-tunnel.h - IPv6 interface class declaration
 * $Id$
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
 * All methods are thread-safe.
 * The constructors and the destructor must be called only one time per
 * process (NOT per thread) and object
 *
 * All methods will report error messages via syslog(). Make sure you called
 * openlog() before you create a tunnel.
 */

class IPv6Tunnel
{
	private:
		int fd;
		char *ifname;

	public:
		/*
		 * Tries to allocate a tunnel interface from the kernel.
		 * req_name may be an interface name for the virtual network
		 * device (it might be ignored on some OSes).
		 *
		 * If it failed, operator! will return true.
		 */
		IPv6Tunnel (const char *req_name = NULL);

		/*
		 * Removes a tunnel from the kernel.
		 * BEWARE: if you fork, child processes must call the
		 * destructor too (or CleanUp ()).
		 *
		 * The kernel will destroy the tunnel interface once all
		 * process called the destructor and/or terminated.
		 */
		~IPv6Tunnel ();

		/*
		 * Removes the tunnel from the kernel and releases any other
		 * allocated resources. The object can no longer be used to
		 * send, receive packets or to change its interfaces settings
		 * thereafter.
		 *
		 * This is NOT thread-safe. Lock the object exclusively before
		 * you call this function.
		 */
		void CleanUp (void);

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
		 * This function will block if there is no input.
		 *
		 * Returns the packet length on success,
		 * -1 if no packet were to be received.
		 */
		int ReceivePacket (const fd_set *readset, void *buffer,
					size_t maxlen);

		/*
		 * Sends an IPv6 packet at <packet>, of length <len>.
		 * Returns the number of bytes succesfully transmitted on
		 * success, -1 on error.
		 */
		int SendPacket (const void *packet, size_t len) const;
};


#endif /* ifndef MIREDO_IPV6TUNNEL_H */

