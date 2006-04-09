/*
 * relay.h - Teredo relay internal declaration
 * $Id$
 *
 * See "Teredo: Tunneling IPv6 over UDP through NATs"
 * for more information
 */

/***********************************************************************
 *  Copyright © 2004-2006 Rémi Denis-Courmont.                         *
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

#ifndef LIBTEREDO_RELAY_H
# define LIBTEREDO_RELAY_H

# include <stdbool.h>

# ifdef __cplusplus
struct teredo_packet;
struct teredo_maintenance;
struct teredo_peerlist;
class teredo_peer;
class TeredoRelay;

// big TODO: make all functions re-entrant safe
//           make all functions thread-safe
class TeredoRelay
{
	private:
		struct teredo_peerlist *list;
		int fd;
		bool allowCone;

		void SendUnreach (int code, const void *in, size_t inlen);

		teredo_state state;
		pthread_rwlock_t state_lock;

#ifdef MIREDO_TEREDO_CLIENT
		struct teredo_maintenance *maintenance;

		/*** Callbacks ***/

		/*
		 * Tries to define the Teredo client IPv6 address. This is an
		 * indication that the Teredo tunneling interface is ready.
		 * The default implementation in base class TeredoRelay does
		 * nothing.
		 *
		 * This function might be called from a separate thread.
		 */
		virtual void NotifyUp (const struct in6_addr *, uint16_t)
		{
		}

		/*
		 * Indicates that the Teredo tunneling interface is no longer
		 * ready to process packets.
		 * Any packet sent when the relay/client is down will be
		 * ignored.
		 *
		 * This function might be called from a separate thread.
		 */
		virtual void NotifyDown (void)
		{
		}

		static void StateChange (const teredo_state *, void *self);
#endif
		virtual void EmitICMPv6Error (const void *packet, size_t length,
		                              const struct in6_addr *dst);

	public: /* FIXME: temporarily public callback because of teredo_list */
		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet, size_t length) = 0;

	protected:
		/*
		 * Creates a Teredo relay manually (ie. one that does not
		 * qualify with a Teredo server and has no Teredo IPv6
		 * address). The prefix must therefore be specified.
		 *
		 * If port is nul, the OS will choose an available UDP port
		 * for communication. This is NOT a good idea if you are
		 * behind a fascist firewall, as the port might be blocked.
		 */
		TeredoRelay (uint32_t pref, uint16_t port /*= 0*/,
		             uint32_t ipv4 /* = 0 */, bool cone /*= true*/);

		/*
		 * Creates a Teredo client/relay automatically. The client
		 * will try to qualify and get a Teredo IPv6 address from the
		 * server.
		 *
		 * TODO: support for secure qualification
		 */
		TeredoRelay (const char *server, const char *server2,
		             uint16_t port = 0, uint32_t ipv4 = 0);

	public:
		virtual ~TeredoRelay ();

		/*
		 * Transmits a packet from IPv6 Internet via Teredo,
		 * i.e. performs "Packet transmission".
		 * Not thread-safe yet.
		 *
		 * It is assumed that len > 40 and that packet is properly
		 * aligned. Otherwise, behavior is undefined.
		 */
		int SendPacket (const struct ip6_hdr *packet, size_t len);

		/*
		 * Receives a packet from Teredo to IPv6 Internet, i.e.
		 * performs "Packet reception". This function will NOT block until
		 * a Teredo packet is received (but maybe it should).
		 * Not thread-safe yet.
		 */
		int ReceivePacket ();

#ifdef MIREDO_TEREDO_CLIENT
		bool IsClient (void) const
		{
			return maintenance != NULL;
		}

		/*static unsigned QualificationRetries;
		static unsigned QualificationTimeOut;
		static unsigned ServerNonceLifetime;
		static unsigned RestartDelay;*/
#endif
		static unsigned MaxPeers;
		static unsigned MaxQueueBytes;
		static unsigned IcmpRateLimitMs;

		void SetConeIgnore (bool ignore = true)
		{
			allowCone = !ignore;
		}

		int RegisterReadSet (fd_set *rs) const
		{
			if (fd != -1)
				FD_SET (fd, rs);
			return fd;
		}
};

# endif /* ifdef __cplusplus */
#endif /* ifndef MIREDO_RELAY_H */

