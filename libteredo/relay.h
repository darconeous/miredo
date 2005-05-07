/*
 * relay.h - Teredo relay peers list declaration
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

#ifndef LIBTEREDO_RELAY_H
# define LIBTEREDO_RELAY_H

# include <sys/time.h> // struct timeval
# include <pthread.h>

# include <libteredo/relay-udp.h> // FIXME: remove?
//-> when local discovery is implemented?

struct ip6_hdr;
struct in6_addr;
union teredo_addr;
class TeredoPacket;


// big TODO: make all functions re-entrant safe
//           make all functions thread-safe
class TeredoRelay
{
	private:
		class peer;
		class OutQueue;
		friend class OutQueue;
		class InQueue;
		friend class InQueue;

		/*** Internal stuff ***/
		union teredo_addr addr;
		class peer *head;

		TeredoRelayUDP sock;
		bool allowCone, isCone;

		peer *AllocatePeer (const struct in6_addr *addr);
		peer *FindPeer (const struct in6_addr *addr);

		int SendUnreach (int code, const void *in, size_t inlen);

#ifdef MIREDO_TEREDO_CLIENT
		struct
		{
			pthread_t thread;
			pthread_mutex_t lock;
			pthread_cond_t received;

			uint8_t nonce[8];

			unsigned state;
			bool success;
			bool working;
		} maintenance;

		static void *do_maintenance (void *object);
		void MaintenanceThread (void);

		uint32_t server_ip2;
		uint16_t mtu;

		int PingPeer (peer *p) const;
		bool IsServerPacket (const TeredoPacket *packet) const;
		int ProcessQualificationPacket (const TeredoPacket *p);

		/*
		 * Tries to define the Teredo client IPv6 address. This is an
		 * indication that the Teredo tunneling interface is ready.
		 * The default implementation in base class TeredoRelay does
		 * nothing.
		 *
		 * Returns 0 on success, -1 on error.
		 * TODO: handle error in calling function.
		 */
		virtual int NotifyUp (const struct in6_addr *addr,
		                      uint16_t mtu = 1280);

		/*
		 * Indicates that the Teredo tunneling interface is no longer
		 * ready to process packets.
		 * Any packet sent when the relay/client is down will be
		 * ignored.
		 */
		virtual int NotifyDown (void);
#endif

		/*** Callbacks ***/
		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet,
						size_t length) = 0;

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
		TeredoRelay (uint32_t server_ip, uint32_t server_ip2,
		             uint16_t port = 0, uint32_t ipv4 = 0);

	public:
		virtual ~TeredoRelay ();

		bool operator! (void) const
		{
			return !sock
#ifdef MIREDO_TEREDO_CLIENT
				|| (IsClient () && !maintenance.working)
#endif
			;
		}

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
		uint32_t GetServerIP (void) const
		{
			return addr.teredo.server_ip;
		}

		uint32_t GetServerIP2 (void) const
		{
			return server_ip2;
		}

		static unsigned QualificationRetries;
		static unsigned QualificationTimeOut;
		static unsigned RestartDelay;
		static unsigned ServerNonceLifetime;
#endif

		/*
		 * Returns true if the relay/client is behind a cone NAT.
		 * The result is not meaningful if the client is not fully
		 * qualified.
		 */
		uint32_t GetPrefix (void) const
		{
			return addr.teredo.prefix;
		}

		bool IsCone (void) const
		{
			return isCone;
		}

		uint16_t GetMappedPort (void) const
		{
			return IN6_TEREDO_PORT (&addr);
		}

		uint32_t GetMappedIP (void) const
		{
			return IN6_TEREDO_IPV4 (&addr);
		}

		bool IsRelay (void) const
		{
#ifdef MIREDO_TEREDO_CLIENT
			return GetServerIP () == 0;
#else
			return true;
#endif
		}

		bool IsClient (void) const
		{
			return !IsRelay ();
		}

		bool IsRunning (void) const
		{
			return is_valid_teredo_prefix (GetPrefix ())
#ifdef MIREDO_TEREDO_CLIENT
				&& (maintenance.state == 0)
#endif
			;
		}

		void SetConeIgnore (bool ignore = true)
		{
			allowCone = !ignore;
		}

		int RegisterReadSet (fd_set *rs) const
		{
			return sock.RegisterReadSet (rs);
		}
};

#endif /* ifndef MIREDO_RELAY_H */

