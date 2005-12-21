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

# ifdef __cplusplus
extern "C" {
# endif

int libteredo_preinit (void);
int libteredo_client_preinit (void);
void libteredo_terminate (void);

# ifdef __cplusplus
}

struct ip6_hdr;
struct in6_addr;

struct teredo_packet;
struct teredo_maintenance;
class TeredoRelay;


typedef struct teredo_state
{
	union teredo_addr addr;
	uint16_t mtu;
	bool up;
	bool cone;
} teredo_state;

#ifdef MIREDO_TEREDO_CLIENT
typedef struct teredo_maintenance
{
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t received;
	const teredo_packet *incoming;
	pthread_barrier_t processed;
	TeredoRelay *relay; /* FIXME: provisional */

	teredo_state *state;
} teredo_maintenance;
#endif


// big TODO: make all functions re-entrant safe
//           make all functions thread-safe
class TeredoRelay
{
	private:
		class peer;

		/*** Internal stuff ***/
		struct
		{
			void *ptr;
			unsigned peerNumber;
		} list;

	public: /* FIXME: temporarily public */
		int fd;

	private:
		bool allowCone;

		peer *AllocatePeer (const struct in6_addr *addr);
		peer *FindPeer (const struct in6_addr *addr);

		void SendUnreach (int code, const void *in, size_t inlen);

		teredo_state state;

#ifdef MIREDO_TEREDO_CLIENT
		teredo_maintenance *maintenance;
		uint32_t server_ip2;

		int PingPeer (const struct in6_addr *addr, peer *p) const;
		bool IsServerPacket (const teredo_packet *packet) const;
		void ProcessQualificationPacket (const teredo_packet *p);
		void ProcessMaintenancePacket (const teredo_packet *p);

	public: /* FIXME: temporary */
		/*
		 * Tries to define the Teredo client IPv6 address. This is an
		 * indication that the Teredo tunneling interface is ready.
		 * The default implementation in base class TeredoRelay does
		 * nothing.
		 *
		 * This function might be called from a separate thread.
		 */
		virtual void NotifyUp (const struct in6_addr *addr,
		                      uint16_t mtu = 1280) { }

		/*
		 * Indicates that the Teredo tunneling interface is no longer
		 * ready to process packets.
		 * Any packet sent when the relay/client is down will be
		 * ignored.
		 *
		 * This function might be called from a separate thread.
		 */
		virtual void NotifyDown (void) { }
	private:
#endif

		/*** Callbacks ***/
		/*
		 * Sends an IPv6 packet from Teredo toward the IPv6 Internet.
		 *
		 * Returns 0 on success, -1 on error.
		 */
		virtual int SendIPv6Packet (const void *packet, size_t length) = 0;

		virtual void EmitICMPv6Error (const void *packet, size_t length,
		                              const struct in6_addr *dst);

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
			return (fd == -1)
#ifdef MIREDO_TEREDO_CLIENT
				|| (IsClient () && (maintenance == NULL));
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
			return state.addr.teredo.server_ip;
		}

		uint32_t GetServerIP2 (void) const
		{
			return server_ip2;
		}

		/*static unsigned QualificationRetries;
		static unsigned QualificationTimeOut;
		static unsigned ServerNonceLifetime;
		static unsigned RestartDelay;*/
#endif
		static unsigned MaxPeers;
		static unsigned MaxQueueBytes;
		static unsigned IcmpRateLimitMs;

		uint32_t GetPrefix (void) const
		{
			return state.addr.teredo.prefix;
		}

		/*
		 * Returns true if the relay/client is behind a cone NAT.
		 * The result is not meaningful if the client is not fully
		 * qualified.
		 */
		bool IsCone (void) const
		{
			return state.cone;
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

