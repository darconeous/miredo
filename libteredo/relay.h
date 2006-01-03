/*
 * relay.h - Teredo relay declaration
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

# include <stdbool.h>

# ifdef __cplusplus
extern "C" {
# endif

int libteredo_preinit (void);
int libteredo_client_preinit (void);
void libteredo_terminate (void);

struct in6_addr;

typedef struct libteredo_tunnel libteredo_tunnel;

libteredo_tunnel *libteredo_tunnel_create (uint32_t ipv4, uint16_t port);
void libteredo_tunnel_destroy (libteredo_tunnel *t);

int libteredo_tunnel_set_prefix (libteredo_tunnel *t, uint32_t pref);
int libteredo_tunnel_set_MTU (libteredo_tunnel *t, uint16_t mtu);
int libteredo_tunnel_set_cone_flag (libteredo_tunnel *t, bool flag);

int libteredo_tunnel_set_client_mode (libteredo_tunnel *t, const char *s1,
                                      const char *s2);

typedef void (*libteredo_recv_cb) (libteredo_tunnel *, const void *, size_t);
void libteredo_set_recv_callback (libteredo_tunnel *t, libteredo_recv_cb cb);
int libteredo_send (libteredo_tunnel *t, const void *data, size_t n);

typedef void (*libteredo_icmpv6_cb) (libteredo_tunnel *, const void *, size_t,
                                     const struct in6_addr *dst);
void libteredo_set_icmpv6_callback (libteredo_tunnel *t,
                                    libteredo_icmpv6_cb cb);

typedef void (*libteredo_state_up_cb) (libteredo_tunnel *,
                                       const struct in6_addr *, uint16_t);
typedef void (*libteredo_state_down_cb) (libteredo_tunnel *);
void libteredo_set_state_cb (libteredo_tunnel *t, libteredo_state_up_cb u,
                             libteredo_state_down_cb d);

/* FIXME: should be internal */
typedef struct teredo_state
{
	union teredo_addr addr;
	uint16_t mtu;
	bool up;
	bool cone;
} teredo_state;

# ifdef __cplusplus
}

struct ip6_hdr;
struct in6_addr;

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

